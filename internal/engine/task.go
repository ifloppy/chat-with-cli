package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/ifloppy/chat-with-cli/internal/protocol"
	"github.com/ifloppy/chat-with-cli/internal/securefile"
)

type TaskManager struct {
	engine  *Engine
	dir     string
	mu      sync.RWMutex
	tasks   map[string]*Task
	history map[string]TaskInfo
	slots   chan struct{}
}

type Task struct {
	mu       sync.RWMutex
	info     TaskInfo
	pty      *os.File
	logPath  string
	tempDir  string
	copyDone chan struct{}
}

func NewTaskManager(engine *Engine, dir string) *TaskManager {
	_ = os.MkdirAll(dir, 0o700)
	m := &TaskManager{
		engine: engine, dir: dir,
		tasks: make(map[string]*Task), history: make(map[string]TaskInfo),
		slots: make(chan struct{}, engine.cfg.MaxActiveTasks),
	}
	m.loadHistory()
	return m
}

func (m *TaskManager) loadHistory() {
	matches, _ := filepath.Glob(filepath.Join(m.dir, "*.json"))
	for _, path := range matches {
		fileInfo, err := os.Lstat(path)
		if err != nil || fileInfo.Mode()&os.ModeSymlink != 0 || !fileInfo.Mode().IsRegular() || securefile.CheckSingleLink(fileInfo, "task history") != nil {
			continue
		}
		data, err := securefile.Read(path, "task history")
		if err != nil {
			continue
		}
		var info TaskInfo
		if json.Unmarshal(data, &info) != nil || !validTaskID(info.ID) {
			continue
		}
		if info.State == "running" {
			if processExists(info.PID) {
				info.State = "orphaned_running"
			} else {
				info.State = "orphaned"
			}
		}
		m.history[info.ID] = info
	}
}

func processExists(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

func (m *TaskManager) Start(ctx context.Context, in StartTaskInput) (TaskInfo, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := m.engine.checkContext(ctx); err != nil {
		return TaskInfo{}, err
	}
	if !m.engine.cfg.AllowExec {
		return TaskInfo{}, errors.New("shell execution is disabled; start the agent with --allow-exec")
	}
	if strings.TrimSpace(in.Command) == "" {
		return TaskInfo{}, errors.New("command is required")
	}
	if len(in.Command) > 256*1024 {
		return TaskInfo{}, errors.New("command is too large (maximum 256 KiB)")
	}
	if len(in.Name) > 256 {
		return TaskInfo{}, errors.New("task name is too large (maximum 256 bytes)")
	}
	cwd, err := m.engine.ResolvePath(in.Cwd)
	if err != nil {
		return TaskInfo{}, err
	}
	if st, err := os.Stat(cwd); err != nil || !st.IsDir() {
		return TaskInfo{}, fmt.Errorf("cwd is not a directory: %s", cwd)
	}
	select {
	case m.slots <- struct{}{}:
	case <-ctx.Done():
		return TaskInfo{}, ctx.Err()
	default:
		return TaskInfo{}, fmt.Errorf("active task limit reached (%d)", cap(m.slots))
	}
	releaseSlot := true
	defer func() {
		if releaseSlot {
			<-m.slots
		}
	}()
	if err := m.engine.checkContext(ctx); err != nil {
		return TaskInfo{}, err
	}
	id := protocol.NewID()
	logPath := filepath.Join(m.dir, id+".log")
	tempDir := ""
	if m.engine.cfg.ExecSandbox == "landlock" {
		tempDir = filepath.Join(m.dir, id+".tmp")
		if err := os.Mkdir(tempDir, 0o700); err != nil {
			return TaskInfo{}, fmt.Errorf("create private task temp directory: %w", err)
		}
	}
	cleanupTemp := func() {
		if tempDir != "" {
			_ = os.RemoveAll(tempDir)
		}
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		cleanupTemp()
		return TaskInfo{}, err
	}
	if info, statErr := logFile.Stat(); statErr != nil || !info.Mode().IsRegular() {
		_ = logFile.Close()
		cleanupTemp()
		if statErr != nil {
			return TaskInfo{}, statErr
		}
		return TaskInfo{}, errors.New("task log must be a regular file")
	} else if linkErr := securefile.CheckSingleLink(info, "task log"); linkErr != nil {
		_ = logFile.Close()
		cleanupTemp()
		return TaskInfo{}, linkErr
	}
	cmd, err := m.engine.command(in.Command, cwd, tempDir)
	if err != nil {
		_ = logFile.Close()
		_ = os.Remove(logPath)
		cleanupTemp()
		return TaskInfo{}, err
	}
	if m.engine.cfg.ExecSandbox == "none" {
		cmd.Dir = cwd
	}
	cmd.Env = mergeEnv(os.Environ(), in.Env)
	if tempDir != "" {
		cmd.Env = setEnv(cmd.Env, "TMPDIR", tempDir)
		cmd.Env = setEnv(cmd.Env, "TMP", tempDir)
		cmd.Env = setEnv(cmd.Env, "TEMP", tempDir)
		// A Landlock child cannot read the operator's real home directory. Give
		// common tools a private synthetic home so git, Go, npm, and similar
		// tooling do not fail while probing private dotfiles or caches outside
		// the workspace. The directory is already granted to the child and is
		// removed when the task finishes.
		cmd.Env = setEnv(cmd.Env, "HOME", tempDir)
		cmd.Env = setEnv(cmd.Env, "USERPROFILE", tempDir)
		cmd.Env = setEnv(cmd.Env, "XDG_CONFIG_HOME", filepath.Join(tempDir, "config"))
		cmd.Env = setEnv(cmd.Env, "XDG_CACHE_HOME", filepath.Join(tempDir, "cache"))
		cmd.Env = setEnv(cmd.Env, "XDG_DATA_HOME", filepath.Join(tempDir, "data"))
		cmd.Env = setEnv(cmd.Env, "XDG_STATE_HOME", filepath.Join(tempDir, "state"))
		cmd.Env = setEnv(cmd.Env, "GIT_CONFIG_GLOBAL", filepath.Join(tempDir, "gitconfig"))
		cmd.Env = setEnv(cmd.Env, "GOPATH", filepath.Join(tempDir, "go"))
		cmd.Env = setEnv(cmd.Env, "GOMODCACHE", filepath.Join(tempDir, "go", "pkg", "mod"))
		cmd.Env = setEnv(cmd.Env, "GOCACHE", filepath.Join(tempDir, "go-cache"))
		cmd.Env = setEnv(cmd.Env, "npm_config_cache", filepath.Join(tempDir, "npm-cache"))
		cmd.Env = setEnv(cmd.Env, "PIP_CACHE_DIR", filepath.Join(tempDir, "pip-cache"))
		cmd.Env = setEnv(cmd.Env, "CARGO_HOME", filepath.Join(tempDir, "cargo"))
	}
	if err := m.engine.checkContext(ctx); err != nil {
		_ = logFile.Close()
		_ = os.Remove(logPath)
		cleanupTemp()
		return TaskInfo{}, err
	}
	ptmx, err := pty.Start(cmd)
	if err != nil {
		_ = logFile.Close()
		_ = os.Remove(logPath)
		cleanupTemp()
		return TaskInfo{}, fmt.Errorf("start PTY: %w", err)
	}
	killStartedProcess := func() {
		pid := cmd.Process.Pid
		if killErr := syscall.Kill(-pid, syscall.SIGKILL); killErr != nil {
			_ = cmd.Process.Kill()
		}
	}
	if err := m.engine.checkContext(ctx); err != nil {
		killStartedProcess()
		_ = ptmx.Close()
		_ = logFile.Close()
		_ = os.Remove(logPath)
		_, _ = cmd.Process.Wait()
		cleanupTemp()
		return TaskInfo{}, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = compactCommand(in.Command, 72)
	}
	info := TaskInfo{
		ID: id, Name: name, Command: in.Command, Cwd: cwd,
		PID: cmd.Process.Pid, State: "running", StartedAt: time.Now(),
	}
	task := &Task{info: info, pty: ptmx, logPath: logPath, tempDir: tempDir, copyDone: make(chan struct{})}
	m.mu.Lock()
	m.tasks[id] = task
	m.history[id] = info
	m.mu.Unlock()
	m.persist(info)

	go func() {
		writer := &cappedLogWriter{w: logFile, remaining: m.engine.cfg.MaxTaskLogBytes}
		_, _ = io.Copy(writer, ptmx)
		task.mu.Lock()
		task.info.LogTruncated = writer.truncated
		task.mu.Unlock()
		close(task.copyDone)
	}()
	releaseSlot = false
	go m.waitTask(task, cmd, logFile)
	if err := m.engine.checkContext(ctx); err != nil {
		killStartedProcess()
		return TaskInfo{}, err
	}
	return info, nil
}

func compactCommand(command string, max int) string {
	command = strings.Join(strings.Fields(command), " ")
	if len(command) <= max {
		return command
	}
	return command[:max-1] + "…"
}

func (m *TaskManager) waitTask(task *Task, cmd *exec.Cmd, logFile *os.File) {
	defer func() { <-m.slots }()
	err := cmd.Wait()
	_ = task.pty.Close()
	<-task.copyDone
	_ = logFile.Close()
	if task.tempDir != "" {
		_ = os.RemoveAll(task.tempDir)
	}

	exitCode := 0
	state := "completed"
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	if err != nil || exitCode != 0 {
		state = "failed"
	}
	now := time.Now()
	task.mu.Lock()
	task.info.State = state
	task.info.ExitCode = &exitCode
	task.info.EndedAt = &now
	info := task.info
	task.mu.Unlock()

	m.mu.Lock()
	m.history[info.ID] = info
	delete(m.tasks, info.ID)
	m.mu.Unlock()
	m.persist(info)
}

func (m *TaskManager) getInfo(id string) (TaskInfo, bool) {
	m.mu.RLock()
	task := m.tasks[id]
	info, historical := m.history[id]
	m.mu.RUnlock()
	if task != nil {
		task.mu.RLock()
		info = task.info
		task.mu.RUnlock()
		return info, true
	}
	return info, historical
}

func (m *TaskManager) Read(in ReadTaskInput) (ReadTaskOutput, error) {
	return m.readContext(context.Background(), in)
}

func (m *TaskManager) readContext(ctx context.Context, in ReadTaskInput) (ReadTaskOutput, error) {
	if err := m.engine.checkContext(ctx); err != nil {
		return ReadTaskOutput{}, err
	}
	if !validTaskID(in.TaskID) {
		return ReadTaskOutput{}, errors.New("invalid task ID")
	}
	info, ok := m.getInfo(in.TaskID)
	if !ok {
		return ReadTaskOutput{}, fmt.Errorf("unknown task %q", in.TaskID)
	}
	if in.Offset < 0 {
		return ReadTaskOutput{}, errors.New("offset must be >= 0")
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 64 * 1024
	}
	if limit > m.engine.cfg.MaxReadChunkBytes {
		limit = m.engine.cfg.MaxReadChunkBytes
	}
	file, err := securefile.Open(filepath.Join(m.dir, in.TaskID+".log"), os.O_RDONLY, 0, "task log")
	if err != nil {
		return ReadTaskOutput{}, err
	}
	defer file.Close()
	if err := m.engine.checkContext(ctx); err != nil {
		return ReadTaskOutput{}, err
	}
	stat, err := file.Stat()
	if err != nil {
		return ReadTaskOutput{}, err
	}
	if !stat.Mode().IsRegular() {
		return ReadTaskOutput{}, errors.New("task log must be a regular file")
	}
	if err := securefile.CheckSingleLink(stat, "task log"); err != nil {
		return ReadTaskOutput{}, err
	}
	if in.Offset > stat.Size() {
		in.Offset = stat.Size()
	}
	if _, err := file.Seek(in.Offset, io.SeekStart); err != nil {
		return ReadTaskOutput{}, err
	}
	buf := make([]byte, limit)
	n, readErr := file.Read(buf)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return ReadTaskOutput{}, readErr
	}
	if err := m.engine.checkContext(ctx); err != nil {
		return ReadTaskOutput{}, err
	}
	next := in.Offset + int64(n)
	stat, _ = file.Stat()
	finished := info.State != "running" && info.State != "orphaned_running"
	return ReadTaskOutput{
		Task: info, Output: string(buf[:n]), NextOffset: next,
		EOF: finished && next >= stat.Size(),
	}, nil
}

func (m *TaskManager) Send(in SendTaskInput) error {
	return m.sendContext(context.Background(), in)
}

func (m *TaskManager) sendContext(ctx context.Context, in SendTaskInput) error {
	if err := m.engine.checkContext(ctx); err != nil {
		return err
	}
	if !validTaskID(in.TaskID) {
		return errors.New("invalid task ID")
	}
	if len(in.Input) > 1024*1024 {
		return errors.New("task input is too large (maximum 1 MiB)")
	}
	m.mu.RLock()
	task := m.tasks[in.TaskID]
	m.mu.RUnlock()
	if task == nil {
		return fmt.Errorf("task %q is not active", in.TaskID)
	}
	task.mu.RLock()
	ptmx := task.pty
	task.mu.RUnlock()
	if err := m.engine.checkContext(ctx); err != nil {
		return err
	}
	_, err := ptmx.Write([]byte(in.Input))
	return err
}

func (m *TaskManager) StopAll(sig syscall.Signal) {
	m.mu.RLock()
	tasks := make([]*Task, 0, len(m.tasks))
	for _, task := range m.tasks {
		tasks = append(tasks, task)
	}
	m.mu.RUnlock()
	for _, task := range tasks {
		task.mu.RLock()
		pid := task.info.PID
		task.mu.RUnlock()
		if pid <= 0 {
			continue
		}
		if err := syscall.Kill(-pid, sig); err == nil {
			continue
		}
		if process, err := os.FindProcess(pid); err == nil {
			_ = process.Signal(sig)
		}
	}
}

func (m *TaskManager) Stop(in StopTaskInput) error {
	return m.stopContext(context.Background(), in)
}

func (m *TaskManager) stopContext(ctx context.Context, in StopTaskInput) error {
	if err := m.engine.checkContext(ctx); err != nil {
		return err
	}
	if !validTaskID(in.TaskID) {
		return errors.New("invalid task ID")
	}
	m.mu.RLock()
	task := m.tasks[in.TaskID]
	m.mu.RUnlock()
	if task == nil {
		return fmt.Errorf("task %q is not active", in.TaskID)
	}
	task.mu.RLock()
	pid := task.info.PID
	task.mu.RUnlock()

	sig := syscall.SIGTERM
	switch strings.ToUpper(strings.TrimSpace(in.Signal)) {
	case "", "TERM":
		sig = syscall.SIGTERM
	case "INT":
		sig = syscall.SIGINT
	case "HUP":
		sig = syscall.SIGHUP
	case "KILL":
		sig = syscall.SIGKILL
	default:
		return fmt.Errorf("unsupported signal %q", in.Signal)
	}
	if err := m.engine.checkContext(ctx); err != nil {
		return err
	}
	if err := syscall.Kill(-pid, sig); err == nil {
		return nil
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Signal(sig)
}

func (m *TaskManager) List() TaskListOutput {
	m.mu.RLock()
	all := make(map[string]TaskInfo, len(m.history)+len(m.tasks))
	for id, info := range m.history {
		all[id] = info
	}
	active := make([]*Task, 0, len(m.tasks))
	for _, task := range m.tasks {
		active = append(active, task)
	}
	m.mu.RUnlock()
	for _, task := range active {
		task.mu.RLock()
		all[task.info.ID] = task.info
		task.mu.RUnlock()
	}
	items := make([]TaskInfo, 0, len(all))
	for _, info := range all {
		items = append(items, info)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].StartedAt.After(items[j].StartedAt) })
	return TaskListOutput{Tasks: items}
}

func (m *TaskManager) persist(info TaskInfo) {
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return
	}
	path := filepath.Join(m.dir, info.ID+".json")
	_ = atomicWriteFileMode(path, data, 0o600)
}

func shellCommand(command string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.Command("cmd.exe", "/C", command)
	}
	return exec.Command("/bin/sh", "-lc", command)
}

func (e *Engine) command(command, cwd, tempDir string) (*exec.Cmd, error) {
	if e.cfg.ExecSandbox == "none" {
		return shellCommand(command), nil
	}
	if err := e.ValidateExecConfiguration(); err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve chat-with-cli executable for exec sandbox: %w", err)
	}
	args := []string{"exec-sandbox", "--cwd", cwd}
	if tempDir != "" {
		args = append(args, "--temp-dir", tempDir)
	}
	for _, root := range e.roots {
		args = append(args, "--root", root)
	}
	if e.cfg.AllowFileWrite {
		args = append(args, "--allow-write")
	}
	if runtime.GOOS == "windows" {
		args = append(args, "--", "cmd.exe", "/C", command)
	} else {
		args = append(args, "--", "/bin/sh", "-lc", command)
	}
	return exec.Command(executable, args...), nil
}

func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	for _, item := range env {
		if !strings.HasPrefix(item, prefix) {
			out = append(out, item)
		}
	}
	return append(out, prefix+value)
}

func mergeEnv(base []string, extra map[string]string) []string {
	if len(extra) == 0 {
		return base
	}
	keys := make([]string, 0, len(extra))
	for key := range extra {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := append([]string(nil), base...)
	for _, key := range keys {
		if key == "" || strings.ContainsRune(key, '=') {
			continue
		}
		out = append(out, key+"="+extra[key])
	}
	return out
}

type cappedLogWriter struct {
	w         io.Writer
	remaining int64
	truncated bool
}

func (w *cappedLogWriter) Write(p []byte) (int, error) {
	original := len(p)
	if w.remaining <= 0 {
		w.truncated = w.truncated || original > 0
		return original, nil
	}
	toWrite := p
	if int64(len(toWrite)) > w.remaining {
		toWrite = toWrite[:w.remaining]
		w.truncated = true
	}
	if len(toWrite) > 0 {
		n, err := w.w.Write(toWrite)
		w.remaining -= int64(n)
		if err != nil {
			return n, err
		}
		if n != len(toWrite) {
			return n, io.ErrShortWrite
		}
	}
	return original, nil
}

func (m *TaskManager) Wait(ctx context.Context, in WaitTaskInput) (ReadTaskOutput, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := m.engine.checkContext(ctx); err != nil {
		return ReadTaskOutput{}, err
	}
	timeout := in.TimeoutMS
	if timeout <= 0 {
		timeout = 15000
	}
	if timeout > 30000 {
		timeout = 30000
	}
	readIn := ReadTaskInput{TaskID: in.TaskID, Offset: in.Offset, Limit: in.Limit}
	deadline := time.NewTimer(time.Duration(timeout) * time.Millisecond)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		out, err := m.readContext(ctx, readIn)
		if err != nil {
			return ReadTaskOutput{}, err
		}
		if out.Output != "" || out.EOF {
			return out, nil
		}
		select {
		case <-ctx.Done():
			return ReadTaskOutput{}, ctx.Err()
		case <-deadline.C:
			return out, nil
		case <-ticker.C:
		}
	}
}

func validTaskID(id string) bool {
	canonical, ok := protocol.NormalizeDeviceID(id)
	return ok && canonical == id
}
