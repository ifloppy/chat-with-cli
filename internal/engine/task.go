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
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var info TaskInfo
		if json.Unmarshal(data, &info) != nil || info.ID == "" {
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
	if !m.engine.cfg.AllowExec {
		return TaskInfo{}, errors.New("shell execution is disabled; start the agent with --allow-exec")
	}
	if strings.TrimSpace(in.Command) == "" {
		return TaskInfo{}, errors.New("command is required")
	}
	select {
	case <-ctx.Done():
		return TaskInfo{}, ctx.Err()
	default:
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
	id := protocol.NewID()
	logPath := filepath.Join(m.dir, id+".log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return TaskInfo{}, err
	}
	cmd, err := m.engine.command(in.Command)
	if err != nil {
		return TaskInfo{}, err
	}
	cmd.Dir = cwd
	cmd.Env = mergeEnv(os.Environ(), in.Env)
	ptmx, err := pty.Start(cmd)
	if err != nil {
		_ = logFile.Close()
		return TaskInfo{}, fmt.Errorf("start PTY: %w", err)
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = compactCommand(in.Command, 72)
	}
	info := TaskInfo{
		ID: id, Name: name, Command: in.Command, Cwd: cwd,
		PID: cmd.Process.Pid, State: "running", StartedAt: time.Now(),
	}
	task := &Task{info: info, pty: ptmx, logPath: logPath, copyDone: make(chan struct{})}
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
	if limit > m.engine.cfg.MaxReadBytes {
		limit = m.engine.cfg.MaxReadBytes
	}
	file, err := os.Open(filepath.Join(m.dir, in.TaskID+".log"))
	if err != nil {
		return ReadTaskOutput{}, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
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
	next := in.Offset + int64(n)
	stat, _ = file.Stat()
	finished := info.State != "running" && info.State != "orphaned_running"
	return ReadTaskOutput{
		Task: info, Output: string(buf[:n]), NextOffset: next,
		EOF: finished && next >= stat.Size(),
	}, nil
}

func (m *TaskManager) Send(in SendTaskInput) error {
	m.mu.RLock()
	task := m.tasks[in.TaskID]
	m.mu.RUnlock()
	if task == nil {
		return fmt.Errorf("task %q is not active", in.TaskID)
	}
	task.mu.RLock()
	ptmx := task.pty
	task.mu.RUnlock()
	_, err := ptmx.Write([]byte(in.Input))
	return err
}

func (m *TaskManager) Stop(in StopTaskInput) error {
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

func (e *Engine) command(command string) (*exec.Cmd, error) {
	if e.cfg.ExecSandbox == "none" {
		return shellCommand(command), nil
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve chat-with-cli executable for exec sandbox: %w", err)
	}
	args := []string{"exec-sandbox"}
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
		out, err := m.Read(readIn)
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
