package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
)

type Engine struct {
	cfg       Config
	roots     []string
	protected []string
	tasks     *TaskManager
	audit     *auditLog

	killSwitchStop     chan struct{}
	killSwitchDone     chan struct{}
	killSwitchStopOnce sync.Once
	killSwitchMu       sync.Mutex
	killSwitchCtx      context.Context
	killSwitchCancel   context.CancelFunc
	killSwitchLatched  bool

	computerMu           sync.Mutex
	kwinDBusDisabled     bool
	lastScreenshotWidth  int
	lastScreenshotHeight int
	portalMu             sync.Mutex
	portalConn           *dbus.Conn
	portal               *portalRemoteDesktopSession
	portalRestoreToken   string
	portalTokenLoaded    bool
}

const (
	maxEngineMethodBytes = 128
	maxEngineArgsBytes   = 8 << 20
)

func New(cfg Config) (*Engine, error) {
	if cfg.MaxReadBytes <= 0 {
		cfg.MaxReadBytes = 256 * 1024
	}
	if cfg.MaxTaskLogBytes <= 0 {
		cfg.MaxTaskLogBytes = 64 << 20
	}
	if cfg.MaxActiveTasks <= 0 {
		cfg.MaxActiveTasks = 32
	}
	if cfg.MaxActiveTasks > 256 {
		return nil, fmt.Errorf("max active tasks must be <= 256, got %d", cfg.MaxActiveTasks)
	}
	// Computer control necessarily needs both visual and semantic UI access.
	cfg.AllowScreen = cfg.AllowScreen || cfg.AllowComputerControl
	cfg.AllowAccessibility = cfg.AllowAccessibility || cfg.AllowComputerControl
	cfg.ExecSandbox = strings.ToLower(strings.TrimSpace(cfg.ExecSandbox))
	if cfg.ExecSandbox == "" {
		cfg.ExecSandbox = "none"
	}
	if cfg.ExecSandbox != "none" && cfg.ExecSandbox != "landlock" {
		return nil, fmt.Errorf("unsupported exec sandbox %q", cfg.ExecSandbox)
	}
	if cfg.ExecSandbox == "landlock" && runtime.GOOS != "linux" {
		return nil, errors.New("the Landlock exec sandbox is supported on Linux only")
	}
	mode, err := normalizeComputerPersistMode(cfg.ComputerPersistMode)
	if err != nil {
		return nil, err
	}
	cfg.ComputerPersistMode = mode
	if cfg.StateDir == "" {
		home, _ := os.UserHomeDir()
		cfg.StateDir = filepath.Join(home, ".local", "state", "chat-with-cli")
	}
	if err := ensurePrivateDir(cfg.StateDir); err != nil {
		return nil, err
	}

	if len(cfg.Roots) == 0 {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		cfg.Roots = []string{cwd}
	}
	roots := make([]string, 0, len(cfg.Roots))
	for _, root := range cfg.Roots {
		abs, err := filepath.Abs(root)
		if err != nil {
			return nil, fmt.Errorf("resolve root %q: %w", root, err)
		}
		real, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return nil, fmt.Errorf("resolve root symlinks %q: %w", root, err)
		}
		roots = append(roots, filepath.Clean(real))
	}
	protectedCandidates := append([]string(nil), cfg.ProtectedPaths...)
	protectedCandidates = append(protectedCandidates, cfg.StateDir)
	if strings.TrimSpace(cfg.KillSwitchPath) != "" {
		protectedCandidates = append(protectedCandidates, cfg.KillSwitchPath)
	}
	if configDir, err := os.UserConfigDir(); err == nil && configDir != "" {
		protectedCandidates = append(protectedCandidates, filepath.Join(configDir, "chat-with-cli"))
	}
	protected := make([]string, 0, len(protectedCandidates))
	seenProtected := make(map[string]struct{}, len(protectedCandidates))
	for _, candidate := range protectedCandidates {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		path, err := canonicalPath(candidate)
		if err != nil {
			return nil, fmt.Errorf("resolve protected path %q: %w", candidate, err)
		}
		if _, exists := seenProtected[path]; exists {
			continue
		}
		seenProtected[path] = struct{}{}
		protected = append(protected, path)
	}
	e := &Engine{cfg: cfg, roots: roots, protected: protected}
	taskDir := filepath.Join(cfg.StateDir, "tasks")
	if err := ensurePrivateDir(taskDir); err != nil {
		return nil, fmt.Errorf("initialize task state: %w", err)
	}
	e.tasks = NewTaskManager(e, taskDir)
	e.audit, err = newAuditLog(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("initialize audit log: %w", err)
	}
	if strings.TrimSpace(cfg.KillSwitchPath) != "" {
		e.killSwitchStop = make(chan struct{})
		e.killSwitchDone = make(chan struct{})
		e.killSwitchCtx, e.killSwitchCancel = context.WithCancel(context.Background())
		e.updateKillSwitchState(e.killSwitchActive())
		go e.watchKillSwitch()
	}
	return e, nil
}

func ensurePrivateDir(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("state directory must not be empty")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("state directory %q must be a real directory", path)
	}
	return os.Chmod(path, 0o700)
}

func (e *Engine) killSwitchActive() bool {
	if strings.TrimSpace(e.cfg.KillSwitchPath) == "" {
		return false
	}
	_, err := os.Lstat(e.cfg.KillSwitchPath)
	return err == nil
}

func (e *Engine) updateKillSwitchState(active bool) {
	e.killSwitchMu.Lock()
	if e.killSwitchLatched == active {
		e.killSwitchMu.Unlock()
		return
	}
	e.killSwitchLatched = active
	if active {
		if e.killSwitchCancel != nil {
			e.killSwitchCancel()
		}
	} else {
		e.killSwitchCtx, e.killSwitchCancel = context.WithCancel(context.Background())
	}
	e.killSwitchMu.Unlock()

	if active {
		// The local panic switch is an out-of-band authority: cancel all
		// in-flight Engine calls and kill every detached PTY immediately.
		e.tasks.StopAll(syscall.SIGKILL)
		e.closePortalSession()
	}
}

func (e *Engine) callContext(parent context.Context) (context.Context, context.CancelFunc, bool) {
	if parent == nil {
		parent = context.Background()
	}
	e.killSwitchMu.Lock()
	killCtx := e.killSwitchCtx
	active := e.killSwitchLatched
	e.killSwitchMu.Unlock()
	if killCtx == nil {
		return parent, func() {}, false
	}
	if active {
		return parent, func() {}, true
	}
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(killCtx, cancel)
	return ctx, func() {
		stop()
		cancel()
	}, false
}

func (e *Engine) checkContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if e.killSwitchActive() {
		e.updateKillSwitchState(true)
		return errors.New("local emergency kill switch is active")
	}
	return nil
}

func (e *Engine) watchKillSwitch() {
	defer close(e.killSwitchDone)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-e.killSwitchStop:
			return
		case <-ticker.C:
			e.updateKillSwitchState(e.killSwitchActive())
		}
	}
}

func (e *Engine) stopKillSwitchWatcher() {
	e.killSwitchStopOnce.Do(func() {
		if e.killSwitchStop == nil {
			return
		}
		close(e.killSwitchStop)
		<-e.killSwitchDone
		e.killSwitchMu.Lock()
		if e.killSwitchCancel != nil {
			e.killSwitchCancel()
		}
		e.killSwitchMu.Unlock()
	})
}

func (e *Engine) closePortalSession() error {
	e.portalMu.Lock()
	portal := e.portal
	conn := e.portalConn
	e.portal = nil
	e.portalConn = nil
	e.portalMu.Unlock()
	if portal != nil {
		portal.close()
	}
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (e *Engine) Close() error {
	e.stopKillSwitchWatcher()
	e.EndRemoteSession()
	return nil
}

// EndRemoteSession fail-closes work that outlives an individual RPC. Detached
// PTYs and a Desktop Portal control session must not survive loss of the Relay
// session that authorized them. In-flight RPCs are canceled by the Agent
// connection context; this method handles background work explicitly.
func (e *Engine) EndRemoteSession() {
	e.tasks.StopAll(syscall.SIGKILL)
	_ = e.closePortalSession()
}

func (e *Engine) Config() Config {
	cfg := e.cfg
	cfg.Roots = append([]string(nil), e.roots...)
	return cfg
}

func canonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return filepath.Clean(real), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return resolveMissingPath(abs)
}

func (e *Engine) isProtectedPath(path string) bool {
	for _, protected := range e.protected {
		if pathWithin(protected, path) {
			return true
		}
	}
	return false
}

func (e *Engine) rootCoversProtectedPath(root string) bool {
	for _, protected := range e.protected {
		if pathWithin(root, protected) {
			return true
		}
	}
	return false
}

func (e *Engine) ResolvePath(path string) (string, error) {
	if path == "" {
		return e.roots[0], nil
	}
	candidate := path
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(e.roots[0], candidate)
	}
	candidate = filepath.Clean(candidate)
	real, err := filepath.EvalSymlinks(candidate)
	if err == nil {
		candidate = real
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	} else {
		resolved, err := resolveMissingPath(candidate)
		if err != nil {
			return "", err
		}
		candidate = resolved
	}
	for _, root := range e.roots {
		if pathWithin(root, candidate) {
			if e.isProtectedPath(candidate) {
				return "", fmt.Errorf("path %q is reserved for chat-with-cli private state", path)
			}
			return candidate, nil
		}
	}
	return "", fmt.Errorf("path %q is outside allowed roots", path)
}

func resolveMissingPath(path string) (string, error) {
	probe := path
	for {
		if _, err := os.Lstat(probe); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return "", os.ErrNotExist
		}
		probe = parent
	}
	realBase, err := filepath.EvalSymlinks(probe)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(probe, path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(filepath.Join(realBase, rel)), nil
}

func pathWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func decode[T any](raw json.RawMessage) (T, error) {
	var value T
	if len(raw) == 0 || string(raw) == "null" {
		return value, nil
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return value, fmt.Errorf("decode arguments: %w", err)
	}
	return value, nil
}

func (e *Engine) Invoke(ctx context.Context, method string, raw json.RawMessage) (result any, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	started := time.Now()
	auditMethod := method
	if len(auditMethod) > maxEngineMethodBytes {
		auditMethod = auditMethod[:maxEngineMethodBytes]
	}
	defer func() { e.audit.record(auditMethod, started, err) }()
	if e.killSwitchActive() {
		e.updateKillSwitchState(true)
		return nil, errors.New("local emergency kill switch is active")
	}
	callCtx, cancel, blocked := e.callContext(ctx)
	if blocked {
		return nil, errors.New("local emergency kill switch is active")
	}
	defer cancel()
	if len(method) == 0 || len(method) > maxEngineMethodBytes {
		return nil, errors.New("method name is missing or too long")
	}
	if len(raw) > maxEngineArgsBytes {
		return nil, errors.New("request arguments are too large")
	}
	return e.invoke(callCtx, method, raw)
}

func (e *Engine) invoke(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	if err := e.checkContext(ctx); err != nil {
		return nil, err
	}
	switch method {
	case "system_info":
		host, _ := os.Hostname()
		return SystemInfoOutput{
			Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH,
			PID: os.Getpid(), Roots: append([]string(nil), e.roots...), AllowFileWrite: e.cfg.AllowFileWrite,
			AllowExec: e.cfg.AllowExec, ExecSandbox: e.cfg.ExecSandbox,
			AllowScreen: e.cfg.AllowScreen, AllowAccessibility: e.cfg.AllowAccessibility,
			AllowComputerControl: e.cfg.AllowComputerControl, MaxActiveTasks: e.cfg.MaxActiveTasks,
			KillSwitchActive: e.killSwitchActive(),
		}, nil
	case "computer_info":
		return e.ComputerInfo(), nil
	case "computer_screenshot":
		in, err := decode[ComputerScreenshotInput](raw)
		if err != nil {
			return nil, err
		}
		return e.Screenshot(ctx, in)
	case "computer_observe":
		in, err := decode[ComputerObserveInput](raw)
		if err != nil {
			return nil, err
		}
		return e.ComputerObserve(ctx, in)
	case "computer_ui_tree":
		in, err := decode[ComputerUITreeInput](raw)
		if err != nil {
			return nil, err
		}
		return e.ComputerUITree(ctx, in)
	case "computer_ui_find":
		in, err := decode[ComputerUIFindInput](raw)
		if err != nil {
			return nil, err
		}
		return e.ComputerUIFind(ctx, in)
	case "computer_ui_wait":
		in, err := decode[ComputerUIWaitInput](raw)
		if err != nil {
			return nil, err
		}
		return e.ComputerUIWait(ctx, in)
	case "task_start":
		in, err := decode[StartTaskInput](raw)
		if err != nil {
			return nil, err
		}
		return e.tasks.Start(ctx, in)
	case "task_read":
		in, err := decode[ReadTaskInput](raw)
		if err != nil {
			return nil, err
		}
		return e.tasks.readContext(ctx, in)
	case "task_wait":
		in, err := decode[WaitTaskInput](raw)
		if err != nil {
			return nil, err
		}
		return e.tasks.Wait(ctx, in)
	case "task_list":
		return e.tasks.List(), nil
	case "audit_recent":
		in, err := decode[AuditRecentInput](raw)
		if err != nil {
			return nil, err
		}
		return e.audit.recent(in.Limit)
	}

	switch method {
	case "computer_ui_focus":
		in, err := decode[ComputerUIRefInput](raw)
		if err != nil {
			return nil, err
		}
		return e.ComputerUIFocus(ctx, in)
	case "computer_ui_action":
		in, err := decode[ComputerUIActionInput](raw)
		if err != nil {
			return nil, err
		}
		return e.ComputerUIAction(ctx, in)
	case "computer_ui_invoke":
		in, err := decode[ComputerUIInvokeInput](raw)
		if err != nil {
			return nil, err
		}
		return e.ComputerUIInvoke(ctx, in)
	case "computer_ui_get_text":
		in, err := decode[ComputerUIGetTextInput](raw)
		if err != nil {
			return nil, err
		}
		return e.ComputerUIGetText(ctx, in)
	case "computer_ui_set_text":
		in, err := decode[ComputerUISetTextInput](raw)
		if err != nil {
			return nil, err
		}
		return e.ComputerUISetText(ctx, in)
	case "computer_move":
		in, err := decode[ComputerMoveInput](raw)
		if err != nil {
			return nil, err
		}
		if err := e.ComputerMove(ctx, in); err != nil {
			return nil, err
		}
		return Ack{OK: true}, nil
	case "computer_click":
		in, err := decode[ComputerClickInput](raw)
		if err != nil {
			return nil, err
		}
		if err := e.ComputerClick(ctx, in); err != nil {
			return nil, err
		}
		return Ack{OK: true}, nil
	case "computer_scroll":
		in, err := decode[ComputerScrollInput](raw)
		if err != nil {
			return nil, err
		}
		if err := e.ComputerScroll(ctx, in); err != nil {
			return nil, err
		}
		return Ack{OK: true}, nil
	case "computer_type":
		in, err := decode[ComputerTypeInput](raw)
		if err != nil {
			return nil, err
		}
		if err := e.ComputerType(ctx, in); err != nil {
			return nil, err
		}
		return Ack{OK: true}, nil
	case "computer_key":
		in, err := decode[ComputerKeyInput](raw)
		if err != nil {
			return nil, err
		}
		if err := e.ComputerKey(ctx, in); err != nil {
			return nil, err
		}
		return Ack{OK: true}, nil
	case "task_send":
		in, err := decode[SendTaskInput](raw)
		if err != nil {
			return nil, err
		}
		if err := e.tasks.sendContext(ctx, in); err != nil {
			return nil, err
		}
		return Ack{OK: true}, nil
	case "task_stop":
		in, err := decode[StopTaskInput](raw)
		if err != nil {
			return nil, err
		}
		if err := e.tasks.stopContext(ctx, in); err != nil {
			return nil, err
		}
		return Ack{OK: true}, nil
	case "fs_read":
		in, err := decode[FileReadInput](raw)
		if err != nil {
			return nil, err
		}
		return e.readFileContext(ctx, in)
	case "fs_write":
		in, err := decode[FileWriteInput](raw)
		if err != nil {
			return nil, err
		}
		if err := e.writeFileContext(ctx, in); err != nil {
			return nil, err
		}
		return Ack{OK: true}, nil
	case "fs_patch":
		in, err := decode[FilePatchInput](raw)
		if err != nil {
			return nil, err
		}
		return e.patchFileContext(ctx, in)
	case "fs_list":
		in, err := decode[FileListInput](raw)
		if err != nil {
			return nil, err
		}
		return e.listFilesContext(ctx, in)
	}

	switch method {
	case "fs_search":
		in, err := decode[FileSearchInput](raw)
		if err != nil {
			return nil, err
		}
		return e.SearchFiles(ctx, in)
	case "checkpoint_write":
		in, err := decode[CheckpointWriteInput](raw)
		if err != nil {
			return nil, err
		}
		if err := e.writeCheckpointContext(ctx, in); err != nil {
			return nil, err
		}
		return Ack{OK: true}, nil
	case "checkpoint_read":
		in, err := decode[CheckpointReadInput](raw)
		if err != nil {
			return nil, err
		}
		return e.readCheckpointContext(ctx, in)
	default:
		return nil, fmt.Errorf("unknown method %q", method)
	}
}
