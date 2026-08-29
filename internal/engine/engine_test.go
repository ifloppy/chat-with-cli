package engine

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testEngine(t *testing.T, allowExec bool) *Engine {
	t.Helper()
	root := t.TempDir()
	eng, err := New(Config{
		Roots: []string{root}, AllowFileWrite: true, AllowExec: allowExec,
		StateDir: t.TempDir(), MaxReadBytes: 64 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func TestFilesystemWritesAreOptIn(t *testing.T) {
	eng, err := New(Config{Roots: []string{t.TempDir()}, StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.WriteFile(FileWriteInput{Path: "new.txt", Content: "blocked"}); err == nil {
		t.Fatal("filesystem write unexpectedly succeeded without capability")
	}
	if _, err := eng.PatchFile(FilePatchInput{Path: "new.txt", OldText: "x", NewText: "y"}); err == nil {
		t.Fatal("filesystem patch unexpectedly succeeded without capability")
	}
	if err := eng.WriteCheckpoint(CheckpointWriteInput{Workspace: ".", Content: "blocked"}); err == nil {
		t.Fatal("checkpoint write unexpectedly succeeded without capability")
	}
}

func TestCheckpointReadRejectsSymlinkAndHardlink(t *testing.T) {
	eng := testEngine(t, false)
	workspace, checkpoint := "", ""
	var err error
	workspace, checkpoint, err = eng.checkpointPath(".")
	if err != nil {
		t.Fatal(err)
	}
	if workspace == "" {
		t.Fatal("checkpoint workspace is empty")
	}
	outside := filepath.Join(t.TempDir(), "secret.md")
	if err := os.WriteFile(outside, []byte("private checkpoint material"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(outside, checkpoint); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skip("symlinks are unavailable")
		}
		t.Fatal(err)
	}
	if _, err := eng.ReadCheckpoint(CheckpointReadInput{Workspace: "."}); err == nil {
		t.Fatal("checkpoint_read followed a private-state symlink")
	}
	if err := os.Remove(checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, checkpoint); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skip("hardlinks are unavailable")
		}
		t.Fatal(err)
	}
	if _, err := eng.ReadCheckpoint(CheckpointReadInput{Workspace: "."}); err == nil {
		t.Fatal("checkpoint_read accepted a hardlinked private-state file")
	}
}

func TestEngineRejectsSymlinkedStateDirectory(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "state")
	if err := os.Symlink(target, link); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skip("symlinks are unavailable")
		}
		t.Fatal(err)
	}
	_, err := New(Config{Roots: []string{t.TempDir()}, StateDir: link})
	if err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Fatalf("symlinked state directory was accepted: %v", err)
	}
}

func TestPatchFileRequiresExactMatchCount(t *testing.T) {
	eng := testEngine(t, false)
	path := filepath.Join(eng.roots[0], "sample.txt")
	if err := os.WriteFile(path, []byte("alpha beta alpha"), 0o640); err != nil {
		t.Fatal(err)
	}

	if _, err := eng.PatchFile(FilePatchInput{
		Path: path, OldText: "alpha", NewText: "omega",
	}); err == nil {
		t.Fatal("expected ambiguous patch to fail")
	}
	out, err := eng.PatchFile(FilePatchInput{
		Path: path, OldText: "alpha", NewText: "omega", Expected: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Replacements != 2 {
		t.Fatalf("replacements=%d", out.Replacements)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "omega beta omega" {
		t.Fatalf("unexpected content %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode changed to %o", info.Mode().Perm())
	}
}

func TestResolvePathRejectsSymlinkEscape(t *testing.T) {
	eng := testEngine(t, false)
	outside := t.TempDir()
	link := filepath.Join(eng.roots[0], "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.ResolvePath(filepath.Join(link, "secret.txt")); err == nil {
		t.Fatal("expected symlink escape to be rejected")
	}
}

func TestComputerCapabilitiesAreOptIn(t *testing.T) {
	eng := testEngine(t, false)
	info := eng.ComputerInfo()
	if info.ScreenAllowed || info.AccessibilityAllowed || info.ControlAllowed {
		t.Fatalf("computer capabilities unexpectedly enabled: %+v", info)
	}
	if _, err := eng.Screenshot(context.Background(), ComputerScreenshotInput{}); err == nil {
		t.Fatal("screen capture should be disabled")
	}
	if err := eng.ComputerMove(context.Background(), ComputerMoveInput{X: 1, Y: 1}); err == nil {
		t.Fatal("computer control should be disabled")
	}
}

func TestLongTaskReturnsIDAndCanBeReadLater(t *testing.T) {
	eng := testEngine(t, true)
	info, err := eng.tasks.Start(context.Background(), StartTaskInput{
		Command: "printf 'hello\\n'; sleep 0.05; printf 'world\\n'",
	})
	if err != nil {
		t.Fatal(err)
	}
	if info.ID == "" || info.State != "running" {
		t.Fatalf("bad start result: %+v", info)
	}
	deadline := time.Now().Add(3 * time.Second)
	var output strings.Builder
	var offset int64
	for time.Now().Before(deadline) {
		read, err := eng.tasks.Read(ReadTaskInput{TaskID: info.ID, Offset: offset})
		if err != nil {
			t.Fatal(err)
		}
		output.WriteString(read.Output)
		offset = read.NextOffset
		if read.EOF {
			if !strings.Contains(output.String(), "hello") || !strings.Contains(output.String(), "world") {
				t.Fatalf("unexpected task output %q", output.String())
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("task did not finish before deadline")
}
func TestActiveTaskLimit(t *testing.T) {
	root := t.TempDir()
	eng, err := New(Config{
		Roots: []string{root}, AllowExec: true,
		StateDir: t.TempDir(), MaxReadBytes: 64 * 1024, MaxActiveTasks: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := eng.tasks.Start(context.Background(), StartTaskInput{Command: "sleep 5"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.tasks.Start(context.Background(), StartTaskInput{Command: "true"}); err == nil || !strings.Contains(err.Error(), "active task limit") {
		t.Fatalf("expected active task limit error, got %v", err)
	}
	if err := eng.tasks.Stop(StopTaskInput{TaskID: first.ID, Signal: "KILL"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		second, err := eng.tasks.Start(context.Background(), StartTaskInput{Command: "true"})
		if err == nil {
			if second.ID == "" {
				t.Fatal("replacement task has empty ID")
			}
			return
		}
		if !strings.Contains(err.Error(), "active task limit") {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("task slot was not released after process exit")
}

func TestMaxActiveTasksHasHardUpperBound(t *testing.T) {
	_, err := New(Config{Roots: []string{t.TempDir()}, StateDir: t.TempDir(), MaxActiveTasks: 257})
	if err == nil || !strings.Contains(err.Error(), "<= 256") {
		t.Fatalf("expected upper-bound error, got %v", err)
	}
}

func TestAuditRecordsMethodWithoutPayload(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	eng, err := New(Config{Roots: []string{root}, AllowFileWrite: true, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	const secret = "audit-secret-marker-must-not-appear"
	raw := []byte(`{"path":"note.txt","content":"` + secret + `","mode":"rewrite"}`)
	if _, err := eng.Invoke(context.Background(), "fs_write", raw); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(stateDir, "audit", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) || !strings.Contains(string(data), `"method":"fs_write"`) {
		t.Fatalf("unsafe or missing audit data: %s", data)
	}
	info, err := os.Stat(filepath.Join(stateDir, "audit", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("audit mode=%o, want 600", info.Mode().Perm())
	}
	out, err := eng.audit.recent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Events) != 1 || out.Events[0].Method != "fs_write" || !out.Events[0].OK {
		t.Fatalf("unexpected audit events: %#v", out.Events)
	}
}

func TestInvokeCanceledContextCannotMutateFilesystem(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	eng, err := New(Config{Roots: []string{root}, AllowFileWrite: true, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = eng.Invoke(ctx, "fs_write", json.RawMessage(`{"path":"canceled.txt","content":"must-not-write"}`))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled filesystem request returned %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "canceled.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled filesystem request mutated workspace: %v", err)
	}
}

func TestTaskOperationsRejectUnsafeIDs(t *testing.T) {
	eng := testEngine(t, false)
	if _, err := eng.tasks.Read(ReadTaskInput{TaskID: "../../outside"}); err == nil {
		t.Fatal("task read accepted a path-traversal task ID")
	}
	if err := eng.tasks.Send(SendTaskInput{TaskID: "../../outside", Input: "x"}); err == nil {
		t.Fatal("task send accepted a path-traversal task ID")
	}
	if err := eng.tasks.Stop(StopTaskInput{TaskID: "../../outside"}); err == nil {
		t.Fatal("task stop accepted a path-traversal task ID")
	}
}

func TestKillSwitchBlocksTaskStartBeforePTY(t *testing.T) {
	root := t.TempDir()
	killSwitch := filepath.Join(t.TempDir(), "PANIC")
	eng, err := New(Config{
		Roots: []string{root}, AllowExec: true,
		StateDir: t.TempDir(), KillSwitchPath: killSwitch,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	if err := os.WriteFile(killSwitch, []byte("stop\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.tasks.Start(context.Background(), StartTaskInput{Command: "touch should-not-run"}); err == nil || !strings.Contains(err.Error(), "kill switch") {
		t.Fatalf("kill switch did not block task start: %v", err)
	}
	if tasks := eng.tasks.List().Tasks; len(tasks) != 0 {
		t.Fatalf("kill-switched task start left active/history entries: %+v", tasks)
	}
}

func TestScreenshotPayloadLeavesWebSocketHeadroom(t *testing.T) {
	encoded := ((maxScreenshotBytes + 2) / 3) * 4
	const websocketLimit = 32 << 20
	const envelopeHeadroom = 1 << 20
	if encoded+envelopeHeadroom >= websocketLimit {
		t.Fatalf("screenshot cap %d leaves insufficient WebSocket headroom", maxScreenshotBytes)
	}
}

func TestKillSwitchStopsRunningTask(t *testing.T) {
	root := t.TempDir()
	killSwitch := filepath.Join(t.TempDir(), "PANIC")
	eng, err := New(Config{
		Roots: []string{root}, AllowExec: true,
		StateDir: t.TempDir(), KillSwitchPath: killSwitch,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	info, err := eng.tasks.Start(context.Background(), StartTaskInput{Command: "sleep 30"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(killSwitch, []byte("stop\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		current, ok := eng.tasks.getInfo(info.ID)
		if ok && current.State != "running" {
			if _, err := eng.Invoke(context.Background(), "system_info", nil); err == nil || !strings.Contains(err.Error(), "kill switch") {
				t.Fatalf("kill switch did not block new calls: %v", err)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("kill switch did not terminate running task")
}

func TestKillSwitchCancelsInFlightContext(t *testing.T) {
	killSwitch := filepath.Join(t.TempDir(), "PANIC")
	eng, err := New(Config{Roots: []string{t.TempDir()}, StateDir: t.TempDir(), KillSwitchPath: killSwitch})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	callCtx, cancel, blocked := eng.callContext(context.Background())
	if blocked {
		cancel()
		t.Fatal("kill switch unexpectedly active")
	}
	defer cancel()
	if err := os.WriteFile(killSwitch, []byte("stop\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-callCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("kill switch did not cancel an in-flight Engine context")
	}

	if err := os.Remove(killSwitch); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ctx, release, blocked := eng.callContext(context.Background())
		if !blocked && ctx.Err() == nil {
			release()
			return
		}
		release()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("kill switch did not recover after PANIC file removal")
}

func TestProtectedPathsAreHiddenFromFilesystemTools(t *testing.T) {
	root := t.TempDir()
	privateDir := filepath.Join(root, "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(privateDir, "credentials.json")
	if err := os.WriteFile(secret, []byte("secret-marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := New(Config{
		Roots: []string{root}, StateDir: t.TempDir(),
		ProtectedPaths: []string{privateDir},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.ReadFile(FileReadInput{Path: secret}); err == nil || !strings.Contains(err.Error(), "private state") {
		t.Fatalf("protected read was not rejected: %v", err)
	}
	listed, err := eng.ListFiles(FileListInput{Path: root, Depth: 4})
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range listed.Entries {
		if strings.Contains(entry.Path, privateDir) {
			t.Fatalf("protected path leaked through fs_list: %+v", entry)
		}
	}
	searched, err := eng.SearchFiles(context.Background(), FileSearchInput{
		Path: root, Pattern: "secret-marker", Kind: "content",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(searched.Hits) != 0 {
		t.Fatalf("protected path leaked through fs_search: %+v", searched.Hits)
	}
}

func TestLandlockRefusesRootContainingPrivateState(t *testing.T) {
	root := t.TempDir()
	privateDir := filepath.Join(root, "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	eng, err := New(Config{
		Roots: []string{root}, StateDir: t.TempDir(), AllowExec: true,
		ExecSandbox: "landlock", ProtectedPaths: []string{privateDir},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.command("true", root, ""); err == nil || !strings.Contains(err.Error(), "contains chat-with-cli private state") {
		t.Fatalf("broad Landlock root was accepted: %v", err)
	}
}

func TestEndRemoteSessionStopsDetachedTasks(t *testing.T) {
	eng := testEngine(t, true)
	defer eng.Close()
	info, err := eng.tasks.Start(context.Background(), StartTaskInput{Command: "sleep 30"})
	if err != nil {
		t.Fatal(err)
	}
	eng.EndRemoteSession()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		current, ok := eng.tasks.getInfo(info.ID)
		if ok && current.State != "running" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("detached PTY survived loss of the remote authorization session")
}
