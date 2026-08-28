package engine

import (
	"context"
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

func TestScreenshotPayloadLeavesWebSocketHeadroom(t *testing.T) {
	encoded := ((maxScreenshotBytes + 2) / 3) * 4
	const websocketLimit = 32 << 20
	const envelopeHeadroom = 1 << 20
	if encoded+envelopeHeadroom >= websocketLimit {
		t.Fatalf("screenshot cap %d leaves insufficient WebSocket headroom", maxScreenshotBytes)
	}
}
