package engine

import (
	"context"
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
		Roots: []string{root}, AllowExec: allowExec,
		StateDir: t.TempDir(), MaxReadBytes: 64 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	return eng
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
	if info.ScreenAllowed || info.ControlAllowed {
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
