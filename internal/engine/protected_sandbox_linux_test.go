//go:build linux

package engine

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func protectedSandboxAvailable() error {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return err
	}
	cmd := exec.Command(bwrap, "--die-with-parent", "--unshare-pid", "--ro-bind", "/", "/", "--proc", "/proc", "--dev-bind", "/dev", "/dev", "--", "/bin/true")
	return cmd.Run()
}

func waitProtectedTask(t *testing.T, eng *Engine, id string) (TaskInfo, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var offset int64
	var output strings.Builder
	for {
		out, err := eng.tasks.Wait(ctx, WaitTaskInput{TaskID: id, Offset: offset, TimeoutMS: 500})
		if err != nil {
			t.Fatal(err)
		}
		output.WriteString(out.Output)
		offset = out.NextOffset
		if out.EOF {
			return out.Task, output.String()
		}
	}
}

func TestMinimalProtectedPathsKeepsOnlyTopmostAncestors(t *testing.T) {
	base := filepath.Join(string(filepath.Separator), "home", "user")
	got := minimalProtectedPaths([]string{
		filepath.Join(base, ".config", "chat-with-cli", "credentials.json"),
		filepath.Join(base, ".config", "chat-with-cli"),
		filepath.Join(base, ".local", "state", "chat-with-cli", "identity.key"),
		filepath.Join(base, ".local", "state", "chat-with-cli"),
	})
	want := []string{
		filepath.Join(base, ".config", "chat-with-cli"),
		filepath.Join(base, ".local", "state", "chat-with-cli"),
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("minimal protected paths=%v want=%v", got, want)
	}
}

func TestProtectedShellKeepsUserFilesystemButMasksPrivatePaths(t *testing.T) {
	if err := protectedSandboxAvailable(); err != nil {
		t.Skipf("bubblewrap protected shell is unavailable: %v", err)
	}
	root := t.TempDir()
	stateDir := t.TempDir()
	privateDir := filepath.Join(root, ".private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	privateNested := filepath.Join(privateDir, "token.txt")
	privateFile := filepath.Join(root, "standalone.secret")
	visible := filepath.Join(root, "visible.txt")
	if err := os.WriteFile(privateNested, []byte("nested-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privateFile, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(visible, []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := New(Config{
		Roots: []string{root}, AllowFileWrite: true, AllowExec: true,
		ExecSandbox: "protected", StateDir: stateDir,
		ProtectedPaths: []string{privateNested, privateDir, privateFile},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	command := strings.Join([]string{
		`printf 'HOME=%s\n' "$HOME"`,
		`cat visible.txt`,
		`if cat .private/token.txt >/dev/null 2>&1; then echo leaked-private-dir; exit 41; fi`,
		`if cat standalone.secret >/dev/null 2>&1; then echo leaked-private-file; exit 42; fi`,
		`printf 'after\n' > visible.txt`,
		`touch created.txt`,
		`if umount .private >/dev/null 2>&1; then echo unmasked-private-dir; exit 43; fi`,
		`echo protected-ok`,
	}, "; ")
	task, err := eng.tasks.Start(context.Background(), StartTaskInput{
		Command: command, Cwd: root, Env: map[string]string{"HOME": root},
	})
	if err != nil {
		t.Fatal(err)
	}
	final, output := waitProtectedTask(t, eng, task.ID)
	if final.State != "completed" || final.ExitCode == nil || *final.ExitCode != 0 {
		t.Fatalf("protected task failed: task=%+v output=%q", final, output)
	}
	if !strings.Contains(output, "HOME="+root) || !strings.Contains(output, "before") || !strings.Contains(output, "protected-ok") {
		t.Fatalf("protected task lost normal HOME/filesystem access: %q", output)
	}
	if strings.Contains(output, "leaked-private") || strings.Contains(output, "unmasked-private") {
		t.Fatalf("protected path masking was bypassed: %q", output)
	}
	if data, err := os.ReadFile(visible); err != nil || string(data) != "after\n" {
		t.Fatalf("normal HOME write failed: data=%q err=%v", data, err)
	}
	if _, err := os.Stat(filepath.Join(root, "created.txt")); err != nil {
		t.Fatalf("normal HOME create failed: %v", err)
	}
	if data, err := os.ReadFile(privateNested); err != nil || string(data) != "nested-secret\n" {
		t.Fatalf("private directory content changed: data=%q err=%v", data, err)
	}
	if data, err := os.ReadFile(privateFile); err != nil || string(data) != "file-secret\n" {
		t.Fatalf("private file content changed: data=%q err=%v", data, err)
	}
}
