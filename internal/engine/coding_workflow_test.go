package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func invokeWorkflow[T any](t *testing.T, eng *Engine, method string, input any) T {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	result, err := eng.Invoke(context.Background(), method, raw)
	if err != nil {
		t.Fatalf("%s failed: %v", method, err)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var output T
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatalf("decode %s result %s: %v", method, data, err)
	}
	return output
}

func waitWorkflowTask(t *testing.T, eng *Engine, taskID string) (ReadTaskOutput, string) {
	t.Helper()
	// The workflow deliberately launches real subprocesses (including `go test`).
	// Under the repository-wide race job those subprocesses compete with the
	// outer Go test process, so allow enough time for a loaded CI runner without
	// weakening the per-poll task_wait timeout below.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var offset int64
	var output bytes.Buffer
	for {
		raw, err := json.Marshal(WaitTaskInput{TaskID: taskID, Offset: offset, TimeoutMS: 500})
		if err != nil {
			t.Fatal(err)
		}
		result, err := eng.Invoke(ctx, "task_wait", raw)
		if err != nil {
			t.Fatalf("task_wait failed: %v", err)
		}
		data, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		var waited ReadTaskOutput
		if err := json.Unmarshal(data, &waited); err != nil {
			t.Fatalf("decode task_wait result %s: %v", data, err)
		}
		output.WriteString(waited.Output)
		offset = waited.NextOffset
		if waited.EOF {
			return waited, output.String()
		}
		if err := ctx.Err(); err != nil {
			t.Fatal(err)
		}
	}
}

func runWorkflowCommand(t *testing.T, root string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func TestCodingWorkflowUsesSnapshotsTasksDiffAndLifecycleTools(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is unavailable")
	}
	root := t.TempDir()
	runWorkflowCommand(t, root, "init", "-q")

	eng, err := New(Config{
		Roots:             []string{root},
		AllowFileWrite:    true,
		AllowExec:         true,
		ExecSandbox:       "none",
		StateDir:          t.TempDir(),
		MaxReadChunkBytes: 64 * 1024,
		MaxHashBytes:      8 << 20,
		MaxPatchBytes:     8 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Close() })

	goMod := "module example.com/chat-with-cli-workflow\n\ngo 1.22\n"
	mainSource := "package main\n\nfunc value() int {\n\treturn 1\n}\n\nfunc main() {}\n"
	invokeWorkflow[Ack](t, eng, "fs_write", FileWriteInput{Path: filepath.Join(root, "go.mod"), Content: goMod, Mode: "rewrite"})
	invokeWorkflow[Ack](t, eng, "fs_write", FileWriteInput{Path: filepath.Join(root, "main.go"), Content: mainSource, Mode: "rewrite"})
	runWorkflowCommand(t, root, "add", "go.mod", "main.go")
	runWorkflowCommand(t, root, "-c", "user.name=workflow-test", "-c", "user.email=workflow@example.invalid", "commit", "-qm", "initial")

	mainPath := filepath.Join(root, "main.go")
	read := invokeWorkflow[FileReadOutput](t, eng, "fs_read", FileReadInput{Path: mainPath})
	if read.SHA256 == "" {
		t.Fatal("workflow fs_read did not return a snapshot")
	}
	invokeWorkflow[FilePatchOutput](t, eng, "fs_patch", FilePatchInput{
		Path: mainPath, OldText: "return 1", NewText: "return 2", ExpectedSHA256: read.SHA256,
	})

	gofmtTask := invokeWorkflow[TaskInfo](t, eng, "task_start", StartTaskInput{Command: "gofmt -w main.go", Cwd: root, Name: "workflow-gofmt"})
	gofmtResult, gofmtOutput := waitWorkflowTask(t, eng, gofmtTask.ID)
	if gofmtResult.Task.State != "completed" || gofmtResult.Task.ExitCode == nil || *gofmtResult.Task.ExitCode != 0 {
		t.Fatalf("gofmt task failed: task=%+v output=%q", gofmtResult.Task, gofmtOutput)
	}

	testTask := invokeWorkflow[TaskInfo](t, eng, "task_start", StartTaskInput{Command: "go test ./...", Cwd: root, Name: "workflow-test"})
	testResult, testOutput := waitWorkflowTask(t, eng, testTask.ID)
	if testResult.Task.State != "completed" || testResult.Task.ExitCode == nil || *testResult.Task.ExitCode != 0 {
		t.Fatalf("go test task failed: task=%+v output=%q", testResult.Task, testOutput)
	}

	read = invokeWorkflow[FileReadOutput](t, eng, "fs_read", FileReadInput{Path: mainPath})
	invokeWorkflow[FilePatchOutput](t, eng, "fs_patch", FilePatchInput{
		Path: mainPath, OldText: "return 2", NewText: "return 3", ExpectedSHA256: read.SHA256,
	})
	diffTask := invokeWorkflow[TaskInfo](t, eng, "task_start", StartTaskInput{Command: "git diff -- main.go", Cwd: root, Name: "workflow-diff"})
	diffResult, diffOutput := waitWorkflowTask(t, eng, diffTask.ID)
	if diffResult.Task.State != "completed" || diffResult.Task.ExitCode == nil || *diffResult.Task.ExitCode != 0 {
		t.Fatalf("git diff task failed: task=%+v output=%q", diffResult.Task, diffOutput)
	}
	if !strings.Contains(diffOutput, "return 1") || !strings.Contains(diffOutput, "return 3") {
		t.Fatalf("git diff did not show the second edit: %q", diffOutput)
	}

	temporaryPath := filepath.Join(root, ".agent-temporary.txt")
	invokeWorkflow[Ack](t, eng, "fs_write", FileWriteInput{Path: temporaryPath, Content: "temporary\n", Mode: "rewrite"})
	temporary := invokeWorkflow[FileReadOutput](t, eng, "fs_read", FileReadInput{Path: temporaryPath})
	invokeWorkflow[Ack](t, eng, "fs_delete", FileDeleteInput{Path: temporaryPath, ExpectedSHA256: temporary.SHA256})
	if _, err := os.Lstat(temporaryPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fs_delete did not remove temporary file: %v", err)
	}
	statusTask := invokeWorkflow[TaskInfo](t, eng, "task_start", StartTaskInput{Command: "git status --short", Cwd: root, Name: "workflow-status"})
	statusResult, statusOutput := waitWorkflowTask(t, eng, statusTask.ID)
	if statusResult.Task.State != "completed" || statusResult.Task.ExitCode == nil || *statusResult.Task.ExitCode != 0 {
		t.Fatalf("git status task failed: task=%+v output=%q", statusResult.Task, statusOutput)
	}
	if strings.Contains(statusOutput, filepath.Base(temporaryPath)) {
		t.Fatalf("deleted temporary file remained in git status: %q", statusOutput)
	}
	if strings.TrimSpace(statusOutput) == "" {
		t.Fatalf("workflow status unexpectedly had no modified-file result: %q", statusOutput)
	}
}
