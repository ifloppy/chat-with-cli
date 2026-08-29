//go:build linux

package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecureFileOperationsRejectOutsideSymlink(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "escape.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	eng, err := New(Config{
		Roots: []string{root}, StateDir: t.TempDir(), AllowFileWrite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.ReadFile(FileReadInput{Path: link}); err == nil {
		t.Fatal("fs_read followed a symlink outside the allowed root")
	}

	if err := eng.WriteFile(FileWriteInput{Path: link, Content: "rewrite", Mode: "rewrite"}); err == nil {
		t.Fatal("fs_write rewrite followed/replaced an outside symlink")
	}
	if err := eng.WriteFile(FileWriteInput{Path: link, Content: "append", Mode: "append"}); err == nil {
		t.Fatal("fs_write append followed an outside symlink")
	}
	data, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "outside" {
		t.Fatalf("outside file changed: %q", data)
	}
}

func TestSecureFileOperationsStillWorkInsideRoot(t *testing.T) {
	root := t.TempDir()
	eng, err := New(Config{
		Roots: []string{root}, StateDir: t.TempDir(), AllowFileWrite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "nested", "note.txt")
	if err := eng.WriteFile(FileWriteInput{Path: path, Content: "alpha", Mode: "rewrite"}); err != nil {
		t.Fatal(err)
	}

	if err := eng.WriteFile(FileWriteInput{Path: path, Content: " beta", Mode: "append"}); err != nil {
		t.Fatal(err)
	}
	read, err := eng.ReadFile(FileReadInput{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if read.Content != "alpha beta" {
		t.Fatalf("content=%q", read.Content)
	}
	patched, err := eng.PatchFile(FilePatchInput{Path: path, OldText: "beta", NewText: "gamma"})
	if err != nil {
		t.Fatal(err)
	}
	if patched.Replacements != 1 {
		t.Fatalf("replacements=%d", patched.Replacements)
	}
	read, err = eng.ReadFile(FileReadInput{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if read.Content != "alpha gamma" {
		t.Fatalf("patched content=%q", read.Content)
	}
}
