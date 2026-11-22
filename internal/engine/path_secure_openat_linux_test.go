//go:build linux

package engine

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSecureOpenBeneathNestedFile(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "one", "two")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "note.txt"), []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	rootFD, err := openRootFD(root)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	fd, err := secureOpenBeneath(rootFD, "one/two/note.txt", unix.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "note.txt")
	defer file.Close()
	data := make([]byte, 4)
	if _, err := file.Read(data); err != nil {
		t.Fatal(err)
	}
	if string(data) != "safe" {
		t.Fatalf("read %q, want safe", data)
	}
}

func TestSecureOpenBeneathRejectsTraversalAndSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "file-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../nested", filepath.Join(root, "nested", "cycle")); err != nil {
		t.Fatal(err)
	}
	rootFD, err := openRootFD(root)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)

	for _, rel := range []string{
		"", "/etc/passwd", "../secret.txt", "nested/../escape/secret.txt",
		"./escape/secret.txt", "nested//secret.txt", "escape/secret.txt",
		"file-link", "nested/cycle/secret.txt",
	} {
		t.Run(rel, func(t *testing.T) {
			fd, err := secureOpenBeneath(rootFD, rel, unix.O_RDONLY)
			if err == nil {
				unix.Close(fd)
				t.Fatalf("unsafe path %q unexpectedly opened", rel)
			}
		})
	}
}

func TestSecureFileOperationsRejectDirectorySymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	eng, err := New(Config{
		Roots: []string{root}, StateDir: t.TempDir(), AllowFileWrite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "escape", "secret.txt")
	if _, err := eng.ReadFile(FileReadInput{Path: path}); err == nil {
		t.Fatal("read followed symlink directory")
	}
	if err := eng.WriteFile(FileWriteInput{Path: path, Content: "tampered", Mode: "rewrite"}); err == nil {
		t.Fatal("write followed symlink directory")
	}
	data, err := os.ReadFile(filepath.Join(outside, "secret.txt"))
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("outside target was touched: %q, %v", data, err)
	}
}
