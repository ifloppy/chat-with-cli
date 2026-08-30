package engine

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newFilesystemTestEngine(t *testing.T, root string, protected ...string) *Engine {
	t.Helper()
	eng, err := New(Config{
		Roots:             []string{root},
		AllowFileWrite:    true,
		StateDir:          t.TempDir(),
		ProtectedPaths:    protected,
		MaxReadChunkBytes: 64 * 1024,
		MaxHashBytes:      8 << 20,
		MaxPatchBytes:     8 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Close() })
	return eng
}

func readSnapshot(t *testing.T, eng *Engine, path string) FileReadOutput {
	t.Helper()
	read, err := eng.ReadFile(FileReadInput{Path: path, Limit: 64 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	if read.SHA256 == "" {
		t.Fatalf("fs_read did not return a snapshot for %q: %+v", path, read)
	}
	return read
}

func TestFileDeleteHonorsSnapshotRootAndLinkBoundaries(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	protected := filepath.Join(root, "private")
	if err := os.Mkdir(protected, 0o700); err != nil {
		t.Fatal(err)
	}
	eng := newFilesystemTestEngine(t, root, protected)

	path := filepath.Join(root, "delete-me.txt")
	if err := os.WriteFile(path, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot := readSnapshot(t, eng, path)
	if err := eng.DeleteFile(FileDeleteInput{Path: path, ExpectedSHA256: snapshot.SHA256}); err != nil {
		t.Fatalf("fresh snapshot delete failed: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted file still exists or returned the wrong error: %v", err)
	}

	racePath := filepath.Join(root, "delete-race.txt")
	if err := os.WriteFile(racePath, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	raceSnapshot := readSnapshot(t, eng, racePath)
	raceReplacement := []byte("replacement")
	var raceHookErr error
	eng.beforeFileCommit = func() { raceHookErr = os.WriteFile(racePath, raceReplacement, 0o600) }
	if err := eng.DeleteFile(FileDeleteInput{Path: racePath, ExpectedSHA256: raceSnapshot.SHA256}); err == nil || !strings.Contains(err.Error(), "file changed since it was read") {
		t.Fatalf("delete race was accepted: %v", err)
	}
	if raceHookErr != nil {
		t.Fatal(raceHookErr)
	}
	if data, err := os.ReadFile(racePath); err != nil || !bytes.Equal(data, raceReplacement) {
		t.Fatalf("delete race did not preserve replacement: data=%q err=%v", data, err)
	}

	stalePath := filepath.Join(root, "stale.txt")
	if err := os.WriteFile(stalePath, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	stale := readSnapshot(t, eng, stalePath)
	if err := os.WriteFile(stalePath, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := eng.DeleteFile(FileDeleteInput{Path: stalePath, ExpectedSHA256: stale.SHA256}); err == nil || !strings.Contains(err.Error(), "file changed since it was read") {
		t.Fatalf("stale delete was accepted: %v", err)
	}
	if data, err := os.ReadFile(stalePath); err != nil || string(data) != "new" {
		t.Fatalf("stale delete changed the newer file: data=%q err=%v", data, err)
	}
	if err := eng.DeleteFile(FileDeleteInput{Path: stalePath}); err == nil || !strings.Contains(err.Error(), "expected_sha256 is required") {
		t.Fatalf("delete without a snapshot was accepted: %v", err)
	}

	protectedFile := filepath.Join(protected, "secret.txt")
	if err := os.WriteFile(protectedFile, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := eng.DeleteFile(FileDeleteInput{Path: protectedFile, ExpectedSHA256: sha256Hex([]byte("secret"))}); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("protected file delete was accepted: %v", err)
	}

	outsideFile := filepath.Join(outside, "outside.txt")
	if err := os.WriteFile(outsideFile, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := eng.DeleteFile(FileDeleteInput{Path: outsideFile, ExpectedSHA256: sha256Hex([]byte("outside"))}); err == nil || !strings.Contains(err.Error(), "outside allowed roots") {
		t.Fatalf("outside delete was accepted: %v", err)
	}

	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(outsideFile, link); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skip("symlinks are unavailable")
		}
		t.Fatal(err)
	}
	if err := eng.DeleteFile(FileDeleteInput{Path: link, ExpectedSHA256: sha256Hex([]byte("outside"))}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink delete was accepted: %v", err)
	}
	if _, err := os.Lstat(outsideFile); err != nil {
		t.Fatalf("symlink delete damaged the target: %v", err)
	}
}

func TestFileDeleteSupportsOnlyExplicitEmptyDirectoryRemoval(t *testing.T) {
	root := t.TempDir()
	eng := newFilesystemTestEngine(t, root)
	dir := filepath.Join(root, "empty", "child")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := eng.DeleteFile(FileDeleteInput{Path: dir}); err == nil || !strings.Contains(err.Error(), "allow_empty_dir") {
		t.Fatalf("directory delete without opt-in was accepted: %v", err)
	}
	if err := eng.DeleteFile(FileDeleteInput{Path: dir, AllowEmptyDir: true}); err != nil {
		t.Fatalf("explicit empty directory delete failed: %v", err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty directory still exists or returned the wrong error: %v", err)
	}
	if err := eng.DeleteFile(FileDeleteInput{Path: root, AllowEmptyDir: true}); err == nil {
		t.Fatal("root deletion was accepted")
	}
}

func TestFileMoveRequiresSnapshotsAndNeverOverwritesByDefault(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	eng := newFilesystemTestEngine(t, root)

	source := filepath.Join(root, "src", "main.go")
	destination := filepath.Join(root, "dst", "main.go")
	if err := os.MkdirAll(filepath.Dir(source), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot := readSnapshot(t, eng, source)
	moved, err := eng.MoveFile(FileMoveInput{Source: source, Destination: destination, ExpectedSHA256: snapshot.SHA256})
	if err != nil {
		t.Fatalf("root-in move failed: %v", err)
	}
	if moved.Source != source || moved.Destination != destination {
		t.Fatalf("unexpected move result: %+v", moved)
	}
	if _, err := os.Stat(source); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("move left source behind: %v", err)
	}
	if data, err := os.ReadFile(destination); err != nil || string(data) != "package main\n" {
		t.Fatalf("move destination content=%q err=%v", data, err)
	}

	if err := os.WriteFile(source, []byte("new source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.MoveFile(FileMoveInput{Source: source, Destination: filepath.Join(root, "other.txt")}); err == nil || !strings.Contains(err.Error(), "expected_sha256 is required") {
		t.Fatalf("move without a snapshot was accepted: %v", err)
	}
	stale := readSnapshot(t, eng, source)
	if err := os.WriteFile(source, []byte("changed source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.MoveFile(FileMoveInput{Source: source, Destination: filepath.Join(root, "stale-destination.txt"), ExpectedSHA256: stale.SHA256}); err == nil || !strings.Contains(err.Error(), "file changed since it was read") {
		t.Fatalf("stale move was accepted: %v", err)
	}

	overwriteSource := filepath.Join(root, "overwrite-source.txt")
	overwriteDestination := filepath.Join(root, "overwrite-destination.txt")
	if err := os.WriteFile(overwriteSource, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overwriteDestination, []byte("destination"), 0o600); err != nil {
		t.Fatal(err)
	}
	sourceSnapshot := readSnapshot(t, eng, overwriteSource)
	if err := func() error {
		_, err := eng.MoveFile(FileMoveInput{Source: overwriteSource, Destination: overwriteDestination, ExpectedSHA256: sourceSnapshot.SHA256})
		return err
	}(); err == nil || !strings.Contains(err.Error(), "destination already exists") {
		t.Fatalf("default overwrite was accepted: %v", err)
	}
	if data, readErr := os.ReadFile(overwriteDestination); readErr != nil || string(data) != "destination" {
		t.Fatalf("default overwrite changed destination: data=%q err=%v", data, readErr)
	}
	destinationSnapshot := readSnapshot(t, eng, overwriteDestination)
	if _, err := eng.MoveFile(FileMoveInput{
		Source: overwriteSource, Destination: overwriteDestination,
		ExpectedSHA256: sourceSnapshot.SHA256, Overwrite: true,
		ExpectedDestinationSHA256: destinationSnapshot.SHA256,
	}); err != nil {
		t.Fatalf("preconditioned overwrite failed: %v", err)
	}
	if data, err := os.ReadFile(overwriteDestination); err != nil || string(data) != "source" {
		t.Fatalf("overwrite destination content=%q err=%v", data, err)
	}

	outsideSource := filepath.Join(outside, "source.txt")
	if err := os.WriteFile(outsideSource, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.MoveFile(FileMoveInput{Source: outsideSource, Destination: filepath.Join(root, "escape.txt"), ExpectedSHA256: sha256Hex([]byte("outside"))}); err == nil || !strings.Contains(err.Error(), "outside allowed roots") {
		t.Fatalf("outside source move was accepted: %v", err)
	}
	if _, err := eng.MoveFile(FileMoveInput{Source: source, Destination: filepath.Join(outside, "escape.txt"), ExpectedSHA256: sha256Hex([]byte("changed source"))}); err == nil || !strings.Contains(err.Error(), "outside allowed roots") {
		t.Fatalf("outside destination move was accepted: %v", err)
	}
}

func TestFileMoveRejectsSymlinkAndHardlinkEndpoints(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	eng := newFilesystemTestEngine(t, root)

	outsideFile := filepath.Join(outside, "outside.txt")
	if err := os.WriteFile(outsideFile, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkSource := filepath.Join(root, "symlink-source.txt")
	if err := os.Symlink(outsideFile, symlinkSource); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skip("symlinks are unavailable")
		}
		t.Fatal(err)
	}
	if _, err := eng.MoveFile(FileMoveInput{Source: symlinkSource, Destination: filepath.Join(root, "moved.txt"), ExpectedSHA256: sha256Hex([]byte("outside"))}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink source move was accepted: %v", err)
	}

	source := filepath.Join(root, "source.txt")
	if err := os.WriteFile(source, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkDestination := filepath.Join(root, "symlink-destination.txt")
	if err := os.Symlink(outsideFile, symlinkDestination); err != nil {
		t.Fatal(err)
	}
	snapshot := readSnapshot(t, eng, source)
	if _, err := eng.MoveFile(FileMoveInput{Source: source, Destination: symlinkDestination, ExpectedSHA256: snapshot.SHA256, Overwrite: true, ExpectedDestinationSHA256: sha256Hex([]byte("outside"))}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink destination move was accepted: %v", err)
	}

	hardlink := filepath.Join(root, "hardlink.txt")
	if err := os.Link(source, hardlink); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skip("hardlinks are unavailable")
		}
		t.Fatal(err)
	}
	if _, err := eng.MoveFile(FileMoveInput{Source: source, Destination: filepath.Join(root, "hardlink-moved.txt"), ExpectedSHA256: snapshot.SHA256}); err == nil || !strings.Contains(err.Error(), "hard link") {
		t.Fatalf("hardlinked source move was accepted: %v", err)
	}
}

func TestFileMkdirIsIdempotentAndStaysInsideWorkspace(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	protected := filepath.Join(root, "private")
	if err := os.Mkdir(protected, 0o700); err != nil {
		t.Fatal(err)
	}
	eng := newFilesystemTestEngine(t, root, protected)

	directory := filepath.Join(root, "one", "two")
	if err := eng.MakeDirectory(FileMkdirInput{Path: directory}); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := eng.MakeDirectory(FileMkdirInput{Path: directory}); err != nil {
		t.Fatalf("idempotent mkdir failed: %v", err)
	}
	if info, err := os.Stat(directory); err != nil || !info.IsDir() {
		t.Fatalf("mkdir result is not a directory: info=%v err=%v", info, err)
	}
	if err := eng.MakeDirectory(FileMkdirInput{Path: protected}); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("protected mkdir was accepted: %v", err)
	}
	if err := eng.MakeDirectory(FileMkdirInput{Path: outside}); err == nil || !strings.Contains(err.Error(), "outside allowed roots") {
		t.Fatalf("outside mkdir was accepted: %v", err)
	}

	link := filepath.Join(root, "linked-parent")
	if err := os.Symlink(outside, link); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skip("symlinks are unavailable")
		}
		t.Fatal(err)
	}
	if err := eng.MakeDirectory(FileMkdirInput{Path: filepath.Join(link, "child")}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("mkdir through symlink was accepted: %v", err)
	}
}
