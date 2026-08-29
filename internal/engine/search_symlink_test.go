package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSearchFilesDoesNotFollowSymlinkOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("OUTSIDE_SECRET_MARKER"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	eng, err := New(Config{Roots: []string{root}, StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	got, err := eng.SearchFiles(context.Background(), FileSearchInput{Path: root, Pattern: "OUTSIDE_SECRET_MARKER", Kind: "content"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Hits) != 0 {
		t.Fatalf("content search followed a symlink outside root: %+v", got.Hits)
	}
}
