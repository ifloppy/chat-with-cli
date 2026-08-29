//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package securefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckSingleLinkRejectsHardlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private")
	link := filepath.Join(dir, "private-link")
	if err := os.WriteFile(path, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, link); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skip("hardlinks are unavailable")
		}
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckSingleLink(info, "private file"); err == nil {
		t.Fatal("hardlinked private file was accepted")
	}
}
