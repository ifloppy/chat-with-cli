package oauthserver

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSystemdPrivateStateDirectoryLinkIsRecognized(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	privateRoot := filepath.Join(root, "private")
	if err := os.Mkdir(privateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(privateRoot, "chat-with-cli")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "chat-with-cli")
	if err := os.Symlink(filepath.Join("private", "chat-with-cli"), link); err != nil {
		t.Fatal(err)
	}
	if !isSystemdPrivateStateLink(link, root) {
		t.Fatal("verified systemd StateDirectory link was rejected")
	}
}

func TestSystemdPrivateStateDirectoryRejectsArbitrarySymlinks(t *testing.T) {
	root := t.TempDir()
	privateRoot := filepath.Join(root, "private")
	if err := os.Mkdir(privateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "chat-with-cli")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if isSystemdPrivateStateLink(link, root) {
		t.Fatal("arbitrary state-directory symlink was accepted")
	}
}

func TestOAuthServerStillRejectsOrdinaryStateDirectorySymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{PublicURL: "http://127.0.0.1:19991", StateDir: link, Mode: ModePublic}); err == nil {
		t.Fatal("ordinary state-directory symlink was accepted")
	}
}
