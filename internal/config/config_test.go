package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAndLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chat-with-cli.toml")
	want := map[string]any{
		"agent.relay_url":        "https://relay.example",
		"agent.allow_exec":       true,
		"agent.max_active_tasks": 32,
		"agent.root":             []string{"/workspace", "/tmp/project"},
		"relay.instance_mode":    "private",
	}
	if err := Write(path, want); err != nil {
		t.Fatal(err)
	}
	values, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := values.String("", "agent.relay_url"); got != "https://relay.example" {
		t.Fatalf("relay URL=%q", got)
	}
	if !values.Bool(false, "agent.allow_exec") {
		t.Fatal("allow_exec did not round-trip")
	}
	if got := values.Int(0, "agent.max_active_tasks"); got != 32 {
		t.Fatalf("max_active_tasks=%d", got)
	}
	if got := values.Strings("agent.root"); len(got) != 2 || got[0] != "/workspace" || got[1] != "/tmp/project" {
		t.Fatalf("roots=%v", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("config mode=%o, want 600", got)
	}
}

func TestLoadRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.toml")
	link := filepath.Join(dir, "link.toml")
	if err := os.WriteFile(target, []byte("[agent]\nallow_exec = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skip("symlinks are unavailable")
		}
		t.Fatal(err)
	}
	if _, err := Load(link); err == nil {
		t.Fatal("Load followed a configuration symlink")
	}
}
