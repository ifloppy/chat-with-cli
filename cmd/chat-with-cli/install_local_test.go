package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallLocalRejectsNonChatCLI(t *testing.T) {
	dir := t.TempDir()
	candidate := filepath.Join(dir, "candidate")
	target := filepath.Join(dir, "chat-with-cli")
	if err := os.WriteFile(candidate, []byte("not a real Go executable"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("existing"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := runInstallLocal([]string{"--candidate", candidate, "--binary", target, "--apply"}); err == nil || !strings.Contains(err.Error(), "Go executable") {
		t.Fatalf("non-Go executable accepted: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "existing" {
		t.Fatalf("target changed: %q %v", got, err)
	}
}

func TestInstallLocalRefusesSelfReplacement(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "chat-with-cli")
	if err := os.WriteFile(target, []byte("existing"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := runInstallLocal([]string{"--candidate", target, "--binary", target, "--apply"}); err == nil {
		t.Fatal("same path upgrade was allowed")
	}
}
