package tui

import (
	tea "charm.land/bubbletea/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadAuditLinesBoundedAndMetadataOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(path, "events.jsonl")
	input := strings.Repeat("{bad json}\n", 10) +
		`{"id":"a","time":"2026-10-14T08:00:00Z","method":"system_info","ok":true,"duration_ms":2,"private":"SECRET_SHOULD_NOT_LEAK"}` + "\n" +
		`{"id":"b","time":"2026-10-14T08:00:01Z","method":"task_start","ok":false,"duration_ms":10}` + "\n"
	if err := os.WriteFile(file, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	lines := readAuditLines(dir, 1)
	if len(lines) != 1 || !strings.Contains(lines[0], "FAIL") || !strings.Contains(lines[0], "task_start") || strings.Contains(lines[0], "SECRET") {
		t.Fatalf("expected one redacted audit event, got %#v", lines)
	}
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	lines = readAuditLines(dir, 10)
	if len(lines) != 1 || !strings.Contains(lines[0], "Unsafe") {
		t.Fatalf("unsafe permissions accepted: %#v", lines)
	}
}

func TestAuditReadRejectsSymlinks(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "audit"), 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "other")
	if err := os.WriteFile(target, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "audit", "events.jsonl")); err != nil {
		t.Fatal(err)
	}
	if got := readAuditLines(dir, 10); len(got) != 1 || !strings.Contains(got[0], "Unsafe") {
		t.Fatalf("accepted symlink: %#v", got)
	}
}

func TestReadAuditLinesSkipsIncompleteTrailingRecord(t *testing.T) {
	dir := t.TempDir()
	_ = os.Mkdir(filepath.Join(dir, "audit"), 0700)
	path := filepath.Join(dir, "audit", "events.jsonl")
	input := `{"time":"2026-10-14T08:00:00Z","method":"fs_read","ok":true,"duration_ms":3}` + "\n" +
		`{"time":"2026-10-14T08:00:01Z","method":"not_finished"`
	_ = os.WriteFile(path, []byte(input), 0600)
	lines := readAuditLines(dir, 10)
	if len(lines) != 1 || !strings.Contains(lines[0], "fs_read") {
		t.Fatalf("invalid tail included: %#v", lines)
	}
}

func TestStartManagedAgentDoesNotStartWithInvalidConfig(t *testing.T) {
	err := startManagedAgent("/bin/echo", filepath.Join(t.TempDir(), "missing.toml"))
	if err == nil || !strings.Contains(err.Error(), "Agent config") {
		t.Fatalf("invalid config accepted: %v", err)
	}
}

func TestLogModeAndFollowControls(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "config.toml"))
	m.page = 2
	_, _ = m.Update(tea.KeyPressMsg(tea.Key{Code: 'g', Text: "g"}))
	if m.logMode != 1 {
		t.Fatalf("g did not switch to audit")
	}
	_, _ = m.Update(tea.KeyPressMsg(tea.Key{Code: 'f', Text: "f"}))
	if m.follow {
		t.Fatal("f did not pause")
	}
	_, _ = m.Update(tea.KeyPressMsg(tea.Key{Code: 'f', Text: "f"}))
	if !m.follow {
		t.Fatal("f did not resume")
	}
}

func TestTerminalLogControlCharactersAreDiscarded(t *testing.T) {
	got := sanitizeTerminalLog("ok\x1b[31m\rbad\t")
	if strings.ContainsAny(got, "\x1b\r\t") {
		t.Fatalf("unsafe text: %q", got)
	}
}
