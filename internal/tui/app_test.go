package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/ifloppy/chat-with-cli/internal/mcpgateway"
)

func TestMCPQuickAddToggleAndDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	m := New(path)
	m.input = true
	m.addInput.SetValue("example http http://127.0.0.1:3000/mcp")
	m.addServer()
	if m.input {
		t.Fatal("input did not close after valid add")
	}
	r, err := mcpgateway.Load(m.path)
	if err != nil || !r.Servers["example"].Enabled {
		t.Fatalf("add: %#v %v", r, err)
	}
	m.changeSelected("enable")
	r, _ = mcpgateway.Load(m.path)
	if r.Servers["example"].Enabled {
		t.Fatal("enable toggle did not disable")
	}
	m.changeSelected("expose")
	r, _ = mcpgateway.Load(m.path)
	if r.Servers["example"].Expose {
		t.Fatal("expose toggle did not hide")
	}
	m.changeSelected("remove")
	r, _ = mcpgateway.Load(m.path)
	if len(r.Servers) != 0 {
		t.Fatal("remove did not remove entry")
	}
	if !m.View().AltScreen {
		t.Fatal("TUI must use alternate screen")
	}
}

func TestTUIInvalidMCPInputIsNotPersisted(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "config.toml"))
	m.input = true
	m.addInput.SetValue("invalid")
	m.addServer()
	if !m.input || !strings.Contains(m.notice, "Use:") {
		t.Fatalf("expected validation error: %#v", m)
	}
	if _, err := os.Stat(m.path); !os.IsNotExist(err) {
		t.Fatalf("unexpected registry creation: %v", err)
	}
}

func TestConnectingWhenAgentMayBeRunningIsBlocked(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "config.toml"))
	m.data.agentProcess = true
	_, cmd := m.Update(tea.KeyPressMsg(tea.Key{Code: 'c', Text: "c"}))
	if cmd != nil || !strings.Contains(m.notice, "already running") {
		t.Fatalf("duplicate connect not blocked: %q command=%v", m.notice, cmd)
	}
}

func TestServiceStartRequiresConfirmation(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "config.toml"))
	m.data.serviceInstalled = true
	_, cmd := m.Update(tea.KeyPressMsg(tea.Key{Code: 's', Text: "s"}))
	if cmd != nil || !m.confirmServiceStart {
		t.Fatalf("start was not gated: %v", cmd)
	}
	_, cmd = m.Update(tea.KeyPressMsg(tea.Key{Code: 'n', Text: "n"}))
	if cmd != nil || m.confirmServiceStart {
		t.Fatal("start cancellation failed")
	}
}
