package tui

import (
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestAddInputKeyboardPasteAndEditing(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "config.toml"))
	m.page = 1

	m.Update(tea.KeyPressMsg(tea.Key{Code: 'a', Text: "a"}))
	if !m.input || !m.addInput.Focused() || m.View().MouseMode != tea.MouseModeCellMotion {
		t.Fatal("add should focus a mouse-enabled textinput")
	}

	const pasted = "example http https://example.com/mcp"
	m.Update(tea.PasteMsg{Content: pasted})
	if m.addInput.Value() != pasted {
		t.Fatalf("paste lost characters: %q", m.addInput.Value())
	}

	m.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyHome}))
	if m.addInput.Position() != 0 {
		t.Fatalf("Home did not move to start: %d", m.addInput.Position())
	}
	m.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyRight}))
	m.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyDelete}))
	if got := m.addInput.Value(); got != "eample http https://example.com/mcp" {
		t.Fatalf("in-place Delete failed: %q", got)
	}
	m.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyEnd}))
	m.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyLeft}))
	m.Update(tea.KeyPressMsg(tea.Key{Code: '!', Text: "!"}))
	if got := m.addInput.Value(); !strings.HasSuffix(got, "mc!p") {
		t.Fatalf("in-place typing failed: %q", got)
	}
	m.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyEsc}))
	if m.input || m.addInput.Value() != "" || m.View().MouseMode != tea.MouseModeNone {
		t.Fatal("cancel should clear field and disable mouse capture")
	}
}

func TestAddInputMouseClickAndUnicode(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "config.toml"))
	m.page = 1
	m.Update(tea.KeyPressMsg(tea.Key{Code: 'a', Text: "a"}))
	m.addInput.SetValue("文档abc")
	m.Update(tea.MouseClickMsg{X: 4, Y: m.addInputY(), Button: tea.MouseLeft})
	if m.addInput.Position() != 0 {
		t.Fatalf("mouse click at start moved to %d", m.addInput.Position())
	}
	m.Update(tea.MouseClickMsg{X: 6, Y: m.addInputY(), Button: tea.MouseLeft})
	if m.addInput.Position() != 1 {
		t.Fatalf("wide rune mouse positioning failed: %d", m.addInput.Position())
	}
	m.Update(tea.MouseClickMsg{X: 8, Y: m.addInputY(), Button: tea.MouseLeft})
	if m.addInput.Position() != 2 {
		t.Fatalf("second wide rune mouse positioning failed: %d", m.addInput.Position())
	}
	m.Update(tea.MouseClickMsg{X: 7, Y: m.addInputY() + 1, Button: tea.MouseLeft})
	if m.addInput.Position() != 2 {
		t.Fatal("click outside the input should not affect the cursor")
	}
}

func TestAddInputMouseClickInScrolledText(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "config.toml"))
	m.page = 1
	m.Update(tea.KeyPressMsg(tea.Key{Code: 'a', Text: "a"}))
	m.addInput.SetWidth(10)
	value := "0123456789abcdefghijklmnopqrstuvwxyz"
	m.addInput.SetValue(value)
	m.addInput.CursorEnd()
	m.Update(tea.MouseClickMsg{X: 4, Y: m.addInputY(), Button: tea.MouseLeft})
	if got := m.addInput.Position(); got < len(value)-11 || got > len(value)-9 {
		t.Fatalf("clicked visible left edge but cursor went to %d of %d", got, len(value))
	}
}
