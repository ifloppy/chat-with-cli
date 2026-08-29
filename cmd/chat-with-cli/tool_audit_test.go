package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ifloppy/chat-with-cli/internal/agent"
	"github.com/ifloppy/chat-with-cli/internal/engine"
)

func TestToolAuditPrintsInventoryInAllowAllMode(t *testing.T) {
	var out bytes.Buffer
	audit := newToolAudit(&out)
	audit.printInventory(approvalAllowAll, engine.Config{
		Roots: []string{"/workspace"}, AllowFileWrite: true, AllowExec: true,
		AllowScreen: true, AllowAccessibility: true, AllowComputerControl: true,
	})
	text := out.String()
	for _, want := range []string{
		"MCP tool audit: 31 advertised tools",
		"approval mode: allow-all",
		"WARNING: allow-all enables temporary capabilities",
		"fs_read",
		"fs_write",
		"computer_ui_invoke",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("inventory missing %q:\n%s", want, text)
		}
	}
}

func TestToolAuditLogsCallsWithoutArguments(t *testing.T) {
	var out bytes.Buffer
	audit := newToolAudit(&out)
	audit.observe(agent.ToolCall{Method: "fs_write"})
	audit.observe(agent.ToolCall{Method: "unknown\nforged"})
	text := out.String()
	if !strings.Contains(text, "MCP tool call: fs_write") || !strings.Contains(text, "Unknown MCP tool") {
		t.Fatalf("call audit missing entries: %s", text)
	}
	if strings.Contains(text, "forged\n") {
		t.Fatalf("call audit allowed a forged line: %q", text)
	}
}
