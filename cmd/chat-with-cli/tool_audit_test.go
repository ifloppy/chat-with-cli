package main

import (
	"bytes"
	"encoding/json"
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
		"MCP tool audit: 34 advertised tools",
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

func TestToolAuditLogsTwoLineArgumentSummaries(t *testing.T) {
	var out bytes.Buffer
	audit := newToolAudit(&out)
	audit.observe(agent.ToolCall{Method: "fs_search", Args: json.RawMessage(`{"path":"/workspace/project","pattern":"needle.*go","kind":"content","max_results":25}`)})
	audit.observe(agent.ToolCall{Method: "fs_patch", Args: json.RawMessage(`{"path":"/workspace/a.go","old_text":"secret\nline","new_text":"replacement","expected_sha256":"deadbeef","api_token":"do-not-print"}`)})
	audit.observe(agent.ToolCall{Method: "unknown\nforged", Args: json.RawMessage(`{"path":"/tmp/demo"}`)})
	text := out.String()

	for _, want := range []string{
		"MCP tool: fs_search",
		`args: kind="content"  max_results=25  path="/workspace/project"  pattern="needle.*go"`,
		"MCP tool: fs_patch",
		`api_token=<redacted>`,
		`new_text=<omitted:11 bytes>`,
		`old_text=<omitted:11 bytes>`,
		`path="/workspace/a.go"`,
		"Unknown MCP tool",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("call audit missing %q:\n%s", want, text)
		}
	}
	for _, forbidden := range []string{"do-not-print", "secret", "replacement", "deadbeef", "forged\n"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("call audit leaked/forged %q: %q", forbidden, text)
		}
	}
	if strings.Count(text, "MCP tool:") != 3 || strings.Count(text, "\n  args:") != 3 {
		t.Fatalf("tool calls are not consistently rendered as two-line records: %q", text)
	}
}
