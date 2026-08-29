package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/ifloppy/chat-with-cli/internal/agent"
	"github.com/ifloppy/chat-with-cli/internal/engine"
	"github.com/ifloppy/chat-with-cli/internal/mcpserver"
)

// toolAudit is intentionally a local, human-readable audit stream. It never
// prints RPC arguments or results; those values may contain credentials,
// source code, commands, or desktop data.
type toolAudit struct {
	mu      sync.Mutex
	writer  io.Writer
	catalog []mcpserver.ToolDescriptor
	byName  map[string]mcpserver.ToolDescriptor
}

func newToolAudit(writer io.Writer) *toolAudit {
	catalog := mcpserver.ToolCatalog()
	byName := make(map[string]mcpserver.ToolDescriptor, len(catalog))
	for _, tool := range catalog {
		byName[tool.Name] = tool
	}
	return &toolAudit{writer: writer, catalog: catalog, byName: byName}
}

func (a *toolAudit) printInventory(mode string, cfg engine.Config) {
	if a == nil || a.writer == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	fmt.Fprintf(a.writer, "\nMCP tool audit: %d advertised tools (approval mode: %s)\n", len(a.catalog), auditValue(mode))
	fmt.Fprintln(a.writer, "  Every inbound tool call is logged below by name only; arguments and results are omitted.")
	fmt.Fprintf(a.writer, "  Local policy: filesystem-read=%s filesystem-write=%s shell-exec=%s screen-read=%s accessibility-read=%s computer-input=%s\n",
		auditOnOff(len(cfg.Roots) > 0), auditOnOff(cfg.AllowFileWrite), auditOnOff(cfg.AllowExec),
		auditOnOff(cfg.AllowScreen), auditOnOff(cfg.AllowAccessibility), auditOnOff(cfg.AllowComputerControl))
	if mode == approvalAllowAll {
		fmt.Fprintln(a.writer, "  WARNING: allow-all enables temporary capabilities, but does not suppress this audit stream.")
	}
	for _, tool := range a.catalog {
		fmt.Fprintf(a.writer, "  %-24s %-19s %-18s %s\n", tool.Name, toolAuditRisk(tool), approvalCategory(tool.Name), tool.Title)
	}
}

func (a *toolAudit) observe(call agent.ToolCall) {
	if a == nil || a.writer == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	tool, known := a.byName[call.Method]
	title := "Unknown MCP tool"
	risk := "unknown"
	if known {
		title = tool.Title
		risk = toolAuditRisk(tool)
	}
	fmt.Fprintf(a.writer, "[%s] MCP tool call: %-24s %-19s %-18s %s\n",
		time.Now().Format(time.RFC3339Nano), auditValue(call.Method), risk, approvalCategory(call.Method), title)
}

func toolAuditRisk(tool mcpserver.ToolDescriptor) string {
	switch {
	case tool.ReadOnly:
		return "read-only"
	case tool.Destructive && tool.OpenWorld:
		return "mutating/open-world"
	case tool.Destructive:
		return "mutating"
	default:
		return "unspecified"
	}
}

func auditOnOff(value bool) string {
	if value {
		return "on"
	}
	return "off"
}

// auditValue prevents an untrusted method name from forging terminal lines or
// flooding the terminal if a malformed peer sends an unusually long value.
func auditValue(value string) string {
	var b strings.Builder
	for count, r := range value {
		if count >= 128 {
			b.WriteString("…")
			break
		}
		if r < 0x20 || r == 0x7f {
			r = '?'
		}
		b.WriteRune(r)
	}
	if b.Len() == 0 {
		return "<empty>"
	}
	return b.String()
}
