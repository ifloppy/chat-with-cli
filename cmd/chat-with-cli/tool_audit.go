package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ifloppy/chat-with-cli/internal/agent"
	"github.com/ifloppy/chat-with-cli/internal/engine"
	"github.com/ifloppy/chat-with-cli/internal/mcpserver"
)

// toolAudit is intentionally a local, human-readable audit stream. It prints
// useful request metadata, but payload-like and secret-like values are withheld
// so the terminal does not become a second copy of file contents or credentials.
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
	fmt.Fprintln(a.writer, "  Every inbound tool call is logged as two lines with a redacted argument summary; payload text and results are omitted.")
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
	fmt.Fprintf(a.writer, "[%s] MCP tool: %s (%s · %s) — %s\n",
		time.Now().Format(time.RFC3339Nano), auditValue(call.Method), risk, approvalCategory(call.Method), auditValue(title))
	fmt.Fprintf(a.writer, "  args: %s\n", toolAuditArgs(call.Args))
}

func toolAuditArgs(raw json.RawMessage) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" || trimmed == "{}" {
		return "(none)"
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal(raw, &args); err != nil {
		return "<invalid arguments>"
	}
	if len(args) == 0 {
		return "(none)"
	}

	keys := make([]string, 0, len(args))
	for key := range args {
		if !auditSkipArgument(key) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		value := args[key]
		switch {
		case auditSensitiveArgument(key):
			parts = append(parts, auditValue(key)+"=<redacted>")
		case auditPayloadArgument(key):
			parts = append(parts, fmt.Sprintf("%s=<omitted:%d bytes>", auditValue(key), auditArgumentSize(value)))
		case strings.EqualFold(key, "env"):
			parts = append(parts, fmt.Sprintf("%s=<%d vars>", auditValue(key), auditMapSize(value)))
		default:
			parts = append(parts, auditValue(key)+"="+auditArgumentValue(value))
		}
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, "  ")
}

func auditSkipArgument(key string) bool {
	return strings.EqualFold(strings.TrimSpace(key), "expected_sha256")
}

func auditSensitiveArgument(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	for _, marker := range []string{"password", "passwd", "secret", "token", "credential", "authorization", "cookie", "private_key", "api_key", "access_key"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

func auditPayloadArgument(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "content", "old_text", "new_text", "input", "text", "body", "payload", "data":
		return true
	default:
		return false
	}
}

func auditArgumentSize(raw json.RawMessage) int {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return len(text)
	}
	return len(raw)
}

func auditMapSize(raw json.RawMessage) int {
	var values map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil {
		return 0
	}
	return len(values)
}

func auditArgumentValue(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return strconv.Quote(auditTextValue(text, 240))
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err == nil {
		return auditTextValue(compact.String(), 240)
	}
	return "<invalid>"
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
	return auditTextValue(value, 128)
}

func auditTextValue(value string, maxRunes int) string {
	if maxRunes <= 0 {
		return "<empty>"
	}
	var b strings.Builder
	count := 0
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		value = value[size:]
		if count >= maxRunes {
			b.WriteString("…")
			break
		}
		if r < 0x20 || r == 0x7f {
			r = '?'
		}
		b.WriteRune(r)
		count++
	}
	if b.Len() == 0 {
		return "<empty>"
	}
	return b.String()
}
