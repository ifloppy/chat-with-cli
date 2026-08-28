package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ifloppy/chat-with-cli/internal/engine"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const Version = "0.1.0-alpha.5"

type Caller interface {
	Call(context.Context, string, json.RawMessage) (json.RawMessage, error)
}

type LocalCaller struct{ Engine *engine.Engine }

func (c LocalCaller) Call(ctx context.Context, method string, raw json.RawMessage) (json.RawMessage, error) {
	value, err := c.Engine.Invoke(ctx, method, raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func addTool[In, Out any](server *mcp.Server, caller Caller, name, description string) {
	handler := func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		var out Out
		raw, err := json.Marshal(in)
		if err != nil {
			return nil, out, err
		}
		result, err := caller.Call(ctx, name, raw)
		if err != nil {
			return nil, out, err
		}
		if err := json.Unmarshal(result, &out); err != nil {
			return nil, out, fmt.Errorf("decode %s result: %w", name, err)
		}
		return nil, out, nil
	}
	tool := &mcp.Tool{Name: name, Title: toolTitle(name), Description: description, Annotations: toolAnnotations(name)}
	mcp.AddTool(server, tool, handler)
}

func boolPtr(value bool) *bool { return &value }

var toolTitles = map[string]string{
	"audit_recent":         "Read recent audit events",
	"checkpoint_read":      "Read workspace checkpoint",
	"checkpoint_write":     "Write workspace checkpoint",
	"computer_click":       "Click pointer",
	"computer_info":        "Inspect computer capabilities",
	"computer_key":         "Send keyboard shortcut",
	"computer_move":        "Move pointer",
	"computer_observe":     "Observe desktop",
	"computer_screenshot":  "Capture desktop screenshot",
	"computer_scroll":      "Scroll desktop",
	"computer_type":        "Type text",
	"computer_ui_action":   "Invoke UI action",
	"computer_ui_find":     "Find UI elements",
	"computer_ui_focus":    "Focus UI element",
	"computer_ui_get_text": "Read UI text",
	"computer_ui_invoke":   "Invoke UI element",
	"computer_ui_set_text": "Set UI text",
	"computer_ui_tree":     "Inspect UI tree",
	"computer_ui_wait":     "Wait for UI element",
	"fs_list":              "List files",
	"fs_patch":             "Patch file",
	"fs_read":              "Read file",
	"fs_search":            "Search files",
	"fs_write":             "Write file",
	"system_info":          "Inspect system",
	"task_list":            "List tasks",
	"task_read":            "Read task output",
	"task_send":            "Send task input",
	"task_start":           "Start task",
	"task_stop":            "Stop task",
	"task_wait":            "Wait for task output",
}

func toolTitle(name string) string { return toolTitles[name] }

func toolAnnotations(name string) *mcp.ToolAnnotations {
	switch name {
	case "system_info", "computer_info", "computer_screenshot", "computer_observe", "computer_ui_tree", "computer_ui_find", "computer_ui_wait", "computer_ui_get_text", "task_read", "task_wait", "task_list", "audit_recent", "fs_read", "fs_list", "fs_search", "checkpoint_read":
		return &mcp.ToolAnnotations{ReadOnlyHint: true, DestructiveHint: boolPtr(false), IdempotentHint: true, OpenWorldHint: boolPtr(false)}
	case "fs_write", "fs_patch", "checkpoint_write":
		return &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(false)}
	case "computer_ui_focus", "computer_ui_action", "computer_ui_invoke", "computer_ui_set_text", "computer_move", "computer_click", "computer_scroll", "computer_type", "computer_key", "task_start", "task_send", "task_stop":
		return &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(true)}
	default:
		return &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(true)}
	}
}

func addScreenshotTool(server *mcp.Server, caller Caller) {
	handler := func(ctx context.Context, _ *mcp.CallToolRequest, in engine.ComputerScreenshotInput) (*mcp.CallToolResult, engine.ComputerScreenshotMetaOutput, error) {
		var shot engine.ComputerScreenshotOutput
		raw, err := json.Marshal(in)
		if err != nil {
			return nil, engine.ComputerScreenshotMetaOutput{}, err
		}
		result, err := caller.Call(ctx, "computer_screenshot", raw)
		if err != nil {
			return nil, engine.ComputerScreenshotMetaOutput{}, err
		}
		if err := json.Unmarshal(result, &shot); err != nil {
			return nil, engine.ComputerScreenshotMetaOutput{}, err
		}
		meta := engine.ComputerScreenshotMetaOutput{MIMEType: shot.MIMEType, Width: shot.Width, Height: shot.Height}
		content := []mcp.Content{&mcp.ImageContent{MIMEType: shot.MIMEType, Data: shot.Data}}
		return &mcp.CallToolResult{Content: content}, meta, nil
	}
	tool := &mcp.Tool{Name: "computer_screenshot", Title: toolTitle("computer_screenshot"), Description: "Capture the current desktop and return it directly as MCP image content for visual reasoning.", Annotations: toolAnnotations("computer_screenshot")}
	mcp.AddTool(server, tool, handler)
}

func addObserveTool(server *mcp.Server, caller Caller) {
	handler := func(ctx context.Context, _ *mcp.CallToolRequest, in engine.ComputerObserveInput) (*mcp.CallToolResult, engine.ComputerObserveMetaOutput, error) {
		var observed engine.ComputerObserveOutput
		raw, err := json.Marshal(in)
		if err != nil {
			return nil, engine.ComputerObserveMetaOutput{}, err
		}
		result, err := caller.Call(ctx, "computer_observe", raw)
		if err != nil {
			return nil, engine.ComputerObserveMetaOutput{}, err
		}
		if err := json.Unmarshal(result, &observed); err != nil {
			return nil, engine.ComputerObserveMetaOutput{}, err
		}
		meta := engine.ComputerObserveMetaOutput{Info: observed.Info, UI: observed.UI, ScreenshotReason: observed.ScreenshotReason}
		var content []mcp.Content
		if observed.Screenshot != nil {
			meta.Screenshot = &engine.ComputerScreenshotMetaOutput{
				MIMEType: observed.Screenshot.MIMEType, Width: observed.Screenshot.Width, Height: observed.Screenshot.Height,
			}
			content = append(content, &mcp.ImageContent{MIMEType: observed.Screenshot.MIMEType, Data: observed.Screenshot.Data})
		}
		return &mcp.CallToolResult{Content: content}, meta, nil
	}
	tool := &mcp.Tool{Name: "computer_observe", Title: toolTitle("computer_observe"), Description: "Observe the current GUI in one call using bounded semantic UI data and an optional screenshot. screenshot=auto avoids image transfer when semantic UI is sufficient.", Annotations: toolAnnotations("computer_observe")}
	mcp.AddTool(server, tool, handler)
}

func New(caller Caller) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name: "chat-with-cli", Version: Version,
	}, &mcp.ServerOptions{Instructions: `For GUI work, start with computer_observe when state is unknown. Prefer computer_ui_invoke for a unique semantic action and computer_ui_get_text/set_text for text fields, then computer_ui_find/tree for inspection. Use screenshots and pointer tools only as fallbacks. For long commands use task_start and task_wait with next_offset. Do not restart a task merely because MCP or chat reconnects. Use checkpoint_write at meaningful development milestones so another agent can resume the workspace.`})

	addTool[struct{}, engine.SystemInfoOutput](server, caller, "system_info",
		"Show the connected machine, allowed filesystem roots, and whether shell execution is enabled.")
	addTool[struct{}, engine.ComputerInfoOutput](server, caller, "computer_info",
		"Show screen/control permission state and detected screenshot/input backends.")
	addScreenshotTool(server, caller)
	addObserveTool(server, caller)
	addTool[engine.ComputerUITreeInput, engine.ComputerUIQueryOutput](server, caller, "computer_ui_tree",
		"Inspect a bounded AT-SPI accessibility tree. Requires --allow-accessibility. Prefer this structured view over screenshots when applications expose accessibility metadata.")
	addTool[engine.ComputerUIFindInput, engine.ComputerUIQueryOutput](server, caller, "computer_ui_find",
		"Find accessible UI elements by application, name/description/role text, and optional exact role. Requires --allow-accessibility. Returns opaque refs, bounds, and semantic actions.")
	addTool[engine.ComputerUIWaitInput, engine.ComputerUIQueryOutput](server, caller, "computer_ui_wait",
		"Wait up to 30 seconds for a matching accessible UI element to appear. Requires --allow-accessibility. Prefer this over repeated screenshots while an app is loading.")
	addTool[engine.ComputerUIRefInput, engine.Ack](server, caller, "computer_ui_focus",
		"Focus an accessible UI element by opaque ref. Requires --allow-computer-use.")
	addTool[engine.ComputerUIActionInput, engine.ComputerUIActionOutput](server, caller, "computer_ui_action",
		"Invoke an accessibility-provided semantic action such as click/press/activate by opaque ref. Requires --allow-computer-use.")
	addTool[engine.ComputerUIInvokeInput, engine.ComputerUIInvokeOutput](server, caller, "computer_ui_invoke",
		"Atomically wait for/find one visible enabled accessible element and invoke its semantic action. Refuses ambiguous or incomplete searches instead of guessing. Requires --allow-computer-use.")
	addTool[engine.ComputerUIGetTextInput, engine.ComputerUIGetTextOutput](server, caller, "computer_ui_get_text",
		"Read bounded UTF-8 contents from one uniquely selected visible AT-SPI Text control without screenshots or OCR. Requires --allow-accessibility.")
	addTool[engine.ComputerUISetTextInput, engine.ComputerUISetTextOutput](server, caller, "computer_ui_set_text",
		"Atomically find one visible enabled AT-SPI EditableText control and replace its UTF-8 contents without pointer or keyboard injection. Requires --allow-computer-use.")
	addTool[engine.ComputerMoveInput, engine.Ack](server, caller, "computer_move", "Move the pointer to absolute screen coordinates.")
	addTool[engine.ComputerClickInput, engine.Ack](server, caller, "computer_click", "Click the current pointer position with left, middle, right, back, or forward button.")
	addTool[engine.ComputerScrollInput, engine.Ack](server, caller, "computer_scroll", "Scroll horizontally and/or vertically at the current pointer position.")
	addTool[engine.ComputerTypeInput, engine.Ack](server, caller, "computer_type", "Type text into the currently focused application.")
	addTool[engine.ComputerKeyInput, engine.Ack](server, caller, "computer_key", "Send a key chord such as ctrl+shift+p or Return to the focused application.")
	addTool[engine.StartTaskInput, engine.TaskInfo](server, caller, "task_start",
		"Start an interactive PTY-backed task. Returns immediately with a task_id; the task continues independently of the MCP request.")
	addTool[engine.ReadTaskInput, engine.ReadTaskOutput](server, caller, "task_read",
		"Read only new task output by byte offset. Reuse next_offset to keep long build/test/agent logs out of context.")
	addTool[engine.WaitTaskInput, engine.ReadTaskOutput](server, caller, "task_wait",
		"Long-poll until a task produces new output, finishes, or the bounded timeout expires. Prefer this over rapid task_read polling.")
	addTool[engine.SendTaskInput, engine.Ack](server, caller, "task_send",
		"Send text or control bytes to an active PTY task, such as an interactive CLI or REPL.")
	addTool[engine.StopTaskInput, engine.Ack](server, caller, "task_stop",
		"Signal an active task and its process group. Defaults to TERM; supports INT, HUP, and KILL.")
	addTool[struct{}, engine.TaskListOutput](server, caller, "task_list",
		"List active and historical tasks so multiple workstreams can be coordinated without losing task IDs.")
	addTool[engine.AuditRecentInput, engine.AuditRecentOutput](server, caller, "audit_recent",
		"Read recent bounded local audit metadata (time, method, duration, success) without request arguments or result contents.")

	addTool[engine.FileReadInput, engine.FileReadOutput](server, caller, "fs_read",
		"Read a bounded byte range from a regular file inside an allowed root. Use next_offset for large files.")
	addTool[engine.FileWriteInput, engine.Ack](server, caller, "fs_write",
		"Rewrite or append a file inside an allowed root. Parent directories are created as needed.")
	addTool[engine.FilePatchInput, engine.FilePatchOutput](server, caller, "fs_patch",
		"Surgically replace exact text only when the expected match count is satisfied; safer and cheaper than rewriting large files.")
	addTool[engine.FileListInput, engine.FileListOutput](server, caller, "fs_list",
		"List a directory tree with bounded depth while skipping common dependency/cache noise by default.")
	addTool[engine.FileSearchInput, engine.FileSearchOutput](server, caller, "fs_search",
		"Regex-search file paths or text content with bounded results and large/binary file protection.")
	addTool[engine.CheckpointWriteInput, engine.Ack](server, caller, "checkpoint_write",
		"Persist concise workspace progress, decisions, risks, and next steps so a later agent/session can resume accurately.")
	addTool[engine.CheckpointReadInput, engine.CheckpointOutput](server, caller, "checkpoint_read",
		"Read the durable checkpoint for a workspace before resuming a long-running development effort.")
	return server
}
