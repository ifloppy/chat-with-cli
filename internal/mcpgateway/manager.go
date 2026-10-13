package mcpgateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ServersListOutput struct {
	Servers []ServerInfo `json:"servers"`
}

type SearchInput struct {
	Query string `json:"query" jsonschema:"Case-insensitive keyword matching tool names, descriptions, and server IDs"`
	Limit int    `json:"limit,omitempty" jsonschema:"Maximum results, up to 30"`
}

type ToolInput struct {
	Server string `json:"server" jsonschema:"MCP server ID from mcp_servers_list"`
	Tool   string `json:"tool" jsonschema:"Exact tool name from mcp_tools_search"`
}

type CallInput struct {
	Server    string         `json:"server" jsonschema:"MCP server ID from mcp_servers_list"`
	Tool      string         `json:"tool" jsonschema:"Exact tool name from mcp_tools_search"`
	Arguments map[string]any `json:"arguments,omitempty" jsonschema:"Arguments matching the tool input_schema returned by mcp_tool_inspect"`
}

type ServerInfo struct {
	ID        string `json:"id"`
	Transport string `json:"transport"`
	Enabled   bool   `json:"enabled"`
	Expose    bool   `json:"expose"`
	Connected bool   `json:"connected"`
}

type ToolInfo struct {
	Server       string `json:"server"`
	Name         string `json:"name"`
	Title        string `json:"title,omitempty"`
	Description  string `json:"description,omitempty"`
	InputSchema  any    `json:"input_schema,omitempty"`
	OutputSchema any    `json:"output_schema,omitempty"`
}

type SearchResult struct {
	Tools  []ToolInfo `json:"tools"`
	Errors []string   `json:"errors,omitempty"`
}

type ToolResult struct {
	IsError           bool `json:"is_error"`
	Content           any  `json:"content"`
	StructuredContent any  `json:"structured_content,omitempty"`
}

type entry struct {
	config  ServerConfig
	mu      sync.Mutex
	session *mcp.ClientSession
}

func (e *entry) close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.session != nil {
		_ = e.session.Close()
		e.session = nil
	}
}

func (e *entry) connect(ctx context.Context) (*mcp.ClientSession, error) {
	if e.session != nil {
		return e.session, nil
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "chat-with-cli-gateway", Version: "1"}, nil)
	var transport mcp.Transport
	switch e.config.Transport {
	case "stdio":
		cmd := exec.Command(e.config.Command, e.config.Args...)
		transport = &mcp.CommandTransport{Command: cmd}
	case "streamable-http":
		transport = &mcp.StreamableClientTransport{Endpoint: e.config.URL, MaxRetries: -1}
	default:
		return nil, fmt.Errorf("unsupported transport %q", e.config.Transport)
	}
	connectCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	session, err := client.Connect(connectCtx, transport, nil)
	if err != nil {
		return nil, err
	}
	e.session = session
	return session, nil
}

func checkHTTPURL(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("invalid MCP HTTP endpoint")
	}
	return nil
}

// Manager lazily connects downstream servers and observes registry edits.
// Its per-server mutex serializes operations and prevents closing an in-use session.
type Manager struct {
	path    string
	mu      sync.Mutex
	entries map[string]*entry
}

func New(path string) *Manager { return &Manager{path: path, entries: make(map[string]*entry)} }

func (m *Manager) refresh() (Registry, error) {
	r, err := Load(m.path)
	if err != nil {
		return r, err
	}
	m.mu.Lock()
	var old []*entry
	for id, e := range m.entries {
		cfg, ok := r.Servers[id]
		if !ok || !reflect.DeepEqual(e.config, cfg) || !cfg.Enabled || !cfg.Expose {
			old = append(old, e)
			delete(m.entries, id)
		}
	}
	for id, cfg := range r.Servers {
		if cfg.Enabled && cfg.Expose {
			if _, ok := m.entries[id]; !ok {
				m.entries[id] = &entry{config: cfg}
			}
		}
	}
	m.mu.Unlock()
	for _, e := range old {
		e.close()
	}
	return r, nil
}

func (m *Manager) get(id string) (*entry, error) {
	_, err := m.refresh()
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.entries[id]
	if e == nil {
		return nil, fmt.Errorf("MCP server %q is not enabled and exposed", id)
	}
	return e, nil
}

func (m *Manager) List() ([]ServerInfo, error) {
	r, err := m.refresh()
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ServerInfo, 0, len(r.Servers))
	for _, id := range ServerIDs(r) {
		cfg := r.Servers[id]
		e := m.entries[id]
		connected := false
		if e != nil {
			e.mu.Lock()
			connected = e.session != nil
			e.mu.Unlock()
		}
		out = append(out, ServerInfo{ID: id, Transport: cfg.Transport, Enabled: cfg.Enabled, Expose: cfg.Expose, Connected: connected})
	}
	return out, nil
}

func toolInfo(server string, t *mcp.Tool, includeSchema bool) ToolInfo {
	info := ToolInfo{Server: server, Name: t.Name, Title: t.Title, Description: t.Description}
	if includeSchema {
		info.InputSchema, info.OutputSchema = t.InputSchema, t.OutputSchema
	}
	return info
}

func (e *entry) tools(ctx context.Context) ([]*mcp.Tool, error) {
	s, err := e.connect(ctx)
	if err != nil {
		return nil, err
	}
	var tools []*mcp.Tool
	for tool, err := range s.Tools(ctx, nil) {
		if err != nil {
			return nil, err
		}
		tools = append(tools, tool)
		if len(tools) >= 512 {
			return nil, fmt.Errorf("downstream MCP returned too many tools")
		}
	}
	return tools, nil
}

func (m *Manager) Search(ctx context.Context, query string, limit int) (SearchResult, error) {
	r, err := m.refresh()
	if err != nil {
		return SearchResult{}, err
	}
	if limit <= 0 || limit > 30 {
		limit = 15
	}
	query = strings.ToLower(strings.TrimSpace(query))
	out := SearchResult{Tools: []ToolInfo{}}
	for _, id := range ServerIDs(r) {
		cfg := r.Servers[id]
		if !cfg.Enabled || !cfg.Expose {
			continue
		}
		e, err := m.get(id)
		if err != nil {
			return out, err
		}
		e.mu.Lock()
		tools, err := e.tools(ctx)
		e.mu.Unlock()
		if err != nil {
			out.Errors = append(out.Errors, fmt.Sprintf("%s: %v", id, err))
			continue
		}
		for _, t := range tools {
			if query == "" || strings.Contains(strings.ToLower(t.Name+" "+t.Title+" "+t.Description+" "+id), query) {
				out.Tools = append(out.Tools, toolInfo(id, t, false))
				if len(out.Tools) >= limit {
					return out, nil
				}
			}
		}
	}
	return out, nil
}

func (m *Manager) Inspect(ctx context.Context, server, tool string) (ToolInfo, error) {
	e, err := m.get(server)
	if err != nil {
		return ToolInfo{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	tools, err := e.tools(ctx)
	if err != nil {
		return ToolInfo{}, err
	}
	for _, t := range tools {
		if t.Name == tool {
			return toolInfo(server, t, true), nil
		}
	}
	return ToolInfo{}, fmt.Errorf("unknown MCP tool %q on %q", tool, server)
}

// Probe connects to one explicitly exposed server and reports its tool count.
func (m *Manager) Probe(ctx context.Context, server string) (int, error) {
	e, err := m.get(server)
	if err != nil {
		return 0, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	tools, err := e.tools(ctx)
	return len(tools), err
}

func (m *Manager) Call(ctx context.Context, server, tool string, args map[string]any) (ToolResult, error) {
	e, err := m.get(server)
	if err != nil {
		return ToolResult{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	tools, err := e.tools(ctx)
	if err != nil {
		return ToolResult{}, err
	}
	found := false
	for _, t := range tools {
		if t.Name == tool {
			found = true
			break
		}
	}
	if !found {
		return ToolResult{}, fmt.Errorf("unknown MCP tool %q on %q", tool, server)
	}
	if args == nil {
		args = map[string]any{}
	}
	result, err := e.session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		return ToolResult{}, err
	}
	// Guard the outer Relay against unexpectedly huge binary/image payloads.
	raw, err := json.Marshal(result)
	if err != nil {
		return ToolResult{}, err
	}
	if len(raw) > 1<<20 {
		return ToolResult{}, fmt.Errorf("MCP tool result exceeds 1 MiB limit")
	}
	return ToolResult{IsError: result.IsError, Content: result.Content, StructuredContent: result.StructuredContent}, nil
}

func (m *Manager) Close() {
	m.mu.Lock()
	old := m.entries
	m.entries = make(map[string]*entry)
	m.mu.Unlock()
	for _, e := range old {
		e.close()
	}
}
