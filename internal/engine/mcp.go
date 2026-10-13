package engine

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/ifloppy/chat-with-cli/internal/mcpgateway"
)

// SetMCPGateway is called during Agent startup, before remote requests are served.
func (e *Engine) SetMCPGateway(g *mcpgateway.Manager) {
	e.gateway = g
}

func (e *Engine) invokeGateway(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	if e.gateway == nil {
		return nil, errors.New("MCP gateway is not configured on this agent")
	}
	switch method {
	case "mcp_servers_list":
		servers, err := e.gateway.List()
		return mcpgateway.ServersListOutput{Servers: servers}, err
	case "mcp_tools_search":
		in, err := decode[mcpgateway.SearchInput](raw)
		if err != nil {
			return nil, err
		}
		return e.gateway.Search(ctx, in.Query, in.Limit)
	case "mcp_tool_inspect":
		in, err := decode[mcpgateway.ToolInput](raw)
		if err != nil {
			return nil, err
		}
		return e.gateway.Inspect(ctx, in.Server, in.Tool)
	case "mcp_tool_call":
		in, err := decode[mcpgateway.CallInput](raw)
		if err != nil {
			return nil, err
		}
		return e.gateway.Call(ctx, in.Server, in.Tool, in.Arguments)
	default:
		return nil, errors.New("unknown MCP gateway method")
	}
}
