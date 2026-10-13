package relay

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ifloppy/chat-with-cli/internal/protocol"
)

func TestGatewayFeatureNegotiation(t *testing.T) {
	broker := NewBroker()
	legacy := &peer{device: "legacy", done: make(chan struct{})}
	modern := &peer{device: "modern", done: make(chan struct{}), capabilities: protocol.AgentCapabilities{Features: []string{"mcp_gateway_v1"}}}
	broker.peers["legacy"] = legacy
	broker.peers["modern"] = modern
	if broker.DeviceSupportsGateway("legacy") || broker.DeviceSupportsGateway("missing") {
		t.Fatal("unsupported gateway reported")
	}
	if !broker.DeviceSupportsGateway("modern") {
		t.Fatal("modern agent capability ignored")
	}
	if _, err := broker.Call(context.Background(), "legacy", "mcp_servers_list", json.RawMessage("{}")); err == nil || !strings.Contains(err.Error(), "does not advertise MCP gateway") {
		t.Fatalf("legacy gateway should fail with actionable error, got %v", err)
	}
}
