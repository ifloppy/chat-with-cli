package mcpserver

import (
	"context"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"testing"
)

type advertisedCaller struct {
	fakeCaller
	gateway bool
}

func (c advertisedCaller) GatewayAvailable() bool { return c.gateway }

func TestLegacyToolAdvertisementDoesNotIncludeGateway(t *testing.T) {
	for _, tc := range []struct {
		gateway bool
		want    int
	}{{false, 34}, {true, 38}} {
		server := New(advertisedCaller{gateway: tc.gateway})
		client := mcp.NewClient(&mcp.Implementation{Name: "capability-test", Version: "1"}, nil)
		a, b := mcp.NewInMemoryTransports()
		ss, err := server.Connect(context.Background(), a, nil)
		if err != nil {
			t.Fatal(err)
		}
		cs, err := client.Connect(context.Background(), b, nil)
		if err != nil {
			t.Fatal(err)
		}
		result, err := cs.ListTools(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Tools) != tc.want {
			t.Errorf("gateway=%v tool count %d wanted %d", tc.gateway, len(result.Tools), tc.want)
		}
		for _, tool := range result.Tools {
			if tool.Name == "mcp_tool_call" && !tc.gateway {
				t.Error("legacy device advertises unsupported gateway method")
			}
		}
		_ = cs.Close()
		_ = ss.Close()
	}
}
