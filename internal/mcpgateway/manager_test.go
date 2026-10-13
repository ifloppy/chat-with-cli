package mcpgateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestRegistryRoundTripAndRejection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	r, err := Load(path)
	if err != nil || len(r.Servers) != 0 {
		t.Fatalf("empty load: %#v %v", r, err)
	}
	r.Servers["echo"] = ServerConfig{Transport: "stdio", Command: "echo", Enabled: true, Expose: true}
	if err := Save(path, r); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || got.Servers["echo"].Command != "echo" {
		t.Fatalf("roundtrip: %#v %v", got, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("registry permissions: %v, %v", info, err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"servers":{}}{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("accepted trailing JSON")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("followed symlink")
	}
}

func TestHTTPGatewayDiscoverInspectCallAndDisable(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "echo-server", Version: "1"}, nil)
	type input struct {
		Text string `json:"text"`
	}
	type output struct {
		Echo string `json:"echo"`
	}
	mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "Echo input text"}, func(_ context.Context, _ *mcp.CallToolRequest, in input) (*mcp.CallToolResult, output, error) {
		return nil, output{Echo: in.Text}, nil
	})
	httpServer := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil))
	defer httpServer.Close()
	path := filepath.Join(t.TempDir(), "mcp.json")
	r := Registry{Version: 1, Servers: map[string]ServerConfig{
		"test": {Transport: "streamable-http", URL: httpServer.URL, Enabled: true, Expose: true},
	}}
	if err := Save(path, r); err != nil {
		t.Fatal(err)
	}
	gw := New(path)
	defer gw.Close()
	ctx := context.Background()
	l, err := gw.List()
	if err != nil || len(l) != 1 {
		t.Fatalf("list: %#v %v", l, err)
	}
	found, err := gw.Search(ctx, "echo", 10)
	if err != nil || len(found.Tools) != 1 || len(found.Errors) != 0 {
		t.Fatalf("search: %#v %v", found, err)
	}
	schema, err := gw.Inspect(ctx, "test", "echo")
	if err != nil || schema.InputSchema == nil {
		t.Fatalf("inspect: %#v %v", schema, err)
	}
	result, err := gw.Call(ctx, "test", "echo", map[string]any{"text": "hello"})
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(result)
	if !strings.Contains(string(blob), "hello") {
		t.Fatalf("missing downstream result: %s", blob)
	}
	if _, err := gw.Call(ctx, "test", "missing", nil); err == nil {
		t.Fatal("unexpectedly called unknown tool")
	}
	r.Servers["test"] = ServerConfig{Transport: "streamable-http", URL: httpServer.URL, Enabled: false, Expose: true}
	if err := Save(path, r); err != nil {
		t.Fatal(err)
	}
	if _, err := gw.Inspect(ctx, "test", "echo"); err == nil {
		t.Fatal("disabled server still callable")
	}
}

func TestRejectMalformedEndpointAndServerID(t *testing.T) {
	for _, tc := range []struct {
		id     string
		config ServerConfig
	}{
		{"bad/id", ServerConfig{Transport: "stdio", Command: "true"}},
		{"x", ServerConfig{Transport: "streamable-http", URL: "file:///etc/passwd"}},
		{"x", ServerConfig{Transport: "streamable-http", URL: "http://user:pass@example.test/mcp"}},
		{"x", ServerConfig{Transport: "stdio", Command: ""}},
	} {
		r := Registry{Version: 1, Servers: map[string]ServerConfig{tc.id: tc.config}}
		if err := r.Validate(); err == nil {
			t.Errorf("accepted invalid %#v", tc)
		}
	}
}
