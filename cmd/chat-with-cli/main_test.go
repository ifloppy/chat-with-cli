package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ifloppy/chat-with-cli/internal/protocol"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestDiagnosticErrorRedactionDoesNotEchoSecrets(t *testing.T) {
	secret := "refresh-secret-that-must-not-be-printed"
	got := redactDiagnosticError(errors.New("request failed for https://relay.example.test/oauth?refresh_token=" + secret))
	if strings.Contains(got, secret) || strings.Contains(got, "relay.example.test") {
		t.Fatalf("diagnostic redaction leaked request details: %q", got)
	}
	if got != "network request failed" {
		t.Fatalf("unexpected redacted network error: %q", got)
	}
	if got := redactDiagnosticError(context.DeadlineExceeded); got != "request timed out" {
		t.Fatalf("unexpected timeout diagnostic: %q", got)
	}
}

func TestDoctorMCPErrorDoesNotEchoRemoteMessage(t *testing.T) {
	const secret = "bearer-or-tool-data-that-must-not-be-printed"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"` + secret + `"}}`))
	}))
	defer server.Close()

	_, err := doctorMCPRequest(context.Background(), server.Client(), server.URL, "unused-token", map[string]any{"probe": true})
	if err == nil {
		t.Fatal("expected MCP JSON-RPC error")
	}
	if strings.Contains(err.Error(), secret) || err.Error() != "MCP returned a JSON-RPC error" {
		t.Fatalf("doctor exposed remote MCP error details: %v", err)
	}
}

func TestBearerAuthFailsClosedOnEmptyToken(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	h := bearerAuth("", next)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/mcp", nil))
	if rr.Code != http.StatusUnauthorized || called {
		t.Fatalf("empty bearer secret failed open: status=%d called=%v", rr.Code, called)
	}
}

func TestBearerAuthRequiresExactToken(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	h := bearerAuth("expected-secret", next)

	for _, header := range []string{"", "Bearer wrong-secret", "bearer expected-secret"} {
		called = false
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/mcp", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized || called {
			t.Fatalf("invalid Authorization header %q was accepted: status=%d called=%v", header, rr.Code, called)
		}
	}

	called = false
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/mcp", nil)
	req.Header.Set("Authorization", "Bearer expected-secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent || !called {
		t.Fatalf("exact bearer secret rejected: status=%d called=%v", rr.Code, called)
	}
}

func TestAgentPathMuxAvoidsServeMuxPatternConflicts(t *testing.T) {
	challenge := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Route", "challenge")
		w.WriteHeader(http.StatusNoContent)
	})
	connection := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Route", "connection")
		w.WriteHeader(http.StatusNoContent)
	})
	mux := http.NewServeMux()
	mux.Handle("/agent/", agentPathMux(challenge, connection))

	for path, want := range map[string]string{
		"/agent/legacy-device":                                 "connection",
		"/agent/id/0123456789abcdef0123456789abcdef":           "connection",
		"/agent/legacy-device/challenge":                       "challenge",
		"/agent/id/0123456789abcdef0123456789abcdef/challenge": "challenge",
	} {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil))
		if rr.Code != http.StatusNoContent || rr.Header().Get("X-Route") != want {
			t.Fatalf("path %s routed to %q status=%d, want %q", path, rr.Header().Get("X-Route"), rr.Code, want)
		}
	}
}

func TestRequestApproverCanGrantCapabilityForSession(t *testing.T) {
	var out bytes.Buffer
	a := &requestApprover{
		reader:     bufio.NewReader(strings.NewReader("s\n")),
		writer:     &out,
		allowedCap: map[string]bool{},
	}
	req := protocol.Request{ID: "1", Method: "fs_read"}
	if err := a.authorize(context.Background(), req); err != nil {
		t.Fatalf("first approval failed: %v", err)
	}
	if !a.allowedCap["filesystem-read"] {
		t.Fatal("session capability was not remembered")
	}
	out.Reset()
	if err := a.authorize(context.Background(), protocol.Request{ID: "2", Method: "fs_list"}); err != nil {
		t.Fatalf("remembered approval failed: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("remembered capability prompted again: %q", out.String())
	}
}

func TestRequestApproverAllowAllAndDeny(t *testing.T) {
	var out bytes.Buffer
	allow := &requestApprover{reader: bufio.NewReader(strings.NewReader("a\n")), writer: &out, allowedCap: map[string]bool{}}
	if err := allow.authorize(context.Background(), protocol.Request{ID: "1", Method: "task_start"}); err != nil {
		t.Fatalf("allow-all failed: %v", err)
	}
	if !allow.allowAll {
		t.Fatal("allow-all was not remembered")
	}
	out.Reset()
	if err := allow.authorize(context.Background(), protocol.Request{ID: "2", Method: "computer_click"}); err != nil {
		t.Fatalf("allow-all did not cover later capability: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("allow-all prompted again: %q", out.String())
	}

	deny := &requestApprover{reader: bufio.NewReader(strings.NewReader("n\n")), writer: &out, allowedCap: map[string]bool{}}
	if err := deny.authorize(context.Background(), protocol.Request{ID: "3", Method: "fs_write"}); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("deny returned %v", err)
	}
}

func TestApprovalCategoryCoversSensitiveMethods(t *testing.T) {
	cases := map[string]string{
		"fs_read":             "filesystem-read",
		"fs_write":            "filesystem-write",
		"task_start":          "shell-exec",
		"computer_screenshot": "screen-read",
		"computer_ui_tree":    "desktop-read",
		"computer_click":      "computer-input",
	}
	for method, want := range cases {
		if got := approvalCategory(method); got != want {
			t.Fatalf("%s category=%q want %q", method, got, want)
		}
	}
}

func TestRelayStreamableHandlerAllowsReverseProxyHostOnLoopback(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "relay-test", Version: "test"}, nil)
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, relayStreamableHTTPOptions("127.0.0.1:18776", "https://chat-with-cli.example"))
	body := `{"jsonrpc":"2.0","id":"discover","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"chatgpt-test","version":"test"},"io.modelcontextprotocol/clientCapabilities":{}}}}`
	req := httptest.NewRequest(http.MethodPost, "https://chat-with-cli.example/mcp/id/0123456789abcdef0123456789abcdef", strings.NewReader(body))
	req.Host = "chat-with-cli.example"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "server/discover")
	req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 18776}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code == http.StatusForbidden {
		t.Fatalf("reverse-proxied Relay request was rejected by localhost protection: %s", rr.Body.String())
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("server/discover status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestDefaultStreamableHandlerStillRejectsPublicHostOnLoopback(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "local-test", Version: "test"}, nil)
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true})
	body := `{"jsonrpc":"2.0","id":"discover","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"chatgpt-test","version":"test"},"io.modelcontextprotocol/clientCapabilities":{}}}}`
	req := httptest.NewRequest(http.MethodPost, "https://attacker.example/mcp", strings.NewReader(body))
	req.Host = "attacker.example"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "server/discover")
	req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 18776}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("default localhost protection status=%d, want 403", rr.Code)
	}
}

func TestRelayStreamableOptionsOnlyRelaxExplicitReverseProxyTopology(t *testing.T) {
	if !relayStreamableHTTPOptions("127.0.0.1:18776", "https://chat-with-cli.example").DisableLocalhostProtection {
		t.Fatal("loopback Relay behind public reverse proxy did not relax SDK localhost protection")
	}
	for _, tc := range []struct{ listen, public string }{
		{"127.0.0.1:18776", "http://127.0.0.1:18776"},
		{"0.0.0.0:18776", "https://chat-with-cli.example"},
		{"[::]:18776", "https://chat-with-cli.example"},
	} {
		if relayStreamableHTTPOptions(tc.listen, tc.public).DisableLocalhostProtection {
			t.Fatalf("unexpected localhost-protection relaxation for listen=%q public=%q", tc.listen, tc.public)
		}
	}
}
