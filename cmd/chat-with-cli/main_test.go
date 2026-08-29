package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
