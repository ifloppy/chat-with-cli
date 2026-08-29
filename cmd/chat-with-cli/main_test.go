package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

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
