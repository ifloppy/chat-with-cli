package oauthclient

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestOAuthHTTPErrorDoesNotExposeResponseBody(t *testing.T) {
	const secret = "refresh-secret-that-must-not-be-logged"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"` + secret + `"}`))
	}))
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader(`{"refresh_token":"`+secret+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	err = doJSON(server.Client(), req, &struct{}{})
	if err == nil {
		t.Fatal("expected OAuth HTTP error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("OAuth HTTP error exposed a credential: %v", err)
	}
	if !strings.Contains(err.Error(), "400 Bad Request") {
		t.Fatalf("OAuth HTTP error lost status detail: %v", err)
	}
}

func TestManualAuthorizationURLIsStoredAsPrivateFile(t *testing.T) {
	const target = "https://relay.example.test/oauth/authorize?code_challenge=challenge-secret"
	path, err := saveManualAuthorizationURL(target)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("manual OAuth URL mode=%o want 600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != target+"\n" {
		t.Fatalf("manual OAuth URL content=%q", data)
	}
}
