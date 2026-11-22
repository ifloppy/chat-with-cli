package agent

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"strings"
	"testing"
)

func TestConnectionDiagnosticsRedactsAndThrottles(t *testing.T) {
	var output bytes.Buffer
	old := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(old)
	debug := connectionDiagnostics{enabled: true}
	secret := "very-secret-token-do-not-print"
	resp := &http.Response{StatusCode: http.StatusForbidden}
	for i := 0; i < 3; i++ {
		debug.report("websocket-handshake", errors.New(secret), resp)
	}
	got := output.String()
	if strings.Contains(got, secret) {
		t.Fatal("diagnostics leaked an error body")
	}
	if !strings.Contains(got, "http=403") || !strings.Contains(got, "websocket-handshake") {
		t.Fatalf("expected safe handshake status; got %q", got)
	}
	if strings.Count(got, "websocket-handshake") != 1 {
		t.Fatalf("repeated error was not throttled: %q", got)
	}
	off := connectionDiagnostics{enabled: false}
	off.report("disabled-diagnostic", errors.New(secret), resp)
	if strings.Contains(output.String(), "disabled-diagnostic") {
		t.Fatal("disabled diagnostics unexpectedly wrote output")
	}
}
