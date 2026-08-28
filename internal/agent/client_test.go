package agent

import (
	"strings"
	"testing"
)

func TestAgentURLForRouteRequiresSecureRemoteOrigin(t *testing.T) {
	if _, err := agentURLForRoute("http://relay.example", "laptop", ""); err == nil {
		t.Fatal("remote HTTP relay was accepted")
	}
	if _, err := agentURLForRoute("ws://relay.example", "laptop", ""); err == nil {
		t.Fatal("remote insecure WebSocket relay was accepted")
	}
	if _, err := agentURLForRoute("https://relay.example/path", "laptop", ""); err == nil {
		t.Fatal("relay URL with a path was accepted")
	}
	endpoint, err := agentURLForRoute("https://relay.example", "display-name", "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "wss://relay.example/agent/id/0123456789abcdef0123456789abcdef" {
		t.Fatalf("endpoint=%q", endpoint)
	}
	loopback, err := agentURLForRoute("http://127.0.0.1:8765", "laptop", "")
	if err != nil || !strings.HasPrefix(loopback, "ws://127.0.0.1:8765/") {
		t.Fatalf("loopback endpoint=%q err=%v", loopback, err)
	}
}
