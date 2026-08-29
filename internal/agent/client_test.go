package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/ifloppy/chat-with-cli/internal/deviceidentity"
	"github.com/ifloppy/chat-with-cli/internal/engine"
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

func TestRelayDisconnectEndsRemoteEngineSession(t *testing.T) {
	eng, err := engine.New(engine.Config{Roots: []string{t.TempDir()}, AllowExec: true, StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	started, err := eng.Invoke(context.Background(), "task_start", json.RawMessage(`{"command":"sleep 30"}`))
	if err != nil {
		t.Fatal(err)
	}
	info, ok := started.(engine.TaskInfo)
	if !ok || info.ID == "" {
		t.Fatalf("unexpected task_start result: %#v", started)
	}

	connected := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		select {
		case connected <- struct{}{}:
		default:
		}
		// Read the capability hello so the Agent reaches its normal serve loop,
		// then terminate the remote authorization session abruptly.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, _, _ = conn.Read(ctx)
		cancel()
		_ = conn.CloseNow()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	client := &Client{Engine: eng, URL: server.URL, Device: "disconnect-test", Token: "test-token"}
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	select {
	case <-connected:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("Agent never connected to test Relay")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		out, readErr := eng.Invoke(context.Background(), "task_read", json.RawMessage(`{"task_id":"`+info.ID+`"}`))
		if readErr == nil {
			read, ok := out.(engine.ReadTaskOutput)
			if ok && read.Task.State != "running" {
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
				}
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
	}
	t.Fatal("detached task survived Relay disconnect")
}

func TestAgentURLCanonicalizesImmutableIDCase(t *testing.T) {
	endpoint, err := agentURLForRoute("https://relay.example", "label", "ABCDEF0123456789ABCDEF0123456789")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "wss://relay.example/agent/id/abcdef0123456789abcdef0123456789" {
		t.Fatalf("endpoint=%q", endpoint)
	}
}

func TestAgentRunSendsEd25519ProofOfPossession(t *testing.T) {
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	const token = "proof-bound-agent-token"
	verified := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
			return
		}
		timestamp, err := strconv.ParseInt(r.Header.Get(deviceidentity.HeaderTimestamp), 10, 64)
		if err != nil || time.Since(time.Unix(timestamp, 0)) > time.Minute || time.Until(time.Unix(timestamp, 0)) > time.Minute {
			http.Error(w, "bad timestamp", http.StatusUnauthorized)
			return
		}
		resource := "http://" + r.Host + r.URL.EscapedPath()
		if !deviceidentity.VerifyProof(identity.PublicKey(), resource, deviceidentity.TokenFingerprint(token), timestamp,
			r.Header.Get(deviceidentity.HeaderNonce), r.Header.Get(deviceidentity.HeaderProof)) {
			http.Error(w, "bad proof", http.StatusUnauthorized)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		select {
		case verified <- struct{}{}:
		default:
		}
		_ = conn.Close(websocket.StatusNormalClosure, "verified")
	}))
	defer server.Close()

	eng, err := engine.New(engine.Config{Roots: []string{t.TempDir()}, StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	ctx, cancel := context.WithCancel(context.Background())
	client := &Client{Engine: eng, URL: server.URL, Device: "proof-device", DeviceID: identity.ID(), Token: token, Identity: identity}
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	select {
	case <-verified:
		cancel()
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("Agent did not complete proof-bound WebSocket handshake")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Agent did not stop after test cancellation")
	}
}
