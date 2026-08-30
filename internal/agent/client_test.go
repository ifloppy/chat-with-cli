package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/ifloppy/chat-with-cli/internal/deviceidentity"
	"github.com/ifloppy/chat-with-cli/internal/engine"
	"github.com/ifloppy/chat-with-cli/internal/protocol"
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

func TestAgentRunSendsRelayChallengeProofOfPossession(t *testing.T) {
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	const token = "proof-bound-agent-token"
	const challenge = "relay-issued-one-time-challenge-1234567890"
	verified := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/challenge") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"challenge": challenge, "expires_in": 30})
			return
		}
		resource := "http://" + r.Host + r.URL.EscapedPath()
		if r.Header.Get(deviceidentity.HeaderChallenge) != challenge ||
			!deviceidentity.VerifyProof(identity.PublicKey(), resource, deviceidentity.TokenFingerprint(token), challenge, r.Header.Get(deviceidentity.HeaderProof)) {
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
		t.Fatal("Agent did not complete challenge-bound WebSocket handshake")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Agent did not stop after test cancellation")
	}
}

func TestRequestAuthorizerRunsBeforeEngineInvocation(t *testing.T) {
	called := false
	var observed ToolCall
	var events []string
	c := &Client{
		OnToolCall: func(call ToolCall) {
			observed = call
			events = append(events, "observe")
		},
		AuthorizeRequest: func(context.Context, protocol.Request) error {
			called = true
			events = append(events, "authorize")
			return errors.New("local approval denied")
		},
	}
	resp := c.handle(context.Background(), protocol.Request{ID: "approval-test", Method: "system_info"})
	if observed.Method != "system_info" {
		t.Fatalf("tool observer saw %#v", observed)
	}
	if !called {
		t.Fatal("request authorizer was not called")
	}
	if got := strings.Join(events, ","); got != "observe,authorize" {
		t.Fatalf("unexpected request handling order: %q", got)
	}
	if !strings.Contains(resp.Error, "local approval denied") {
		t.Fatalf("unexpected response error: %q", resp.Error)
	}
}

func TestToolCallObserverRunsWithoutAuthorization(t *testing.T) {
	eng, err := engine.New(engine.Config{Roots: []string{t.TempDir()}, StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	observed := make(chan ToolCall, 1)
	c := &Client{Engine: eng, OnToolCall: func(call ToolCall) { observed <- call }}
	resp := c.handle(context.Background(), protocol.Request{ID: "observer-test", Method: "system_info"})
	call := <-observed
	if call.Method != "system_info" {
		t.Fatalf("tool observer saw %#v", call)
	}
	if resp.Error != "" {
		t.Fatalf("unexpected engine error: %q", resp.Error)
	}
}

func TestRejectedCachedOAuthTokenIsDiscardedBeforeReconnect(t *testing.T) {
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	const challenge = "fresh-challenge-for-token-recovery-1234567890"
	verified := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if strings.HasSuffix(r.URL.Path, "/challenge") {
			if token == "stale-token" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if token != "fresh-token" {
				http.Error(w, "unexpected token", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"challenge": challenge, "expires_in": 30})
			return
		}
		resource := "http://" + r.Host + r.URL.EscapedPath()
		if token != "fresh-token" || !deviceidentity.VerifyProof(identity.PublicKey(), resource, deviceidentity.TokenFingerprint(token), challenge, r.Header.Get(deviceidentity.HeaderProof)) {
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
	current := "stale-token"
	rejected := 0
	providerCalls := 0
	ctx, cancel := context.WithCancel(context.Background())
	client := &Client{
		Engine: eng, URL: server.URL, Device: "recovery-device", DeviceID: identity.ID(), Identity: identity,
		TokenProvider: func(context.Context) (string, error) {
			providerCalls++
			return current, nil
		},
		TokenRejected: func(context.Context) error {
			rejected++
			current = "fresh-token"
			return nil
		},
	}
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	select {
	case <-verified:
		cancel()
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("Agent did not retry with a fresh OAuth token")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Agent did not stop after cancellation")
	}
	if rejected != 1 || providerCalls < 2 {
		t.Fatalf("rejected=%d providerCalls=%d", rejected, providerCalls)
	}
}

func TestRetiredDeviceChallengeStopsForIdentityRotation(t *testing.T) {
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/challenge") {
			http.Error(w, "retired", http.StatusGone)
			return
		}
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()
	eng, err := engine.New(engine.Config{Roots: []string{t.TempDir()}, StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	client := &Client{
		Engine: eng, URL: server.URL, Device: "retired-device", DeviceID: identity.ID(), Identity: identity,
		TokenProvider: func(context.Context) (string, error) { return "cached-token", nil },
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = client.Run(ctx)
	if !IsChallengeHTTPStatus(err, http.StatusGone) {
		t.Fatalf("retired device error=%v, want detectable HTTP 410", err)
	}
}
