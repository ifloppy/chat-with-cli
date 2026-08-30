package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/ifloppy/chat-with-cli/internal/protocol"
)

func TestBrokerRechecksAgentAuthorizationBeforeRPC(t *testing.T) {
	broker := NewBroker()
	var valid atomic.Bool
	valid.Store(true)
	broker.SetAgentConnectionAuthorizer(func(_ string, fingerprint string) bool {
		return valid.Load() && fingerprint == TokenFingerprint("agent-secret")
	})
	mux := http.NewServeMux()
	mux.Handle("/agent/{device}", broker.AgentHandler())
	server := httptest.NewServer(mux)
	defer server.Close()
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http") + "/agent/laptop"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer agent-secret"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	deadline := time.Now().Add(time.Second)
	for len(broker.Devices()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(broker.Devices()) != 1 {
		t.Fatal("agent did not connect")
	}

	responseDone := make(chan error, 1)
	go func() {
		_, data, err := conn.Read(ctx)
		if err != nil {
			responseDone <- err
			return
		}
		var request protocol.Request
		if err := json.Unmarshal(data, &request); err != nil {
			responseDone <- err
			return
		}
		result, err := json.Marshal(protocol.Response{ID: request.ID, Result: json.RawMessage(`{"ok":true}`)})
		if err != nil {
			responseDone <- err
			return
		}
		responseDone <- conn.Write(ctx, websocket.MessageText, result)
	}()

	result, err := broker.Call(ctx, "laptop", "system_info", json.RawMessage(`{}`))
	if err != nil || string(result) != `{"ok":true}` {
		t.Fatalf("first broker call result=%s err=%v", result, err)
	}
	if err := <-responseDone; err != nil {
		t.Fatal(err)
	}

	valid.Store(false)
	if _, err := broker.Call(ctx, "laptop", "system_info", json.RawMessage(`{}`)); err == nil || !strings.Contains(err.Error(), "authorization revoked") {
		t.Fatalf("revoked connection call err=%v", err)
	}
}

func TestBrokerRevocationCancelsInFlightRPC(t *testing.T) {
	broker := NewBroker()
	var valid atomic.Bool
	valid.Store(true)
	broker.SetAgentConnectionAuthorizer(func(_ string, fingerprint string) bool {
		return valid.Load() && fingerprint == TokenFingerprint("agent-secret")
	})
	mux := http.NewServeMux()
	mux.Handle("/agent/{device}", broker.AgentHandler())
	server := httptest.NewServer(mux)
	defer server.Close()
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http") + "/agent/laptop"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer agent-secret"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	deadline := time.Now().Add(time.Second)
	for len(broker.Devices()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(broker.Devices()) != 1 {
		t.Fatal("agent did not connect")
	}

	requestSeen := make(chan struct{})
	go func() {
		if _, _, err := conn.Read(ctx); err == nil {
			close(requestSeen)
		}
	}()
	callDone := make(chan error, 1)
	go func() {
		_, err := broker.Call(ctx, "laptop", "computer_ui_wait", json.RawMessage(`{}`))
		callDone <- err
	}()
	select {
	case <-requestSeen:
	case <-time.After(time.Second):
		t.Fatal("broker did not send in-flight request")
	}
	valid.Store(false)
	select {
	case err := <-callDone:
		if err == nil || !strings.Contains(err.Error(), "authorization revoked") {
			t.Fatalf("in-flight revoke err=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight RPC was not canceled after authorization revoke")
	}
}

func TestAgentProbeDoesNotReplaceOnlinePeer(t *testing.T) {
	broker := NewBroker()
	broker.SetAgentConnectionAuthorizer(func(_ string, fingerprint string) bool {
		return fingerprint == TokenFingerprint("agent-secret")
	})
	mux := http.NewServeMux()
	mux.Handle("/agent/{device}", broker.AgentHandler())
	server := httptest.NewServer(mux)
	defer server.Close()
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http") + "/agent/laptop"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer agent-secret"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	deadline := time.Now().Add(time.Second)
	for len(broker.Devices()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(broker.Devices()) != 1 {
		t.Fatal("agent did not connect")
	}

	probe, err := http.Get(server.URL + "/agent/laptop?probe=1")
	if err != nil {
		t.Fatal(err)
	}
	_ = probe.Body.Close()
	if probe.StatusCode != http.StatusNoContent {
		t.Fatalf("probe status=%d", probe.StatusCode)
	}

	responseDone := make(chan error, 1)
	go func() {
		_, data, err := conn.Read(ctx)
		if err != nil {
			responseDone <- err
			return
		}
		var request protocol.Request
		if err := json.Unmarshal(data, &request); err != nil {
			responseDone <- err
			return
		}
		encoded, _ := json.Marshal(protocol.Response{ID: request.ID, Result: json.RawMessage(`{"ok":true}`)})
		responseDone <- conn.Write(ctx, websocket.MessageText, encoded)
	}()
	result, err := broker.Call(ctx, "laptop", "system_info", json.RawMessage(`{}`))
	if err != nil || string(result) != `{"ok":true}` {
		t.Fatalf("original Agent was disturbed by probe: result=%s err=%v", result, err)
	}
	if err := <-responseDone; err != nil {
		t.Fatal(err)
	}
}

func TestIdleAgentIsDisconnectedAfterAuthorizationRevoke(t *testing.T) {
	broker := NewBroker()
	var valid atomic.Bool
	valid.Store(true)
	broker.SetAgentConnectionAuthorizer(func(_ string, fingerprint string) bool {
		return valid.Load() && fingerprint == TokenFingerprint("idle-agent-secret")
	})
	mux := http.NewServeMux()
	mux.Handle("/agent/{device}", broker.AgentHandler())
	server := httptest.NewServer(mux)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http") + "/agent/idle-laptop"
	conn, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer idle-agent-secret"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	deadline := time.Now().Add(time.Second)
	for len(broker.Devices()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(broker.Devices()) != 1 {
		t.Fatal("agent did not connect")
	}

	valid.Store(false)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(broker.Devices()) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("idle revoked Agent remained connected: %v", broker.Devices())
}

func TestBrokerReportsForwardedPayloadTraffic(t *testing.T) {
	broker := NewBroker()
	var total atomic.Int64
	broker.SetTrafficObserver(func(device string, bytes int64) {
		if device == "metered-laptop" {
			total.Add(bytes)
		}
	})
	mux := http.NewServeMux()
	mux.Handle("/agent/{device}", broker.AgentHandler())
	server := httptest.NewServer(mux)
	defer server.Close()
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http") + "/agent/metered-laptop"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer agent-secret"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	broker.SetAgentConnectionAuthorizer(func(_ string, fingerprint string) bool {
		return fingerprint == TokenFingerprint("agent-secret")
	})
	deadline := time.Now().Add(time.Second)
	for len(broker.Devices()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(broker.Devices()) != 1 {
		t.Fatal("agent did not connect")
	}

	responseDone := make(chan error, 1)
	go func() {
		_, data, readErr := conn.Read(ctx)
		if readErr != nil {
			responseDone <- readErr
			return
		}
		var request protocol.Request
		if unmarshalErr := json.Unmarshal(data, &request); unmarshalErr != nil {
			responseDone <- unmarshalErr
			return
		}
		response, marshalErr := json.Marshal(protocol.Response{ID: request.ID, Result: json.RawMessage(`{"ok":true}`)})
		if marshalErr != nil {
			responseDone <- marshalErr
			return
		}
		responseDone <- conn.Write(ctx, websocket.MessageText, response)
	}()
	if _, err := broker.Call(ctx, "metered-laptop", "system_info", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := <-responseDone; err != nil {
		t.Fatal(err)
	}
	if total.Load() <= 0 {
		t.Fatal("broker did not report forwarded payload bytes")
	}
}
