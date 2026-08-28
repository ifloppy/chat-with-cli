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
