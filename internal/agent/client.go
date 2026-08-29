package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/ifloppy/chat-with-cli/internal/engine"
	"github.com/ifloppy/chat-with-cli/internal/protocol"
)

type Client struct {
	Engine        *engine.Engine
	URL           string
	Device        string
	DeviceID      string
	Token         string
	TokenProvider func(context.Context) (string, error)
}

func (c *Client) Run(ctx context.Context) error {
	if c.Engine == nil {
		return errors.New("engine is required")
	}
	if strings.TrimSpace(c.Device) == "" && strings.TrimSpace(c.DeviceID) == "" {
		return errors.New("device name or immutable device ID is required")
	}
	if c.Token == "" && c.TokenProvider == nil {
		return errors.New("agent OAuth token provider or legacy token is required")
	}
	endpoint, err := agentURLForRoute(c.URL, c.Device, c.DeviceID)
	if err != nil {
		return err
	}
	backoff := time.Second
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		token := c.Token
		if c.TokenProvider != nil {
			token, err = c.TokenProvider(ctx)
			if err != nil {
				return fmt.Errorf("agent OAuth: %w", err)
			}
		}
		header := http.Header{}
		header.Set("Authorization", "Bearer "+token)
		dialCtx, cancelDial := context.WithTimeout(ctx, 15*time.Second)
		conn, _, err := websocket.Dial(dialCtx, endpoint, &websocket.DialOptions{HTTPHeader: header})
		cancelDial()
		if err == nil {
			conn.SetReadLimit(32 << 20)
			err = c.serve(ctx, conn)
			// A detached PTY must not keep executing after the remote authority
			// disappears. Treat every Relay disconnect as the end of that remote
			// authorization session; reconnect starts from a clean local state.
			c.Engine.EndRemoteSession()
			_ = conn.CloseNow()
			backoff = time.Second
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func agentURL(base, device string) (string, error) {
	return agentURLForRoute(base, device, "")
}

func agentURLForRoute(base, device, deviceID string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid relay URL %q", base)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("relay URL must be an origin without credentials, path, query, or fragment")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	switch u.Scheme {
	case "http":
		if !loopback {
			return "", errors.New("Agent WebSocket requires wss/https except for loopback testing")
		}
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
		if u.Scheme == "ws" && !loopback {
			return "", errors.New("Agent WebSocket requires wss except for loopback testing")
		}
	default:
		return "", fmt.Errorf("unsupported relay scheme %q", u.Scheme)
	}
	route := strings.TrimSpace(device)
	if strings.TrimSpace(deviceID) != "" {
		canonicalID, ok := protocol.NormalizeDeviceID(deviceID)
		if !ok {
			return "", errors.New("invalid immutable device ID")
		}
		route = "id/" + canonicalID
	} else if !protocol.ValidDeviceName(route) {
		return "", errors.New("invalid device name")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/agent/" + route
	u.RawQuery = ""
	return u.String(), nil
}

func (c *Client) serve(parent context.Context, conn *websocket.Conn) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var writeMu sync.Mutex
	sem := make(chan struct{}, 32)
	if err := c.sendCapabilities(ctx, conn); err != nil {
		return err
	}

	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		var request protocol.Request
		if err := json.Unmarshal(data, &request); err != nil || request.ID == "" || request.Method == "" {
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		go func(request protocol.Request) {
			defer func() { <-sem }()
			response := c.handle(ctx, request)
			encoded, err := json.Marshal(response)
			if err != nil {
				return
			}
			writeMu.Lock()
			_ = conn.Write(ctx, websocket.MessageText, encoded)
			writeMu.Unlock()
		}(request)
	}
}

func (c *Client) sendCapabilities(ctx context.Context, conn *websocket.Conn) error {
	cfg := c.Engine.Config()
	capabilities, err := json.Marshal(protocol.AgentCapabilities{
		FilesystemRead:    len(cfg.Roots) > 0,
		FilesystemWrite:   cfg.AllowFileWrite,
		Exec:              cfg.AllowExec,
		ExecSandbox:       cfg.ExecSandbox,
		ScreenRead:        cfg.AllowScreen,
		AccessibilityRead: cfg.AllowAccessibility || cfg.AllowComputerControl,
		ComputerInput:     cfg.AllowComputerControl,
		MaxActiveTasks:    cfg.MaxActiveTasks,
	})
	if err != nil {
		return err
	}
	message, err := json.Marshal(protocol.Request{ID: protocol.NewID(), Method: "agent_hello", Args: capabilities})
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageText, message)
}

func (c *Client) handle(ctx context.Context, request protocol.Request) protocol.Response {
	value, err := c.Engine.Invoke(ctx, request.Method, request.Args)
	if err != nil {
		return protocol.Response{ID: request.ID, Error: err.Error()}
	}
	data, err := json.Marshal(value)
	if err != nil {
		return protocol.Response{ID: request.ID, Error: err.Error()}
	}
	return protocol.Response{ID: request.ID, Result: data}
}
