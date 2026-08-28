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
		conn, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPHeader: header})
		if err == nil {
			conn.SetReadLimit(32 << 20)
			err = c.serve(ctx, conn)
			_ = conn.Close(websocket.StatusNormalClosure, "reconnect")
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
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
	default:
		return "", fmt.Errorf("unsupported relay scheme %q", u.Scheme)
	}
	route := strings.TrimSpace(device)
	if strings.TrimSpace(deviceID) != "" {
		if !protocol.ValidDeviceID(strings.TrimSpace(deviceID)) {
			return "", errors.New("invalid immutable device ID")
		}
		route = "id/" + strings.TrimSpace(deviceID)
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
