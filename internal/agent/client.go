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
	Token         string
	TokenProvider func(context.Context) (string, error)
}

func (c *Client) Run(ctx context.Context) error {
	if c.Engine == nil {
		return errors.New("engine is required")
	}
	if strings.TrimSpace(c.Device) == "" {
		return errors.New("device name is required")
	}
	if c.Token == "" && c.TokenProvider == nil {
		return errors.New("agent OAuth token provider or legacy token is required")
	}
	endpoint, err := agentURL(c.URL, c.Device)
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
	u.Path = strings.TrimRight(u.Path, "/") + "/agent/" + url.PathEscape(device)
	u.RawQuery = ""
	return u.String(), nil
}

func (c *Client) serve(parent context.Context, conn *websocket.Conn) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var writeMu sync.Mutex
	sem := make(chan struct{}, 64)

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
