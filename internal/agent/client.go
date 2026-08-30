package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/ifloppy/chat-with-cli/internal/deviceidentity"
	"github.com/ifloppy/chat-with-cli/internal/engine"
	"github.com/ifloppy/chat-with-cli/internal/protocol"
)

type Client struct {
	Engine           *engine.Engine
	URL              string
	Device           string
	DeviceID         string
	Token            string
	TokenProvider    func(context.Context) (string, error)
	TokenRejected    func(context.Context) error
	AuthorizeRequest func(context.Context, protocol.Request) error
	OnToolCall       ToolCallObserver
	Identity         *deviceidentity.Identity
}

// ToolCall contains only the method name of an inbound MCP RPC. It is passed
// to the optional CLI audit observer before local authorization and execution;
// arguments and results are deliberately not exposed to keep audit output
// from becoming a second data-exfiltration channel.
type ToolCall struct {
	Method string
}

// ToolCallObserver observes every valid inbound RPC, including calls that are
// subsequently denied by AuthorizeRequest.
type ToolCallObserver func(ToolCall)

func (c *Client) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if c.Engine == nil {
		return errors.New("engine is required")
	}
	if strings.TrimSpace(c.Device) == "" && strings.TrimSpace(c.DeviceID) == "" {
		return errors.New("device name or immutable device ID is required")
	}
	if c.Token == "" && c.TokenProvider == nil {
		return errors.New("agent OAuth token provider or legacy token is required")
	}
	if c.Identity != nil && strings.TrimSpace(c.DeviceID) != "" {
		canonicalID, ok := protocol.NormalizeDeviceID(c.DeviceID)
		if !ok || canonicalID != c.Identity.ID() {
			return errors.New("immutable device ID does not match the loaded Ed25519 device identity")
		}
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
		err = nil
		header := http.Header{}
		header.Set("Authorization", "Bearer "+token)
		if c.Identity != nil {
			resource, proofErr := agentResourceForEndpoint(endpoint)
			if proofErr != nil {
				return proofErr
			}
			challenge, proofErr := fetchAgentChallenge(ctx, resource, token)
			if proofErr != nil {
				var statusErr *ChallengeHTTPError
				if errors.As(proofErr, &statusErr) {
					if statusErr.StatusCode == http.StatusUnauthorized && c.TokenProvider != nil && c.TokenRejected != nil {
						if resetErr := c.TokenRejected(ctx); resetErr != nil {
							return fmt.Errorf("discard rejected Agent OAuth credential: %w", resetErr)
						}
						backoff = time.Second
						continue
					}
					if statusErr.StatusCode == http.StatusGone {
						return fmt.Errorf("obtain Agent device challenge: %w", proofErr)
					}
				}
				err = fmt.Errorf("obtain Agent device challenge: %w", proofErr)
			} else {
				proof, signErr := c.Identity.SignProof(resource, token, challenge)
				if signErr != nil {
					return fmt.Errorf("sign Agent device proof: %w", signErr)
				}
				header.Set(deviceidentity.HeaderChallenge, challenge)
				header.Set(deviceidentity.HeaderProof, proof)
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
		} else {
			dialCtx, cancelDial := context.WithTimeout(ctx, 15*time.Second)
			conn, _, dialErr := websocket.Dial(dialCtx, endpoint, &websocket.DialOptions{HTTPHeader: header})
			cancelDial()
			err = dialErr
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

type ChallengeHTTPError struct {
	StatusCode int
}

func (e *ChallengeHTTPError) Error() string {
	return fmt.Sprintf("challenge endpoint returned HTTP %d", e.StatusCode)
}

func IsChallengeHTTPStatus(err error, status int) bool {
	var target *ChallengeHTTPError
	return errors.As(err, &target) && target.StatusCode == status
}

func fetchAgentChallenge(ctx context.Context, resource, token string) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, strings.TrimRight(resource, "/")+"/challenge", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return "", &ChallengeHTTPError{StatusCode: resp.StatusCode}
	}
	var payload struct {
		Challenge string `json:"challenge"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode challenge: %w", err)
	}
	if len(payload.Challenge) < 40 || len(payload.Challenge) > 256 || payload.ExpiresIn <= 0 || payload.ExpiresIn > 60 {
		return "", errors.New("Relay returned an invalid Agent challenge")
	}
	return payload.Challenge, nil
}

func agentResourceForEndpoint(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return "", errors.New("invalid Agent WebSocket endpoint")
	}
	switch strings.ToLower(u.Scheme) {
	case "wss":
		u.Scheme = "https"
	case "ws":
		u.Scheme = "http"
	default:
		return "", errors.New("Agent endpoint is not WebSocket")
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func agentURL(base, device string) (string, error) {
	return agentURLForRoute(base, device, "")
}

func agentURLForRoute(base, device, deviceID string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", errors.New("invalid relay URL")
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
	if c.OnToolCall != nil {
		c.OnToolCall(ToolCall{Method: request.Method})
	}
	if c.AuthorizeRequest != nil {
		if err := c.AuthorizeRequest(ctx, request); err != nil {
			return protocol.Response{ID: request.ID, Error: err.Error()}
		}
	}
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
