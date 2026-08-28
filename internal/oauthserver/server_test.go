package oauthserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

var requestIDPattern = regexp.MustCompile(`name="request_id" value="([^"]+)"`)

func testListener(t *testing.T) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln, "http://" + ln.Addr().String()
}
func startOAuthMCPServer(t *testing.T) (*Server, string, func()) {
	t.Helper()
	ln, base := testListener(t)
	oauthServer, err := New(Config{PublicURL: base, Password: "correct-horse-battery-staple-0123456789", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "oauth-test", Version: "1"}, nil)
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "ping"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, struct{}, error) {
		return nil, struct{}{}, nil
	})
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpServer }, &mcp.StreamableHTTPOptions{Stateless: true})
	mux := http.NewServeMux()
	oauthServer.RegisterRoutes(mux)
	mux.Handle("/mcp/device-a", oauthServer.ProtectResource("", mcpHandler))
	mux.Handle("/mcp/device-b", oauthServer.ProtectResource("", mcpHandler))
	httpServer := &http.Server{Handler: mux}
	go func() { _ = httpServer.Serve(ln) }()
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	}
	return oauthServer, base, cleanup
}
func browserFetcher(t *testing.T, password string) auth.AuthorizationCodeFetcher {
	t.Helper()
	return func(ctx context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, args.URL, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		match := requestIDPattern.FindSubmatch(body)
		if len(match) != 2 {
			t.Fatalf("authorization page missing request id: status=%d body=%s", resp.StatusCode, body)
		}
		authURL, _ := url.Parse(args.URL)
		form := url.Values{"request_id": {string(match[1])}, "password": {password}, "decision": {"allow"}}
		post, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL.Scheme+"://"+authURL.Host+"/oauth/authorize", strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err = client.Do(post)
		if err != nil {
			return nil, err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			return nil, fmt.Errorf("authorization POST status %d", resp.StatusCode)
		}
		location, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			return nil, err
		}
		q := location.Query()
		return &auth.AuthorizationResult{Code: q.Get("code"), State: q.Get("state"), Iss: q.Get("iss")}, nil
	}
}

func TestOAuthMCPAuthorizationFlow(t *testing.T) {
	oauthServer, base, cleanup := startOAuthMCPServer(t)
	defer cleanup()
	redirect := "http://127.0.0.1:43119/callback"
	handler, err := auth.NewAuthorizationCodeHandler(&auth.AuthorizationCodeHandlerConfig{
		DynamicClientRegistrationConfig: &auth.DynamicClientRegistrationConfig{Metadata: &oauthex.ClientRegistrationMetadata{
			RedirectURIs: []string{redirect}, TokenEndpointAuthMethod: "none",
			GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, ClientName: "chat-with-cli test",
		}},
		RedirectURL: redirect, AuthorizationCodeFetcher: browserFetcher(t, "correct-horse-battery-staple-0123456789"), RequestRefreshToken: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	transport := &mcp.StreamableClientTransport{Endpoint: base + "/mcp/device-a", OAuthHandler: handler}
	session, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "ping" {
		t.Fatalf("unexpected tools: %#v", tools.Tools)
	}

	ts, err := handler.TokenSource(context.Background())
	if err != nil || ts == nil {
		t.Fatalf("token source: %v", err)
	}
	token, err := ts.Token()
	if err != nil {
		t.Fatal(err)
	}
	if token.RefreshToken == "" {
		t.Fatal("expected refresh token")
	}
	if !oauthServer.VerifyAccess(token.AccessToken, base+"/mcp/device-a") {
		t.Fatal("access token should authorize device-a")
	}
	if oauthServer.VerifyAccess(token.AccessToken, base+"/mcp/device-b") {
		t.Fatal("access token must not authorize another device")
	}
}
func TestOAuthStateSurvivesRestartAndRefreshRotates(t *testing.T) {
	stateDir := t.TempDir()
	cfg := Config{PublicURL: "http://127.0.0.1:18888", Password: "persistent-test-password-0123456789", StateDir: stateDir}
	s1, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s1.mu.Lock()
	access, refresh, _, err := s1.issueTokensLocked("client-1", cfg.PublicURL+"/mcp/device-a", "mcp offline_access")
	s1.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	s2, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.VerifyAccess(access, cfg.PublicURL+"/mcp/device-a") {
		t.Fatal("persisted access token was not restored")
	}
	s2.mu.Lock()
	record := s2.refresh[tokenKey(refresh)]
	s2.mu.Unlock()
	if record.ClientID != "client-1" {
		t.Fatalf("refresh record=%+v", record)
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {"client-1"}}
	req := httptest.NewRequest(http.MethodPost, cfg.PublicURL+"/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s2.handleToken(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh status=%d body=%s", rr.Code, rr.Body.String())
	}
	var response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.AccessToken == "" || response.RefreshToken == "" || response.RefreshToken == refresh {
		t.Fatalf("bad rotated token response: %+v", response)
	}
	if s2.VerifyAccess(access, cfg.PublicURL+"/mcp/device-a") == false {
		t.Fatal("access token should remain valid until expiry")
	}
	s2.mu.Lock()
	_, oldRefreshStillValid := s2.refresh[tokenKey(refresh)]
	s2.mu.Unlock()
	if oldRefreshStillValid {
		t.Fatal("refresh token was not rotated")
	}
}
func TestOAuthPasswordMinimumLength(t *testing.T) {
	_, err := New(Config{
		PublicURL: "http://127.0.0.1:18889",
		Password:  "too-short",
		StateDir:  t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "at least 32") {
		t.Fatalf("expected password length error, got %v", err)
	}
}

func TestPersistedStateContainsNoRawTokens(t *testing.T) {
	stateDir := t.TempDir()
	cfg := Config{
		PublicURL: "http://127.0.0.1:18890",
		Password:  "state-file-test-password-0123456789",
		StateDir:  stateDir,
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	access, refresh, _, err := s.issueTokensLocked(
		"client", cfg.PublicURL+"/mcp/device", "mcp offline_access",
	)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(stateDir, "oauth-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(access)) || bytes.Contains(data, []byte(refresh)) {
		t.Fatal("OAuth state persisted a raw bearer token")
	}
	info, err := os.Stat(filepath.Join(stateDir, "oauth-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("OAuth state mode=%o, want 600", info.Mode().Perm())
	}
}

func TestProtectedResourceChallengeAndDeviceValidation(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18891", Password: "challenge-test-password-0123456789", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18891/mcp/device-a", nil)
	s.ProtectResource("", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unauthorized request reached resource") })).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Header().Get("WWW-Authenticate"), `scope="mcp"`) {
		t.Fatalf("challenge status=%d header=%q", rr.Code, rr.Header().Get("WWW-Authenticate"))
	}
	if _, ok := s.validateResource("http://127.0.0.1:18891/mcp/a/b"); ok {
		t.Fatal("resource with embedded slash should be rejected")
	}
}

func TestAuthorizationPasswordAttemptsAreBounded(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18892", Password: "attempt-test-password-0123456789012", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.pending["request"] = pendingAuth{RedirectURI: "http://127.0.0.1:43120/callback", Expires: time.Now().Add(time.Minute)}
	for attempt := 1; attempt <= 5; attempt++ {
		form := url.Values{"request_id": {"request"}, "password": {"wrong-password"}, "decision": {"allow"}}
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18892/oauth/authorize", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		s.handleAuthorizePOST(rr, req)
		want := http.StatusUnauthorized
		if attempt == 5 {
			want = http.StatusTooManyRequests
		}
		if rr.Code != want {
			t.Fatalf("attempt %d status=%d want=%d", attempt, rr.Code, want)
		}
	}
	if _, ok := s.pending["request"]; ok {
		t.Fatal("locked authorization request was not removed")
	}
}
