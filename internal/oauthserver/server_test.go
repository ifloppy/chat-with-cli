package oauthserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/ifloppy/chat-with-cli/internal/deviceidentity"
	"github.com/ifloppy/chat-with-cli/internal/relay"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

var requestIDPattern = regexp.MustCompile(`name="request_id" value="([^"]+)"`)
var csrfTokenPattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

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
	oauthServer.mu.Lock()
	ownerID := oauthServer.usernames["owner"]
	oauthServer.devices["device-a"] = ownerID
	oauthServer.devices["device-b"] = ownerID
	if err := oauthServer.saveLocked(); err != nil {
		oauthServer.mu.Unlock()
		t.Fatal(err)
	}
	oauthServer.mu.Unlock()
	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "oauth-test", Version: "1"}, nil)
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "ping"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, struct{}, error) {
		return nil, struct{}{}, nil
	})
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpServer }, &mcp.StreamableHTTPOptions{Stateless: true})
	mux := http.NewServeMux()
	oauthServer.RegisterRoutes(mux)
	mux.Handle("/mcp/device-a", oauthServer.ProtectResource(mcpHandler))
	mux.Handle("/mcp/device-b", oauthServer.ProtectResource(mcpHandler))
	httpServer := &http.Server{Handler: mux}
	go func() { _ = httpServer.Serve(ln) }()
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	}
	return oauthServer, base, cleanup
}
func browserFetcher(t *testing.T, username, password string) auth.AuthorizationCodeFetcher {
	t.Helper()
	return func(ctx context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, err
		}
		client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
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
		csrf := csrfTokenPattern.FindSubmatch(body)
		if len(csrf) != 2 {
			t.Fatalf("authorization page missing CSRF token: status=%d body=%s", resp.StatusCode, body)
		}
		authURL, _ := url.Parse(args.URL)
		form := url.Values{"request_id": {string(match[1])}, "csrf_token": {string(csrf[1])}, "username": {username}, "password": {password}, "decision": {"login"}}
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
		RedirectURL: redirect, AuthorizationCodeFetcher: browserFetcher(t, "owner", "correct-horse-battery-staple-0123456789"), RequestRefreshToken: true,
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
	ownerID := s1.usernames["owner"]
	s1.clients["client-1"] = Client{ID: "client-1", Approved: true}
	s1.devices["device-a"] = ownerID
	access, refresh, _, err := s1.issueTokensLocked("client-1", ownerID, cfg.PublicURL+"/mcp/device-a", "mcp offline_access")
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
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {"client-1"}, "resource": {cfg.PublicURL + "/mcp/device-a"}}
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
func TestOwnerPasswordMinimumLength(t *testing.T) {
	_, err := New(Config{
		PublicURL: "http://127.0.0.1:18889",
		Password:  "too-short",
		StateDir:  t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "at least 12") {
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
	ownerID := s.usernames["owner"]
	access, refresh, _, err := s.issueTokensLocked(
		"client", ownerID, cfg.PublicURL+"/mcp/device", "mcp offline_access",
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
	s.ProtectResource(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unauthorized request reached resource") })).ServeHTTP(rr, req)
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
	csrf := "test-csrf-token"
	s.pending["request"] = pendingAuth{RedirectURI: "http://127.0.0.1:43120/callback", CSRFTokenHash: tokenKey(csrf), Expires: time.Now().Add(time.Minute)}
	for attempt := 1; attempt <= 5; attempt++ {
		form := url.Values{"request_id": {"request"}, "csrf_token": {csrf}, "password": {"wrong-password"}, "decision": {"allow"}}
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18892/oauth/authorize", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: oauthCSRFCookie, Value: csrf})
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

func TestPKCEParametersAreStrictlyValidated(t *testing.T) {
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if !validPKCEChallenge(challenge) || !validPKCEVerifier(strings.Repeat("a", 43)) {
		t.Fatal("valid PKCE parameters were rejected")
	}
	for _, value := range []string{"", strings.Repeat("a", 42), strings.Repeat("a", 129), strings.Repeat("!", 43)} {
		if validPKCEVerifier(value) {
			t.Fatalf("invalid verifier was accepted: %q", value)
		}
	}
	if validPKCEChallenge(strings.Repeat("!", 43)) {
		t.Fatal("non-base64 PKCE challenge was accepted")
	}
}

func TestPrivateInstanceRestartNeedsNoBootstrapPassword(t *testing.T) {
	stateDir := t.TempDir()
	first, err := New(Config{
		PublicURL: "http://127.0.0.1:18901", StateDir: stateDir,
		Mode: ModePrivate, OwnerUsername: "owner", OwnerPassword: "private-owner-password-123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.UserCount() != 1 {
		t.Fatalf("user count=%d", first.UserCount())
	}
	second, err := New(Config{
		PublicURL: "http://127.0.0.1:18901", StateDir: stateDir,
		Mode: ModePrivate,
	})
	if err != nil {
		t.Fatalf("private restart unexpectedly needs bootstrap password: %v", err)
	}
	if second.UserCount() != 1 {
		t.Fatalf("restarted user count=%d", second.UserCount())
	}
}

func TestPublicModeStartsWithoutOwnerAndShowsRegistration(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18902", StateDir: t.TempDir(), Mode: ModePublic})
	if err != nil {
		t.Fatal(err)
	}
	if s.UserCount() != 0 {
		t.Fatalf("public instance unexpectedly bootstrapped %d users", s.UserCount())
	}
	rr := httptest.NewRecorder()
	s.renderAuthorization(rr, "request", Client{ID: "client", Name: "test"},
		"http://127.0.0.1:18902/agent/device-a", "agent:connect offline_access", User{}, false)
	if !strings.Contains(rr.Body.String(), "Create account") {
		t.Fatalf("public authorization page has no registration form: %s", rr.Body.String())
	}
}

func TestAuthorizationPageShowsUnverifiedClientCallbackOrigin(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18912", StateDir: t.TempDir(), Mode: ModePublic})
	if err != nil {
		t.Fatal(err)
	}
	client := Client{ID: "unverified-client-id", Name: "ChatGPT", RedirectURIs: []string{"https://benign.example/callback", "https://attacker.example/oauth/callback?ignored=1"}}
	rr := httptest.NewRecorder()
	s.renderAuthorizationWithCSRF(rr, "request", client, s.absolute("/mcp/device-a"), "mcp offline_access", client.RedirectURIs[1], "", User{}, false)
	body := rr.Body.String()
	if !strings.Contains(body, "Unverified dynamic OAuth client") || !strings.Contains(body, "https://attacker.example") || !strings.Contains(body, "unverified-client-id") {
		t.Fatalf("authorization page hid dynamic-client trust context: %s", body)
	}
	if strings.Contains(body, "https://benign.example") || strings.Contains(body, "/oauth/callback") || strings.Contains(body, "ignored=1") {
		t.Fatalf("authorization page should show the exact requested callback origin only, not another registered redirect or callback path/query: %s", body)
	}
}

func TestDCRRejectsClientNameControlAndFormatCharacters(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18913", StateDir: t.TempDir(), Mode: ModePublic})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"trusted\nclient", "ChatGPT\u202Eevil"} {
		body, _ := json.Marshal(map[string]any{
			"redirect_uris": []string{"https://client.example/callback"}, "client_name": name,
			"token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code"}, "response_types": []string{"code"},
		})
		req := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/register"), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		s.handleRegister(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("DCR accepted deceptive client name %q: status=%d body=%s", name, rr.Code, rr.Body.String())
		}
	}
}

func TestPublicDeviceOwnershipIsIsolated(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18903", StateDir: t.TempDir(), Mode: ModePublic})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	alice, err := s.createUserLocked("alice", "alice-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	bob, err := s.createUserLocked("bob", "bob-password-1234567")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	id := identity.ID()
	resourceAgent := s.absolute("/agent/id/" + id)
	resourceMCP := s.absolute("/mcp/id/" + id)
	s.clients["client-a"] = Client{ID: "client-a", DeviceID: id, DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true, Approved: true}
	if err := s.authorizeResourceLocked(alice.ID, "client-a", resourceAgent); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	if err := s.authorizeResourceLocked(alice.ID, "client-a", resourceMCP); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	if err := s.authorizeResourceLocked(bob.ID, "client-a", resourceAgent); err == nil {
		s.mu.Unlock()
		t.Fatal("bob unexpectedly claimed alice device")
	}
	if err := s.authorizeResourceLocked(bob.ID, "client-a", resourceMCP); err == nil {
		s.mu.Unlock()
		t.Fatal("bob unexpectedly authorized alice MCP resource")
	}
	access, _, _, err := s.issueTokensLocked("client-a", alice.ID, resourceAgent, "agent:connect offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !s.VerifyAccessScope(access, resourceAgent, "agent:connect") {
		t.Fatal("alice agent token did not authorize its resource")
	}
	if s.VerifyAccessScope(access, resourceAgent, "mcp") {
		t.Fatal("agent token unexpectedly has MCP scope")
	}
}

func TestRefreshTokenReplayRevokesTokenFamily(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18904", Password: "replay-test-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.clients["client"] = Client{ID: "client", Approved: true}
	s.devices["device"] = ownerID
	access, refresh, _, err := s.issueTokensLocked("client", ownerID, s.absolute("/mcp/device"), "mcp offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {"client"}, "resource": {s.absolute("/mcp/device")}}
	req := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/token"), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s.handleToken(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("first refresh status=%d body=%s", rr.Code, rr.Body.String())
	}
	var rotated struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	if !s.VerifyAccess(access, s.absolute("/mcp/device")) {
		t.Fatal("original access token unexpectedly revoked before replay")
	}
	replay := httptest.NewRecorder()
	replayReq := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/token"), strings.NewReader(form.Encode()))
	replayReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleToken(replay, replayReq)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replay status=%d body=%s", replay.Code, replay.Body.String())
	}
	if s.VerifyAccess(access, s.absolute("/mcp/device")) || s.VerifyAccess(rotated.AccessToken, s.absolute("/mcp/device")) {
		t.Fatal("refresh replay did not revoke the entire token family")
	}
	_ = rotated.RefreshToken
}

func TestSetupIsOneTimeAndLandingIsGeneric(t *testing.T) {
	stateDir := t.TempDir()
	setupFile := filepath.Join(stateDir, "setup-token")
	s, err := New(Config{PublicURL: "http://127.0.0.1:18905", StateDir: stateDir, SetupToken: "one-time-setup-token-123456", SetupTokenPath: setupFile})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)
	secured := SecurityHeaders(mux)
	landing := httptest.NewRecorder()
	secured.ServeHTTP(landing, httptest.NewRequest(http.MethodGet, s.absolute("/"), nil))
	if landing.Code != http.StatusOK || !strings.Contains(landing.Body.String(), "Chat with CLI") || !strings.Contains(landing.Body.String(), "Finish first-run setup") || strings.Contains(landing.Body.String(), "hostname") {
		t.Fatalf("unexpected landing page: status=%d body=%s", landing.Code, landing.Body.String())
	}
	if landing.Header().Get("Content-Security-Policy") == "" || landing.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("security headers missing: %#v", landing.Header())
	}
	setupGet := httptest.NewRecorder()
	secured.ServeHTTP(setupGet, httptest.NewRequest(http.MethodGet, s.absolute("/setup"), nil))
	csrfMatch := csrfTokenPattern.FindSubmatch(setupGet.Body.Bytes())
	if setupGet.Code != http.StatusOK || len(csrfMatch) != 2 {
		t.Fatalf("setup page missing CSRF token: status=%d body=%s", setupGet.Code, setupGet.Body.String())
	}
	setCookie := setupGet.Result().Cookies()
	if len(setCookie) != 1 {
		t.Fatalf("setup response cookies=%v", setCookie)
	}
	form := url.Values{"csrf_token": {string(csrfMatch[1])}, "setup_token": {"one-time-setup-token-123456"}, "username": {"owner"}, "password": {"setup-owner-password-12345"}, "mode": {"private"}}
	setupPost := httptest.NewRecorder()
	postReq := httptest.NewRequest(http.MethodPost, s.absolute("/setup"), strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.AddCookie(setCookie[0])
	secured.ServeHTTP(setupPost, postReq)
	if setupPost.Code != http.StatusSeeOther {
		t.Fatalf("setup POST status=%d body=%s", setupPost.Code, setupPost.Body.String())
	}
	after := httptest.NewRecorder()
	secured.ServeHTTP(after, httptest.NewRequest(http.MethodGet, s.absolute("/setup"), nil))
	if after.Code != http.StatusNotFound {
		t.Fatalf("setup remained available after initialization: status=%d", after.Code)
	}
	configuredLanding := httptest.NewRecorder()
	secured.ServeHTTP(configuredLanding, httptest.NewRequest(http.MethodGet, s.absolute("/"), nil))
	if configuredLanding.Code != http.StatusOK || !strings.Contains(configuredLanding.Body.String(), "Add a workstation") || strings.Contains(configuredLanding.Body.String(), "Finish first-run setup") {
		t.Fatalf("configured landing did not switch to onboarding state: status=%d body=%s", configuredLanding.Code, configuredLanding.Body.String())
	}
	if _, err := os.Stat(setupFile); !os.IsNotExist(err) {
		t.Fatalf("setup token file was not removed: %v", err)
	}
}

func TestPendingSetupClosesPublicRegistration(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18909", Mode: ModePublic, SetupToken: "pending-setup-token-123456", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	registrationEnabled := s.registrationEnabled
	users := len(s.users)
	s.mu.Unlock()
	if registrationEnabled || users != 0 {
		t.Fatalf("public registration was available before setup: enabled=%v users=%d", registrationEnabled, users)
	}
}

func TestImmutableDeviceResourceRouteIsAccepted(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18906", Password: "device-id-test-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	id := identity.ID()
	kind, route, canonical, ok := s.resourceParts(s.absolute("/agent/id/" + id))
	if !ok || kind != "agent" || route != "id/"+id || canonical != s.absolute("/agent/id/"+id) {
		t.Fatalf("unexpected immutable resource parts: %q %q %q %v", kind, route, canonical, ok)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.clients["device-id-client"] = Client{ID: "device-id-client", DeviceID: id, DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true}
	if err := s.authorizeResourceLocked(ownerID, "device-id-client", canonical); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	record := s.deviceRecords[route]
	s.mu.Unlock()
	if record.ID != id || record.OwnerID != ownerID {
		t.Fatalf("unexpected device record: %+v", record)
	}
}

func TestAgentAuthorizationUsesSafeClientNameAsInitialDisplayLabel(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19035", Password: "display-hint-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	id := identity.ID()
	route := "id/" + id
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	const redirect = "http://127.0.0.1:43201/callback"
	s.clients["agent-hint-client"] = Client{ID: "agent-hint-client", Name: "chat-with-cli agent 工作站 · 上海", RedirectURIs: []string{redirect}, DeviceID: id, DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true, Approved: false, IssuedAt: time.Now().Unix()}
	s.pending["agent-hint-request"] = pendingAuth{ClientID: "agent-hint-client", RedirectURI: redirect, Resource: s.absolute("/agent/id/" + id), Scope: "agent:connect offline_access", Expires: time.Now().Add(time.Minute)}
	s.mu.Unlock()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/authorize"), nil)
	if err := s.grantAuthorization(rr, req, "agent-hint-request", ownerID); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	record := s.deviceRecords[route]
	s.mu.Unlock()
	if record.DisplayName != "工作站 · 上海" {
		t.Fatalf("display name=%q", record.DisplayName)
	}
	// A non-Agent client name is not trusted as a device label hint.
	if got := agentDisplayNameHint(Client{Name: "arbitrary OAuth client"}); got != "" {
		t.Fatalf("unexpected arbitrary display hint %q", got)
	}
}

func TestImmutableDeviceIDCanonicalizationPreventsAliases(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19032", Password: "device-case-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	const upper = "ABCDEF0123456789ABCDEF0123456789"
	const lower = "abcdef0123456789abcdef0123456789"
	kind, route, canonical, ok := s.resourceParts(s.absolute("/agent/id/" + upper))
	if !ok || kind != "agent" || route != "id/"+lower || canonical != s.absolute("/agent/id/"+lower) {
		t.Fatalf("uppercase immutable resource was not canonicalized: kind=%q route=%q canonical=%q ok=%v", kind, route, canonical, ok)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.devices["id/"+lower] = ownerID
	s.clients["case-client"] = Client{ID: "case-client", Approved: true}
	access, _, _, err := s.issueTokensLocked("case-client", ownerID, s.absolute("/mcp/id/"+lower), "mcp offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	reached := false
	h := s.ProtectScopedResource("mcp", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, s.absolute("/mcp/id/"+upper), nil)
	req.Header.Set("Authorization", "Bearer "+access)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent || !reached {
		t.Fatalf("uppercase alias did not resolve to the canonical authorized device: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestPersistedImmutableDeviceAliasesFailClosed(t *testing.T) {
	stateDir := t.TempDir()
	state := `{"devices":{"id/ABCDEF0123456789ABCDEF0123456789":"alice","id/abcdef0123456789abcdef0123456789":"bob"}}`
	if err := os.WriteFile(filepath.Join(stateDir, "oauth-state.json"), []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{PublicURL: "http://127.0.0.1:19033", StateDir: stateDir, Mode: ModePublic}); err == nil || !strings.Contains(err.Error(), "alias the same immutable identity") {
		t.Fatalf("persisted route alias collision did not fail closed: %v", err)
	}
}

func TestAgentConnectionRevalidationFollowsRevocation(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18911", Password: "agent-revalidation-test-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.clients["agent-client"] = Client{ID: "agent-client", Approved: true}
	s.devices["agent-device"] = ownerID
	access, _, _, err := s.issueTokensLocked("agent-client", ownerID, s.absolute("/agent/agent-device"), "agent:connect offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !s.VerifyAgentConnection(tokenKey(access), "agent-device") {
		t.Fatal("active Agent connection was rejected")
	}
	s.mu.Lock()
	s.agentEnabled = false
	s.mu.Unlock()
	if s.VerifyAgentConnection(tokenKey(access), "agent-device") {
		t.Fatal("disabled Agent connection remained authorized")
	}
	s.mu.Lock()
	s.agentEnabled = true
	delete(s.access, tokenKey(access))
	s.mu.Unlock()
	if s.VerifyAgentConnection(tokenKey(access), "agent-device") {
		t.Fatal("revoked Agent access remained authorized")
	}
}

func TestDeviceDisplayNameIsUnicodeLabelNotRouteIdentity(t *testing.T) {
	if !validateDeviceDisplayName("工作站 · 上海") {
		t.Fatal("safe Unicode device display name was rejected")
	}
	if validateDeviceDisplayName("bad\nname") || validateDeviceDisplayName("") {
		t.Fatal("unsafe or empty device display name was accepted")
	}
	if validateDeviceRoute("工作站") {
		t.Fatal("Unicode display name was incorrectly accepted as a security route")
	}
}

func TestKillSwitchEmergencyEngageIsImmediateButReleaseIsGuarded(t *testing.T) {
	if requiresFreshAdminAuth("set-kill-switch", "on") {
		t.Fatal("engaging the global kill switch must not require recent re-authentication")
	}
	if isConfirmRequired("set-kill-switch", "on") {
		t.Fatal("engaging the global kill switch must not require typed confirmation")
	}
	if !requiresFreshAdminAuth("set-kill-switch", "off") {
		t.Fatal("releasing the global kill switch must require recent re-authentication")
	}
	if !isConfirmRequired("set-kill-switch", "off") || !validConfirmation("set-kill-switch", "off", "RELEASE") {
		t.Fatal("releasing the global kill switch must require RELEASE confirmation")
	}
}

func TestDisableActionsAreIdempotentAndFailSafe(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19031", Password: "disable-idempotent-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	owner := s.users[ownerID]
	victim, err := s.createUserLocked("victim-user", "victim-user-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	const route = "id/abababababababababababababababab"
	s.devices[route] = victim.ID
	s.ensureDeviceRecordLocked(route, victim.ID)
	s.mu.Unlock()
	req := httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil)

	for i := 0; i < 2; i++ {
		if err := s.applyAdminAction("disable-device", route, "on", owner, req); err != nil {
			t.Fatal(err)
		}
		if err := s.applyAdminAction("disable-user", victim.ID, "on", owner, req); err != nil {
			t.Fatal(err)
		}
	}
	s.mu.Lock()
	deviceDisabled := s.disabledDevices[route] && s.deviceRecords[route].Disabled
	userDisabled := s.users[victim.ID].Disabled
	s.mu.Unlock()
	if !deviceDisabled || !userDisabled {
		t.Fatalf("repeated disable request toggled authority back on: device=%v user=%v", deviceDisabled, userDisabled)
	}
	if requiresFreshAdminAuth("disable-device", "on") || requiresFreshAdminAuth("disable-user", "on") {
		t.Fatal("authority-reducing disable should not require recent re-authentication")
	}
	if !requiresFreshAdminAuth("disable-device", "off") || !requiresFreshAdminAuth("disable-user", "off") {
		t.Fatal("authority-expanding re-enable must require recent re-authentication")
	}
	if isConfirmRequired("disable-device", "on") || isConfirmRequired("disable-user", "on") {
		t.Fatal("emergency disable should not depend on typed confirmation")
	}
}

func TestAdminReauthenticationRotatesAndRefreshesOnlyCurrentSession(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19030", Password: "admin-reauth-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.mcpEnabled = false
	s.mu.Unlock()
	session, err := s.createSession(s.users[ownerID])
	if err != nil {
		t.Fatal(err)
	}
	handle := tokenKey(session)
	s.mu.Lock()
	record := s.sessions[handle]
	record.LastReauthAt = time.Now().Add(-time.Hour).Unix()
	s.sessions[handle] = record
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()

	mux := http.NewServeMux()
	s.RegisterRoutes(mux)
	adminGet := httptest.NewRequest(http.MethodGet, s.absolute("/admin"), nil)
	adminGet.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	adminRR := httptest.NewRecorder()
	mux.ServeHTTP(adminRR, adminGet)
	csrf := csrfTokenPattern.FindSubmatch(adminRR.Body.Bytes())
	var csrfCookie *http.Cookie
	for _, cookie := range adminRR.Result().Cookies() {
		if cookie.Name == adminCSRFCookie {
			csrfCookie = cookie
		}
	}
	if len(csrf) != 2 || csrfCookie == nil {
		t.Fatalf("admin page missing CSRF state: status=%d body=%s", adminRR.Code, adminRR.Body.String())
	}
	form := url.Values{"csrf_token": {string(csrf[1])}, "action": {"set-mcp"}, "value": {"on"}}
	actionReq := httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), strings.NewReader(form.Encode()))
	actionReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	actionReq.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	actionReq.AddCookie(csrfCookie)
	actionRR := httptest.NewRecorder()
	mux.ServeHTTP(actionRR, actionReq)
	if actionRR.Code != http.StatusSeeOther || actionRR.Header().Get("Location") != "/admin/reauth" {
		t.Fatalf("stale high-risk action did not redirect to reauth: status=%d location=%q body=%s", actionRR.Code, actionRR.Header().Get("Location"), actionRR.Body.String())
	}
	s.mu.Lock()
	if s.mcpEnabled {
		s.mu.Unlock()
		t.Fatal("stale session expanded MCP authority before re-authentication")
	}
	s.mu.Unlock()

	reauthGet := httptest.NewRequest(http.MethodGet, s.absolute("/admin/reauth"), nil)
	reauthGet.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	reauthGetRR := httptest.NewRecorder()
	mux.ServeHTTP(reauthGetRR, reauthGet)
	reauthCSRF := csrfTokenPattern.FindSubmatch(reauthGetRR.Body.Bytes())
	var reauthCSRFCookie *http.Cookie
	for _, cookie := range reauthGetRR.Result().Cookies() {
		if cookie.Name == adminCSRFCookie {
			reauthCSRFCookie = cookie
		}
	}
	if reauthGetRR.Code != http.StatusOK || len(reauthCSRF) != 2 || reauthCSRFCookie == nil || !strings.Contains(reauthGetRR.Body.String(), "Confirm it’s you") {
		t.Fatalf("reauth page invalid: status=%d body=%s", reauthGetRR.Code, reauthGetRR.Body.String())
	}
	reauthForm := url.Values{"csrf_token": {string(reauthCSRF[1])}, "password": {"admin-reauth-password-12345"}}
	reauthPost := httptest.NewRequest(http.MethodPost, s.absolute("/admin/reauth"), strings.NewReader(reauthForm.Encode()))
	reauthPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reauthPost.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	reauthPost.AddCookie(reauthCSRFCookie)
	reauthRR := httptest.NewRecorder()
	mux.ServeHTTP(reauthRR, reauthPost)
	if reauthRR.Code != http.StatusSeeOther || reauthRR.Header().Get("Location") != "/admin" {
		t.Fatalf("reauth failed: status=%d location=%q body=%s", reauthRR.Code, reauthRR.Header().Get("Location"), reauthRR.Body.String())
	}
	rotatedSession := ""
	for _, cookie := range reauthRR.Result().Cookies() {
		if cookie.Name == sessionCookie && cookie.Value != "" {
			rotatedSession = cookie.Value
		}
	}
	if rotatedSession == "" || rotatedSession == session {
		t.Fatalf("successful re-authentication did not rotate the administrator session: old=%q new=%q", shortHandle(tokenKey(session)), shortHandle(tokenKey(rotatedSession)))
	}
	stolenReq := httptest.NewRequest(http.MethodGet, s.absolute("/admin"), nil)
	stolenReq.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	if adminSessionFresh(s, stolenReq) {
		t.Fatal("pre-reauth session clone inherited fresh administrator authority")
	}
	if _, ok := s.sessionUser(stolenReq); ok {
		t.Fatal("pre-reauth session remained authenticated after session rotation")
	}
	freshReq := httptest.NewRequest(http.MethodGet, s.absolute("/admin"), nil)
	freshReq.AddCookie(&http.Cookie{Name: sessionCookie, Value: rotatedSession})
	if !adminSessionFresh(s, freshReq) {
		t.Fatal("rotated administrator session was not marked freshly authenticated")
	}
}

func TestAdminReauthRotationRollsBackOnPersistenceFailure(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19031", Password: "reauth-rollback-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ownerID := s.usernames["owner"]
	session, err := s.createSession(s.users[ownerID])
	if err != nil {
		t.Fatal(err)
	}
	handle := tokenKey(session)
	s.mu.Lock()
	record := s.sessions[handle]
	record.LastReauthAt = time.Now().Add(-time.Hour).Unix()
	s.sessions[handle] = record
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()

	forceOAuthPersistenceFailure(t, s)
	csrf := "reauth-rollback-csrf"
	form := url.Values{"csrf_token": {csrf}, "password": {"reauth-rollback-password-12345"}}
	req := httptest.NewRequest(http.MethodPost, s.absolute("/admin/reauth"), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	req.AddCookie(&http.Cookie{Name: adminCSRFCookie, Value: csrf})
	rr := httptest.NewRecorder()
	s.handleAdminReauthPOST(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("reauth persistence failure status=%d want 503 body=%s", rr.Code, rr.Body.String())
	}
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == sessionCookie && cookie.Value != "" && cookie.Value != session {
			t.Fatal("failed re-authentication emitted a rotated administrator session")
		}
	}
	s.mu.Lock()
	rolledBack, oldExists := s.sessions[handle]
	sessionCount := len(s.sessions)
	s.mu.Unlock()
	if !oldExists || sessionCount != 1 || rolledBack.LastReauthAt != record.LastReauthAt {
		t.Fatalf("failed re-authentication did not roll back session atomically: old=%v sessions=%d last_reauth=%d want=%d", oldExists, sessionCount, rolledBack.LastReauthAt, record.LastReauthAt)
	}
}

func TestAdminCanRevokeDeviceAndDisableMCP(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18907", Password: "admin-test-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.devices["admin-device"] = ownerID
	if _, _, _, err := s.issueTokensLocked("client", ownerID, s.absolute("/mcp/admin-device"), "mcp offline_access"); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)
	session, err := s.createSession(s.users[ownerID])
	if err != nil {
		t.Fatal(err)
	}
	get := httptest.NewRequest(http.MethodGet, s.absolute("/admin"), nil)
	get.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	getResponse := httptest.NewRecorder()
	mux.ServeHTTP(getResponse, get)
	if getResponse.Code != http.StatusOK || !strings.Contains(getResponse.Body.String(), "admin-device") {
		t.Fatalf("admin dashboard status=%d body=%s", getResponse.Code, getResponse.Body.String())
	}
	csrf := csrfTokenPattern.FindSubmatch(getResponse.Body.Bytes())
	if len(csrf) != 2 {
		t.Fatal("admin dashboard did not contain CSRF token")
	}
	var csrfCookie *http.Cookie
	for _, cookie := range getResponse.Result().Cookies() {
		if cookie.Name == adminCSRFCookie {
			csrfCookie = cookie
		}
	}
	if csrfCookie == nil {
		t.Fatal("admin dashboard did not set CSRF cookie")
	}
	form := url.Values{"csrf_token": {string(csrf[1])}, "action": {"revoke-device"}, "target": {"admin-device"}, "confirm": {"REVOKE"}}
	post := httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	post.AddCookie(csrfCookie)
	postResponse := httptest.NewRecorder()
	mux.ServeHTTP(postResponse, post)
	if postResponse.Code != http.StatusSeeOther {
		t.Fatalf("revoke device status=%d body=%s", postResponse.Code, postResponse.Body.String())
	}
	if _, ok := s.DeviceOwner("admin-device"); ok {
		t.Fatal("revoked device remained owned")
	}
	if s.VerifyAccess("not-a-token", s.absolute("/mcp/admin-device")) {
		t.Fatal("invalid token unexpectedly verified")
	}
	s.mu.Lock()
	s.mcpEnabled = false
	s.mu.Unlock()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, s.absolute("/mcp/admin-device"), nil)
	s.ProtectResource(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("disabled MCP reached handler") })).ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled MCP status=%d", rr.Code)
	}
}

func TestAdminCanRevokeIndividualTokensAndSessions(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18908", Password: "admin-token-test-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	owner := s.users[ownerID]
	s.clients["client"] = Client{ID: "client", Approved: true}
	s.devices["admin-device"] = ownerID
	access, refresh, _, err := s.issueTokensLocked("client", ownerID, s.absolute("/mcp/admin-device"), "mcp offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	firstSession, err := s.createSession(s.users[ownerID])
	if err != nil {
		t.Fatal(err)
	}
	secondSession, err := s.createSession(s.users[ownerID])
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil)
	if err := s.applyAdminAction("revoke-token", tokenKey(refresh), "", owner, request); err != nil {
		t.Fatal(err)
	}
	if s.VerifyAccess(access, s.absolute("/mcp/admin-device")) {
		t.Fatal("revoking a refresh token left its access-token family usable")
	}
	s.mu.Lock()
	_, refreshPresent := s.refresh[tokenKey(refresh)]
	s.mu.Unlock()
	if refreshPresent {
		t.Fatal("revoked refresh token remained present")
	}

	s.mu.Lock()
	access2, refresh2, _, err := s.issueTokensLocked("client", ownerID, s.absolute("/mcp/admin-device"), "mcp offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.applyAdminAction("revoke-token", tokenKey(access2), "", owner, request); err != nil {
		t.Fatal(err)
	}
	if s.VerifyAccess(access2, s.absolute("/mcp/admin-device")) {
		t.Fatal("revoked access token remained usable")
	}
	s.mu.Lock()
	_, refresh2Present := s.refresh[tokenKey(refresh2)]
	s.mu.Unlock()
	if refresh2Present {
		t.Fatal("revoking an access token left its refresh-token family usable")
	}

	if err := s.applyAdminAction("logout-session", tokenKey(secondSession), "", owner, request); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	_, firstPresent := s.sessions[tokenKey(firstSession)]
	_, secondPresent := s.sessions[tokenKey(secondSession)]
	s.mu.Unlock()
	if !firstPresent || secondPresent {
		t.Fatalf("unexpected session state after individual logout: first=%v second=%v", firstPresent, secondPresent)
	}
}

func TestDeviceRevocationRemovesImmutableRouteTokenFamilies(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18910", Password: "device-revoke-test-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	const device = "id/0123456789abcdef0123456789abcdef"
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.clients["device-client"] = Client{ID: "device-client", Approved: true}
	s.devices[device] = ownerID
	access, refresh, _, err := s.issueTokensLocked("device-client", ownerID, s.absolute("/mcp/"+device), "mcp offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	owner := s.users[ownerID]
	if err := s.applyAdminAction("revoke-device", device, "", owner, httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil)); err != nil {
		t.Fatal(err)
	}
	if s.VerifyAccess(access, s.absolute("/mcp/"+device)) {
		t.Fatal("immutable-route access token remained usable after device revocation")
	}
	s.mu.Lock()
	_, accessPresent := s.access[tokenKey(access)]
	_, refreshPresent := s.refresh[tokenKey(refresh)]
	s.mu.Unlock()
	if accessPresent || refreshPresent {
		t.Fatalf("immutable-route tokens remained after device revocation: access=%v refresh=%v", accessPresent, refreshPresent)
	}
}

func TestClientRevocationRemovesAuthorizationArtifacts(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18911", Password: "client-revoke-test-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ownerID := s.usernames["owner"]
	s.mu.Lock()
	s.clients["client-to-revoke"] = Client{ID: "client-to-revoke", Approved: true}
	s.pending["pending"] = pendingAuth{ClientID: "client-to-revoke", Expires: time.Now().Add(time.Minute)}
	s.codes[tokenKey("code-to-revoke")] = authCode{pendingAuth: pendingAuth{ClientID: "client-to-revoke", UserID: ownerID}, Expires: time.Now().Add(time.Minute)}
	s.mu.Unlock()
	if err := s.applyAdminAction("revoke-client", "client-to-revoke", "", s.users[ownerID], httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil)); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	_, pendingPresent := s.pending["pending"]
	_, codePresent := s.codes[tokenKey("code-to-revoke")]
	s.mu.Unlock()
	if pendingPresent || codePresent {
		t.Fatalf("client authorization artifacts remained: pending=%v code=%v", pendingPresent, codePresent)
	}
}

func TestPasswordRotationRevokesOAuthCredentials(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18912", Password: "rotation-test-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	owner := s.users[ownerID]
	s.clients["rotation-client"] = Client{ID: "rotation-client", Approved: true}
	s.devices["rotation-device"] = ownerID
	access, refresh, _, err := s.issueTokensLocked("rotation-client", ownerID, s.absolute("/agent/rotation-device"), "agent:connect offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !s.VerifyAgentConnection(tokenKey(access), "rotation-device") {
		t.Fatal("precondition: Agent credential is not active")
	}
	request := httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil)
	if err := s.applyAdminAction("rotate-password", ownerID, "new-rotation-password-67890", owner, request); err != nil {
		t.Fatal(err)
	}
	if s.VerifyAgentConnection(tokenKey(access), "rotation-device") {
		t.Fatal("password rotation left Agent access token usable")
	}
	s.mu.Lock()
	_, refreshPresent := s.refresh[tokenKey(refresh)]
	s.mu.Unlock()
	if refreshPresent {
		t.Fatal("password rotation left refresh token usable")
	}
}

func TestAdminFreshAuthPolicyFavorsEmergencyDisable(t *testing.T) {
	for _, action := range []string{"set-registration", "set-dcr", "set-mcp", "set-agent"} {
		if !requiresFreshAdminAuth(action, "on") {
			t.Fatalf("%s enable should require recent authentication", action)
		}
		if requiresFreshAdminAuth(action, "off") {
			t.Fatalf("%s disable should remain available without recent re-authentication", action)
		}
	}
	if requiresFreshAdminAuth("set-kill-switch", "on") {
		t.Fatal("engaging emergency kill switch should not require recent re-authentication")
	}
	if !requiresFreshAdminAuth("set-kill-switch", "off") {
		t.Fatal("releasing emergency kill switch should require recent re-authentication")
	}
	if !requiresFreshAdminAuth("set-mode", ModePrivate) || !requiresFreshAdminAuth("set-mode", ModePublic) {
		t.Fatal("changing instance mode should require recent authentication")
	}
}

func TestAdminCanSwitchMutableInstanceModeAndKeepsRegistrationClosed(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18922", Password: "mode-switch-admin-password-12345", StateDir: t.TempDir(), Mode: ModePrivate})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.mu.Lock()
	owner := s.users[s.usernames["owner"]]
	s.mu.Unlock()
	request := httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil)
	if err := s.applyAdminAction("set-mode", "", ModePublic, owner, request); err != nil {
		t.Fatalf("switching to public mode failed: %v", err)
	}
	s.mu.Lock()
	if s.cfg.Mode != ModePublic || s.registrationEnabled {
		s.mu.Unlock()
		t.Fatalf("public mode did not start with closed registration: mode=%q registration=%v", s.cfg.Mode, s.registrationEnabled)
	}
	s.mu.Unlock()
	if err := s.applyAdminAction("set-registration", "", "on", owner, request); err != nil {
		t.Fatalf("opening registration in public mode failed: %v", err)
	}
	if err := s.applyAdminAction("set-mode", "", ModePrivate, owner, request); err != nil {
		t.Fatalf("switching back to private mode failed: %v", err)
	}
	s.mu.Lock()
	mode, registration := s.cfg.Mode, s.registrationEnabled
	s.mu.Unlock()
	if mode != ModePrivate || registration {
		t.Fatalf("private mode did not close registration: mode=%q registration=%v", mode, registration)
	}
}

func TestConfiguredInstanceModeCannotBeChangedFromAdmin(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18923", Password: "fixed-mode-admin-password-12345", StateDir: t.TempDir(), Mode: ModePrivate, ModeConfigured: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.mu.Lock()
	owner := s.users[s.usernames["owner"]]
	s.mu.Unlock()
	if err := s.applyAdminAction("set-mode", "", ModePublic, owner, httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil)); !errors.Is(err, errInvalidAdminAction) {
		t.Fatalf("configured mode change returned %v, want invalid administrator action", err)
	}
}

func forceOAuthPersistenceFailure(t *testing.T, s *Server) {
	t.Helper()
	s.stateFile = filepath.Join(t.TempDir(), "missing-parent", "oauth-state.json")
}

func TestAdminMutationRollsBackWhenPersistenceFails(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18921", Password: "rollback-admin-password-12345", StateDir: t.TempDir(), Mode: ModePublic})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	owner := s.users[ownerID]
	s.mu.Unlock()
	forceOAuthPersistenceFailure(t, s)
	req := httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil)

	if err := s.applyAdminAction("set-mcp", "", "off", owner, req); err == nil {
		t.Fatal("expected persistence failure while disabling MCP")
	}
	s.mu.Lock()
	if !s.mcpEnabled {
		s.mu.Unlock()
		t.Fatal("failed admin transaction changed in-memory MCP state")
	}
	s.mcpEnabled = false
	s.mu.Unlock()
	if err := s.applyAdminAction("set-mcp", "", "on", owner, req); err == nil {
		t.Fatal("expected persistence failure while enabling MCP")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mcpEnabled {
		t.Fatal("failed privilege-expanding transaction remained enabled in memory")
	}
}

func TestPasswordRotationRollsBackCredentialsWhenPersistenceFails(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18922", Password: "rollback-password-original-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	owner := s.users[ownerID]
	s.clients["rollback-client"] = Client{ID: "rollback-client", Approved: true}
	s.devices["rollback-device"] = ownerID
	access, refresh, _, err := s.issueTokensLocked("rollback-client", ownerID, s.absolute("/agent/rollback-device"), "agent:connect offline_access")
	oldHash := s.users[ownerID].PasswordHash
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	forceOAuthPersistenceFailure(t, s)
	request := httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil)
	if err := s.applyAdminAction("rotate-password", ownerID, "rollback-password-new-67890", owner, request); err == nil {
		t.Fatal("expected password rotation persistence failure")
	}
	s.mu.Lock()
	gotHash := s.users[ownerID].PasswordHash
	_, refreshPresent := s.refresh[tokenKey(refresh)]
	s.mu.Unlock()
	if gotHash != oldHash {
		t.Fatal("failed password rotation changed in-memory password hash")
	}
	if !refreshPresent {
		t.Fatal("failed password rotation did not roll back the persisted credential maps")
	}
	if s.VerifyAgentConnection(tokenKey(access), "rollback-device") {
		t.Fatal("persistence failure did not fail closed; Agent credential remained usable")
	}
}

func TestAuthorizationGrantRollsBackDeviceClaimWhenPersistenceFails(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18923", Password: "rollback-grant-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	route := "id/" + identity.ID()
	const redirect = "http://127.0.0.1:43199/callback"
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.clients["grant-client"] = Client{
		ID: "grant-client", RedirectURIs: []string{redirect}, Approved: false, IssuedAt: time.Now().Unix(),
		DeviceID: identity.ID(), DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true,
	}
	s.pending["grant-request"] = pendingAuth{
		ClientID: "grant-client", RedirectURI: redirect,
		Resource: s.absolute("/agent/" + route), Scope: "agent:connect offline_access", Expires: time.Now().Add(time.Minute),
	}
	s.mu.Unlock()
	forceOAuthPersistenceFailure(t, s)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/authorize"), nil)
	if err := s.grantAuthorization(rr, req, "grant-request", ownerID); err == nil {
		t.Fatal("expected authorization persistence failure")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, claimed := s.devices[route]; claimed {
		t.Fatal("failed authorization left device claimed in memory")
	}
	if _, pending := s.pending["grant-request"]; !pending {
		t.Fatal("failed authorization consumed pending request")
	}
	if s.clients["grant-client"].Approved {
		t.Fatal("failed authorization approved OAuth client")
	}
	if len(s.codes) != 0 {
		t.Fatal("failed authorization left an authorization code in memory")
	}
}

func TestDCRRegistrationRollsBackEvictionWhenPersistenceFails(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18924", Password: "rollback-dcr-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	const (
		clientName = "chat-with-cli agent rollback-registration"
		redirect   = "http://127.0.0.1:43224/callback"
	)
	publicKey := deviceidentity.EncodePublicKey(identity.PublicKey())
	challenge, err := s.issueRegistrationChallenge(identity.ID(), publicKey, clientName, redirect, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.SignRegistrationProof(clientName, redirect, challenge)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	s.mu.Lock()
	s.clients["oldest-unapproved-client"] = Client{ID: "oldest-unapproved-client", IssuedAt: now.Add(-time.Minute).Unix()}
	s.pending["oldest-client-pending"] = pendingAuth{
		ClientID: "oldest-unapproved-client", RedirectURI: redirect,
		Resource: s.absolute("/agent/id/" + identity.ID()), Scope: "agent:connect offline_access",
		Expires: now.Add(time.Minute),
	}
	for i := 0; len(s.clients) < maxClients; i++ {
		id := fmt.Sprintf("dcr-capacity-approved-%d", i)
		s.clients[id] = Client{ID: id, Approved: true, IssuedAt: now.Unix()}
	}
	s.mu.Unlock()

	body, err := json.Marshal(map[string]any{
		"redirect_uris": []string{redirect}, "token_endpoint_auth_method": "none",
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
		"client_name": clientName, "scope": "agent:connect offline_access",
		"chat_with_cli_device_id": identity.ID(), "chat_with_cli_device_public_key": publicKey,
		"chat_with_cli_device_challenge": challenge, "chat_with_cli_device_proof": proof,
	})
	if err != nil {
		t.Fatal(err)
	}
	forceOAuthPersistenceFailure(t, s)
	req := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/register"), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.handleRegister(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("DCR persistence failure status=%d want 500 body=%s", rr.Code, rr.Body.String())
	}

	s.mu.Lock()
	_, oldClientPresent := s.clients["oldest-unapproved-client"]
	_, pendingPresent := s.pending["oldest-client-pending"]
	clientCount := len(s.clients)
	newDeviceClient := false
	for _, client := range s.clients {
		if client.DeviceID == identity.ID() {
			newDeviceClient = true
			break
		}
	}
	persistenceFault := s.persistenceFault
	s.mu.Unlock()
	if !oldClientPresent || !pendingPresent || clientCount != maxClients || newDeviceClient {
		t.Fatalf("failed DCR transaction did not roll back client eviction/registration: old=%v pending=%v clients=%d new_device_client=%v", oldClientPresent, pendingPresent, clientCount, newDeviceClient)
	}
	if !persistenceFault {
		t.Fatal("failed DCR persistence did not latch the fail-closed state")
	}
}

func TestResourceOwnershipRejectsConflictingDeviceRecord(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:18925", Password: "record-conflict-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	const route = "record-conflict-device"
	resource := s.absolute("/mcp/" + route)
	s.devices[route] = ownerID
	s.deviceRecords[route] = DeviceRecord{ID: "record-conflict-record", OwnerID: "another-user"}
	owned := s.resourceOwnedByUserLocked(ownerID, resource, "mcp")
	unknownScope := s.resourceOwnedByUserLocked(ownerID, resource, "unexpected-scope")
	s.mu.Unlock()
	if owned {
		t.Fatal("resource ownership ignored a conflicting immutable device record")
	}
	if unknownScope {
		t.Fatal("resource ownership accepted an unknown required scope")
	}
}

func TestCrossUserTokensCannotCrossDeviceOrScope(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19020", StateDir: t.TempDir(), Mode: ModePublic, AllowLegacyUnboundAgents: true})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	alice, err := s.createUserLocked("alice-authz", "alice-authz-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	bob, err := s.createUserLocked("bob-authz", "bob-authz-password-123456")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	const aliceID = "11111111111111111111111111111111"
	const bobID = "22222222222222222222222222222222"
	aliceRoutes := []string{"id/" + aliceID, "alice-authz-device"}
	bobRoutes := []string{"id/" + bobID, "bob-authz-device"}
	for _, route := range aliceRoutes {
		s.devices[route] = alice.ID
		s.ensureDeviceRecordLocked(route, alice.ID)
	}
	for _, route := range bobRoutes {
		s.devices[route] = bob.ID
		s.ensureDeviceRecordLocked(route, bob.ID)
	}
	s.clients["alice-client"] = Client{ID: "alice-client", Approved: true}
	s.clients["bob-client"] = Client{ID: "bob-client", Approved: true}
	aliceMCP, _, _, err := s.issueTokensLocked("alice-client", alice.ID, s.absolute("/mcp/id/"+aliceID), "mcp offline_access")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	aliceAgent, _, _, err := s.issueTokensLocked("alice-client", alice.ID, s.absolute("/agent/id/"+aliceID), "agent:connect offline_access")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	bobMCP, _, _, err := s.issueTokensLocked("bob-client", bob.ID, s.absolute("/mcp/id/"+bobID), "mcp offline_access")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()

	allow := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mcp := s.ProtectScopedResource("mcp", allow)
	agent := s.ProtectScopedResource("agent:connect", allow)
	check := func(name string, h http.Handler, path, token string, want int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, s.absolute(path), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != want {
			t.Fatalf("%s status=%d want=%d body=%s", name, rr.Code, want, rr.Body.String())
		}
	}
	check("alice own mcp", mcp, "/mcp/id/"+aliceID, aliceMCP, http.StatusNoContent)
	check("alice token -> bob mcp", mcp, "/mcp/id/"+bobID, aliceMCP, http.StatusUnauthorized)
	check("bob token -> alice mcp", mcp, "/mcp/id/"+aliceID, bobMCP, http.StatusUnauthorized)
	check("mcp scope -> agent", agent, "/agent/id/"+aliceID, aliceMCP, http.StatusUnauthorized)
	check("alice own agent", agent, "/agent/id/"+aliceID, aliceAgent, http.StatusNoContent)
	check("alice agent -> bob agent", agent, "/agent/id/"+bobID, aliceAgent, http.StatusUnauthorized)

	// Ownership is checked at request time, not only when the token is issued.
	s.mu.Lock()
	s.devices["id/"+aliceID] = bob.ID
	s.mu.Unlock()
	check("old alice token after ownership change", mcp, "/mcp/id/"+aliceID, aliceMCP, http.StatusUnauthorized)
	check("old alice agent after ownership change", agent, "/agent/id/"+aliceID, aliceAgent, http.StatusUnauthorized)
}

func TestMCPRouteConfusionCannotChangeAuthorizedDevice(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19029", StateDir: t.TempDir(), Mode: ModePublic})
	if err != nil {
		t.Fatal(err)
	}
	const aliceID = "1234567890abcdef1234567890abcdef"
	const bobID = "fedcba0987654321fedcba0987654321"
	s.mu.Lock()
	alice, err := s.createUserLocked("alice-route", "alice-route-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	bob, err := s.createUserLocked("bob-route", "bob-route-password-123456")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.devices["id/"+aliceID] = alice.ID
	s.devices["id/"+bobID] = bob.ID
	s.clients["alice-route-client"] = Client{ID: "alice-route-client", Approved: true}
	token, _, _, err := s.issueTokensLocked("alice-route-client", alice.ID, s.absolute("/mcp/id/"+aliceID), "mcp offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	var reached bool
	mux := http.NewServeMux()
	mux.Handle("/mcp/id/{id}", s.ProtectScopedResource("mcp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		if got := r.PathValue("id"); got != aliceID {
			t.Fatalf("authorized middleware dispatched a different device id %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	})))

	request := func(path string) int {
		t.Helper()
		reached = false
		req := httptest.NewRequest(http.MethodPost, s.absolute(path), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr.Code
	}
	if got := request("/mcp/id/" + aliceID); got != http.StatusNoContent || !reached {
		t.Fatalf("own canonical route status=%d reached=%v", got, reached)
	}
	attacks := []string{
		"/mcp/id/" + bobID,
		"/mcp/id/" + aliceID + "%2Fextra",
		"/mcp/id/%2e%2e%2F" + aliceID,
		"/mcp/id/%252e%252e",
		"/mcp/id/" + aliceID + "/..",
	}
	for _, path := range attacks {
		status := request(path)
		if reached || (status >= 200 && status < 300) {
			t.Fatalf("confused route %q reached protected device handler with status=%d", path, status)
		}
	}
}

func TestSharedOAuthClientStillIsolatesUsersAndDevices(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19034", StateDir: t.TempDir(), Mode: ModePublic})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	alice, err := s.createUserLocked("alice-shared-client", "alice-shared-client-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	bob, err := s.createUserLocked("bob-shared-client", "bob-shared-client-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	const aliceOne = "10101010101010101010101010101010"
	const aliceTwo = "20202020202020202020202020202020"
	const bobOne = "30303030303030303030303030303030"
	for _, pair := range []struct{ route, owner string }{
		{"id/" + aliceOne, alice.ID}, {"id/" + aliceTwo, alice.ID}, {"id/" + bobOne, bob.ID},
	} {
		s.devices[pair.route] = pair.owner
		s.ensureDeviceRecordLocked(pair.route, pair.owner)
	}
	// One DCR client may legitimately be reused by a client application across
	// accounts. Approval must never make that client a cross-user principal.
	s.clients["shared-client"] = Client{ID: "shared-client", Approved: true}
	aliceToken, _, _, err := s.issueTokensLocked("shared-client", alice.ID, s.absolute("/mcp/id/"+aliceOne), "mcp offline_access")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	bobToken, _, _, err := s.issueTokensLocked("shared-client", bob.ID, s.absolute("/mcp/id/"+bobOne), "mcp offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !s.VerifyAccess(aliceToken, s.absolute("/mcp/id/"+aliceOne)) || !s.VerifyAccess(bobToken, s.absolute("/mcp/id/"+bobOne)) {
		t.Fatal("precondition: same-client tokens are not valid on their own resources")
	}
	if s.VerifyAccess(aliceToken, s.absolute("/mcp/id/"+aliceTwo)) {
		t.Fatal("alice token crossed from one of her devices to another")
	}
	if s.VerifyAccess(aliceToken, s.absolute("/mcp/id/"+bobOne)) || s.VerifyAccess(bobToken, s.absolute("/mcp/id/"+aliceOne)) {
		t.Fatal("shared OAuth client allowed a cross-user device access")
	}
}

func TestCrossUserAgentCannotReplaceVictimConnection(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19021", StateDir: t.TempDir(), Mode: ModePublic, AllowLegacyUnboundAgents: true})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	alice, err := s.createUserLocked("alice-ws", "alice-websocket-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	bob, err := s.createUserLocked("bob-ws", "bob-websocket-password-123456")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	const aliceID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const bobID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	aliceRoute, bobRoute := "id/"+aliceID, "id/"+bobID
	s.devices[aliceRoute] = alice.ID
	s.devices[bobRoute] = bob.ID
	s.ensureDeviceRecordLocked(aliceRoute, alice.ID)
	s.ensureDeviceRecordLocked(bobRoute, bob.ID)
	s.clients["alice-ws-client"] = Client{ID: "alice-ws-client", Approved: true}
	s.clients["bob-ws-client"] = Client{ID: "bob-ws-client", Approved: true}
	aliceToken, _, _, err := s.issueTokensLocked("alice-ws-client", alice.ID, s.absolute("/agent/id/"+aliceID), "agent:connect offline_access")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	bobToken, _, _, err := s.issueTokensLocked("bob-ws-client", bob.ID, s.absolute("/agent/id/"+bobID), "agent:connect offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	broker := relay.NewBroker()
	broker.SetAgentConnectionAuthorizer(func(device, credentialHash string) bool {
		return s.VerifyAgentConnection(credentialHash, device)
	})
	mux := http.NewServeMux()
	mux.Handle("/agent/id/{id}", s.ProtectScopedResource("agent:connect", broker.AgentHandler()))
	server := httptest.NewServer(mux)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dial := func(id, token string) (*websocket.Conn, *http.Response, error) {
		endpoint := "ws" + strings.TrimPrefix(server.URL, "http") + "/agent/id/" + id
		return websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}}})
	}
	aliceConn, resp, err := dial(aliceID, aliceToken)
	if err != nil {
		t.Fatalf("alice own Agent connection failed: response=%v err=%v", resp, err)
	}
	defer aliceConn.CloseNow()
	deadline := time.Now().Add(time.Second)
	for len(broker.Devices()) != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := broker.Devices(); len(got) != 1 || got[0] != aliceRoute {
		t.Fatalf("unexpected online devices after alice connect: %v", got)
	}

	attackerConn, attackerResp, attackerErr := dial(aliceID, bobToken)
	if attackerConn != nil {
		attackerConn.CloseNow()
		t.Fatal("bob unexpectedly established a WebSocket to alice device")
	}
	if attackerErr == nil || attackerResp == nil || attackerResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bob -> alice Agent handshake response=%v err=%v", attackerResp, attackerErr)
	}
	if got := broker.Devices(); len(got) != 1 || got[0] != aliceRoute {
		t.Fatalf("victim connection was replaced/disturbed: %v", got)
	}

	// Alice's exact-resource token must not authenticate to Bob's route either.
	wrongConn, wrongResp, wrongErr := dial(bobID, aliceToken)
	if wrongConn != nil {
		wrongConn.CloseNow()
		t.Fatal("alice unexpectedly established a WebSocket to bob device")
	}
	if wrongErr == nil || wrongResp == nil || wrongResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("alice -> bob Agent handshake response=%v err=%v", wrongResp, wrongErr)
	}
}

func TestPublicFirstClaimRequiresImmutableDeviceID(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19022", StateDir: t.TempDir(), Mode: ModePublic})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	alice, err := s.createUserLocked("alice-claim", "alice-claim-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	if err := s.authorizeResourceLocked(alice.ID, "", s.absolute("/agent/predictable-hostname")); err == nil {
		s.mu.Unlock()
		t.Fatal("public user claimed a new predictable legacy device name")
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	id := identity.ID()
	s.clients["claim-client"] = Client{ID: "claim-client", DeviceID: id, DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true}
	if err := s.authorizeResourceLocked(alice.ID, "claim-client", s.absolute("/agent/id/"+id)); err != nil {
		s.mu.Unlock()
		t.Fatalf("immutable device ID claim failed: %v", err)
	}
	// Existing legacy routes remain usable for migration/compatibility.
	s.devices["old-alpha-device"] = alice.ID
	if err := s.authorizeResourceLocked(alice.ID, "", s.absolute("/agent/old-alpha-device")); err != nil {
		s.mu.Unlock()
		t.Fatalf("existing legacy route stopped working: %v", err)
	}
	s.mu.Unlock()
}

func TestInFlightMCPRequestIsCanceledWhenCallerTokenIsRevoked(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19023", StateDir: t.TempDir(), Mode: ModePublic})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	alice, err := s.createUserLocked("alice-inflight", "alice-inflight-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	const id = "dddddddddddddddddddddddddddddddd"
	route := "id/" + id
	s.devices[route] = alice.ID
	s.ensureDeviceRecordLocked(route, alice.ID)
	s.clients["alice-inflight-client"] = Client{ID: "alice-inflight-client", Approved: true}
	access, _, _, err := s.issueTokensLocked("alice-inflight-client", alice.ID, s.absolute("/mcp/id/"+id), "mcp offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	canceled := make(chan struct{})
	handler := s.ProtectScopedResource("mcp", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(canceled)
	}))
	req := httptest.NewRequest(http.MethodPost, s.absolute("/mcp/id/"+id), nil)
	req.Header.Set("Authorization", "Bearer "+access)
	done := make(chan struct{})
	go func() { handler.ServeHTTP(httptest.NewRecorder(), req); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("authorized request never entered handler")
	}
	s.mu.Lock()
	delete(s.access, tokenKey(access))
	s.mu.Unlock()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("in-flight MCP request context was not canceled after token revoke")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not exit after authorization cancellation")
	}
}

func TestOAuthPersistenceFailureFreezesExistingCrossUserAccess(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19024", Password: "persistence-freeze-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.clients["freeze-client"] = Client{ID: "freeze-client", Approved: true}
	s.devices["freeze-device"] = ownerID
	access, _, _, err := s.issueTokensLocked("freeze-client", ownerID, s.absolute("/mcp/freeze-device"), "mcp offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !s.VerifyAccess(access, s.absolute("/mcp/freeze-device")) {
		t.Fatal("precondition: access token is not valid")
	}
	forceOAuthPersistenceFailure(t, s)
	s.mu.Lock()
	s.mcpEnabled = false
	err = s.saveLocked()
	s.mu.Unlock()
	if err == nil {
		t.Fatal("expected persistence failure")
	}
	if s.VerifyAccess(access, s.absolute("/mcp/freeze-device")) {
		t.Fatal("existing access remained usable after authorization persistence failure")
	}
	if s.Ready() {
		t.Fatal("Relay readiness remained healthy after authorization persistence failure")
	}
}

func TestDisabledDeviceOldAgentTokenCannotReconnectOrRevive(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19025", StateDir: t.TempDir(), Mode: ModePublic, AllowLegacyUnboundAgents: true})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	admin, err := s.createUserLocked("security-admin", "security-admin-password-12345", true)
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	alice, err := s.createUserLocked("alice-revoke", "alice-revoke-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	const id = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	route := "id/" + id
	s.devices[route] = alice.ID
	s.ensureDeviceRecordLocked(route, alice.ID)
	s.clients["alice-revoke-client"] = Client{ID: "alice-revoke-client", Approved: true}
	access, _, _, err := s.issueTokensLocked("alice-revoke-client", alice.ID, s.absolute("/agent/id/"+id), "agent:connect offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	broker := relay.NewBroker()
	broker.SetAgentConnectionAuthorizer(func(device, credentialHash string) bool { return s.VerifyAgentConnection(credentialHash, device) })
	mux := http.NewServeMux()
	mux.Handle("/agent/id/{id}", s.ProtectScopedResource("agent:connect", broker.AgentHandler()))
	server := httptest.NewServer(mux)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dial := func() (*websocket.Conn, *http.Response, error) {
		endpoint := "ws" + strings.TrimPrefix(server.URL, "http") + "/agent/id/" + id
		return websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + access}}})
	}
	conn, resp, err := dial()
	if err != nil {
		t.Fatalf("precondition Agent connect failed: response=%v err=%v", resp, err)
	}
	defer conn.CloseNow()

	request := httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil)
	if err := s.applyAdminAction("disable-device", route, "on", admin, request); err != nil {
		t.Fatal(err)
	}
	if s.VerifyAgentConnection(tokenKey(access), route) {
		t.Fatal("disabled device retained valid Agent authorization")
	}
	newConn, disabledResp, disabledErr := dial()
	if newConn != nil {
		newConn.CloseNow()
		t.Fatal("old token reconnected while device disabled")
	}
	if disabledErr == nil || disabledResp == nil || disabledResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("disabled reconnect response=%v err=%v", disabledResp, disabledErr)
	}

	// Re-enabling the device must not resurrect token families revoked on disable.
	if err := s.applyAdminAction("disable-device", route, "off", admin, request); err != nil {
		t.Fatal(err)
	}
	if s.VerifyAgentConnection(tokenKey(access), route) {
		t.Fatal("re-enabling device resurrected the old Agent token")
	}
	oldConn, oldResp, oldErr := dial()
	if oldConn != nil {
		oldConn.CloseNow()
		t.Fatal("revoked token reconnected after device re-enable")
	}
	if oldErr == nil || oldResp == nil || oldResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("re-enabled old-token response=%v err=%v", oldResp, oldErr)
	}
}

func TestDisabledUserOldCredentialsDoNotRevive(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19026", StateDir: t.TempDir(), Mode: ModePublic})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	admin, err := s.createUserLocked("disable-admin", "disable-admin-password-12345", true)
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	alice, err := s.createUserLocked("alice-disabled", "alice-disabled-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	const id = "ffffffffffffffffffffffffffffffff"
	route := "id/" + id
	s.devices[route] = alice.ID
	s.ensureDeviceRecordLocked(route, alice.ID)
	s.clients["alice-disabled-client"] = Client{ID: "alice-disabled-client", Approved: true}
	agentAccess, _, _, err := s.issueTokensLocked("alice-disabled-client", alice.ID, s.absolute("/agent/id/"+id), "agent:connect offline_access")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	mcpAccess, _, _, err := s.issueTokensLocked("alice-disabled-client", alice.ID, s.absolute("/mcp/id/"+id), "mcp offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !s.VerifyAgentConnection(tokenKey(agentAccess), route) || !s.VerifyAccess(mcpAccess, s.absolute("/mcp/id/"+id)) {
		t.Fatal("precondition credentials invalid")
	}

	req := httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil)
	if err := s.applyAdminAction("disable-user", alice.ID, "on", admin, req); err != nil {
		t.Fatal(err)
	}
	if s.VerifyAgentConnection(tokenKey(agentAccess), route) || s.VerifyAccess(mcpAccess, s.absolute("/mcp/id/"+id)) {
		t.Fatal("disabled user retained usable credentials")
	}
	if err := s.applyAdminAction("disable-user", alice.ID, "off", admin, req); err != nil {
		t.Fatal(err)
	}
	if s.VerifyAgentConnection(tokenKey(agentAccess), route) || s.VerifyAccess(mcpAccess, s.absolute("/mcp/id/"+id)) {
		t.Fatal("re-enabling user resurrected revoked credentials")
	}
}

func TestRFCRevocationByAccessTokenRevokesRefreshFamily(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19027", Password: "rfc-revoke-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.clients["rfc-revoke-client"] = Client{ID: "rfc-revoke-client", Approved: true}
	s.devices["rfc-revoke-device"] = ownerID
	access, refresh, _, err := s.issueTokensLocked("rfc-revoke-client", ownerID, s.absolute("/mcp/rfc-revoke-device"), "mcp offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"token": {access}}
	req := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/revoke"), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s.handleRevoke(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", rr.Code, rr.Body.String())
	}
	if s.VerifyAccess(access, s.absolute("/mcp/rfc-revoke-device")) {
		t.Fatal("revoked access token remained usable")
	}
	s.mu.Lock()
	_, refreshPresent := s.refresh[tokenKey(refresh)]
	s.mu.Unlock()
	if refreshPresent {
		t.Fatal("access-token revocation left related refresh token usable")
	}
}

func TestMCPTokenRevocationResetsDeviceRemoteSession(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19028", Password: "session-reset-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	resets := make(chan string, 4)
	s.SetAgentSessionResetter(func(device string) { resets <- device })
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	owner := s.users[ownerID]
	const route = "id/abababababababababababababababab"
	s.devices[route] = ownerID
	s.ensureDeviceRecordLocked(route, ownerID)
	s.clients["session-reset-client"] = Client{ID: "session-reset-client", Approved: true}
	access, refresh, _, err := s.issueTokensLocked("session-reset-client", ownerID, s.absolute("/mcp/"+route), "mcp offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil)
	if err := s.applyAdminAction("revoke-token", tokenKey(access), "", owner, request); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-resets:
		if got != route {
			t.Fatalf("reset device=%q want=%q", got, route)
		}
	case <-time.After(time.Second):
		t.Fatal("MCP token revocation did not reset the device remote session")
	}
	if s.VerifyAccess(access, s.absolute("/mcp/"+route)) {
		t.Fatal("revoked MCP access token remained usable")
	}
	s.mu.Lock()
	_, refreshPresent := s.refresh[tokenKey(refresh)]
	s.mu.Unlock()
	if refreshPresent {
		t.Fatal("revoked MCP token family retained refresh token")
	}
}

func TestAuthorizationCodeCannotResurrectAfterOwnershipChange(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19029", StateDir: t.TempDir(), Mode: ModePublic})
	if err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("A", 43)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	const route = "id/12121212121212121212121212121212"
	const redirect = "http://127.0.0.1:43155/callback"
	const codeValue = "authorization-code-before-owner-change"
	s.mu.Lock()
	alice, err := s.createUserLocked("alice-code", "alice-code-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	bob, err := s.createUserLocked("bob-code", "bob-code-password-123456")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.clients["code-client"] = Client{ID: "code-client", Approved: true, RedirectURIs: []string{redirect}}
	s.devices[route] = alice.ID
	s.ensureDeviceRecordLocked(route, alice.ID)
	resource := s.absolute("/agent/" + route)
	s.codes[tokenKey(codeValue)] = authCode{pendingAuth: pendingAuth{ClientID: "code-client", UserID: alice.ID, RedirectURI: redirect, Resource: resource, Scope: "agent:connect offline_access", CodeChallenge: challenge}, Expires: time.Now().Add(time.Minute)}
	// Simulate a security-sensitive owner transition occurring after consent but before code exchange.
	s.devices[route] = bob.ID
	s.mu.Unlock()
	form := url.Values{"code": {codeValue}, "client_id": {"code-client"}, "redirect_uri": {redirect}, "code_verifier": {verifier}, "resource": {resource}}
	req := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/token"), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s.exchangeCode(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid_grant") {
		t.Fatalf("stale code exchange status=%d body=%s", rr.Code, rr.Body.String())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.access) != 0 || len(s.refresh) != 0 {
		t.Fatal("stale authorization code minted credentials after ownership change")
	}
}

func TestRefreshCannotRotateAfterOwnershipChange(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19030", StateDir: t.TempDir(), Mode: ModePublic})
	if err != nil {
		t.Fatal(err)
	}
	const route = "id/34343434343434343434343434343434"
	s.mu.Lock()
	alice, err := s.createUserLocked("alice-refresh-owner", "alice-refresh-owner-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	bob, err := s.createUserLocked("bob-refresh-owner", "bob-refresh-owner-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.clients["ownership-refresh-client"] = Client{ID: "ownership-refresh-client", Approved: true}
	s.devices[route] = alice.ID
	resource := s.absolute("/mcp/" + route)
	_, refresh, _, err := s.issueTokensLocked("ownership-refresh-client", alice.ID, resource, "mcp offline_access")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.devices[route] = bob.ID
	s.mu.Unlock()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {"ownership-refresh-client"}, "resource": {resource}}
	req := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/token"), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s.handleToken(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid_grant") {
		t.Fatalf("stale refresh status=%d body=%s", rr.Code, rr.Body.String())
	}
	s.mu.Lock()
	_, present := s.refresh[tokenKey(refresh)]
	s.mu.Unlock()
	if present {
		t.Fatal("refresh token survived ownership change rejection")
	}
}

func TestDeviceRevocationClearsPendingAuthorizationAndCodes(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19031", Password: "device-code-revoke-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	const route = "id/56565656565656565656565656565656"
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	owner := s.users[ownerID]
	s.devices[route] = ownerID
	resource := s.absolute("/mcp/" + route)
	s.pending["pending-device-revoke"] = pendingAuth{ClientID: "client", Resource: resource, Expires: time.Now().Add(time.Minute)}
	s.codes[tokenKey("code-device-revoke")] = authCode{pendingAuth: pendingAuth{ClientID: "client", UserID: ownerID, Resource: resource}, Expires: time.Now().Add(time.Minute)}
	s.mu.Unlock()
	if err := s.applyAdminAction("revoke-device", route, "", owner, httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil)); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) != 0 || len(s.codes) != 0 {
		t.Fatalf("device revoke left authorization artifacts: pending=%d codes=%d", len(s.pending), len(s.codes))
	}
}

func TestTokenExchangeRequiresExactResource(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19032", Password: "resource-required-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	const redirect = "http://127.0.0.1:43156/callback"
	verifier := strings.Repeat("B", 43)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.clients["resource-client"] = Client{ID: "resource-client", Approved: true, RedirectURIs: []string{redirect}}
	s.devices["resource-device"] = ownerID
	resource := s.absolute("/mcp/resource-device")
	s.codes[tokenKey("resource-code")] = authCode{pendingAuth: pendingAuth{ClientID: "resource-client", UserID: ownerID, RedirectURI: redirect, Resource: resource, Scope: "mcp offline_access", CodeChallenge: challenge}, Expires: time.Now().Add(time.Minute)}
	s.mu.Unlock()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {"resource-code"}, "client_id": {"resource-client"}, "redirect_uri": {redirect}, "code_verifier": {verifier}}
	req := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/token"), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s.handleToken(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid_target") {
		t.Fatalf("missing resource exchange status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestRefreshRequiresExactResource(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19033", Password: "refresh-resource-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.clients["refresh-resource-client"] = Client{ID: "refresh-resource-client", Approved: true}
	s.devices["refresh-resource-device"] = ownerID
	resource := s.absolute("/mcp/refresh-resource-device")
	_, refresh, _, err := s.issueTokensLocked("refresh-resource-client", ownerID, resource, "mcp offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	for _, badResource := range []string{"", s.absolute("/mcp/other-device")} {
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {"refresh-resource-client"}}
		if badResource != "" {
			form.Set("resource", badResource)
		}
		req := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/token"), strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		s.handleToken(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid_grant") {
			t.Fatalf("resource=%q status=%d body=%s", badResource, rr.Code, rr.Body.String())
		}
	}
}

func TestImmutableDeviceClaimRequiresMatchingEd25519Key(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19040", StateDir: t.TempDir(), Mode: ModePublic})
	if err != nil {
		t.Fatal(err)
	}
	good, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	resource := s.absolute("/agent/id/" + good.ID())
	s.mu.Lock()
	user, err := s.createUserLocked("device-key-user", "device-key-user-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.clients["no-key"] = Client{ID: "no-key"}
	if err := s.authorizeResourceLocked(user.ID, "no-key", resource); err == nil {
		s.mu.Unlock()
		t.Fatal("new immutable device was claimed without a device public key")
	}
	s.clients["wrong-key"] = Client{ID: "wrong-key", DeviceID: wrong.ID(), DevicePublicKey: deviceidentity.EncodePublicKey(wrong.PublicKey()), DeviceKeyVerified: true}
	if err := s.authorizeResourceLocked(user.ID, "wrong-key", resource); err == nil {
		s.mu.Unlock()
		t.Fatal("new immutable device was claimed with a mismatched device public key")
	}
	s.clients["good-key"] = Client{ID: "good-key", DeviceID: good.ID(), DevicePublicKey: deviceidentity.EncodePublicKey(good.PublicKey()), DeviceKeyVerified: true}
	if err := s.authorizeResourceLocked(user.ID, "good-key", resource); err != nil {
		s.mu.Unlock()
		t.Fatalf("matching device key claim failed: %v", err)
	}
	record := s.deviceRecords["id/"+good.ID()]
	if record.DevicePublicKey != deviceidentity.EncodePublicKey(good.PublicKey()) {
		s.mu.Unlock()
		t.Fatalf("device key was not bound: %+v", record)
	}
	// Even the same owner cannot silently replace the device cryptographic
	// identity with another key.
	if err := s.authorizeResourceLocked(user.ID, "wrong-key", resource); err == nil {
		s.mu.Unlock()
		t.Fatal("existing device identity was silently rebound")
	}
	s.mu.Unlock()
}

func TestBoundAgentRequiresRelayChallengeProofAndRejectsReplay(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19041", Password: "device-proof-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	resource := s.absolute("/agent/id/" + identity.ID())
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.clients["proof-client"] = Client{ID: "proof-client", DeviceID: identity.ID(), DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true, Approved: true}
	if err := s.authorizeResourceLocked(ownerID, "proof-client", resource); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	access, _, _, err := s.issueTokensLocked("proof-client", ownerID, resource, "agent:connect offline_access")
	access2, _, _, err2 := s.issueTokensLocked("proof-client", ownerID, resource, "agent:connect offline_access")
	s.mu.Unlock()
	if err != nil || err2 != nil {
		t.Fatalf("issue tokens: %v / %v", err, err2)
	}

	challengeHandler := s.AgentChallengeHandler()
	getChallenge := func(token string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, resource+"/challenge", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		challengeHandler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("challenge status=%d body=%s", rr.Code, rr.Body.String())
		}
		var payload struct {
			Challenge string `json:"challenge"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil || payload.Challenge == "" {
			t.Fatalf("invalid challenge response: %v body=%s", err, rr.Body.String())
		}
		return payload.Challenge
	}

	handler := s.ProtectScopedResource("agent:connect", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	request := func(id *deviceidentity.Identity, token, challenge string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, resource, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		if id != nil && challenge != "" {
			proof, err := id.SignProof(resource, token, challenge)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(deviceidentity.HeaderChallenge, challenge)
			req.Header.Set(deviceidentity.HeaderProof, proof)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}
	if got := request(nil, access, ""); got != http.StatusUnauthorized {
		t.Fatalf("bearer-only bound Agent status=%d want 401", got)
	}
	challenge := getChallenge(access)
	if got := request(wrong, access, challenge); got != http.StatusUnauthorized {
		t.Fatalf("wrong-key Agent proof status=%d want 401", got)
	}
	if got := request(identity, access, challenge); got != http.StatusNoContent {
		t.Fatalf("valid Agent proof after wrong-key attempt status=%d want 204", got)
	}
	if got := request(identity, access, challenge); got != http.StatusUnauthorized {
		t.Fatalf("replayed Agent challenge status=%d want 401", got)
	}
	expired, err := s.issueAgentChallenge(resource, tokenKey(access), time.Now().Add(-2*agentChallengeLifetime))
	if err != nil {
		t.Fatal(err)
	}
	if got := request(identity, access, expired); got != http.StatusUnauthorized {
		t.Fatalf("expired Agent challenge status=%d want 401", got)
	}
	boundToFirstToken := getChallenge(access)
	if got := request(identity, access2, boundToFirstToken); got != http.StatusUnauthorized {
		t.Fatalf("challenge was transferable to another access token: status=%d", got)
	}
	if got := request(identity, access2, getChallenge(access2)); got != http.StatusNoContent {
		t.Fatalf("fresh second-token challenge status=%d want 204", got)
	}
}

func TestAgentChallengeFromPreviousRelayProcessIsRejected(t *testing.T) {
	stateDir := t.TempDir()
	cfg := Config{PublicURL: "http://127.0.0.1:19046", Password: "restart-proof-password-12345", StateDir: stateDir}
	s1, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	resource := s1.absolute("/agent/id/" + identity.ID())
	s1.mu.Lock()
	ownerID := s1.usernames["owner"]
	s1.clients["restart-proof-client"] = Client{ID: "restart-proof-client", DeviceID: identity.ID(), DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true, Approved: true}
	if err := s1.authorizeResourceLocked(ownerID, "restart-proof-client", resource); err != nil {
		s1.mu.Unlock()
		t.Fatal(err)
	}
	access, _, _, err := s1.issueTokensLocked("restart-proof-client", ownerID, resource, "agent:connect offline_access")
	if err == nil {
		err = s1.saveLocked()
	}
	s1.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := s1.issueAgentChallenge(resource, tokenKey(access), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.SignProof(resource, access, challenge)
	if err != nil {
		t.Fatal(err)
	}

	s2, err := New(Config{PublicURL: cfg.PublicURL, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	handler := s2.ProtectScopedResource("agent:connect", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	req := httptest.NewRequest(http.MethodGet, resource, nil)
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set(deviceidentity.HeaderChallenge, challenge)
	req.Header.Set(deviceidentity.HeaderProof, proof)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("challenge from previous Relay process status=%d want 401", rr.Code)
	}
}

func TestAgentDCRProofRequiresRelayChallengePrivateKeyAndRejectsReplay(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19042", Password: "dcr-proof-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	const redirect = "http://127.0.0.1:43123/callback"
	const clientName = "chat-with-cli agent proof-workstation"
	publicKey := deviceidentity.EncodePublicKey(identity.PublicKey())
	challengeRequest := func(name, callback, deviceID, key string) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"client_name": name, "redirect_uri": callback,
			"chat_with_cli_device_id": deviceID, "chat_with_cli_device_public_key": key,
		})
		req := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/register/challenge"), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		s.handleRegistrationChallenge(rr, req)
		return rr
	}
	challengeRR := challengeRequest(clientName, redirect, identity.ID(), publicKey)
	if challengeRR.Code != http.StatusOK {
		t.Fatalf("registration challenge status=%d body=%s", challengeRR.Code, challengeRR.Body.String())
	}
	var challengeBody struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(challengeRR.Body.Bytes(), &challengeBody); err != nil || challengeBody.Challenge == "" {
		t.Fatalf("decode registration challenge: challenge=%q err=%v", challengeBody.Challenge, err)
	}
	proof, err := identity.SignRegistrationProof(clientName, redirect, challengeBody.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	validBody := map[string]any{
		"redirect_uris": []string{redirect}, "token_endpoint_auth_method": "none",
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
		"client_name": clientName, "scope": "agent:connect offline_access",
		"chat_with_cli_device_id": identity.ID(), "chat_with_cli_device_public_key": publicKey,
		"chat_with_cli_device_challenge": challengeBody.Challenge, "chat_with_cli_device_proof": proof,
	}
	register := func(body map[string]any) *httptest.ResponseRecorder {
		t.Helper()
		encoded, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/register"), bytes.NewReader(encoded))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		s.handleRegister(rr, req)
		return rr
	}

	wrongProofBody := maps.Clone(validBody)
	wrongProof, err := wrong.SignRegistrationProof(clientName, redirect, challengeBody.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	wrongProofBody["chat_with_cli_device_proof"] = wrongProof
	if rr := register(wrongProofBody); rr.Code != http.StatusBadRequest {
		t.Fatalf("wrong-private-key DCR status=%d want 400 body=%s", rr.Code, rr.Body.String())
	}
	if rr := register(validBody); rr.Code != http.StatusCreated {
		t.Fatalf("valid Agent DCR proof status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr := register(validBody); rr.Code != http.StatusBadRequest {
		t.Fatalf("replayed Agent DCR challenge status=%d want 400 body=%s", rr.Code, rr.Body.String())
	}

	publicOnly := maps.Clone(validBody)
	publicOnly["chat_with_cli_device_challenge"] = ""
	publicOnly["chat_with_cli_device_proof"] = ""
	if rr := register(publicOnly); rr.Code != http.StatusBadRequest {
		t.Fatalf("public-key-only DCR status=%d want 400 body=%s", rr.Code, rr.Body.String())
	}

	freshRR := challengeRequest(clientName, redirect, identity.ID(), publicKey)
	var fresh struct {
		Challenge string `json:"challenge"`
	}
	_ = json.Unmarshal(freshRR.Body.Bytes(), &fresh)
	freshProof, _ := identity.SignRegistrationProof(clientName, redirect, fresh.Challenge)
	tampered := maps.Clone(validBody)
	tampered["chat_with_cli_device_challenge"] = fresh.Challenge
	tampered["chat_with_cli_device_proof"] = freshProof
	tampered["client_name"] = clientName + " tampered"
	if rr := register(tampered); rr.Code != http.StatusBadRequest {
		t.Fatalf("challenge rebound to another client name status=%d want 400 body=%s", rr.Code, rr.Body.String())
	}
}

func TestRegistrationChallengeFromPreviousRelayProcessIsRejected(t *testing.T) {
	stateDir := t.TempDir()
	cfg := Config{PublicURL: "http://127.0.0.1:19046", Password: "dcr-restart-password-12345", StateDir: stateDir}
	s1, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := deviceidentity.Generate()
	const redirect = "http://127.0.0.1:44123/callback"
	const clientName = "chat-with-cli agent restart-proof"
	publicKey := deviceidentity.EncodePublicKey(identity.PublicKey())
	challenge, err := s1.issueRegistrationChallenge(identity.ID(), publicKey, clientName, redirect, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := identity.SignRegistrationProof(clientName, redirect, challenge)

	s2, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"redirect_uris": []string{redirect}, "token_endpoint_auth_method": "none",
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
		"client_name": clientName, "scope": "agent:connect offline_access",
		"chat_with_cli_device_id": identity.ID(), "chat_with_cli_device_public_key": publicKey,
		"chat_with_cli_device_challenge": challenge, "chat_with_cli_device_proof": proof,
	})
	req := httptest.NewRequest(http.MethodPost, s2.absolute("/oauth/register"), bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s2.handleRegister(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("challenge from previous Relay process status=%d want 400 body=%s", rr.Code, rr.Body.String())
	}
}

func TestPersistedProofStateRejectsMismatchedDeviceKeys(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19043", Password: "persisted-proof-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	state := diskState{
		Clients: map[string]Client{
			"verified-client": {
				ID: "verified-client", DeviceID: identity.ID(),
				DevicePublicKey: deviceidentity.EncodePublicKey(wrong.PublicKey()), DeviceKeyVerified: true,
			},
		},
	}
	if err := s.canonicalizeDiskState(&state); err == nil {
		t.Fatal("persisted OAuth client with mismatched device key was accepted")
	}

	state = diskState{
		DeviceRecords: map[string]DeviceRecord{
			"id/" + identity.ID(): {
				ID: identity.ID(), DevicePublicKey: deviceidentity.EncodePublicKey(wrong.PublicKey()),
			},
		},
	}
	if err := s.canonicalizeDiskState(&state); err == nil {
		t.Fatal("persisted device record with mismatched public key was accepted")
	}
}

func TestPersistedProofStateRoundTripsWhenConsistent(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19044", Password: "persisted-proof-ok-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	encoded := deviceidentity.EncodePublicKey(identity.PublicKey())
	state := diskState{
		Clients: map[string]Client{
			"verified-client": {
				ID: "verified-client", DeviceID: strings.ToUpper(identity.ID()), DevicePublicKey: encoded, DeviceKeyVerified: true,
			},
		},
		Users:   map[string]User{"owner-id": {ID: "owner-id", Username: "owner", PasswordHash: "test-only"}},
		Devices: map[string]string{"id/" + strings.ToUpper(identity.ID()): "owner-id"},
		DeviceRecords: map[string]DeviceRecord{
			"id/" + strings.ToUpper(identity.ID()): {ID: strings.ToUpper(identity.ID()), OwnerID: "owner-id", DevicePublicKey: encoded},
		},
	}
	if err := s.canonicalizeDiskState(&state); err != nil {
		t.Fatal(err)
	}
	client := state.Clients["verified-client"]
	if client.DeviceID != identity.ID() || client.DevicePublicKey != encoded || !client.DeviceKeyVerified {
		t.Fatalf("client proof state was not canonicalized: %+v", client)
	}
	record, ok := state.DeviceRecords["id/"+identity.ID()]
	if !ok || record.ID != identity.ID() || record.DevicePublicKey != encoded {
		t.Fatalf("device proof state was not canonicalized: %+v ok=%v", record, ok)
	}
}

func TestPersistedIdentityCrossReferencesFailClosed(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19046", Password: "state-integrity-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("user-map-id-mismatch", func(t *testing.T) {
		state := diskState{Users: map[string]User{"map-id": {ID: "different-id", Username: "alice"}}}
		if err := s.canonicalizeDiskState(&state); err == nil {
			t.Fatal("persisted user map key and immutable user ID mismatch was accepted")
		}
	})
	t.Run("duplicate-normalized-username", func(t *testing.T) {
		state := diskState{Users: map[string]User{
			"alice-1": {ID: "alice-1", Username: "Alice"},
			"alice-2": {ID: "alice-2", Username: "alice"},
		}}
		if err := s.canonicalizeDiskState(&state); err == nil {
			t.Fatal("duplicate normalized persisted usernames were accepted")
		}
	})
	t.Run("client-map-id-mismatch", func(t *testing.T) {
		state := diskState{Clients: map[string]Client{"map-id": {ID: "different-id"}}}
		if err := s.canonicalizeDiskState(&state); err == nil {
			t.Fatal("persisted OAuth client map key and immutable client ID mismatch was accepted")
		}
	})
	t.Run("device-unknown-owner", func(t *testing.T) {
		state := diskState{Devices: map[string]string{"device-a": "missing-user"}}
		if err := s.canonicalizeDiskState(&state); err == nil {
			t.Fatal("persisted device referencing a missing owner was accepted")
		}
	})
	t.Run("device-record-owner-conflict", func(t *testing.T) {
		state := diskState{
			Users: map[string]User{
				"alice-id": {ID: "alice-id", Username: "alice"},
				"bob-id":   {ID: "bob-id", Username: "bob"},
			},
			Devices:       map[string]string{"device-a": "alice-id"},
			DeviceRecords: map[string]DeviceRecord{"device-a": {OwnerID: "bob-id"}},
		}
		if err := s.canonicalizeDiskState(&state); err == nil {
			t.Fatal("conflicting persisted device ownership records were accepted")
		}
	})
}

func TestAuthorizationPageExplainsVerifiedDeviceIdentity(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19045", Password: "consent-proof-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	client := Client{
		ID: "consent-client", Name: "chat-with-cli agent workstation", DeviceID: identity.ID(),
		DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true,
	}
	rr := httptest.NewRecorder()
	s.renderAuthorization(rr, "request", client, s.absolute("/agent/id/"+identity.ID()), "agent:connect offline_access", User{}, false)
	body := rr.Body.String()
	if !strings.Contains(body, "Verified device identity") || !strings.Contains(body, identity.ID()) || strings.Contains(body, client.DevicePublicKey) {
		t.Fatalf("verified device consent page missing safe identity context or leaked public key: %s", body)
	}
}

func TestProofReplayCapacityIsIsolatedPerDevice(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19120", Password: "nonce-isolation-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	expires := now.Add(agentChallengeLifetime).Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	registrationExpires := now.Add(registrationChallengeLifetime).Unix()
	for i := 0; i < maxRegistrationChallengesConsumedDevice; i++ {
		if !s.consumeRegistrationChallengeLocked("alice", fmt.Sprintf("reg-%d", i), registrationExpires, now) {
			t.Fatalf("alice registration challenge bucket filled early at %d", i)
		}
	}
	if s.consumeRegistrationChallengeLocked("alice", "overflow", registrationExpires, now) {
		t.Fatal("alice registration challenge bucket exceeded per-device limit")
	}
	if !s.consumeRegistrationChallengeLocked("bob", "fresh", registrationExpires, now) {
		t.Fatal("alice registration challenge bucket blocked bob")
	}
	for i := 0; i < maxAgentChallengesConsumedDevice; i++ {
		if !s.consumeAgentChallengeLocked("alice", fmt.Sprintf("challenge-%d", i), expires, now) {
			t.Fatalf("alice Agent replay bucket filled early at %d", i)
		}
	}
	if s.consumeAgentChallengeLocked("alice", "overflow", expires, now) {
		t.Fatal("alice Agent replay bucket exceeded per-device limit")
	}
	if !s.consumeAgentChallengeLocked("bob", "fresh", expires, now) {
		t.Fatal("alice Agent replay bucket blocked bob")
	}
}

func TestRevokedCryptographicDeviceCannotBeReclaimedAndPersists(t *testing.T) {
	stateDir := t.TempDir()
	cfg := Config{PublicURL: "http://127.0.0.1:19130", Password: "retired-device-password-12345", StateDir: stateDir}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	route := "id/" + identity.ID()
	resource := s.absolute("/agent/" + route)
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.clients["retire-client"] = Client{ID: "retire-client", DeviceID: identity.ID(), DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true}
	if err := s.authorizeResourceLocked(ownerID, "retire-client", resource); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()
	owner := s.users[ownerID]
	if err := s.applyAdminAction("revoke-device", route, "", owner, httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil)); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	if !s.retiredDevices[route] {
		s.mu.Unlock()
		t.Fatal("revoked device was not permanently retired")
	}
	if _, exists := s.clients["retire-client"]; exists {
		s.mu.Unlock()
		t.Fatal("permanent device revocation left its cryptographically bound OAuth client registered")
	}
	attacker, err := s.createUserLocked("attacker", "attacker-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.clients["stolen-key-client"] = Client{ID: "stolen-key-client", DeviceID: identity.ID(), DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true}
	err = s.authorizeResourceLocked(attacker.ID, "stolen-key-client", resource)
	s.mu.Unlock()
	if err == nil {
		t.Fatal("holder of revoked device private key reclaimed the retired identity")
	}

	s2, err := New(Config{PublicURL: cfg.PublicURL, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	s2.mu.Lock()
	retired := s2.retiredDevices[route]
	err = s2.authorizeResourceLocked(s2.usernames["owner"], "retire-client", resource)
	s2.mu.Unlock()
	if !retired || err == nil {
		t.Fatalf("retired device did not survive restart: retired=%v authorizeErr=%v", retired, err)
	}
}

func TestDeletingUserRetiresOwnedCryptographicDevices(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19131", Password: "delete-user-retire-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	route := "id/" + identity.ID()
	resource := s.absolute("/agent/" + route)
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	victim, err := s.createUserLocked("victim", "victim-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.clients["victim-device-client"] = Client{ID: "victim-device-client", DeviceID: identity.ID(), DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true}
	if err := s.authorizeResourceLocked(victim.ID, "victim-device-client", resource); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()
	owner := s.users[ownerID]
	if err := s.applyAdminAction("delete-user", victim.ID, "", owner, httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil)); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	retired := s.retiredDevices[route]
	_, stillOwned := s.devices[route]
	_, oldClientPresent := s.clients["victim-device-client"]
	s.clients["reclaim-client"] = Client{ID: "reclaim-client", DeviceID: identity.ID(), DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true}
	err = s.authorizeResourceLocked(ownerID, "reclaim-client", resource)
	s.mu.Unlock()
	if !retired || stillOwned || oldClientPresent {
		t.Fatalf("deleted user's device retirement state wrong: retired=%v stillOwned=%v oldClientPresent=%v", retired, stillOwned, oldClientPresent)
	}
	if err == nil {
		t.Fatal("deleted user's retired device identity was reclaimable")
	}
}

func TestPersistedActiveAndRetiredDeviceConflictFailsClosed(t *testing.T) {
	stateDir := t.TempDir()
	state := diskState{
		Users:          map[string]User{"owner-id": {ID: "owner-id", Username: "owner", PasswordHash: "irrelevant", Admin: true}},
		Devices:        map[string]string{"id/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": "owner-id"},
		RetiredDevices: map[string]bool{"id/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": true},
		Clients:        map[string]Client{}, Access: map[string]tokenRecord{}, Refresh: map[string]tokenRecord{},
		RefreshUsed: map[string]tokenRecord{}, DisabledDevices: map[string]bool{}, DeviceRecords: map[string]DeviceRecord{}, Sessions: map[string]sessionRecord{},
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "oauth-state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = New(Config{PublicURL: "http://127.0.0.1:19132", StateDir: stateDir})
	if err == nil || !strings.Contains(err.Error(), "both active and permanently retired") {
		t.Fatalf("conflicting active/retired state did not fail closed: %v", err)
	}
}

func TestLegacyUnboundAgentDeniedByDefaultAndAllowedOnlyForMigration(t *testing.T) {
	test := func(t *testing.T, allowLegacy bool, want int) {
		t.Helper()
		s, err := New(Config{PublicURL: "http://127.0.0.1:19133", Password: "legacy-migration-password-12345", StateDir: t.TempDir(), AllowLegacyUnboundAgents: allowLegacy})
		if err != nil {
			t.Fatal(err)
		}
		const route = "legacy-alpha-agent"
		resource := s.absolute("/agent/" + route)
		s.mu.Lock()
		ownerID := s.usernames["owner"]
		s.devices[route] = ownerID
		s.deviceRecords[route] = DeviceRecord{DisplayName: route, OwnerID: ownerID, CreatedAt: time.Now().Unix()}
		s.clients["legacy-agent-client"] = Client{ID: "legacy-agent-client", Approved: true}
		access, _, _, err := s.issueTokensLocked("legacy-agent-client", ownerID, resource, "agent:connect offline_access")
		s.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		h := s.ProtectScopedResource("agent:connect", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
		req := httptest.NewRequest(http.MethodGet, resource, nil)
		req.Header.Set("Authorization", "Bearer "+access)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != want {
			t.Fatalf("legacy Agent status=%d want=%d body=%s", rr.Code, want, rr.Body.String())
		}
	}
	t.Run("default-deny", func(t *testing.T) {
		test(t, false, http.StatusUnauthorized)
	})
	t.Run("explicit-migration-mode", func(t *testing.T) {
		test(t, true, http.StatusNoContent)
	})
}

func TestRegistrationChallengeBindsMetadataAndExpires(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19140", Password: "registration-challenge-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := deviceidentity.Generate()
	other, _ := deviceidentity.Generate()
	const clientName = "chat-with-cli agent challenge-bound"
	const redirect = "http://127.0.0.1:45123/callback"
	key := deviceidentity.EncodePublicKey(identity.PublicKey())
	now := time.Now().UTC()
	challenge, err := s.issueRegistrationChallenge(identity.ID(), key, clientName, redirect, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.validateRegistrationChallenge(identity.ID(), key, clientName, redirect, challenge, now); !ok {
		t.Fatal("valid registration challenge was rejected")
	}
	if _, _, ok := s.validateRegistrationChallenge(identity.ID(), key, clientName+"-other", redirect, challenge, now); ok {
		t.Fatal("registration challenge was accepted for another client name")
	}
	if _, _, ok := s.validateRegistrationChallenge(identity.ID(), key, clientName, "http://127.0.0.1:45124/callback", challenge, now); ok {
		t.Fatal("registration challenge was accepted for another redirect")
	}
	otherKey := deviceidentity.EncodePublicKey(other.PublicKey())
	if _, _, ok := s.validateRegistrationChallenge(identity.ID(), otherKey, clientName, redirect, challenge, now); ok {
		t.Fatal("registration challenge was accepted after changing only the public key")
	}
	if _, _, ok := s.validateRegistrationChallenge(other.ID(), otherKey, clientName, redirect, challenge, now); ok {
		t.Fatal("registration challenge was accepted for another device identity")
	}
	if _, _, ok := s.validateRegistrationChallenge(identity.ID(), key, clientName, redirect, challenge, now.Add(registrationChallengeLifetime+time.Second)); ok {
		t.Fatal("expired registration challenge was accepted")
	}
}

func TestRegistrationChallengeEndpointRejectsRetiredIdentity(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19141", Password: "retired-challenge-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := deviceidentity.Generate()
	s.mu.Lock()
	s.retiredDevices["id/"+identity.ID()] = true
	s.mu.Unlock()
	body, _ := json.Marshal(map[string]any{
		"client_name": "chat-with-cli agent retired", "redirect_uri": "http://127.0.0.1:45125/callback",
		"chat_with_cli_device_id": identity.ID(), "chat_with_cli_device_public_key": deviceidentity.EncodePublicKey(identity.PublicKey()),
	})
	req := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/register/challenge"), bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleRegistrationChallenge(rr, req)
	if rr.Code != http.StatusGone {
		t.Fatalf("retired identity challenge status=%d want 410 body=%s", rr.Code, rr.Body.String())
	}
}

func TestAgentDCRRequiresLoopbackRedirectButGenericMCPAllowsHTTPS(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19145", Password: "agent-loopback-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	const clientName = "chat-with-cli agent redirect-bound"
	const externalRedirect = "https://attacker.example/callback"
	publicKey := deviceidentity.EncodePublicKey(identity.PublicKey())

	challengeBody, _ := json.Marshal(map[string]any{
		"client_name": clientName, "redirect_uri": externalRedirect,
		"chat_with_cli_device_id": identity.ID(), "chat_with_cli_device_public_key": publicKey,
	})
	challengeReq := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/register/challenge"), bytes.NewReader(challengeBody))
	challengeReq.Header.Set("Content-Type", "application/json")
	challengeRR := httptest.NewRecorder()
	s.handleRegistrationChallenge(challengeRR, challengeReq)
	if challengeRR.Code != http.StatusBadRequest {
		t.Fatalf("Agent DCR challenge accepted external HTTPS redirect: status=%d body=%s", challengeRR.Code, challengeRR.Body.String())
	}

	// Defense in depth: even a challenge produced internally for an external
	// redirect must not let a device-bound Agent client bypass the DCR endpoint
	// redirect policy.
	challenge, err := s.issueRegistrationChallenge(identity.ID(), publicKey, clientName, externalRedirect, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.SignRegistrationProof(clientName, externalRedirect, challenge)
	if err != nil {
		t.Fatal(err)
	}
	agentBody, _ := json.Marshal(map[string]any{
		"redirect_uris": []string{externalRedirect}, "token_endpoint_auth_method": "none",
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
		"client_name": clientName, "scope": "agent:connect offline_access",
		"chat_with_cli_device_id": identity.ID(), "chat_with_cli_device_public_key": publicKey,
		"chat_with_cli_device_challenge": challenge, "chat_with_cli_device_proof": proof,
	})
	agentReq := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/register"), bytes.NewReader(agentBody))
	agentReq.Header.Set("Content-Type", "application/json")
	agentRR := httptest.NewRecorder()
	s.handleRegister(agentRR, agentReq)
	if agentRR.Code != http.StatusBadRequest || !strings.Contains(agentRR.Body.String(), "invalid_redirect_uri") {
		t.Fatalf("device-bound Agent DCR accepted external HTTPS redirect: status=%d body=%s", agentRR.Code, agentRR.Body.String())
	}

	genericBody, _ := json.Marshal(map[string]any{
		"redirect_uris":              []string{"https://chatgpt.example/oauth/callback"},
		"token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"}, "client_name": "generic MCP client", "scope": "mcp offline_access",
	})
	genericReq := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/register"), bytes.NewReader(genericBody))
	genericReq.Header.Set("Content-Type", "application/json")
	genericRR := httptest.NewRecorder()
	s.handleRegister(genericRR, genericReq)
	if genericRR.Code != http.StatusCreated {
		t.Fatalf("generic MCP DCR lost HTTPS callback support: status=%d body=%s", genericRR.Code, genericRR.Body.String())
	}
}

func TestDeviceBoundOAuthClientCannotRequestMCPOrAnotherAgent(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19142", Password: "client-bound-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := deviceidentity.Generate()
	other, _ := deviceidentity.Generate()
	const redirect = "http://127.0.0.1:45126/callback"
	s.mu.Lock()
	s.clients["device-bound-client"] = Client{
		ID: "device-bound-client", Name: "chat-with-cli agent bound", RedirectURIs: []string{redirect}, IssuedAt: time.Now().Unix(),
		DeviceID: identity.ID(), DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true,
	}
	s.mu.Unlock()
	authorize := func(resource, scope string) *httptest.ResponseRecorder {
		t.Helper()
		codeChallenge := strings.Repeat("a", 43)
		authorizationChallenge, err := s.issueAuthorizationChallenge("device-bound-client", redirect, resource, scope, "state", codeChallenge, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		proof, err := identity.SignAuthorizationProof("device-bound-client", redirect, resource, scope, "state", codeChallenge, authorizationChallenge)
		if err != nil {
			t.Fatal(err)
		}
		q := url.Values{
			"response_type": {"code"}, "client_id": {"device-bound-client"}, "redirect_uri": {redirect},
			"code_challenge": {codeChallenge}, "code_challenge_method": {"S256"},
			"resource": {resource}, "scope": {scope}, "state": {"state"},
			"chat_with_cli_authorization_challenge": {authorizationChallenge},
			"chat_with_cli_device_proof":            {proof},
		}
		req := httptest.NewRequest(http.MethodGet, s.absolute("/oauth/authorize")+"?"+q.Encode(), nil)
		rr := httptest.NewRecorder()
		s.handleAuthorizeGET(rr, req)
		return rr
	}
	exactAgent := s.absolute("/agent/id/" + identity.ID())
	if rr := authorize(exactAgent, "agent:connect offline_access"); rr.Code != http.StatusOK {
		t.Fatalf("device-bound client exact Agent authorization status=%d want 200 body=%s", rr.Code, rr.Body.String())
	}
	if rr := authorize(s.absolute("/mcp/id/"+identity.ID()), "mcp offline_access"); rr.Code != http.StatusForbidden {
		t.Fatalf("device-bound client obtained MCP authorization page: status=%d want 403 body=%s", rr.Code, rr.Body.String())
	}
	if rr := authorize(s.absolute("/agent/id/"+other.ID()), "agent:connect offline_access"); rr.Code != http.StatusForbidden {
		t.Fatalf("device-bound client targeted another Agent: status=%d want 403 body=%s", rr.Code, rr.Body.String())
	}
	if rr := authorize(s.absolute("/agent/legacy-device-name"), "agent:connect offline_access"); rr.Code != http.StatusForbidden {
		t.Fatalf("device-bound client fell back to a legacy Agent name route: status=%d want 403 body=%s", rr.Code, rr.Body.String())
	}
}

func TestAuthorizationChallengeIsBoundAndSingleUse(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19143", Password: "authorization-challenge-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	const (
		clientID    = "authorization-challenge-client"
		redirectURI = "http://127.0.0.1:45143/callback"
		state       = "authorization-state"
	)
	resource := s.absolute("/agent/id/" + identity.ID())
	codeChallenge := strings.Repeat("b", 43)
	s.mu.Lock()
	s.clients[clientID] = Client{ID: clientID, RedirectURIs: []string{redirectURI}, IssuedAt: time.Now().Unix(), DeviceID: identity.ID(), DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true}
	s.mu.Unlock()

	body, err := json.Marshal(authorizationChallengeRequest{ClientID: clientID, RedirectURI: redirectURI, Resource: resource, Scope: "agent:connect offline_access", State: state, CodeChallenge: codeChallenge})
	if err != nil {
		t.Fatal(err)
	}
	challengeReq := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/authorize/challenge"), bytes.NewReader(body))
	challengeReq.Header.Set("Content-Type", "application/json")
	challengeRR := httptest.NewRecorder()
	s.handleAuthorizationChallenge(challengeRR, challengeReq)
	if challengeRR.Code != http.StatusOK {
		t.Fatalf("authorization challenge status=%d body=%s", challengeRR.Code, challengeRR.Body.String())
	}
	var challengeResponse struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(challengeRR.Body.Bytes(), &challengeResponse); err != nil || challengeResponse.Challenge == "" {
		t.Fatalf("authorization challenge response=%q err=%v", challengeResponse.Challenge, err)
	}
	proof, err := identity.SignAuthorizationProof(clientID, redirectURI, resource, "agent:connect offline_access", state, codeChallenge, challengeResponse.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
		"code_challenge": {codeChallenge}, "code_challenge_method": {"S256"}, "resource": {resource},
		"scope": {"agent:connect offline_access"}, "state": {state},
		"chat_with_cli_authorization_challenge": {challengeResponse.Challenge}, "chat_with_cli_device_proof": {proof},
	}
	get := func() *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		s.handleAuthorizeGET(rr, httptest.NewRequest(http.MethodGet, s.absolute("/oauth/authorize")+"?"+q.Encode(), nil))
		return rr
	}
	if rr := get(); rr.Code != http.StatusOK {
		t.Fatalf("valid authorization challenge status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr := get(); rr.Code != http.StatusForbidden {
		t.Fatalf("authorization challenge replay status=%d want 403 body=%s", rr.Code, rr.Body.String())
	}

	wrongState := maps.Clone(q)
	wrongState.Set("state", "other-state")
	if rr := func() *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		s.handleAuthorizeGET(rr, httptest.NewRequest(http.MethodGet, s.absolute("/oauth/authorize")+"?"+wrongState.Encode(), nil))
		return rr
	}(); rr.Code != http.StatusForbidden {
		t.Fatalf("authorization challenge accepted altered state: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestDeviceBoundAuthorizationRequiresCurrentPrivateKey(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19144", Password: "authorization-proof-password-12345", StateDir: t.TempDir(), Mode: ModePublic})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	const clientID = "authorization-proof-client"
	const redirect = "http://127.0.0.1:45144/callback"
	resource := s.absolute("/agent/id/" + identity.ID())
	codeChallenge := strings.Repeat("a", 43)
	authorizationChallenge, err := s.issueAuthorizationChallenge(clientID, redirect, resource, "agent:connect offline_access", "fresh-state", codeChallenge, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	s.mu.Lock()
	s.clients[clientID] = Client{
		ID: clientID, RedirectURIs: []string{redirect}, IssuedAt: time.Now().Unix(),
		DeviceID: identity.ID(), DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true,
	}
	s.mu.Unlock()

	authorize := func(proof string) *httptest.ResponseRecorder {
		t.Helper()
		q := url.Values{
			"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
			"code_challenge": {codeChallenge}, "code_challenge_method": {"S256"},
			"resource": {resource}, "scope": {"agent:connect offline_access"}, "state": {"fresh-state"},
			"chat_with_cli_authorization_challenge": {authorizationChallenge},
		}
		if proof != "" {
			q.Set("chat_with_cli_device_proof", proof)
		}
		rr := httptest.NewRecorder()
		s.handleAuthorizeGET(rr, httptest.NewRequest(http.MethodGet, s.absolute("/oauth/authorize")+"?"+q.Encode(), nil))
		return rr
	}
	if rr := authorize(""); rr.Code != http.StatusForbidden {
		t.Fatalf("authorization without device private-key proof status=%d want 403 body=%s", rr.Code, rr.Body.String())
	}
	wrongProof, err := wrong.SignAuthorizationProof(clientID, redirect, resource, "agent:connect offline_access", "fresh-state", codeChallenge, authorizationChallenge)
	if err != nil {
		t.Fatal(err)
	}
	if rr := authorize(wrongProof); rr.Code != http.StatusForbidden {
		t.Fatalf("authorization with wrong device private-key proof status=%d want 403 body=%s", rr.Code, rr.Body.String())
	}
	validProof, err := identity.SignAuthorizationProof(clientID, redirect, resource, "agent:connect offline_access", "fresh-state", codeChallenge, authorizationChallenge)
	if err != nil {
		t.Fatal(err)
	}
	if rr := authorize(validProof); rr.Code != http.StatusOK {
		t.Fatalf("authorization with current device private-key proof status=%d want 200 body=%s", rr.Code, rr.Body.String())
	}

	s.mu.Lock()
	owner := s.devices["id/"+identity.ID()]
	pending := len(s.pending)
	s.mu.Unlock()
	if owner != "" || pending != 1 {
		t.Fatalf("authorization page changed device ownership or created unexpected requests: owner=%q pending=%d", owner, pending)
	}
}

func TestGenericOAuthClientCannotGainAgentScopeWithoutLegacyMigration(t *testing.T) {
	const redirect = "http://127.0.0.1:45127/callback"
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	resourcePath := "/agent/id/" + identity.ID()

	test := func(t *testing.T, allowLegacy bool, want int) {
		t.Helper()
		s, err := New(Config{
			PublicURL:                "http://127.0.0.1:19143",
			Password:                 "generic-client-password-12345",
			StateDir:                 t.TempDir(),
			AllowLegacyUnboundAgents: allowLegacy,
		})
		if err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		s.clients["generic-mcp-client"] = Client{ID: "generic-mcp-client", Name: "generic MCP client", RedirectURIs: []string{redirect}, IssuedAt: time.Now().Unix()}
		// Model an already-owned legacy/unbound device. Without the explicit
		// migration flag, a generic DCR client must still be unable to request
		// agent:connect merely by choosing an Agent resource and scope.
		s.devices["id/"+identity.ID()] = s.usernames["owner"]
		s.deviceRecords["id/"+identity.ID()] = DeviceRecord{ID: identity.ID(), OwnerID: s.usernames["owner"], CreatedAt: time.Now().Unix()}
		s.mu.Unlock()

		q := url.Values{
			"response_type": {"code"}, "client_id": {"generic-mcp-client"}, "redirect_uri": {redirect},
			"code_challenge": {strings.Repeat("a", 43)}, "code_challenge_method": {"S256"},
			"resource": {s.absolute(resourcePath)}, "scope": {"agent:connect offline_access"}, "state": {"state"},
		}
		req := httptest.NewRequest(http.MethodGet, s.absolute("/oauth/authorize")+"?"+q.Encode(), nil)
		rr := httptest.NewRecorder()
		s.handleAuthorizeGET(rr, req)
		if rr.Code != want {
			t.Fatalf("generic client Agent authorization status=%d want %d body=%s", rr.Code, want, rr.Body.String())
		}
	}

	t.Run("secure-default-deny", func(t *testing.T) { test(t, false, http.StatusForbidden) })
	t.Run("explicit-legacy-migration", func(t *testing.T) { test(t, true, http.StatusOK) })
}

func TestProductionStateLeaseRejectsSecondRelayWriter(t *testing.T) {
	stateDir := t.TempDir()
	cfg := Config{PublicURL: "http://127.0.0.1:19160", Password: "single-writer-password-12345", StateDir: stateDir, EnforceSingleWriter: true}
	first, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := New(cfg); err == nil {
		_ = second.Close()
		t.Fatal("second Relay writer acquired the same OAuth state directory")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := New(cfg)
	if err != nil {
		t.Fatalf("state lease was not released on close: %v", err)
	}
	defer third.Close()
}

func TestProductionStateLeaseRejectsSymlink(t *testing.T) {
	stateDir := t.TempDir()
	target := filepath.Join(t.TempDir(), "lease-target")
	if err := os.WriteFile(target, []byte("not-a-lease\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(stateDir, "oauth-state.lease")); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{PublicURL: "http://127.0.0.1:19161", Password: "lease-symlink-password-12345", StateDir: stateDir, EnforceSingleWriter: true})
	if err == nil {
		t.Fatal("symlinked OAuth state lease was accepted")
	}
}

func TestExplicitInstanceModeCannotBeOverriddenByPersistedState(t *testing.T) {
	stateDir := t.TempDir()
	public, err := New(Config{PublicURL: "http://127.0.0.1:19162", Password: "mode-state-password-12345", StateDir: stateDir, Mode: ModePublic})
	if err != nil {
		t.Fatal(err)
	}
	public.mu.Lock()
	public.registrationEnabled = true
	if err := public.saveLocked(); err != nil {
		public.mu.Unlock()
		t.Fatal(err)
	}
	public.mu.Unlock()

	private, err := New(Config{PublicURL: "http://127.0.0.1:19162", StateDir: stateDir, Mode: ModePrivate, ModeConfigured: true, OwnerPassword: "explicit-private-owner-password-12345"})
	if err != nil {
		t.Fatal(err)
	}
	if private.cfg.Mode != ModePrivate || private.registrationEnabled {
		t.Fatalf("persisted public state overrode explicit private mode: mode=%q registration=%v", private.cfg.Mode, private.registrationEnabled)
	}
}

func TestConfiguredPrivateModeCannotBeReexpandedByPersistedPublicState(t *testing.T) {
	stateDir := t.TempDir()
	first, err := New(Config{PublicURL: "http://127.0.0.1:19144", Password: "mode-authority-password-12345", StateDir: stateDir, Mode: ModePrivate})
	if err != nil {
		t.Fatal(err)
	}
	first.mu.Lock()
	first.cfg.Mode = ModePublic
	first.registrationEnabled = true
	err = first.saveLocked()
	first.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	restarted, err := New(Config{PublicURL: "http://127.0.0.1:19144", StateDir: stateDir, Mode: ModePrivate, ModeConfigured: true})
	if err != nil {
		t.Fatal(err)
	}
	restarted.mu.Lock()
	mode := restarted.cfg.Mode
	registrationEnabled := restarted.registrationEnabled
	restarted.mu.Unlock()
	if mode != ModePrivate || registrationEnabled {
		t.Fatalf("persisted public state overrode configured private mode: mode=%q registration=%v", mode, registrationEnabled)
	}
}

func TestPersistedSetupModeStillRestoresWhenModeIsNotConfigured(t *testing.T) {
	stateDir := t.TempDir()
	first, err := New(Config{PublicURL: "http://127.0.0.1:19145", Password: "mode-persist-password-12345", StateDir: stateDir, Mode: ModePrivate})
	if err != nil {
		t.Fatal(err)
	}
	first.mu.Lock()
	first.cfg.Mode = ModePublic
	first.registrationEnabled = true
	err = first.saveLocked()
	first.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	restarted, err := New(Config{PublicURL: "http://127.0.0.1:19145", StateDir: stateDir, Mode: ModePrivate})
	if err != nil {
		t.Fatal(err)
	}
	restarted.mu.Lock()
	mode := restarted.cfg.Mode
	registrationEnabled := restarted.registrationEnabled
	restarted.mu.Unlock()
	if mode != ModePublic || !registrationEnabled {
		t.Fatalf("persisted first-run mode was not restored: mode=%q registration=%v", mode, registrationEnabled)
	}
}

func TestRetiringDeviceAfterChallengeIssuanceBlocksRegistration(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19146", Password: "retire-after-challenge-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	const clientName = "chat-with-cli agent retirement-race"
	const redirect = "http://127.0.0.1:45128/callback"
	publicKey := deviceidentity.EncodePublicKey(identity.PublicKey())
	challenge, err := s.issueRegistrationChallenge(identity.ID(), publicKey, clientName, redirect, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.SignRegistrationProof(clientName, redirect, challenge)
	if err != nil {
		t.Fatal(err)
	}

	s.mu.Lock()
	s.retiredDevices["id/"+identity.ID()] = true
	s.mu.Unlock()
	body, _ := json.Marshal(map[string]any{
		"redirect_uris": []string{redirect}, "token_endpoint_auth_method": "none",
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
		"client_name": clientName, "scope": "agent:connect offline_access",
		"chat_with_cli_device_id": identity.ID(), "chat_with_cli_device_public_key": publicKey,
		"chat_with_cli_device_challenge": challenge, "chat_with_cli_device_proof": proof,
	})
	req := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/register"), bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleRegister(rr, req)
	if rr.Code != http.StatusGone {
		t.Fatalf("retired device used a pre-issued valid DCR challenge: status=%d want 410 body=%s", rr.Code, rr.Body.String())
	}
}

func TestSetupCannotOverrideExplicitOperatorMode(t *testing.T) {
	stateDir := t.TempDir()
	s, err := New(Config{PublicURL: "http://127.0.0.1:19163", StateDir: stateDir, Mode: ModePrivate, ModeConfigured: true, SetupToken: "fixed-mode-setup-token-123456"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)
	get := httptest.NewRecorder()
	mux.ServeHTTP(get, httptest.NewRequest(http.MethodGet, s.absolute("/setup"), nil))
	csrf := csrfTokenPattern.FindSubmatch(get.Body.Bytes())
	cookies := get.Result().Cookies()
	if len(csrf) != 2 || len(cookies) != 1 {
		t.Fatalf("setup bootstrap missing csrf/cookie: status=%d body=%s", get.Code, get.Body.String())
	}
	form := url.Values{"csrf_token": {string(csrf[1])}, "setup_token": {"fixed-mode-setup-token-123456"}, "username": {"owner"}, "password": {"fixed-mode-password-12345"}, "mode": {"public"}}
	post := httptest.NewRequest(http.MethodPost, s.absolute("/setup"), strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(cookies[0])
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, post)
	if rr.Code != http.StatusBadRequest || s.cfg.Mode != ModePrivate || len(s.users) != 0 {
		t.Fatalf("setup overrode explicit mode: status=%d mode=%q users=%d body=%s", rr.Code, s.cfg.Mode, len(s.users), rr.Body.String())
	}
}

func TestDeleteUserInvalidatesAllOldDeviceAuthority(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19164", Password: "delete-authority-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	const clientID = "victim-authority-client"
	const redirect = "http://127.0.0.1:45129/callback"
	const codeValue = "victim-code-before-delete"
	verifier := strings.Repeat("C", 43)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	route := "id/" + identity.ID()
	resource := s.absolute("/agent/" + route)

	s.mu.Lock()
	adminID := s.usernames["owner"]
	admin := s.users[adminID]
	victim, err := s.createUserLocked("delete-victim", "delete-victim-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.clients[clientID] = Client{
		ID: clientID, Name: "chat-with-cli agent delete-victim", RedirectURIs: []string{redirect}, Approved: true,
		DeviceID: identity.ID(), DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true, IssuedAt: time.Now().Unix(),
	}
	if err := s.authorizeResourceLocked(victim.ID, clientID, resource); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	access, refresh, _, err := s.issueTokensLocked(clientID, victim.ID, resource, "agent:connect offline_access")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.codes[tokenKey(codeValue)] = authCode{pendingAuth: pendingAuth{
		ClientID: clientID, UserID: victim.ID, RedirectURI: redirect, Resource: resource,
		Scope: "agent:connect offline_access", CodeChallenge: challenge,
	}, Expires: time.Now().Add(time.Minute)}
	s.mu.Unlock()

	if err := s.applyAdminAction("delete-user", victim.ID, "", admin, httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil)); err != nil {
		t.Fatal(err)
	}

	s.mu.Lock()
	_, userPresent := s.users[victim.ID]
	_, clientPresent := s.clients[clientID]
	_, codePresent := s.codes[tokenKey(codeValue)]
	_, accessPresent := s.access[tokenKey(access)]
	_, refreshPresent := s.refresh[tokenKey(refresh)]
	retired := s.retiredDevices[route]
	_, owned := s.devices[route]
	s.mu.Unlock()
	if userPresent || clientPresent || codePresent || accessPresent || refreshPresent || !retired || owned {
		t.Fatalf("delete-user left stale authority: user=%v client=%v code=%v access=%v refresh=%v retired=%v owned=%v", userPresent, clientPresent, codePresent, accessPresent, refreshPresent, retired, owned)
	}

	codeForm := url.Values{"grant_type": {"authorization_code"}, "code": {codeValue}, "client_id": {clientID}, "redirect_uri": {redirect}, "code_verifier": {verifier}, "resource": {resource}}
	codeReq := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/token"), strings.NewReader(codeForm.Encode()))
	codeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	codeRR := httptest.NewRecorder()
	s.handleToken(codeRR, codeReq)
	if codeRR.Code != http.StatusBadRequest || !strings.Contains(codeRR.Body.String(), "invalid_grant") {
		t.Fatalf("deleted user's old authorization code revived: status=%d body=%s", codeRR.Code, codeRR.Body.String())
	}

	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}, "resource": {resource}}
	refreshReq := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/token"), strings.NewReader(refreshForm.Encode()))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshRR := httptest.NewRecorder()
	s.handleToken(refreshRR, refreshReq)
	if refreshRR.Code != http.StatusBadRequest || !strings.Contains(refreshRR.Body.String(), "invalid_grant") {
		t.Fatalf("deleted user's old refresh token revived: status=%d body=%s", refreshRR.Code, refreshRR.Body.String())
	}

	authQ := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
		"resource": {resource}, "scope": {"agent:connect offline_access"}, "state": {"state"},
	}
	authRR := httptest.NewRecorder()
	s.handleAuthorizeGET(authRR, httptest.NewRequest(http.MethodGet, s.absolute("/oauth/authorize")+"?"+authQ.Encode(), nil))
	if authRR.Code != http.StatusBadRequest {
		t.Fatalf("deleted user's old DCR client remained authorizable: status=%d body=%s", authRR.Code, authRR.Body.String())
	}

	challengeBody, _ := json.Marshal(map[string]any{
		"client_name": "chat-with-cli agent delete-victim", "redirect_uri": redirect,
		"chat_with_cli_device_id": identity.ID(), "chat_with_cli_device_public_key": deviceidentity.EncodePublicKey(identity.PublicKey()),
	})
	challengeReq := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/register/challenge"), bytes.NewReader(challengeBody))
	challengeReq.Header.Set("Content-Type", "application/json")
	challengeRR := httptest.NewRecorder()
	s.handleRegistrationChallenge(challengeRR, challengeReq)
	if challengeRR.Code != http.StatusGone {
		t.Fatalf("deleted user's old real device private key could request a new DCR challenge: status=%d want 410 body=%s", challengeRR.Code, challengeRR.Body.String())
	}
}

func TestPersistenceFaultGuardPreventsCredentialResurrectionAcrossRestart(t *testing.T) {
	stateDir := t.TempDir()
	cfg := Config{PublicURL: "http://127.0.0.1:19164", Password: "guard-recovery-password-12345", StateDir: stateDir}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	owner := s.users[ownerID]
	const device = "guard-recovery-device"
	s.clients["guard-client"] = Client{ID: "guard-client", Approved: true}
	s.devices[device] = ownerID
	access, _, _, err := s.issueTokensLocked("guard-client", ownerID, s.absolute("/mcp/"+device), "mcp offline_access")
	s.mu.Unlock()
	if err != nil || !s.VerifyAccess(access, s.absolute("/mcp/"+device)) {
		t.Fatalf("token setup failed: err=%v", err)
	}
	if err := os.Chmod(stateDir, 0o500); err != nil {
		t.Fatal(err)
	}
	revokeErr := s.applyAdminAction("revoke-token", tokenKey(access), "", owner, httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil))
	if revokeErr == nil || s.Ready() || s.VerifyAccess(access, s.absolute("/mcp/"+device)) {
		t.Fatalf("failed persistence did not freeze authorization: err=%v ready=%v", revokeErr, s.Ready())
	}
	guardBytes, err := os.ReadFile(filepath.Join(stateDir, "oauth-state.guard"))
	if err != nil || string(guardBytes) != stateGuardDirty {
		t.Fatalf("persistence fault was not durably marked dirty: state=%q err=%v", guardBytes, err)
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	restarted, err := New(Config{PublicURL: cfg.PublicURL, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Ready() || restarted.VerifyAccess(access, restarted.absolute("/mcp/"+device)) {
		t.Fatal("dirty authorization state became usable after Relay restart")
	}
	if err := restarted.applyAdminAction("revoke-token", tokenKey(access), "", restarted.users[ownerID], httptest.NewRequest(http.MethodPost, restarted.absolute("/admin/action"), nil)); err != nil {
		t.Fatalf("recovery revocation could not be persisted: %v", err)
	}
	if !restarted.killSwitch || restarted.Ready() {
		t.Fatal("recovery write did not retain fail-closed state until restart")
	}
	_ = restarted.Close()

	recovered, err := New(Config{PublicURL: cfg.PublicURL, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if recovered.persistenceFault || !recovered.killSwitch || recovered.VerifyAccess(access, recovered.absolute("/mcp/"+device)) {
		t.Fatalf("recovered Relay did not remain safely blocked: fault=%v kill=%v", recovered.persistenceFault, recovered.killSwitch)
	}
}

func TestStateGuardRejectsSymlink(t *testing.T) {
	stateDir := t.TempDir()
	target := filepath.Join(t.TempDir(), "guard-target")
	if err := os.WriteFile(target, []byte(stateGuardClean), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(stateDir, "oauth-state.guard")); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{PublicURL: "http://127.0.0.1:19165", Password: "guard-symlink-password-12345", StateDir: stateDir})
	if err == nil {
		t.Fatal("symlinked OAuth state guard was accepted")
	}
}

func TestPersistenceFaultRecoveryRejectsAuthorityExpansion(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19165", Password: "recovery-boundary-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	owner := s.users[ownerID]
	s.persistenceFault = true
	s.killSwitch = true
	s.mu.Unlock()
	req := httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil)

	for _, tc := range []struct {
		action string
		target string
		value  string
	}{
		{"create-user", "new-user", "new-user-password-12345"},
		{"set-mode", "", ModePublic},
		{"set-registration", "", "on"},
		{"set-dcr", "", "on"},
		{"set-mcp", "", "on"},
		{"set-agent", "", "on"},
		{"set-kill-switch", "", "off"},
		{"rename-device", "missing", "renamed"},
	} {
		if err := s.applyAdminAction(tc.action, tc.target, tc.value, owner, req); !errors.Is(err, errPersistenceRecoveryOnly) {
			t.Fatalf("recovery action %s value=%s err=%v want recovery-only denial", tc.action, tc.value, err)
		}
	}

	// Authority reduction remains available so an operator can repeat the
	// revoke/disable action that originally failed to persist.
	if err := s.applyAdminAction("set-agent", "", "off", owner, req); err != nil {
		t.Fatalf("authority-reducing recovery action was blocked: %v", err)
	}
	if s.agentEnabled || !s.killSwitch || !s.persistenceFault {
		t.Fatalf("recovery contraction state wrong: agent=%v kill=%v fault=%v", s.agentEnabled, s.killSwitch, s.persistenceFault)
	}
}

func TestExpiredUnapprovedClientCannotSurviveThroughPendingAuthorization(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19166", Password: "stale-client-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.clients["stale-client"] = Client{ID: "stale-client", IssuedAt: time.Now().Add(-2 * time.Hour).Unix()}
	s.pending["stale-pending"] = pendingAuth{ClientID: "stale-client", UserID: ownerID, Resource: s.absolute("/mcp/stale-device"), RedirectURI: "http://127.0.0.1:45555/callback", Expires: time.Now().Add(5 * time.Minute)}
	s.cleanupLocked(time.Now())
	_, clientExists := s.clients["stale-client"]
	_, pendingExists := s.pending["stale-pending"]
	s.mu.Unlock()
	if clientExists || pendingExists {
		t.Fatalf("expired DCR client left authorization artifacts: client=%v pending=%v", clientExists, pendingExists)
	}
}

func TestGrantAuthorizationCannotReanimateMissingClient(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19167", Password: "missing-client-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.pending["orphan-pending"] = pendingAuth{ClientID: "deleted-client", Resource: s.absolute("/mcp/orphan-device"), RedirectURI: "http://127.0.0.1:45556/callback", Expires: time.Now().Add(time.Minute)}
	s.mu.Unlock()
	rr := httptest.NewRecorder()
	if err := s.grantAuthorization(rr, httptest.NewRequest(http.MethodPost, s.absolute("/oauth/authorize"), nil), "orphan-pending", ownerID); err == nil {
		t.Fatal("authorization grant recreated a missing OAuth client")
	}
	s.mu.Lock()
	_, clientExists := s.clients["deleted-client"]
	_, pendingExists := s.pending["orphan-pending"]
	s.mu.Unlock()
	if clientExists || pendingExists {
		t.Fatalf("missing-client grant left stale authority artifacts: client=%v pending=%v", clientExists, pendingExists)
	}
}

func TestGrantAuthorizationRechecksExactClientRedirect(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19168", Password: "redirect-recheck-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.clients["redirect-client"] = Client{ID: "redirect-client", RedirectURIs: []string{"http://127.0.0.1:45558/callback"}, IssuedAt: time.Now().Unix()}
	s.pending["redirect-pending"] = pendingAuth{ClientID: "redirect-client", Resource: s.absolute("/mcp/redirect-device"), RedirectURI: "http://127.0.0.1:45557/callback", Expires: time.Now().Add(time.Minute)}
	s.mu.Unlock()
	rr := httptest.NewRecorder()
	if err := s.grantAuthorization(rr, httptest.NewRequest(http.MethodPost, s.absolute("/oauth/authorize"), nil), "redirect-pending", ownerID); err == nil {
		t.Fatal("authorization grant ignored changed client redirect binding")
	}
	s.mu.Lock()
	client := s.clients["redirect-client"]
	_, pendingExists := s.pending["redirect-pending"]
	codes := len(s.codes)
	s.mu.Unlock()
	if client.Approved || pendingExists || codes != 0 {
		t.Fatalf("redirect mismatch left grant artifacts: approved=%v pending=%v codes=%d", client.Approved, pendingExists, codes)
	}
}

func TestDirtyRecoveryGuardCannotBeConsumedByOrdinaryPersistence(t *testing.T) {
	stateDir := t.TempDir()
	s, err := New(Config{PublicURL: "http://127.0.0.1:19166", Password: "dirty-ordinary-password-12345", StateDir: stateDir, Mode: ModePublic})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	owner, err := s.createUserLocked("recovery-owner", "recovery-owner-password-12345", true)
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	ownerID := owner.ID
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.registrationEnabled = true
	s.persistenceFault = true
	if err := writeStateGuard(s.stateGuard, stateGuardDirty); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()

	if _, err, _ := s.register("ordinary-new-user", "ordinary-new-user-password-12345"); !errors.Is(err, errAuthorizationRecoveryRequired) {
		t.Fatalf("public registration was able to persist during dirty recovery: %v", err)
	}
	s.mu.Lock()
	_, registered := s.usernames["ordinary-new-user"]
	s.mu.Unlock()
	if registered {
		t.Fatal("failed dirty-recovery registration remained in memory")
	}
	guard, err := os.ReadFile(filepath.Join(stateDir, "oauth-state.guard"))
	if err != nil || string(guard) != stateGuardDirty {
		t.Fatalf("ordinary registration consumed dirty guard: guard=%q err=%v", guard, err)
	}

	session, err := s.createSession(s.users[ownerID])
	if err != nil || session == "" {
		t.Fatalf("recovery administrator could not obtain an ephemeral session: token=%q err=%v", session, err)
	}
	guard, err = os.ReadFile(filepath.Join(stateDir, "oauth-state.guard"))
	if err != nil || string(guard) != stateGuardDirty {
		t.Fatalf("recovery login session consumed dirty guard: guard=%q err=%v", guard, err)
	}

	owner = s.users[ownerID]
	if err := s.applyAdminAction("set-agent", "", "off", owner, httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil)); err != nil {
		t.Fatalf("explicit authority-reducing recovery transaction failed: %v", err)
	}
	guard, err = os.ReadFile(filepath.Join(stateDir, "oauth-state.guard"))
	if err != nil || string(guard) != stateGuardClean {
		t.Fatalf("explicit recovery action did not complete guard transaction: guard=%q err=%v", guard, err)
	}
	if !s.persistenceFault || !s.killSwitch || s.agentEnabled {
		t.Fatalf("post-recovery in-memory safety state wrong: fault=%v kill=%v agent=%v", s.persistenceFault, s.killSwitch, s.agentEnabled)
	}
}

func TestDirtyStateDoesNotResurrectPersistedBrowserSession(t *testing.T) {
	stateDir := t.TempDir()
	s, err := New(Config{PublicURL: "http://127.0.0.1:19170", Password: "dirty-session-password-12345", StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	ownerID := s.usernames["owner"]
	session, err := s.createSession(s.users[ownerID])
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.persistenceFault = true
	if err := writeStateGuard(s.stateGuard, stateGuardDirty); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()

	logout := httptest.NewRequest(http.MethodPost, s.absolute("/admin/logout"), nil)
	logout.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	s.clearSession(httptest.NewRecorder(), logout)
	if _, ok := s.sessionUser(logout); ok {
		t.Fatal("logged-out session remained usable during dirty recovery")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := New(Config{PublicURL: "http://127.0.0.1:19170", Password: "dirty-session-password-12345", StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	stale := httptest.NewRequest(http.MethodGet, restarted.absolute("/admin"), nil)
	stale.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	if _, ok := restarted.sessionUser(stale); ok {
		t.Fatal("persisted browser session resurrected while the state guard was dirty")
	}

	fresh, err := restarted.createSession(restarted.users[ownerID])
	if err != nil || fresh == "" {
		t.Fatalf("fresh recovery login could not create an ephemeral session: token=%q err=%v", fresh, err)
	}
	current := httptest.NewRequest(http.MethodGet, restarted.absolute("/admin"), nil)
	current.AddCookie(&http.Cookie{Name: sessionCookie, Value: fresh})
	if _, ok := restarted.sessionUser(current); !ok {
		t.Fatal("fresh process-local recovery session was rejected")
	}
	if !restarted.persistenceFault {
		t.Fatal("fresh recovery login unexpectedly cleared the dirty guard")
	}
}

func TestDirtyRecoveryReauthKeepsFreshSessionProcessLocal(t *testing.T) {
	const password = "dirty-reauth-password-12345"
	s, err := New(Config{PublicURL: "http://127.0.0.1:19171", Password: password, StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.mu.Lock()
	ownerID := s.usernames["owner"]
	owner := s.users[ownerID]
	s.persistenceFault = true
	s.mu.Unlock()
	oldSession, err := s.createSession(owner)
	if err != nil {
		t.Fatal(err)
	}

	csrf := "reauth-csrf"
	form := url.Values{"csrf_token": {csrf}, "password": {password}}
	req := httptest.NewRequest(http.MethodPost, s.absolute("/admin/reauth"), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: oldSession})
	req.AddCookie(&http.Cookie{Name: adminCSRFCookie, Value: csrf})
	rr := httptest.NewRecorder()
	s.handleAdminReauthPOST(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("dirty recovery reauth status=%d body=%s", rr.Code, rr.Body.String())
	}

	var newSession string
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == sessionCookie {
			newSession = cookie.Value
			break
		}
	}
	if newSession == "" || newSession == oldSession {
		t.Fatalf("dirty recovery reauth did not rotate the session cookie: empty=%v unchanged=%v", newSession == "", newSession == oldSession)
	}
	check := httptest.NewRequest(http.MethodGet, s.absolute("/admin"), nil)
	check.AddCookie(&http.Cookie{Name: sessionCookie, Value: newSession})
	if _, ok := s.sessionUser(check); !ok {
		t.Fatal("freshly reauthenticated recovery session was rejected")
	}
	s.mu.Lock()
	_, oldPresent := s.sessions[tokenKey(oldSession)]
	_, newPresent := s.sessions[tokenKey(newSession)]
	_, newEphemeral := s.ephemeralSessions[tokenKey(newSession)]
	fault := s.persistenceFault
	s.mu.Unlock()
	if oldPresent || !newPresent || !newEphemeral || !fault {
		t.Fatalf("dirty reauth session state wrong: old=%v new=%v ephemeral=%v fault=%v", oldPresent, newPresent, newEphemeral, fault)
	}
}

func TestDisabledUserCannotCompleteStaleAgentClaim(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19169", Password: "disabled-claim-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	const clientID = "disabled-claim-client"
	const redirect = "http://127.0.0.1:45569/callback"
	route := "id/" + identity.ID()
	resource := s.absolute("/agent/" + route)

	s.mu.Lock()
	admin := s.users[s.usernames["owner"]]
	victim, err := s.createUserLocked("disabled-claim-victim", "disabled-claim-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.clients[clientID] = Client{
		ID: clientID, Name: "chat-with-cli agent disabled-claim", RedirectURIs: []string{redirect}, IssuedAt: time.Now().Unix(),
		DeviceID: identity.ID(), DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true,
	}
	s.pending["disabled-claim-pending"] = pendingAuth{
		ClientID: clientID, RedirectURI: redirect, Resource: resource,
		Scope: "agent:connect offline_access", Expires: time.Now().Add(time.Minute),
	}
	s.mu.Unlock()

	if err := s.applyAdminAction("disable-user", victim.ID, "on", admin, httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil)); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	if err := s.grantAuthorization(rr, httptest.NewRequest(http.MethodPost, s.absolute("/oauth/authorize"), nil), "disabled-claim-pending", victim.ID); err == nil {
		t.Fatal("disabled user completed a stale Agent authorization and device claim")
	}

	s.mu.Lock()
	owner, claimed := s.devices[route]
	codes := len(s.codes)
	approved := s.clients[clientID].Approved
	s.mu.Unlock()
	if claimed || owner != "" || codes != 0 || approved {
		t.Fatalf("disabled-user race mutated authority: claimed=%v owner=%q codes=%d approved=%v", claimed, owner, codes, approved)
	}
}

func TestReplayedRegistrationChallengeCannotEvictOtherClient(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19170", Password: "replay-eviction-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	const clientName = "chat-with-cli agent replay-eviction"
	const redirect = "http://127.0.0.1:45570/callback"
	publicKey := deviceidentity.EncodePublicKey(identity.PublicKey())
	challenge, err := s.issueRegistrationChallenge(identity.ID(), publicKey, clientName, redirect, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.SignRegistrationProof(clientName, redirect, challenge)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"redirect_uris": []string{redirect}, "token_endpoint_auth_method": "none",
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
		"client_name": clientName, "scope": "agent:connect offline_access",
		"chat_with_cli_device_id": identity.ID(), "chat_with_cli_device_public_key": publicKey,
		"chat_with_cli_device_challenge": challenge, "chat_with_cli_device_proof": proof,
	})
	register := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/register"), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		s.handleRegister(rr, req)
		return rr
	}
	if rr := register(); rr.Code != http.StatusCreated {
		t.Fatalf("initial registration status=%d body=%s", rr.Code, rr.Body.String())
	}

	s.mu.Lock()
	s.clients["other-pending-client"] = Client{ID: "other-pending-client", IssuedAt: time.Now().Add(-30 * time.Second).Unix()}
	for i := 0; len(s.clients) < maxClients; i++ {
		id := fmt.Sprintf("capacity-approved-%d", i)
		s.clients[id] = Client{ID: id, Approved: true, IssuedAt: time.Now().Unix()}
	}
	s.mu.Unlock()

	if rr := register(); rr.Code != http.StatusBadRequest {
		t.Fatalf("replayed registration status=%d want 400 body=%s", rr.Code, rr.Body.String())
	}
	s.mu.Lock()
	_, otherStillPresent := s.clients["other-pending-client"]
	clientCount := len(s.clients)
	s.mu.Unlock()
	if !otherStillPresent || clientCount != maxClients {
		t.Fatalf("replayed challenge changed other client state: other_present=%v clients=%d want=%d", otherStillPresent, clientCount, maxClients)
	}
}

func TestSessionCreationRejectsRevokedAuthenticationSnapshot(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19171", Password: "session-race-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	authenticated := s.users[ownerID]
	current := authenticated
	current.Disabled = true
	s.users[ownerID] = current
	s.mu.Unlock()
	if token, err := s.createSession(authenticated); err == nil || token != "" {
		t.Fatalf("disabled user received a post-revocation session: token=%q err=%v", token, err)
	}

	rotatedHash, err := hashPassword("rotated-session-race-password-12345")
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	current = s.users[ownerID]
	current.Disabled = false
	current.PasswordHash = rotatedHash
	s.users[ownerID] = current
	s.mu.Unlock()
	if token, err := s.createSession(authenticated); err == nil || token != "" {
		t.Fatalf("old password snapshot received a session after password rotation: token=%q err=%v", token, err)
	}

	s.mu.Lock()
	delete(s.users, ownerID)
	s.mu.Unlock()
	if token, err := s.createSession(current); err == nil || token != "" {
		t.Fatalf("deleted user received a session: token=%q err=%v", token, err)
	}
}

func TestDeleteUserRetiresOrphanedDeviceRecord(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19172", Password: "orphan-device-delete-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	const clientID = "orphan-device-client"
	const redirect = "http://127.0.0.1:45572/callback"
	const codeValue = "orphan-device-code"
	route := "id/" + identity.ID()
	resource := s.absolute("/agent/" + route)

	s.mu.Lock()
	admin := s.users[s.usernames["owner"]]
	victim, err := s.createUserLocked("orphan-device-victim", "orphan-device-victim-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.clients[clientID] = Client{
		ID: clientID, RedirectURIs: []string{redirect}, Approved: true, IssuedAt: time.Now().Unix(),
		DeviceID: identity.ID(), DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true,
	}
	// Simulate a legacy/interrupted deletion that removed the ownership index
	// but left the immutable device record and its credentials behind.
	s.deviceRecords[route] = DeviceRecord{
		ID: route[len("id/"):], OwnerID: victim.ID, DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), CreatedAt: time.Now().Unix(),
	}
	access, refresh, _, err := s.issueTokensLocked(clientID, victim.ID, resource, "agent:connect offline_access")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.pending["orphan-device-pending"] = pendingAuth{ClientID: clientID, UserID: victim.ID, RedirectURI: redirect, Resource: resource, Expires: time.Now().Add(time.Minute)}
	s.codes[tokenKey(codeValue)] = authCode{pendingAuth: pendingAuth{ClientID: clientID, UserID: victim.ID, RedirectURI: redirect, Resource: resource}, Expires: time.Now().Add(time.Minute)}
	s.mu.Unlock()

	if err := s.applyAdminAction("delete-user", victim.ID, "", admin, httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil)); err != nil {
		t.Fatal(err)
	}

	s.mu.Lock()
	_, recordPresent := s.deviceRecords[route]
	_, active := s.devices[route]
	retired := s.retiredDevices[route]
	_, clientPresent := s.clients[clientID]
	_, accessPresent := s.access[tokenKey(access)]
	_, refreshPresent := s.refresh[tokenKey(refresh)]
	_, pendingPresent := s.pending["orphan-device-pending"]
	_, codePresent := s.codes[tokenKey(codeValue)]
	s.clients["reclaim-client"] = Client{ID: "reclaim-client", DeviceID: identity.ID(), DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true}
	reclaimErr := s.authorizeResourceLocked(admin.ID, "reclaim-client", resource)
	s.mu.Unlock()
	if recordPresent || active || clientPresent || accessPresent || refreshPresent || pendingPresent || codePresent || !retired {
		t.Fatalf("orphaned device authority survived deletion: record=%v active=%v client=%v access=%v refresh=%v pending=%v code=%v retired=%v", recordPresent, active, clientPresent, accessPresent, refreshPresent, pendingPresent, codePresent, retired)
	}
	if reclaimErr == nil {
		t.Fatal("deleted user's orphaned immutable device identity was reclaimable")
	}
}

func TestCleanupRemovesCredentialsForDisabledUsers(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19173", Password: "cleanup-disabled-user-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	victim, err := s.createUserLocked("cleanup-disabled-user", "cleanup-disabled-user-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	victim.Disabled = true
	s.users[victim.ID] = victim
	const clientID = "cleanup-disabled-client"
	const device = "cleanup-disabled-device"
	resource := s.absolute("/mcp/" + device)
	s.clients[clientID] = Client{ID: clientID, Approved: true}
	s.devices[device] = victim.ID
	future := time.Now().Add(time.Hour).Unix()
	s.access["cleanup-access"] = tokenRecord{ClientID: clientID, UserID: victim.ID, Resource: resource, Scope: "mcp offline_access", Expires: future}
	s.refresh["cleanup-refresh"] = tokenRecord{ClientID: clientID, UserID: victim.ID, Resource: resource, Scope: "mcp offline_access", Expires: future}
	s.refreshUsed["cleanup-refresh-used"] = tokenRecord{ClientID: clientID, UserID: victim.ID, Resource: resource, Scope: "mcp offline_access", Expires: future}
	s.sessions["cleanup-session"] = sessionRecord{UserID: victim.ID, CreatedAt: time.Now().Unix(), LastSeenAt: time.Now().Unix(), Expires: future}
	s.pending["cleanup-pending"] = pendingAuth{ClientID: clientID, UserID: victim.ID, Resource: resource, Expires: time.Now().Add(time.Minute)}
	s.codes["cleanup-code"] = authCode{pendingAuth: pendingAuth{ClientID: clientID, UserID: victim.ID, Resource: resource, Scope: "mcp offline_access"}, Expires: time.Now().Add(time.Minute)}
	s.cleanupLocked(time.Now())
	remaining := len(s.access) + len(s.refresh) + len(s.refreshUsed) + len(s.sessions) + len(s.pending) + len(s.codes)
	victim.Disabled = false
	s.users[victim.ID] = victim
	s.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("disabled-user credentials survived cleanup: %d records", remaining)
	}
	if s.VerifyAccess("cleanup-access-secret", resource) {
		t.Fatal("disabled-user access credential was usable after re-enable")
	}
}

func TestStaleAdministratorSnapshotCannotMutateState(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19174", Password: "stale-admin-snapshot-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	stale := s.users[ownerID]
	live := stale
	live.Disabled = true
	s.users[ownerID] = live
	s.mu.Unlock()
	request := httptest.NewRequest(http.MethodPost, s.absolute("/admin/action"), nil)
	if err := s.applyAdminAction("create-user", "stale-admin-created", "stale-admin-created-password-12345", stale, request); err == nil {
		t.Fatal("disabled administrator snapshot performed an action")
	}
	s.mu.Lock()
	_, created := s.usernames["stale-admin-created"]
	live = s.users[ownerID]
	live.Disabled = false
	live.Admin = false
	s.users[ownerID] = live
	s.mu.Unlock()
	if err := s.applyAdminAction("set-agent", "", "off", stale, request); err == nil {
		t.Fatal("demoted administrator snapshot performed an action")
	}
	if created {
		t.Fatal("stale administrator action created a user")
	}
}

func TestAgentProofRechecksLiveAccessBeforeConsumingChallenge(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19175", Password: "proof-revalidation-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	resource := s.absolute("/agent/id/" + identity.ID())
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.clients["proof-revalidation-client"] = Client{ID: "proof-revalidation-client", Approved: true, DeviceID: identity.ID(), DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true}
	if err := s.authorizeResourceLocked(ownerID, "proof-revalidation-client", resource); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	access, _, _, err := s.issueTokensLocked("proof-revalidation-client", ownerID, resource, "agent:connect offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := s.issueAgentChallenge(resource, tokenKey(access), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.SignProof(resource, access, challenge)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	delete(s.access, tokenKey(access))
	s.mu.Unlock()
	req := httptest.NewRequest(http.MethodGet, resource, nil)
	req.Header.Set(deviceidentity.HeaderChallenge, challenge)
	req.Header.Set(deviceidentity.HeaderProof, proof)
	if s.verifyAgentDeviceProof(req, resource, tokenKey(access)) {
		t.Fatal("revoked access token completed Agent proof")
	}
	s.mu.Lock()
	consumed := len(s.consumedAgentChallenges["id/"+identity.ID()])
	s.mu.Unlock()
	if consumed != 0 {
		t.Fatal("revoked proof consumed a challenge")
	}
}
