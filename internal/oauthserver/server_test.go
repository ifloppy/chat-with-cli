package oauthserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	if err := s.authorizeResourceLocked(alice.ID, s.absolute("/agent/alice-laptop")); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	if err := s.authorizeResourceLocked(alice.ID, s.absolute("/mcp/alice-laptop")); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	if err := s.authorizeResourceLocked(bob.ID, s.absolute("/agent/alice-laptop")); err == nil {
		s.mu.Unlock()
		t.Fatal("bob unexpectedly claimed alice device")
	}
	if err := s.authorizeResourceLocked(bob.ID, s.absolute("/mcp/alice-laptop")); err == nil {
		s.mu.Unlock()
		t.Fatal("bob unexpectedly authorized alice MCP resource")
	}
	s.clients["client-a"] = Client{ID: "client-a", Approved: true}
	access, _, _, err := s.issueTokensLocked("client-a", alice.ID,
		s.absolute("/agent/alice-laptop"), "agent:connect offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !s.VerifyAccessScope(access, s.absolute("/agent/alice-laptop"), "agent:connect") {
		t.Fatal("alice agent token did not authorize its resource")
	}
	if s.VerifyAccessScope(access, s.absolute("/agent/alice-laptop"), "mcp") {
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
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {"client"}}
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
	if landing.Code != http.StatusOK || !strings.Contains(landing.Body.String(), "Chat with CLI") || strings.Contains(landing.Body.String(), "hostname") {
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
	id := "0123456789abcdef0123456789abcdef"
	kind, route, canonical, ok := s.resourceParts(s.absolute("/agent/id/" + id))
	if !ok || kind != "agent" || route != "id/"+id || canonical != s.absolute("/agent/id/"+id) {
		t.Fatalf("unexpected immutable resource parts: %q %q %q %v", kind, route, canonical, ok)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	if err := s.authorizeResourceLocked(ownerID, canonical); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	record := s.deviceRecords[route]
	s.mu.Unlock()
	if record.ID != id || record.OwnerID != ownerID {
		t.Fatalf("unexpected device record: %+v", record)
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
	session, err := s.createSession(ownerID)
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
	s.ProtectResource("", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("disabled MCP reached handler") })).ServeHTTP(rr, req)
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
	firstSession, err := s.createSession(ownerID)
	if err != nil {
		t.Fatal(err)
	}
	secondSession, err := s.createSession(ownerID)
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
	if !refresh2Present {
		t.Fatal("revoking an access token unexpectedly revoked its refresh token")
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
