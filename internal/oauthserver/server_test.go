package oauthserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
	s.clients["agent-hint-client"] = Client{ID: "agent-hint-client", Name: "chat-with-cli agent 工作站 · 上海", DeviceID: id, DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true, Approved: false}
	s.pending["agent-hint-request"] = pendingAuth{ClientID: "agent-hint-client", RedirectURI: "http://127.0.0.1:43201/callback", Resource: s.absolute("/agent/id/" + id), Scope: "agent:connect offline_access", Expires: time.Now().Add(time.Minute)}
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

func TestAdminReauthenticationRefreshesOnlyCurrentSession(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19030", Password: "admin-reauth-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.mcpEnabled = false
	s.mu.Unlock()
	session, err := s.createSession(ownerID)
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
	freshReq := httptest.NewRequest(http.MethodGet, s.absolute("/admin"), nil)
	freshReq.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	if !adminSessionFresh(s, freshReq) {
		t.Fatal("successful re-authentication did not refresh the current session")
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
	const route = "id/0123456789abcdef0123456789abcdef"
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.clients["grant-client"] = Client{ID: "grant-client", Approved: false}
	s.pending["grant-request"] = pendingAuth{
		ClientID: "grant-client", RedirectURI: "http://127.0.0.1:43199/callback",
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

func TestCrossUserTokensCannotCrossDeviceOrScope(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19020", StateDir: t.TempDir(), Mode: ModePublic})
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
	s, err := New(Config{PublicURL: "http://127.0.0.1:19021", StateDir: t.TempDir(), Mode: ModePublic})
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
	s, err := New(Config{PublicURL: "http://127.0.0.1:19025", StateDir: t.TempDir(), Mode: ModePublic})
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

func TestBoundAgentRequiresProofOfPossessionAndRejectsReplay(t *testing.T) {
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
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	handler := s.ProtectScopedResource("agent:connect", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	request := func(id *deviceidentity.Identity, now time.Time, nonce string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, resource, nil)
		req.Header.Set("Authorization", "Bearer "+access)
		if id != nil {
			proof, err := id.SignProof(resource, access, now, nonce)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(deviceidentity.HeaderTimestamp, fmt.Sprintf("%d", now.Unix()))
			req.Header.Set(deviceidentity.HeaderNonce, nonce)
			req.Header.Set(deviceidentity.HeaderProof, proof)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}
	if got := request(nil, time.Now(), ""); got != http.StatusUnauthorized {
		t.Fatalf("bearer-only bound Agent status=%d want 401", got)
	}
	if got := request(wrong, time.Now(), "wrong-key-nonce-123456"); got != http.StatusUnauthorized {
		t.Fatalf("wrong-key Agent proof status=%d want 401", got)
	}
	if got := request(identity, time.Now().Add(-10*time.Minute), "expired-proof-nonce-1"); got != http.StatusUnauthorized {
		t.Fatalf("expired Agent proof status=%d want 401", got)
	}
	now := time.Now().UTC()
	const nonce = "valid-proof-nonce-123456"
	if got := request(identity, now, nonce); got != http.StatusNoContent {
		t.Fatalf("valid Agent proof status=%d want 204", got)
	}
	if got := request(identity, now, nonce); got != http.StatusUnauthorized {
		t.Fatalf("replayed Agent proof status=%d want 401", got)
	}
	if got := request(identity, time.Now().UTC(), "fresh-proof-nonce-654321"); got != http.StatusNoContent {
		t.Fatalf("fresh Agent proof status=%d want 204", got)
	}
}

func TestAgentDCRProofRequiresPrivateKeyAndRejectsReplay(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19042", Password: "dcr-proof-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	const redirect = "http://127.0.0.1:43123/callback"
	const clientName = "chat-with-cli agent proof-workstation"
	now := time.Now().UTC()
	nonce := "registration-proof-nonce-123456"
	proof, err := identity.SignRegistrationProof(clientName, redirect, now, nonce)
	if err != nil {
		t.Fatal(err)
	}
	validBody := map[string]any{
		"redirect_uris":                        []string{redirect},
		"token_endpoint_auth_method":           "none",
		"grant_types":                          []string{"authorization_code", "refresh_token"},
		"response_types":                       []string{"code"},
		"client_name":                          clientName,
		"scope":                                "agent:connect offline_access",
		"chat_with_cli_device_id":              identity.ID(),
		"chat_with_cli_device_public_key":      deviceidentity.EncodePublicKey(identity.PublicKey()),
		"chat_with_cli_device_proof_timestamp": now.Unix(),
		"chat_with_cli_device_proof_nonce":     nonce,
		"chat_with_cli_device_proof":           proof,
	}
	register := func(body map[string]any) *httptest.ResponseRecorder {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/register"), bytes.NewReader(encoded))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		s.handleRegister(rr, req)
		return rr
	}
	if rr := register(validBody); rr.Code != http.StatusCreated {
		t.Fatalf("valid Agent DCR proof status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr := register(validBody); rr.Code != http.StatusBadRequest {
		t.Fatalf("replayed Agent DCR proof status=%d want 400 body=%s", rr.Code, rr.Body.String())
	}

	publicOnly := maps.Clone(validBody)
	publicOnly["chat_with_cli_device_proof_nonce"] = ""
	publicOnly["chat_with_cli_device_proof"] = ""
	if rr := register(publicOnly); rr.Code != http.StatusBadRequest {
		t.Fatalf("public-key-only DCR status=%d want 400 body=%s", rr.Code, rr.Body.String())
	}

	tamperedNonce := "tampered-proof-nonce-654321"
	tampered := maps.Clone(validBody)
	tampered["chat_with_cli_device_proof_nonce"] = tamperedNonce
	// Reuse the signature from another nonce/client payload: signature must fail.
	if rr := register(tampered); rr.Code != http.StatusBadRequest {
		t.Fatalf("tampered Agent DCR proof status=%d want 400 body=%s", rr.Code, rr.Body.String())
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

func TestProofNonceCapacityIsIsolatedPerDevice(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19120", Password: "nonce-isolation-password-12345", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 0; i < maxRegistrationProofNoncesDevice; i++ {
		if !s.consumeRegistrationProofNonceLocked("alice", fmt.Sprintf("reg-%d", i), now) {
			t.Fatalf("alice registration bucket filled early at %d", i)
		}
	}
	if s.consumeRegistrationProofNonceLocked("alice", "overflow", now) {
		t.Fatal("alice registration bucket exceeded per-device limit")
	}
	if !s.consumeRegistrationProofNonceLocked("bob", "fresh", now) {
		t.Fatal("alice registration bucket blocked bob")
	}
	for i := 0; i < maxAgentProofNoncesDevice; i++ {
		if !s.consumeAgentProofNonceLocked("alice", fmt.Sprintf("agent-%d", i), now) {
			t.Fatalf("alice Agent bucket filled early at %d", i)
		}
	}
	if !s.consumeAgentProofNonceLocked("bob", "fresh", now) {
		t.Fatal("alice Agent bucket blocked bob")
	}
}
