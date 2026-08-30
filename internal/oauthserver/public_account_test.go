package oauthserver

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ifloppy/chat-with-cli/internal/deviceidentity"
)

func TestInviteOnlyRegistrationIsVisibleAndInviteIsStoredOneWay(t *testing.T) {
	stateDir := t.TempDir()
	s, err := New(Config{PublicURL: "http://127.0.0.1:19201", StateDir: stateDir, Mode: ModePublic, RegistrationDisabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	rr := httptest.NewRecorder()
	s.renderAuthorization(rr, "request", Client{ID: "client", Name: "test"}, s.absolute("/agent/device"), "agent:connect offline_access", User{}, false)
	if strings.Contains(rr.Body.String(), "Create account") {
		t.Fatal("closed public registration unexpectedly showed a registration form without an invite")
	}

	code := randomToken(24)
	s.mu.Lock()
	s.invites[tokenKey(code)] = inviteRecord{CreatedAt: time.Now().Unix(), Expires: time.Now().Add(time.Hour).Unix(), UsesRemaining: 1, CreatedBy: "owner"}
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()

	rr = httptest.NewRecorder()
	s.renderAuthorization(rr, "request", Client{ID: "client", Name: "test"}, s.absolute("/agent/device"), "agent:connect offline_access", User{}, false)
	body := rr.Body.String()
	if !strings.Contains(body, "Create account") || !strings.Contains(body, "Invite code") {
		t.Fatalf("invite-only registration form missing: %s", body)
	}
	if !strings.Contains(body, "Public Relay operator is inside the trust boundary") {
		t.Fatal("public authorization page did not disclose the operator trust boundary")
	}
	stateBytes, err := os.ReadFile(s.stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stateBytes), code) {
		t.Fatal("persisted OAuth state contains the plaintext invite code")
	}
	if !strings.Contains(string(stateBytes), tokenKey(code)) {
		t.Fatal("persisted OAuth state does not contain the one-way invite handle")
	}
}

func TestInviteRegistrationAndFirstAuthorizationCommitAtomically(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19202", StateDir: t.TempDir(), Mode: ModePublic, RegistrationDisabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	route := "id/" + identity.ID()
	resource := s.absolute("/agent/" + route)
	redirect := "http://127.0.0.1:49202/callback"
	clientID := "invite-agent-client"
	invite := randomToken(24)
	s.mu.Lock()
	s.clients[clientID] = Client{ID: clientID, Name: "chat-with-cli agent invited", RedirectURIs: []string{redirect}, DeviceID: identity.ID(), DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true, IssuedAt: time.Now().Unix()}
	s.pending["invite-register"] = pendingAuth{ClientID: clientID, RedirectURI: redirect, Resource: resource, Scope: "agent:connect offline_access", Expires: time.Now().Add(time.Minute)}
	s.invites[tokenKey(invite)] = inviteRecord{CreatedAt: time.Now().Unix(), Expires: time.Now().Add(time.Hour).Unix(), UsesRemaining: 1}
	s.mu.Unlock()
	prepared, err, busy := s.prepareRegistration("invited-user", "invited-user-password-12345")
	if err != nil || busy {
		t.Fatalf("prepare registration: err=%v busy=%v", err, busy)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, s.absolute("/oauth/authorize"), nil)
	if err := s.registerAndGrantAuthorization(rr, req, "invite-register", prepared, invite); err != nil {
		t.Fatal(err)
	}
	if rr.Code != http.StatusFound {
		t.Fatalf("registration status=%d body=%s", rr.Code, rr.Body.String())
	}
	s.mu.Lock()
	_, inviteStillPresent := s.invites[tokenKey(invite)]
	owner := s.devices[route]
	_, userExists := s.users[prepared.ID]
	_, pendingExists := s.pending["invite-register"]
	approved := s.clients[clientID].Approved
	sessions := 0
	for _, rec := range s.sessions {
		if rec.UserID == prepared.ID {
			sessions++
		}
	}
	s.mu.Unlock()
	if inviteStillPresent || !userExists || owner != prepared.ID || pendingExists || !approved || sessions != 1 {
		t.Fatalf("atomic registration state wrong: invite=%v user=%v owner=%q pending=%v approved=%v sessions=%d", inviteStillPresent, userExists, owner, pendingExists, approved, sessions)
	}
}

func TestFailedRegistrationDoesNotLeaveOrphanAccount(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19203", StateDir: t.TempDir(), Mode: ModePublic})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	redirect := "http://127.0.0.1:49203/callback"
	s.mu.Lock()
	s.clients["generic-client"] = Client{ID: "generic-client", RedirectURIs: []string{redirect}, IssuedAt: time.Now().Unix()}
	s.pending["bad-register"] = pendingAuth{ClientID: "generic-client", RedirectURI: redirect, Resource: s.absolute("/mcp/unowned-device"), Scope: "mcp offline_access", Expires: time.Now().Add(time.Minute)}
	s.mu.Unlock()
	prepared, err, busy := s.prepareRegistration("orphan-candidate", "orphan-candidate-password-12345")
	if err != nil || busy {
		t.Fatalf("prepare registration: err=%v busy=%v", err, busy)
	}
	if err := s.registerAndGrantAuthorization(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, s.absolute("/oauth/authorize"), nil), "bad-register", prepared, ""); err == nil {
		t.Fatal("registration unexpectedly succeeded for an unowned MCP resource")
	}
	s.mu.Lock()
	_, userExists := s.users[prepared.ID]
	_, usernameExists := s.usernames["orphan-candidate"]
	_, pendingExists := s.pending["bad-register"]
	sessions := len(s.sessions)
	s.mu.Unlock()
	if userExists || usernameExists || !pendingExists || sessions != 0 {
		t.Fatalf("failed registration left artifacts: user=%v username=%v pending=%v sessions=%d", userExists, usernameExists, pendingExists, sessions)
	}
}

func TestRegistrationPersistenceFailureRestoresInviteAndDeviceClaim(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19204", StateDir: t.TempDir(), Mode: ModePublic, RegistrationDisabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	route := "id/" + identity.ID()
	redirect := "http://127.0.0.1:49204/callback"
	invite := randomToken(24)
	s.mu.Lock()
	s.clients["rollback-register-client"] = Client{ID: "rollback-register-client", RedirectURIs: []string{redirect}, DeviceID: identity.ID(), DevicePublicKey: deviceidentity.EncodePublicKey(identity.PublicKey()), DeviceKeyVerified: true, IssuedAt: time.Now().Unix()}
	s.pending["rollback-register"] = pendingAuth{ClientID: "rollback-register-client", RedirectURI: redirect, Resource: s.absolute("/agent/" + route), Scope: "agent:connect offline_access", Expires: time.Now().Add(time.Minute)}
	s.invites[tokenKey(invite)] = inviteRecord{CreatedAt: time.Now().Unix(), Expires: time.Now().Add(time.Hour).Unix(), UsesRemaining: 1}
	s.mu.Unlock()
	prepared, err, busy := s.prepareRegistration("rollback-register-user", "rollback-register-password-12345")
	if err != nil || busy {
		t.Fatalf("prepare registration: err=%v busy=%v", err, busy)
	}
	forceOAuthPersistenceFailure(t, s)
	if err := s.registerAndGrantAuthorization(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, s.absolute("/oauth/authorize"), nil), "rollback-register", prepared, invite); err == nil {
		t.Fatal("expected registration persistence failure")
	}
	s.mu.Lock()
	inviteRecord, invitePresent := s.invites[tokenKey(invite)]
	_, userPresent := s.users[prepared.ID]
	_, devicePresent := s.devices[route]
	_, pendingPresent := s.pending["rollback-register"]
	approved := s.clients["rollback-register-client"].Approved
	codes := len(s.codes)
	s.mu.Unlock()
	if !invitePresent || inviteRecord.UsesRemaining != 1 || userPresent || devicePresent || !pendingPresent || approved || codes != 0 {
		t.Fatalf("failed transaction did not fully roll back: invite=%v/%d user=%v device=%v pending=%v approved=%v codes=%d", invitePresent, inviteRecord.UsesRemaining, userPresent, devicePresent, pendingPresent, approved, codes)
	}
}

func TestAccountViewAndActionsAreTenantScoped(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19205", StateDir: t.TempDir(), Mode: ModePublic})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.mu.Lock()
	alice, err := s.createUserLocked("account-alice", "account-alice-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	bob, err := s.createUserLocked("account-bob", "account-bob-password-123456")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.devices["alice-device"] = alice.ID
	s.deviceRecords["alice-device"] = DeviceRecord{ID: "alice-device", DisplayName: "Alice laptop", OwnerID: alice.ID}
	s.devices["bob-device"] = bob.ID
	s.deviceRecords["bob-device"] = DeviceRecord{ID: "bob-device", DisplayName: "Bob laptop", OwnerID: bob.ID}
	aliceFamily, bobFamily := randomToken(24), randomToken(24)
	s.access[tokenKey("alice-access")] = tokenRecord{ClientID: "shared", UserID: alice.ID, Resource: s.absolute("/mcp/alice-device"), Scope: "mcp", Family: aliceFamily, Expires: time.Now().Add(time.Hour).Unix()}
	s.refresh[tokenKey("alice-refresh")] = tokenRecord{ClientID: "shared", UserID: alice.ID, Resource: s.absolute("/mcp/alice-device"), Scope: "mcp", Family: aliceFamily, Expires: time.Now().Add(time.Hour).Unix()}
	s.access[tokenKey("bob-access")] = tokenRecord{ClientID: "shared", UserID: bob.ID, Resource: s.absolute("/mcp/bob-device"), Scope: "mcp", Family: bobFamily, Expires: time.Now().Add(time.Hour).Unix()}
	s.clients["shared"] = Client{ID: "shared", Name: "Shared MCP client", Approved: true}
	s.mu.Unlock()

	data := s.accountData(httptest.NewRequest(http.MethodGet, s.absolute("/account"), nil), alice)
	if len(data.Devices) != 1 || data.Devices[0].Route != "alice-device" || len(data.Grants) != 1 || data.Grants[0].Resource != s.absolute("/mcp/alice-device") {
		t.Fatalf("alice account leaked or omitted tenant data: devices=%#v grants=%#v", data.Devices, data.Grants)
	}

	s.mu.Lock()
	err = s.applyAccountActionLocked("disable-device", "bob-device", "on", alice, httptest.NewRequest(http.MethodPost, s.absolute("/account/action"), nil))
	s.mu.Unlock()
	if err == nil {
		t.Fatal("alice account action disabled bob's device")
	}

	s.mu.Lock()
	err = s.applyAccountActionLocked("revoke-family", tokenKey(bobFamily), "", alice, httptest.NewRequest(http.MethodPost, s.absolute("/account/action"), nil))
	_, bobTokenStillPresent := s.access[tokenKey("bob-access")]
	s.mu.Unlock()
	if err == nil || !bobTokenStillPresent {
		t.Fatal("alice account action reached bob's token family")
	}
}

func TestConfiguredRegistrationDisableOverridesPersistedOpenState(t *testing.T) {
	stateDir := t.TempDir()
	first, err := New(Config{PublicURL: "http://127.0.0.1:19206", StateDir: stateDir, Mode: ModePublic})
	if err != nil {
		t.Fatal(err)
	}
	first.mu.Lock()
	first.registrationEnabled = true
	if err := first.saveLocked(); err != nil {
		first.mu.Unlock()
		t.Fatal(err)
	}
	first.mu.Unlock()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := New(Config{PublicURL: "http://127.0.0.1:19206", StateDir: stateDir, Mode: ModePublic, ModeConfigured: true, RegistrationDisabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restarted.mu.Lock()
	enabled := restarted.registrationEnabled
	restarted.mu.Unlock()
	if enabled {
		t.Fatal("operator registration-disable configuration was overridden by persisted open-registration state")
	}
}

func TestSetupPendingCannotBeBypassedByInvite(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19207", StateDir: t.TempDir(), Mode: ModePublic, SetupToken: "setup-token-that-is-long-enough-12345"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.mu.Lock()
	s.invites[tokenKey("invite-that-would-otherwise-be-valid-12345")] = inviteRecord{Expires: time.Now().Add(time.Hour).Unix(), UsesRemaining: 1}
	open, inviteOnly := s.registrationPolicyLocked(time.Now())
	s.mu.Unlock()
	if open || inviteOnly {
		t.Fatalf("pending first-run setup was bypassed by registration policy: open=%v inviteOnly=%v", open, inviteOnly)
	}
}

func TestPublicWebSurfacesDiscloseOperatorTrustAndSelfHostingPath(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19208", StateDir: t.TempDir(), Mode: ModePublic})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	landing := httptest.NewRecorder()
	s.handleLanding(landing, httptest.NewRequest(http.MethodGet, s.absolute("/"), nil))
	landingBody := landing.Body.String()
	if !strings.Contains(landingBody, "Do not trust a public Relay with sensitive access") || !strings.Contains(landingBody, "/connect") || !strings.Contains(landingBody, "/account") {
		t.Fatalf("public landing is missing trust/onboarding surfaces: %s", landingBody)
	}

	connect := httptest.NewRecorder()
	s.handleConnect(connect, httptest.NewRequest(http.MethodGet, s.absolute("/connect"), nil))
	connectBody := connect.Body.String()
	if !strings.Contains(connectBody, "Public Relay warning") || !strings.Contains(connectBody, "Self-hosting guide") || !strings.Contains(connectBody, "http://127.0.0.1:19208/mcp") {
		t.Fatalf("connect page is missing trust/self-host guidance: %s", connectBody)
	}

	account := httptest.NewRecorder()
	s.handleAccount(account, httptest.NewRequest(http.MethodGet, s.absolute("/account"), nil))
	if !strings.Contains(account.Body.String(), "Do not trust a public Relay with sensitive access") {
		t.Fatalf("public account login is missing operator trust warning: %s", account.Body.String())
	}
}

func TestAccountDeviceRevokeContractsAuthorityWithoutPassword(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19209", StateDir: t.TempDir(), Mode: ModePublic})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.mu.Lock()
	user, err := s.createUserLocked("revoke-user", "revoke-user-password-12345")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.devices["revoke-device"] = user.ID
	s.deviceRecords["revoke-device"] = DeviceRecord{ID: "revoke-device", DisplayName: "Revoke me", OwnerID: user.ID}
	s.devices["disabled-device"] = user.ID
	s.disabledDevices["disabled-device"] = true
	s.deviceRecords["disabled-device"] = DeviceRecord{ID: "disabled-device", DisplayName: "Disabled", OwnerID: user.ID, Disabled: true}
	s.mu.Unlock()

	session, err := s.createSession(user)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)
	get := httptest.NewRequest(http.MethodGet, s.absolute("/account"), nil)
	get.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	getResponse := httptest.NewRecorder()
	mux.ServeHTTP(getResponse, get)
	csrf := csrfTokenPattern.FindSubmatch(getResponse.Body.Bytes())
	if len(csrf) != 2 {
		t.Fatal("account page did not contain CSRF token")
	}
	var csrfCookie *http.Cookie
	for _, cookie := range getResponse.Result().Cookies() {
		if cookie.Name == accountCSRFCookie {
			csrfCookie = cookie
		}
	}
	if csrfCookie == nil {
		t.Fatal("account page did not set CSRF cookie")
	}

	form := url.Values{"csrf_token": {string(csrf[1])}, "action": {"revoke-device"}, "target": {"revoke-device"}, "confirm": {"REVOKE"}}
	post := httptest.NewRequest(http.MethodPost, s.absolute("/account/action"), strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	post.AddCookie(csrfCookie)
	postResponse := httptest.NewRecorder()
	mux.ServeHTTP(postResponse, post)
	if postResponse.Code != http.StatusSeeOther {
		t.Fatalf("passwordless revoke status=%d body=%s", postResponse.Code, postResponse.Body.String())
	}
	s.mu.Lock()
	_, stillOwned := s.devices["revoke-device"]
	retired := s.retiredDevices["revoke-device"]
	s.mu.Unlock()
	if stillOwned || !retired {
		t.Fatalf("revoke did not retire device: owned=%v retired=%v", stillOwned, retired)
	}

	form = url.Values{"csrf_token": {string(csrf[1])}, "action": {"disable-device"}, "target": {"disabled-device"}, "value": {"off"}}
	post = httptest.NewRequest(http.MethodPost, s.absolute("/account/action"), strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	post.AddCookie(csrfCookie)
	postResponse = httptest.NewRecorder()
	mux.ServeHTTP(postResponse, post)
	if postResponse.Code != http.StatusUnauthorized {
		t.Fatalf("passwordless re-enable status=%d, want 401", postResponse.Code)
	}
}

func TestInstallScriptRoutePointsToCanonicalReviewedScript(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19210", StateDir: t.TempDir(), Mode: ModePublic, GitHubURL: "https://github.com/ifloppy/chat-with-cli"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, s.absolute("/install.sh"), nil))
	if rr.Code != http.StatusTemporaryRedirect {
		t.Fatalf("install route status=%d body=%s", rr.Code, rr.Body.String())
	}
	want := "https://github.com/ifloppy/chat-with-cli/raw/refs/heads/main/install.sh"
	if got := rr.Header().Get("Location"); got != want {
		t.Fatalf("install route location=%q want=%q", got, want)
	}
}
