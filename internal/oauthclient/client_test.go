package oauthclient

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ifloppy/chat-with-cli/internal/deviceidentity"
	"github.com/ifloppy/chat-with-cli/internal/oauthserver"
)

var requestIDPattern = regexp.MustCompile(`name="request_id" value="([^"]+)"`)
var csrfTokenPattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func startTestOAuthServer(t *testing.T, mode string) (*oauthserver.Server, string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	cfg := oauthserver.Config{PublicURL: base, StateDir: t.TempDir(), Mode: mode}
	if mode == oauthserver.ModePrivate {
		cfg.OwnerUsername = "owner"
		cfg.OwnerPassword = "owner-password-123456"
	}
	s, err := oauthserver.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)
	httpServer := &http.Server{Handler: mux}
	go func() { _ = httpServer.Serve(ln) }()
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	}
	return s, base, cleanup
}

func loginBrowser(t *testing.T, username, password, decision string, calls *int) func(string) error {
	t.Helper()
	return func(target string) error {
		*calls = *calls + 1
		cookieJar, err := cookiejar.New(nil)
		if err != nil {
			return err
		}
		client := &http.Client{Jar: cookieJar}
		resp, err := client.Get(target)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		match := requestIDPattern.FindSubmatch(body)
		if len(match) != 2 {
			t.Fatalf("authorization page missing request_id: %s", body)
		}
		csrf := csrfTokenPattern.FindSubmatch(body)
		if len(csrf) != 2 {
			t.Fatalf("authorization page missing CSRF token: %s", body)
		}
		u, _ := url.Parse(target)
		form := url.Values{
			"request_id": {string(match[1])}, "username": {username},
			"password": {password}, "decision": {decision}, "csrf_token": {string(csrf[1])},
		}
		post, err := http.NewRequest(http.MethodPost, u.Scheme+"://"+u.Host+"/oauth/authorize", strings.NewReader(form.Encode()))
		if err != nil {
			return err
		}
		post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err = client.Do(post)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			data, _ := io.ReadAll(resp.Body)
			t.Fatalf("browser authorization status=%d body=%s", resp.StatusCode, data)
		}
		return nil
	}
}

func TestAgentBrowserOAuthPersistsAndRefreshes(t *testing.T) {
	oauth, base, cleanup := startTestOAuthServer(t, oauthserver.ModePrivate)
	defer cleanup()
	path := filepath.Join(t.TempDir(), "credentials.json")
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	manager := &Manager{
		RelayURL: base, Device: "laptop-a", DeviceID: identity.ID(), DeviceIdentity: identity, CredentialsPath: path,
		OpenBrowser: loginBrowser(t, "owner", "owner-password-123456", "login", &calls),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	access, err := manager.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resource, _ := manager.Resource()
	if !oauth.VerifyAccessScope(access, resource, "agent:connect") {
		t.Fatal("browser OAuth access token did not authorize Agent resource")
	}
	if calls != 1 {
		t.Fatalf("browser calls=%d want=1", calls)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("credentials mode=%o want 600", info.Mode().Perm())
	}
	store, err := loadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	cred := store.Profiles[resource]
	if cred.RefreshToken == "" {
		t.Fatal("refresh token was not persisted")
	}
	oldRefresh := cred.RefreshToken
	cred.ExpiresAt = 0
	store.Profiles[resource] = cred
	if err := saveStore(path, store); err != nil {
		t.Fatal(err)
	}
	refreshedAccess, err := manager.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("refresh unexpectedly reopened browser; calls=%d", calls)
	}
	if refreshedAccess == "" || refreshedAccess == access {
		t.Fatal("access token was not refreshed")
	}
	store, err = loadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if store.Profiles[resource].RefreshToken == oldRefresh {
		t.Fatal("refresh token was not rotated in credential store")
	}
}

func TestPublicAgentOAuthCanRegisterAndClaimDevice(t *testing.T) {
	oauth, base, cleanup := startTestOAuthServer(t, oauthserver.ModePublic)
	defer cleanup()
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	manager := &Manager{
		RelayURL: base, Device: "new-user-laptop", DeviceID: identity.ID(), DeviceIdentity: identity, CredentialsPath: filepath.Join(t.TempDir(), "credentials.json"),
		OpenBrowser: loginBrowser(t, "newuser", "new-user-password-123", "register", &calls),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	access, err := manager.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resource, _ := manager.Resource()
	if !oauth.VerifyAccessScope(access, resource, "agent:connect") {
		t.Fatal("registered user did not receive Agent access")
	}
	owner, ok := oauth.DeviceOwner("id/" + identity.ID())
	if !ok || strings.ToLower(owner.Username) != "newuser" {
		t.Fatalf("unexpected device owner: %+v ok=%v", owner, ok)
	}
}

func TestManagerResourceCanonicalizesDeviceIDCase(t *testing.T) {
	manager := &Manager{RelayURL: "https://relay.example", Device: "label", DeviceID: "ABCDEF0123456789ABCDEF0123456789"}
	resource, err := manager.Resource()
	if err != nil {
		t.Fatal(err)
	}
	if resource != "https://relay.example/agent/id/abcdef0123456789abcdef0123456789" {
		t.Fatalf("resource=%q", resource)
	}
}

func TestExplicitLoginReauthorizesAndLogoutRevokesExactResource(t *testing.T) {
	oauth, base, cleanup := startTestOAuthServer(t, oauthserver.ModePrivate)
	defer cleanup()
	path := filepath.Join(t.TempDir(), "credentials.json")
	identity, err := deviceidentity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	manager := &Manager{
		RelayURL: base, Device: "login-device", DeviceID: identity.ID(), DeviceIdentity: identity, CredentialsPath: path,
		OpenBrowser: loginBrowser(t, "owner", "owner-password-123456", "login", &calls),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := manager.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("initial browser calls=%d", calls)
	}
	second, err := manager.Login(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("explicit Login reused cache; browser calls=%d want=2", calls)
	}
	if second == "" || second == first {
		t.Fatal("explicit Login did not replace the access token")
	}
	resource, _ := manager.Resource()
	store, err := loadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	otherResource := base + "/agent/id/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	store.Profiles[otherResource] = Credential{Issuer: base, Resource: otherResource, AccessToken: "other", RefreshToken: "other-refresh", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	if err := saveStore(path, store); err != nil {
		t.Fatal(err)
	}
	removed, err := manager.Logout(ctx)
	if err != nil || !removed {
		t.Fatalf("Logout removed=%v err=%v", removed, err)
	}
	if oauth.VerifyAccessScope(second, resource, "agent:connect") {
		t.Fatal("Logout left the current access token family active")
	}
	store, err = loadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Profiles[resource]; ok {
		t.Fatal("Logout left current resource in local credential store")
	}
	if _, ok := store.Profiles[otherResource]; !ok {
		t.Fatal("Logout removed another device resource")
	}
}
