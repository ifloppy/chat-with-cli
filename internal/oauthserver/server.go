package oauthserver

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ifloppy/chat-with-cli/internal/protocol"
)

const (
	accessLifetime  = time.Hour
	refreshLifetime = 30 * 24 * time.Hour
	codeLifetime    = 5 * time.Minute
	pendingLifetime = 10 * time.Minute
	maxClients      = 2048
)

type Config struct {
	PublicURL     string
	StateDir      string
	Mode          string
	OwnerUsername string
	OwnerPassword string
	// Password is the legacy private-instance bootstrap password alias.
	Password string
}

type Client struct {
	ID           string   `json:"id"`
	Name         string   `json:"name,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	IssuedAt     int64    `json:"issued_at"`
	Approved     bool     `json:"approved,omitempty"`
}

type tokenRecord struct {
	ClientID string `json:"client_id"`
	UserID   string `json:"user_id"`
	Resource string `json:"resource"`
	Scope    string `json:"scope"`
	Expires  int64  `json:"expires"`
}

type diskState struct {
	Clients  map[string]Client        `json:"clients"`
	Access   map[string]tokenRecord   `json:"access"`
	Refresh  map[string]tokenRecord   `json:"refresh"`
	Users    map[string]User          `json:"users"`
	Devices  map[string]string        `json:"devices"`
	Sessions map[string]sessionRecord `json:"sessions"`
}
type pendingAuth struct {
	ClientID      string
	RedirectURI   string
	State         string
	Scope         string
	Resource      string
	CodeChallenge string
	Expires       time.Time
	Attempts      int
	UserID        string
}

type authCode struct {
	pendingAuth
	Expires time.Time
}

type Server struct {
	cfg           Config
	base          *url.URL
	mu            sync.Mutex
	clients       map[string]Client
	access        map[string]tokenRecord
	refresh       map[string]tokenRecord
	pending       map[string]pendingAuth
	codes         map[string]authCode
	users         map[string]User
	usernames     map[string]string
	devices       map[string]string
	sessions      map[string]sessionRecord
	passwordSlots chan struct{}
	stateFile     string
}

func New(cfg Config) (*Server, error) {
	base, err := validatePublicURL(cfg.PublicURL)
	if err != nil {
		return nil, err
	}
	mode, err := normalizeMode(cfg.Mode)
	if err != nil {
		return nil, err
	}
	cfg.Mode = mode
	if cfg.OwnerUsername == "" {
		cfg.OwnerUsername = "owner"
	}
	if cfg.OwnerPassword == "" {
		cfg.OwnerPassword = cfg.Password
	}
	if cfg.StateDir == "" {
		return nil, errors.New("OAuth state directory must not be empty")
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create OAuth state directory: %w", err)
	}
	if err := os.Chmod(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("secure OAuth state directory: %w", err)
	}
	s := &Server{
		cfg: cfg, base: base,
		clients: make(map[string]Client), access: make(map[string]tokenRecord),
		refresh: make(map[string]tokenRecord), pending: make(map[string]pendingAuth),
		codes: make(map[string]authCode), users: make(map[string]User), usernames: make(map[string]string),
		devices: make(map[string]string), sessions: make(map[string]sessionRecord), passwordSlots: make(chan struct{}, 4),
		stateFile: filepath.Join(cfg.StateDir, "oauth-state.json"),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	if mode == ModePrivate && len(s.users) == 0 {
		if cfg.OwnerPassword == "" {
			return nil, errors.New("private instance has no owner yet; provide an owner bootstrap password")
		}
		s.mu.Lock()
		_, err = s.createUserLocked(cfg.OwnerUsername, cfg.OwnerPassword)
		if err == nil {
			err = s.saveLocked()
		}
		s.mu.Unlock()
		if err != nil {
			return nil, fmt.Errorf("create private owner: %w", err)
		}
	}
	return s, nil
}

func validatePublicURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid --public-url %q", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("--public-url must be an origin without credentials, query, or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, errors.New("--public-url must not contain a path")
	}
	host := strings.ToLower(u.Hostname())
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if u.Scheme != "https" && !(loopback && u.Scheme == "http") {
		return nil, errors.New("--public-url must use https except for loopback testing")
	}
	u.Path = ""
	return u, nil
}

func randomToken(bytes int) string {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func tokenKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Server) absolute(path string) string {
	return strings.TrimRight(s.base.String(), "/") + path
}
func (s *Server) load() error {
	data, err := os.ReadFile(s.stateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read OAuth state: %w", err)
	}
	var state diskState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("decode OAuth state: %w", err)
	}
	if state.Clients != nil {
		s.clients = state.Clients
	}
	if state.Access != nil {
		s.access = state.Access
	}
	if state.Refresh != nil {
		s.refresh = state.Refresh
	}
	if state.Users != nil {
		s.users = state.Users
	}
	if state.Devices != nil {
		s.devices = state.Devices
	}
	if state.Sessions != nil {
		s.sessions = state.Sessions
	}
	for id, user := range s.users {
		if normalized, ok := normalizeUsername(user.Username); ok {
			s.usernames[normalized] = id
		}
	}
	s.cleanupLocked(time.Now())
	return s.saveLocked()
}

func (s *Server) saveLocked() error {
	approvedClients := make(map[string]Client)
	for id, client := range s.clients {
		if client.Approved {
			approvedClients[id] = client
		}
	}
	state := diskState{Clients: approvedClients, Access: s.access, Refresh: s.refresh, Users: s.users, Devices: s.devices, Sessions: s.sessions}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.stateFile + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, s.stateFile)
}

func (s *Server) cleanupLocked(now time.Time) {
	unix := now.Unix()
	for key, rec := range s.access {
		if rec.Expires <= unix {
			delete(s.access, key)
		}
	}
	for key, rec := range s.refresh {
		if rec.Expires <= unix || rec.UserID == "" || s.users[rec.UserID].ID == "" {
			delete(s.refresh, key)
		}
	}
	for key, rec := range s.access {
		if rec.UserID == "" || s.users[rec.UserID].ID == "" {
			delete(s.access, key)
		}
	}
	for key, rec := range s.sessions {
		if rec.Expires <= unix || s.users[rec.UserID].ID == "" {
			delete(s.sessions, key)
		}
	}
	for key, p := range s.pending {
		if now.After(p.Expires) {
			delete(s.pending, key)
		}
	}
	for key, code := range s.codes {
		if now.After(code.Expires) {
			delete(s.codes, key)
		}
	}
	for key, client := range s.clients {
		if !client.Approved && now.Sub(time.Unix(client.IssuedAt, 0)) > time.Hour {
			delete(s.clients, key)
		}
	}
}
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleAuthorizationMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.handleRootResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp/{device}", s.handleMCPResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/agent/{device}", s.handleAgentResourceMetadata)
	mux.HandleFunc("POST /oauth/register", s.handleRegister)
	mux.HandleFunc("GET /oauth/authorize", s.handleAuthorizeGET)
	mux.HandleFunc("POST /oauth/authorize", s.handleAuthorizePOST)
	mux.HandleFunc("POST /oauth/token", s.handleToken)
	mux.HandleFunc("POST /oauth/revoke", s.handleRevoke)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) handleAuthorizationMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         s.base.String(),
		"authorization_endpoint":                         s.absolute("/oauth/authorize"),
		"token_endpoint":                                 s.absolute("/oauth/token"),
		"registration_endpoint":                          s.absolute("/oauth/register"),
		"revocation_endpoint":                            s.absolute("/oauth/revoke"),
		"scopes_supported":                               []string{"mcp", "agent:connect", "offline_access"},
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"code_challenge_methods_supported":               []string{"S256"},
		"authorization_response_iss_parameter_supported": true,
	})
}

func (s *Server) resourceMetadata(resource, requiredScope string) map[string]any {
	return map[string]any{
		"resource":                 resource,
		"authorization_servers":    []string{s.base.String()},
		"scopes_supported":         []string{requiredScope},
		"bearer_methods_supported": []string{"header"},
	}
}

func (s *Server) handleRootResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.resourceMetadata(s.base.String(), "mcp"))
}

func (s *Server) handleMCPResourceMetadata(w http.ResponseWriter, r *http.Request) {
	s.handleDeviceResourceMetadata(w, r, "mcp", "mcp")
}

func (s *Server) handleAgentResourceMetadata(w http.ResponseWriter, r *http.Request) {
	s.handleDeviceResourceMetadata(w, r, "agent", "agent:connect")
}

func (s *Server) handleDeviceResourceMetadata(w http.ResponseWriter, r *http.Request, kind, scope string) {
	device := strings.TrimSpace(r.PathValue("device"))
	if !protocol.ValidDeviceName(device) {
		http.NotFound(w, r)
		return
	}
	resource := s.absolute("/" + kind + "/" + device)
	writeJSON(w, http.StatusOK, s.resourceMetadata(resource, scope))
}

func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Fragment != "" || u.User != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if u.Scheme == "https" {
		return true
	}
	return u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1")
}

type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, 64<<10)
	defer body.Close()
	var req registrationRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": "invalid JSON registration metadata"})
		return
	}
	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > 8 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri"})
		return
	}
	for _, redirect := range req.RedirectURIs {
		if !validRedirectURI(redirect) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri", "error_description": "redirect URIs must use HTTPS or loopback HTTP"})
			return
		}
	}
	if req.TokenEndpointAuthMethod != "" && req.TokenEndpointAuthMethod != "none" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": "only token_endpoint_auth_method=none is supported"})
		return
	}
	if len(req.ResponseTypes) > 0 && !contains(req.ResponseTypes, "code") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": "response_types must include code"})
		return
	}
	if len(req.GrantTypes) > 0 && !contains(req.GrantTypes, "authorization_code") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": "grant_types must include authorization_code"})
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(time.Now())
	if len(s.clients) >= maxClients {
		oldestID := ""
		oldestAt := time.Now().Unix() + 1
		for id, client := range s.clients {
			if !client.Approved && client.IssuedAt < oldestAt {
				oldestID, oldestAt = id, client.IssuedAt
			}
		}
		if oldestID == "" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable", "error_description": "client registration limit reached"})
			return
		}
		delete(s.clients, oldestID)
	}
	clientID := randomToken(24)
	client := Client{ID: clientID, Name: strings.TrimSpace(req.ClientName), RedirectURIs: append([]string(nil), req.RedirectURIs...), IssuedAt: time.Now().Unix()}
	s.clients[clientID] = client
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id": clientID, "client_id_issued_at": client.IssuedAt, "client_name": client.Name,
		"redirect_uris": client.RedirectURIs, "token_endpoint_auth_method": "none",
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
		"scope": "mcp agent:connect offline_access",
	})
}

func (s *Server) resourceParts(raw string) (kind, device, canonical string, ok bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !u.IsAbs() || u.RawQuery != "" || u.Fragment != "" {
		return "", "", "", false
	}
	if !strings.EqualFold(u.Scheme, s.base.Scheme) || !strings.EqualFold(u.Host, s.base.Host) {
		return "", "", "", false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 || (parts[0] != "mcp" && parts[0] != "agent") || !protocol.ValidDeviceName(parts[1]) {
		return "", "", "", false
	}
	return parts[0], parts[1], s.absolute("/" + parts[0] + "/" + parts[1]), true
}

func (s *Server) validateResource(raw string) (string, bool) {
	_, _, canonical, ok := s.resourceParts(raw)
	return canonical, ok
}

func normalizeScope(raw, kind string) (string, bool) {
	required := "mcp"
	if kind == "agent" {
		required = "agent:connect"
	}
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return required + " offline_access", true
	}
	seen := map[string]bool{}
	for _, scope := range fields {
		if scope != required && scope != "offline_access" {
			return "", false
		}
		seen[scope] = true
	}
	if !seen[required] {
		return "", false
	}
	out := []string{required}
	if seen["offline_access"] {
		out = append(out, "offline_access")
	}
	return strings.Join(out, " "), true
}

func exactRedirect(client Client, redirect string) bool {
	for _, candidate := range client.RedirectURIs {
		if len(candidate) == len(redirect) && subtle.ConstantTimeCompare([]byte(candidate), []byte(redirect)) == 1 {
			return true
		}
	}
	return false
}

func (s *Server) handleAuthorizeGET(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		s.oauthPageError(w, http.StatusBadRequest, "OAuth client must use authorization code with PKCE S256")
		return
	}
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	kind, _, resource, ok := s.resourceParts(q.Get("resource"))
	if !ok {
		s.oauthPageError(w, http.StatusBadRequest, "OAuth resource must be a local /mcp/<device> or /agent/<device> URL")
		return
	}
	scope, ok := normalizeScope(q.Get("scope"), kind)
	if !ok {
		s.oauthPageError(w, http.StatusBadRequest, "unsupported OAuth scope")
		return
	}

	s.mu.Lock()
	s.cleanupLocked(time.Now())
	client, exists := s.clients[clientID]
	if !exists || !exactRedirect(client, redirectURI) {
		s.mu.Unlock()
		s.oauthPageError(w, http.StatusBadRequest, "unknown client or redirect URI")
		return
	}
	requestID := randomToken(24)
	s.pending[requestID] = pendingAuth{
		ClientID: clientID, RedirectURI: redirectURI, State: q.Get("state"), Scope: scope,
		Resource: resource, CodeChallenge: q.Get("code_challenge"), Expires: time.Now().Add(pendingLifetime),
	}
	s.mu.Unlock()
	user, loggedIn := s.sessionUser(r)
	s.renderAuthorization(w, requestID, client, resource, scope, user, loggedIn)
}

var authorizationTemplate = template.Must(template.New("authorization").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize chat-with-cli</title><style>body{font:16px system-ui;max-width:620px;margin:6vh auto;padding:24px}input,button{font:inherit;padding:10px;width:100%;box-sizing:border-box}button{margin-top:12px}.meta,form{background:#f3f3f3;padding:14px;border-radius:8px;margin-top:14px}.secondary{background:#fafafa}</style></head><body>
<h1>Authorize chat-with-cli</h1><div class="meta"><b>Client:</b> {{.Client}}<br><b>Resource:</b> {{.Resource}}<br><b>Scope:</b> {{.Scope}}</div>
{{if .LoggedIn}}<form method="post" action="/oauth/authorize"><input type="hidden" name="request_id" value="{{.RequestID}}"><p>Signed in as <b>{{.Username}}</b>.</p><button name="decision" value="allow" type="submit">Authorize</button><button name="decision" value="deny" type="submit">Deny</button><button name="decision" value="logout" type="submit">Sign out</button></form>
{{else}}<form method="post" action="/oauth/authorize"><input type="hidden" name="request_id" value="{{.RequestID}}"><h2>Sign in</h2><input name="username" autocomplete="username" placeholder="Username" required><input type="password" name="password" autocomplete="current-password" placeholder="Password" required><button name="decision" value="login" type="submit">Sign in and authorize</button></form>
{{if .Public}}<form class="secondary" method="post" action="/oauth/authorize"><input type="hidden" name="request_id" value="{{.RequestID}}"><h2>Create account</h2><input name="username" autocomplete="username" placeholder="Username" required><input type="password" name="password" autocomplete="new-password" placeholder="Password (12+ characters)" minlength="12" required><button name="decision" value="register" type="submit">Register and authorize</button></form>{{end}}{{end}}
</body></html>`))

func (s *Server) renderAuthorization(w http.ResponseWriter, requestID string, client Client, resource, scope string, user User, loggedIn bool) {
	name := strings.TrimSpace(client.Name)
	if name == "" {
		name = client.ID
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = authorizationTemplate.Execute(w, map[string]any{
		"RequestID": requestID, "Client": name, "Resource": resource, "Scope": scope,
		"LoggedIn": loggedIn, "Username": user.Username, "Public": s.cfg.Mode == ModePublic,
	})
}

func (s *Server) oauthPageError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = fmt.Fprintln(w, message)
}

func redirectOAuthError(w http.ResponseWriter, r *http.Request, redirectURI, state, code string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect URI", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) failAuthorization(requestID string) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, ok := s.pending[requestID]
	if !ok {
		return 0, false
	}
	pending.Attempts++
	if pending.Attempts >= 5 {
		delete(s.pending, requestID)
	} else {
		s.pending[requestID] = pending
	}
	return pending.Attempts, true
}

func (s *Server) handleAuthorizePOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.oauthPageError(w, http.StatusBadRequest, "invalid form")
		return
	}
	requestID := r.Form.Get("request_id")
	s.mu.Lock()
	s.cleanupLocked(time.Now())
	pending, ok := s.pending[requestID]
	s.mu.Unlock()
	if !ok {
		s.oauthPageError(w, http.StatusBadRequest, "authorization request expired")
		return
	}
	decision := r.Form.Get("decision")
	if decision == "logout" {
		s.clearSession(w, r)
		s.mu.Lock()
		client := s.clients[pending.ClientID]
		s.mu.Unlock()
		s.renderAuthorization(w, requestID, client, pending.Resource, pending.Scope, User{}, false)
		return
	}
	if decision == "deny" {
		s.mu.Lock()
		delete(s.pending, requestID)
		s.mu.Unlock()
		redirectOAuthError(w, r, pending.RedirectURI, pending.State, "access_denied")
		return
	}

	var user User
	var authenticated bool
	switch decision {
	case "allow":
		user, authenticated = s.sessionUser(r)
	case "login":
		var busy bool
		user, authenticated, busy = s.authenticate(r.Form.Get("username"), r.Form.Get("password"))
		if busy {
			s.oauthPageError(w, http.StatusTooManyRequests, "login capacity is busy; retry shortly")
			return
		}
	case "register":
		if s.cfg.Mode != ModePublic {
			s.oauthPageError(w, http.StatusForbidden, "registration is disabled on this private instance")
			return
		}
		var err error
		var busy bool
		user, err, busy = s.register(r.Form.Get("username"), r.Form.Get("password"))
		if busy {
			s.oauthPageError(w, http.StatusTooManyRequests, err.Error())
			return
		}
		if err != nil {
			s.oauthPageError(w, http.StatusBadRequest, "registration failed: "+err.Error())
			return
		}
		authenticated = true
	default:
		s.oauthPageError(w, http.StatusBadRequest, "invalid authorization decision")
		return
	}
	if !authenticated {
		attempts, exists := s.failAuthorization(requestID)
		if !exists {
			s.oauthPageError(w, http.StatusBadRequest, "authorization request expired")
		} else if attempts >= 5 {
			s.oauthPageError(w, http.StatusTooManyRequests, "authorization request locked after repeated login failures")
		} else {
			s.oauthPageError(w, http.StatusUnauthorized, "username or password is incorrect")
		}
		return
	}
	if decision == "login" || decision == "register" {
		session, err := s.createSession(user.ID)
		if err != nil {
			s.oauthPageError(w, http.StatusInternalServerError, "failed to persist login session")
			return
		}
		s.setSessionCookie(w, session)
	}
	if err := s.grantAuthorization(w, r, requestID, user.ID); err != nil {
		s.oauthPageError(w, http.StatusForbidden, err.Error())
	}
}

func (s *Server) authorizeResourceLocked(userID, resource string) error {
	kind, device, _, ok := s.resourceParts(resource)
	if !ok {
		return errors.New("invalid authorization resource")
	}
	if s.users[userID].ID == "" {
		return errors.New("unknown authorization user")
	}
	owner := s.devices[device]
	if kind == "agent" {
		if owner == "" {
			s.devices[device] = userID
			return nil
		}
		if owner != userID {
			return errors.New("this device name belongs to another account")
		}
		return nil
	}
	if owner != userID {
		return errors.New("this device is not owned by the signed-in account; connect its Agent first")
	}
	return nil
}

func (s *Server) grantAuthorization(w http.ResponseWriter, r *http.Request, requestID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, ok := s.pending[requestID]
	if !ok || time.Now().After(pending.Expires) {
		return errors.New("authorization request expired")
	}
	if err := s.authorizeResourceLocked(userID, pending.Resource); err != nil {
		return err
	}
	pending.UserID = userID
	code := randomToken(32)
	delete(s.pending, requestID)
	s.codes[tokenKey(code)] = authCode{pendingAuth: pending, Expires: time.Now().Add(codeLifetime)}
	client := s.clients[pending.ClientID]
	client.Approved = true
	s.clients[pending.ClientID] = client
	if err := s.saveLocked(); err != nil {
		delete(s.codes, tokenKey(code))
		return errors.New("failed to persist authorization")
	}
	u, _ := url.Parse(pending.RedirectURI)
	q := u.Query()
	q.Set("code", code)
	if pending.State != "" {
		q.Set("state", pending.State)
	}
	q.Set("iss", s.base.String())
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
	return nil
}

func pkceMatches(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return len(got) == len(challenge) && subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}

func oauthError(w http.ResponseWriter, status int, code, description string) {
	value := map[string]string{"error": code}
	if description != "" {
		value["error_description"] = description
	}
	writeJSON(w, status, value)
}

func (s *Server) issueTokensLocked(clientID, userID, resource, scope string) (access, refresh string, expiresIn int64, err error) {
	now := time.Now()
	access = randomToken(32)
	refresh = randomToken(48)
	s.access[tokenKey(access)] = tokenRecord{ClientID: clientID, UserID: userID, Resource: resource, Scope: scope, Expires: now.Add(accessLifetime).Unix()}
	s.refresh[tokenKey(refresh)] = tokenRecord{ClientID: clientID, UserID: userID, Resource: resource, Scope: scope, Expires: now.Add(refreshLifetime).Unix()}
	if err = s.saveLocked(); err != nil {
		delete(s.access, tokenKey(access))
		delete(s.refresh, tokenKey(refresh))
		return "", "", 0, err
	}
	return access, refresh, int64(accessLifetime.Seconds()), nil
}
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "invalid form")
		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		s.exchangeCode(w, r)
	case "refresh_token":
		s.exchangeRefresh(w, r)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "supported grants are authorization_code and refresh_token")
	}
}

func (s *Server) exchangeCode(w http.ResponseWriter, r *http.Request) {
	codeValue := r.Form.Get("code")
	clientID := r.Form.Get("client_id")
	redirectURI := r.Form.Get("redirect_uri")
	resource := r.Form.Get("resource")
	verifier := r.Form.Get("code_verifier")

	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(time.Now())
	code, ok := s.codes[tokenKey(codeValue)]
	if !ok {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid or expired")
		return
	}
	delete(s.codes, tokenKey(codeValue))
	if code.ClientID != clientID || code.RedirectURI != redirectURI || !pkceMatches(verifier, code.CodeChallenge) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code binding check failed")
		return
	}
	if resource != "" && resource != code.Resource {
		oauthError(w, http.StatusBadRequest, "invalid_target", "resource does not match authorization request")
		return
	}
	access, refresh, expires, err := s.issueTokensLocked(code.ClientID, code.UserID, code.Resource, code.Scope)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to persist token state")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": access, "token_type": "Bearer", "expires_in": expires,
		"refresh_token": refresh, "scope": code.Scope,
	})
}

func (s *Server) exchangeRefresh(w http.ResponseWriter, r *http.Request) {
	refreshValue := r.Form.Get("refresh_token")
	clientID := r.Form.Get("client_id")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(time.Now())
	key := tokenKey(refreshValue)
	record, ok := s.refresh[key]
	if !ok || record.ClientID != clientID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid or expired")
		return
	}
	delete(s.refresh, key)
	access, refresh, expires, err := s.issueTokensLocked(record.ClientID, record.UserID, record.Resource, record.Scope)
	if err != nil {
		// Keep the old refresh token usable in-memory if persistence of the
		// replacement failed. This avoids turning a transient disk failure into
		// an unnecessary re-authorization requirement.
		s.refresh[key] = record
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to persist token state")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": access, "token_type": "Bearer", "expires_in": expires,
		"refresh_token": refresh, "scope": record.Scope,
	})
}
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	key := tokenKey(r.Form.Get("token"))
	s.mu.Lock()
	delete(s.access, key)
	delete(s.refresh, key)
	_ = s.saveLocked()
	s.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) ResourceMetadataURL(resourcePath string) string {
	return s.absolute("/.well-known/oauth-protected-resource" + resourcePath)
}

func bearerValue(header string) string {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

func (s *Server) VerifyAccess(token, resource string) bool {
	return s.VerifyAccessScope(token, resource, "mcp")
}

func (s *Server) VerifyAccessScope(token, resource, requiredScope string) bool {
	if token == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(time.Now())
	record, ok := s.access[tokenKey(token)]
	return ok && record.UserID != "" && record.Resource == resource &&
		strings.Contains(" "+record.Scope+" ", " "+requiredScope+" ")
}

func (s *Server) ProtectResource(staticToken string, next http.Handler) http.Handler {
	return s.ProtectScopedResource(staticToken, "mcp", next)
}

func (s *Server) ProtectScopedResource(staticToken, requiredScope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerValue(r.Header.Get("Authorization"))
		if staticToken != "" && len(token) == len(staticToken) && subtle.ConstantTimeCompare([]byte(token), []byte(staticToken)) == 1 {
			next.ServeHTTP(w, r)
			return
		}
		resource := s.absolute(r.URL.EscapedPath())
		if s.VerifyAccessScope(token, resource, requiredScope) {
			next.ServeHTTP(w, r)
			return
		}
		metadataURL := s.ResourceMetadataURL(r.URL.EscapedPath())
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata=%q, scope=%q`, metadataURL, requiredScope))
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func (s *Server) ClientCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clients)
}

func (s *Server) ApprovedClients() []Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Client, 0, len(s.clients))
	for _, client := range s.clients {
		if client.Approved {
			out = append(out, client)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt > out[j].IssuedAt })
	return out
}
