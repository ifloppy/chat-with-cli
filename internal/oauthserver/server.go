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
	"net"
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
	maxPendingAuth  = 1024
	maxPendingIP    = 8
)

type Config struct {
	PublicURL     string
	StateDir      string
	Mode          string
	OwnerUsername string
	OwnerPassword string
	// RegistrationDisabled closes public account registration. Private mode is
	// always closed regardless of this value.
	RegistrationDisabled bool
	// TrustedProxyCIDRs controls whether X-Forwarded-For/X-Real-IP are used for
	// abuse limits. No proxy headers are trusted when it is empty.
	TrustedProxyCIDRs []string
	// SetupToken enables the local first-run setup endpoint. It is intentionally
	// supplied out-of-band and is never persisted in OAuth state.
	SetupToken     string
	SetupTokenPath string
	Version        string
	GitHubURL      string
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
	Family   string `json:"family,omitempty"`
	Expires  int64  `json:"expires"`
}

type diskState struct {
	Clients         map[string]Client        `json:"clients"`
	Access          map[string]tokenRecord   `json:"access"`
	Refresh         map[string]tokenRecord   `json:"refresh"`
	RefreshUsed     map[string]tokenRecord   `json:"refresh_used,omitempty"`
	Users           map[string]User          `json:"users"`
	Devices         map[string]string        `json:"devices"`
	DisabledDevices map[string]bool          `json:"disabled_devices,omitempty"`
	DeviceRecords   map[string]DeviceRecord  `json:"device_records,omitempty"`
	Sessions        map[string]sessionRecord `json:"sessions"`
	Settings        *settingsState           `json:"settings,omitempty"`
	SecurityEvents  []SecurityEvent          `json:"security_events,omitempty"`
}

type settingsState struct {
	Mode                string `json:"mode"`
	RegistrationEnabled bool   `json:"registration_enabled"`
	DCREnabled          bool   `json:"dcr_enabled"`
	MCPEnabled          bool   `json:"mcp_enabled"`
	AgentEnabled        bool   `json:"agent_enabled"`
	KillSwitch          bool   `json:"kill_switch"`
}

type SecurityEvent struct {
	Time     time.Time `json:"time"`
	Event    string    `json:"event"`
	User     string    `json:"user,omitempty"`
	Device   string    `json:"device,omitempty"`
	RemoteIP string    `json:"remote_ip,omitempty"`
	Success  bool      `json:"success"`
}

type DeviceRecord struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	OwnerID     string `json:"owner_id"`
	CreatedAt   int64  `json:"created_at"`
	LastSeenAt  int64  `json:"last_seen_at,omitempty"`
	Disabled    bool   `json:"disabled,omitempty"`
}
type pendingAuth struct {
	ClientID      string
	RedirectURI   string
	State         string
	Scope         string
	Resource      string
	CodeChallenge string
	CSRFTokenHash string
	RemoteIP      string
	Expires       time.Time
	Attempts      int
	UserID        string
}

type authCode struct {
	pendingAuth
	Expires time.Time
}

type Server struct {
	cfg                 Config
	base                *url.URL
	mu                  sync.Mutex
	clients             map[string]Client
	access              map[string]tokenRecord
	refresh             map[string]tokenRecord
	refreshUsed         map[string]tokenRecord
	pending             map[string]pendingAuth
	codes               map[string]authCode
	users               map[string]User
	usernames           map[string]string
	devices             map[string]string
	disabledDevices     map[string]bool
	deviceRecords       map[string]DeviceRecord
	sessions            map[string]sessionRecord
	passwordSlots       chan struct{}
	stateFile           string
	registrationEnabled bool
	dcrEnabled          bool
	mcpEnabled          bool
	agentEnabled        bool
	killSwitch          bool
	trustedProxies      []*net.IPNet
	rateMu              sync.Mutex
	rates               map[string]rateWindow
	setupTokenHash      string
	setupTokenPath      string
	securityEvents      []SecurityEvent
	statusProvider      func() map[string]DeviceStatus
	startedAt           time.Time
}

type DeviceStatus struct {
	Device      string
	Online      bool
	ConnectedAt time.Time
	LastSeen    time.Time
	InFlight    int
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
	trustedProxies, err := parseTrustedProxyCIDRs(cfg.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create OAuth state directory: %w", err)
	}
	if info, err := os.Lstat(cfg.StateDir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		if err != nil {
			return nil, fmt.Errorf("inspect OAuth state directory: %w", err)
		}
		return nil, errors.New("OAuth state directory must be a real directory")
	}
	if err := os.Chmod(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("secure OAuth state directory: %w", err)
	}
	s := &Server{
		cfg: cfg, base: base,
		clients: make(map[string]Client), access: make(map[string]tokenRecord),
		refresh: make(map[string]tokenRecord), refreshUsed: make(map[string]tokenRecord), pending: make(map[string]pendingAuth),
		codes: make(map[string]authCode), users: make(map[string]User), usernames: make(map[string]string),
		devices: make(map[string]string), disabledDevices: make(map[string]bool), deviceRecords: make(map[string]DeviceRecord), sessions: make(map[string]sessionRecord), passwordSlots: make(chan struct{}, 4),
		stateFile:           filepath.Join(cfg.StateDir, "oauth-state.json"),
		registrationEnabled: mode == ModePublic && !cfg.RegistrationDisabled,
		dcrEnabled:          true,
		mcpEnabled:          true, agentEnabled: true, trustedProxies: trustedProxies,
		rates: make(map[string]rateWindow), setupTokenPath: cfg.SetupTokenPath,
		startedAt: time.Now(),
	}
	if cfg.SetupToken != "" {
		s.setupTokenHash = tokenKey(cfg.SetupToken)
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	if len(s.users) > 0 {
		s.setupTokenHash = ""
	}
	if s.setupTokenHash != "" && len(s.users) == 0 {
		// The local setup token is the only first-run authority. Do not let
		// public registration create a user before the owner completes setup.
		s.registrationEnabled = false
	}
	if s.cfg.Mode == ModePrivate && len(s.users) == 0 {
		if cfg.OwnerPassword == "" {
			if s.setupTokenHash == "" {
				return nil, errors.New("private instance has no owner yet; provide an owner bootstrap password or setup token")
			}
		} else {
			s.mu.Lock()
			_, err = s.createUserLocked(cfg.OwnerUsername, cfg.OwnerPassword, true)
			if err == nil {
				err = s.saveLocked()
			}
			s.mu.Unlock()
			if err != nil {
				return nil, fmt.Errorf("create private owner: %w", err)
			}
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

const oauthCSRFCookie = "cwc_oauth_csrf"

func (s *Server) setCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: oauthCSRFCookie, Value: token, Path: "/oauth/authorize", MaxAge: int(pendingLifetime.Seconds()),
		HttpOnly: true, Secure: s.base.Scheme == "https", SameSite: http.SameSiteStrictMode,
	})
}

func csrfMatches(r *http.Request, expectedHash string) bool {
	if expectedHash == "" {
		return false
	}
	cookie, err := r.Cookie(oauthCSRFCookie)
	if err != nil || cookie.Value == "" || r.FormValue("csrf_token") == "" {
		return false
	}
	provided := r.FormValue("csrf_token")
	return len(cookie.Value) == len(provided) &&
		subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(provided)) == 1 &&
		len(expectedHash) == len(tokenKey(provided)) &&
		subtle.ConstantTimeCompare([]byte(expectedHash), []byte(tokenKey(provided))) == 1
}

func (s *Server) load() error {
	return withStateFileLock(s.stateFile, func() error {
		if info, err := os.Lstat(s.stateFile); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("OAuth state file must not be a symlink")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect OAuth state: %w", err)
		}
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
		if state.RefreshUsed != nil {
			s.refreshUsed = state.RefreshUsed
		}
		if state.Users != nil {
			s.users = state.Users
		}
		if state.Devices != nil {
			s.devices = state.Devices
		}
		if state.DisabledDevices != nil {
			s.disabledDevices = state.DisabledDevices
		}
		if state.DeviceRecords != nil {
			s.deviceRecords = state.DeviceRecords
		}
		if state.Sessions != nil {
			s.sessions = state.Sessions
		}
		if state.Settings != nil {
			if persistedMode, err := normalizeMode(state.Settings.Mode); err == nil && state.Settings.Mode != "" {
				s.cfg.Mode = persistedMode
			}
			s.registrationEnabled = state.Settings.RegistrationEnabled && s.cfg.Mode == ModePublic
			s.dcrEnabled = state.Settings.DCREnabled
			s.mcpEnabled = state.Settings.MCPEnabled
			s.agentEnabled = state.Settings.AgentEnabled
			s.killSwitch = state.Settings.KillSwitch
		}
		if state.SecurityEvents != nil {
			s.securityEvents = append([]SecurityEvent(nil), state.SecurityEvents...)
		}
		for id, user := range s.users {
			if normalized, ok := normalizeUsername(user.Username); ok {
				s.usernames[normalized] = id
			}
			if !user.Admin && strings.EqualFold(user.Username, s.cfg.OwnerUsername) && s.cfg.Mode == ModePrivate {
				user.Admin = true
				s.users[id] = user
			}
		}
		for route, ownerID := range s.devices {
			s.ensureDeviceRecordLocked(route, ownerID)
		}
		s.cleanupLocked(time.Now())
		return s.saveLockedUnlocked()
	})
}

func (s *Server) saveLocked() error {
	return withStateFileLock(s.stateFile, s.saveLockedUnlocked)
}

func (s *Server) saveLockedUnlocked() error {
	registrationEnabled := s.registrationEnabled && s.cfg.Mode == ModePublic
	state := diskState{
		Clients: s.clients, Access: s.access, Refresh: s.refresh, RefreshUsed: s.refreshUsed,
		Users: s.users, Devices: s.devices, DisabledDevices: s.disabledDevices, DeviceRecords: s.deviceRecords, Sessions: s.sessions,
		Settings:       &settingsState{Mode: s.cfg.Mode, RegistrationEnabled: registrationEnabled, DCREnabled: s.dcrEnabled, MCPEnabled: s.mcpEnabled, AgentEnabled: s.agentEnabled, KillSwitch: s.killSwitch},
		SecurityEvents: append([]SecurityEvent(nil), s.securityEvents...),
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if info, err := os.Lstat(s.stateFile); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("OAuth state file must not be a symlink")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(s.stateFile), ".oauth-state-*")
	if err != nil {
		return err
	}
	tmp := tmpFile.Name()
	defer os.Remove(tmp)
	if err := tmpFile.Chmod(0o600); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if _, err := tmpFile.Write(append(data, '\n')); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.stateFile); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(s.stateFile))
	if err != nil {
		return err
	}
	err = dir.Sync()
	_ = dir.Close()
	return err
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
	for key, rec := range s.refreshUsed {
		if rec.Expires <= unix || rec.UserID == "" || s.users[rec.UserID].ID == "" {
			delete(s.refreshUsed, key)
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
	mux.HandleFunc("GET /{$}", s.handleLanding)
	mux.HandleFunc("GET /docs", s.handleDocs)
	mux.HandleFunc("GET /setup", s.handleSetupGET)
	mux.HandleFunc("POST /setup", s.handleSetupPOST)
	mux.HandleFunc("GET /admin", s.handleAdmin)
	mux.HandleFunc("POST /admin/login", s.handleAdminLogin)
	mux.HandleFunc("POST /admin/logout", s.handleAdminLogout)
	mux.HandleFunc("POST /admin/action", s.handleAdminAction)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleAuthorizationMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.handleRootResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp/{device}", s.handleMCPResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp/id/{id}", s.handleMCPResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/agent/{device}", s.handleAgentResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/agent/id/{id}", s.handleAgentResourceMetadata)
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
	if device == "" {
		id := strings.TrimSpace(r.PathValue("id"))
		if !protocol.ValidDeviceID(id) {
			http.NotFound(w, r)
			return
		}
		device = "id/" + id
	}
	if !protocol.ValidDeviceName(device) && !(strings.HasPrefix(device, "id/") && protocol.ValidDeviceID(strings.TrimPrefix(device, "id/"))) {
		http.NotFound(w, r)
		return
	}
	resource := s.absolute("/" + kind + "/" + device)
	writeJSON(w, http.StatusOK, s.resourceMetadata(resource, scope))
}

func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Fragment != "" || u.User != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if strings.EqualFold(u.Scheme, "https") {
		return true
	}
	return strings.EqualFold(u.Scheme, "http") && (host == "localhost" || host == "127.0.0.1" || host == "::1")
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
	if !s.allowRate(r, "dcr", 30, time.Minute) {
		rateLimited(w, 60)
		return
	}
	s.mu.Lock()
	dcrEnabled := s.dcrEnabled
	s.mu.Unlock()
	if !dcrEnabled {
		oauthError(w, http.StatusForbidden, "access_denied", "dynamic client registration is disabled")
		return
	}
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
	if len(req.ClientName) > 256 || len(req.Scope) > 512 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": "client metadata is too large"})
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
	if err := s.saveLocked(); err != nil {
		delete(s.clients, clientID)
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to persist client registration")
		return
	}
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
	if len(parts) < 2 || len(parts) > 3 || (parts[0] != "mcp" && parts[0] != "agent") {
		return "", "", "", false
	}
	device = parts[1]
	if len(parts) == 2 {
		if !protocol.ValidDeviceName(device) {
			return "", "", "", false
		}
	} else {
		if parts[1] != "id" || !protocol.ValidDeviceID(parts[2]) {
			return "", "", "", false
		}
		device = "id/" + parts[2]
	}
	return parts[0], device, s.absolute("/" + parts[0] + "/" + strings.Join(parts[1:], "/")), true
}

func (s *Server) ensureDeviceRecordLocked(route, ownerID string) DeviceRecord {
	record := s.deviceRecords[route]
	if record.ID == "" {
		if strings.HasPrefix(route, "id/") && protocol.ValidDeviceID(strings.TrimPrefix(route, "id/")) {
			record.ID = strings.TrimPrefix(route, "id/")
		} else {
			record.ID = protocol.NewID()
		}
	}
	if record.DisplayName == "" {
		record.DisplayName = strings.TrimPrefix(route, "id/")
	}
	if record.OwnerID == "" {
		record.OwnerID = ownerID
	}
	if record.CreatedAt == 0 {
		record.CreatedAt = time.Now().Unix()
	}
	if s.disabledDevices[route] {
		record.Disabled = true
	}
	s.deviceRecords[route] = record
	return record
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
	if !s.allowRate(r, "authorize-get", 60, time.Minute) {
		rateLimited(w, 60)
		return
	}
	q := r.URL.Query()
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		s.oauthPageError(w, http.StatusBadRequest, "OAuth client must use authorization code with PKCE S256")
		return
	}
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	if len(clientID) == 0 || len(clientID) > 256 || len(redirectURI) == 0 || len(redirectURI) > 2048 || len(q.Get("state")) > 512 || len(q.Get("code_challenge")) != 43 {
		s.oauthPageError(w, http.StatusBadRequest, "OAuth authorization request is too large or has invalid PKCE parameters")
		return
	}
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

	csrfToken := randomToken(24)
	remoteIP := requestIP(r, s.trustedProxies)
	s.mu.Lock()
	s.cleanupLocked(time.Now())
	client, exists := s.clients[clientID]
	if !exists || !exactRedirect(client, redirectURI) {
		s.mu.Unlock()
		s.oauthPageError(w, http.StatusBadRequest, "unknown client or redirect URI")
		return
	}
	if len(s.pending) >= maxPendingAuth {
		s.mu.Unlock()
		rateLimited(w, 60)
		return
	}
	pendingForIP := 0
	for _, pending := range s.pending {
		if pending.RemoteIP == remoteIP {
			pendingForIP++
		}
	}
	if pendingForIP >= maxPendingIP {
		s.mu.Unlock()
		rateLimited(w, 60)
		return
	}
	requestID := randomToken(24)
	s.pending[requestID] = pendingAuth{
		ClientID: clientID, RedirectURI: redirectURI, State: q.Get("state"), Scope: scope,
		Resource: resource, CodeChallenge: q.Get("code_challenge"), CSRFTokenHash: tokenKey(csrfToken), RemoteIP: remoteIP,
		Expires: time.Now().Add(pendingLifetime),
	}
	s.mu.Unlock()
	s.setCSRFCookie(w, csrfToken)
	user, loggedIn := s.sessionUser(r)
	s.renderAuthorizationWithCSRF(w, requestID, client, resource, scope, csrfToken, user, loggedIn)
}

var authorizationTemplate = template.Must(template.New("authorization").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize chat-with-cli</title><style>body{font:16px system-ui;max-width:620px;margin:6vh auto;padding:24px}input,button{font:inherit;padding:10px;width:100%;box-sizing:border-box}button{margin-top:12px}.meta,form{background:#f3f3f3;padding:14px;border-radius:8px;margin-top:14px}.secondary{background:#fafafa}</style></head><body>
<h1>Authorize chat-with-cli</h1><div class="meta"><b>Client:</b> {{.Client}}<br><b>Resource:</b> {{.Resource}}<br><b>Scope:</b> {{.Scope}}</div>
{{if .LoggedIn}}<form method="post" action="/oauth/authorize"><input type="hidden" name="request_id" value="{{.RequestID}}"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><p>Signed in as <b>{{.Username}}</b>.</p><button name="decision" value="allow" type="submit">Authorize</button><button name="decision" value="deny" type="submit">Deny</button><button name="decision" value="logout" type="submit">Sign out</button></form>
{{else}}<form method="post" action="/oauth/authorize"><input type="hidden" name="request_id" value="{{.RequestID}}"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><h2>Sign in</h2><input name="username" autocomplete="username" placeholder="Username" required><input type="password" name="password" autocomplete="current-password" placeholder="Password" required><button name="decision" value="login" type="submit">Sign in and authorize</button></form>
{{if .Public}}<form class="secondary" method="post" action="/oauth/authorize"><input type="hidden" name="request_id" value="{{.RequestID}}"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><h2>Create account</h2><input name="username" autocomplete="username" placeholder="Username" required><input type="password" name="password" autocomplete="new-password" placeholder="Password (12+ characters)" minlength="12" required><button name="decision" value="register" type="submit">Register and authorize</button></form>{{end}}{{end}}
</body></html>`))

func (s *Server) renderAuthorization(w http.ResponseWriter, requestID string, client Client, resource, scope string, user User, loggedIn bool) {
	s.renderAuthorizationWithCSRF(w, requestID, client, resource, scope, "", user, loggedIn)
}

func (s *Server) renderAuthorizationWithCSRF(w http.ResponseWriter, requestID string, client Client, resource, scope, csrfToken string, user User, loggedIn bool) {
	name := strings.TrimSpace(client.Name)
	if name == "" {
		name = client.ID
	}
	s.mu.Lock()
	publicRegistration := s.cfg.Mode == ModePublic && s.registrationEnabled
	s.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = authorizationTemplate.Execute(w, map[string]any{
		"RequestID": requestID, "Client": name, "Resource": resource, "Scope": scope,
		"CSRFToken": csrfToken, "LoggedIn": loggedIn, "Username": user.Username, "Public": publicRegistration,
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
	if !s.allowRate(r, "authorize-post", 30, time.Minute) {
		rateLimited(w, 60)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
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
	if !csrfMatches(r, pending.CSRFTokenHash) {
		s.oauthPageError(w, http.StatusForbidden, "invalid authorization form")
		return
	}
	decision := r.Form.Get("decision")
	if decision == "logout" {
		s.clearSession(w, r)
		csrfToken := randomToken(24)
		s.mu.Lock()
		client := s.clients[pending.ClientID]
		if current, exists := s.pending[requestID]; exists {
			current.CSRFTokenHash = tokenKey(csrfToken)
			s.pending[requestID] = current
		}
		s.mu.Unlock()
		s.setCSRFCookie(w, csrfToken)
		s.renderAuthorizationWithCSRF(w, requestID, client, pending.Resource, pending.Scope, csrfToken, User{}, false)
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
		s.mu.Lock()
		registrationEnabled := s.cfg.Mode == ModePublic && s.registrationEnabled
		s.mu.Unlock()
		if !registrationEnabled {
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
	if s.killSwitch || (kind == "mcp" && !s.mcpEnabled) || (kind == "agent" && !s.agentEnabled) {
		return errors.New("this capability is temporarily disabled by the administrator")
	}
	if s.disabledDevices[device] {
		return errors.New("this device is disabled")
	}
	owner := s.devices[device]
	record := s.ensureDeviceRecordLocked(device, owner)
	if record.Disabled {
		return errors.New("this device is disabled")
	}
	if kind == "agent" {
		if owner == "" {
			s.devices[device] = userID
			record = s.ensureDeviceRecordLocked(device, userID)
			record.OwnerID = userID
			s.deviceRecords[device] = record
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
	return s.issueTokensInFamilyLocked(clientID, userID, resource, scope, randomToken(24))
}

func (s *Server) issueTokensInFamilyLocked(clientID, userID, resource, scope, family string) (access, refresh string, expiresIn int64, err error) {
	now := time.Now()
	access = randomToken(32)
	refresh = randomToken(48)
	if family == "" {
		family = randomToken(24)
	}
	s.access[tokenKey(access)] = tokenRecord{ClientID: clientID, UserID: userID, Resource: resource, Scope: scope, Family: family, Expires: now.Add(accessLifetime).Unix()}
	s.refresh[tokenKey(refresh)] = tokenRecord{ClientID: clientID, UserID: userID, Resource: resource, Scope: scope, Family: family, Expires: now.Add(refreshLifetime).Unix()}
	if err = s.saveLocked(); err != nil {
		delete(s.access, tokenKey(access))
		delete(s.refresh, tokenKey(refresh))
		return "", "", 0, err
	}
	return access, refresh, int64(accessLifetime.Seconds()), nil
}
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if !s.allowRate(r, "token", 120, time.Minute) {
		rateLimited(w, 60)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
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
		if used, replay := s.refreshUsed[key]; replay && (clientID == "" || used.ClientID == clientID) {
			s.revokeFamilyLocked(used.Family)
			_ = s.saveLocked()
		}
		oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid or expired")
		return
	}
	delete(s.refresh, key)
	if record.Family == "" {
		record.Family = randomToken(24)
	}
	s.refreshUsed[key] = record
	access, refresh, expires, err := s.issueTokensInFamilyLocked(record.ClientID, record.UserID, record.Resource, record.Scope, record.Family)
	if err != nil {
		// Keep the old refresh token usable in-memory if persistence of the
		// replacement failed. This avoids turning a transient disk failure into
		// an unnecessary re-authorization requirement.
		delete(s.refreshUsed, key)
		s.refresh[key] = record
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to persist token state")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": access, "token_type": "Bearer", "expires_in": expires,
		"refresh_token": refresh, "scope": record.Scope,
	})
}

func (s *Server) revokeFamilyLocked(family string) {
	if family == "" {
		return
	}
	for key, record := range s.access {
		if record.Family == family {
			delete(s.access, key)
		}
	}
	for key, record := range s.refresh {
		if record.Family == family {
			delete(s.refresh, key)
		}
	}
	for key, record := range s.refreshUsed {
		if record.Family == family {
			delete(s.refreshUsed, key)
		}
	}
}
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.allowRate(r, "revoke", 60, time.Minute) {
		rateLimited(w, 60)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	key := tokenKey(r.Form.Get("token"))
	s.mu.Lock()
	if record, ok := s.refresh[key]; ok {
		s.revokeFamilyLocked(record.Family)
	} else if record, ok := s.refreshUsed[key]; ok {
		s.revokeFamilyLocked(record.Family)
	}
	delete(s.access, key)
	delete(s.refresh, key)
	delete(s.refreshUsed, key)
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
	if !ok || !s.resourceEnabledLocked(resource, requiredScope) {
		return false
	}
	return record.UserID != "" && record.Resource == resource &&
		strings.Contains(" "+record.Scope+" ", " "+requiredScope+" ")
}

func (s *Server) resourceEnabledLocked(resource, requiredScope string) bool {
	if s.killSwitch || (requiredScope == "mcp" && !s.mcpEnabled) || (requiredScope == "agent:connect" && !s.agentEnabled) {
		return false
	}
	_, device, _, ok := s.resourceParts(resource)
	if !ok || s.disabledDevices[device] {
		return false
	}
	if record, exists := s.deviceRecords[device]; exists && record.Disabled {
		return false
	}
	return true
}

func (s *Server) ProtectResource(staticToken string, next http.Handler) http.Handler {
	return s.ProtectScopedResource(staticToken, "mcp", next)
}

func (s *Server) ProtectScopedResource(staticToken, requiredScope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resource := s.absolute(r.URL.EscapedPath())
		s.mu.Lock()
		enabled := s.resourceEnabledLocked(resource, requiredScope)
		s.mu.Unlock()
		if !enabled {
			http.Error(w, "capability disabled", http.StatusServiceUnavailable)
			return
		}
		token := bearerValue(r.Header.Get("Authorization"))
		if staticToken != "" && len(token) == len(staticToken) && subtle.ConstantTimeCompare([]byte(token), []byte(staticToken)) == 1 {
			next.ServeHTTP(w, r)
			return
		}
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
