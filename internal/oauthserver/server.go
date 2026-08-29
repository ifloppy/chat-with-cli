package oauthserver

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
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
	"unicode"
	"unicode/utf8"

	"github.com/ifloppy/chat-with-cli/internal/authzctx"
	"github.com/ifloppy/chat-with-cli/internal/deviceidentity"
	"github.com/ifloppy/chat-with-cli/internal/protocol"
	"github.com/ifloppy/chat-with-cli/internal/securefile"
)

const (
	accessLifetime                          = time.Hour
	refreshLifetime                         = 30 * 24 * time.Hour
	codeLifetime                            = 5 * time.Minute
	pendingLifetime                         = 10 * time.Minute
	maxClients                              = 2048
	maxPendingAuth                          = 1024
	maxPendingIP                            = 8
	maxDevicesUser                          = 16
	maxRateEntries                          = 8192
	maxRegistrationChallengesConsumedDevice = 64
	maxAgentChallengesConsumedDevice        = 64
	registrationChallengeLifetime           = 30 * time.Second
	authorizationChallengeLifetime          = 30 * time.Second
	agentChallengeLifetime                  = 30 * time.Second
	maxAuthorizationChallengesClient        = 64
)

var (
	errAuthorizationRecoveryRequired = errors.New("authorization state recovery is required before ordinary state changes can be persisted")
	errAuthorizationClientInvalid    = errors.New("OAuth client was revoked, expired, or no longer matches the authorization redirect")
)

type Config struct {
	PublicURL string
	StateDir  string
	Mode      string
	// ModeConfigured marks Mode as an explicit operator choice (CLI/config/env).
	// When false, first-run /setup may choose and persist the mode. When true,
	// persisted state must never override the operator's current mode.
	ModeConfigured bool
	OwnerUsername  string
	OwnerPassword  string
	// RegistrationDisabled closes public account registration. Private mode is
	// always closed regardless of this value.
	RegistrationDisabled bool
	// TrustedProxyCIDRs controls whether X-Forwarded-For/X-Real-IP are used for
	// abuse limits. No proxy headers are trusted when it is empty.
	TrustedProxyCIDRs []string
	// EnforceSingleWriter acquires a process-lifetime lease for StateDir.
	// Production Relays must enable it so a stale second process cannot
	// overwrite newer authorization/revocation state.
	EnforceSingleWriter bool
	// AllowLegacyUnboundAgents is an explicit migration-only escape hatch.
	// New deployments must keep it false so Agent bearer tokens are always
	// sender-constrained by an Ed25519 device identity.
	AllowLegacyUnboundAgents bool
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
	ID                string   `json:"id"`
	Name              string   `json:"name,omitempty"`
	RedirectURIs      []string `json:"redirect_uris"`
	DeviceID          string   `json:"device_id,omitempty"`
	DevicePublicKey   string   `json:"device_public_key,omitempty"`
	DeviceKeyVerified bool     `json:"device_key_verified,omitempty"`
	IssuedAt          int64    `json:"issued_at"`
	Approved          bool     `json:"approved,omitempty"`
}

type tokenRecord struct {
	ClientID string `json:"client_id"`
	UserID   string `json:"user_id"`
	Resource string `json:"resource"`
	Scope    string `json:"scope"`
	Family   string `json:"family,omitempty"`
	Expires  int64  `json:"expires"`
}

type inviteRecord struct {
	CreatedAt     int64  `json:"created_at"`
	Expires       int64  `json:"expires"`
	UsesRemaining int    `json:"uses_remaining"`
	CreatedBy     string `json:"created_by,omitempty"`
}

type diskState struct {
	Clients         map[string]Client        `json:"clients"`
	Access          map[string]tokenRecord   `json:"access"`
	Refresh         map[string]tokenRecord   `json:"refresh"`
	RefreshUsed     map[string]tokenRecord   `json:"refresh_used,omitempty"`
	Users           map[string]User          `json:"users"`
	Devices         map[string]string        `json:"devices"`
	DisabledDevices map[string]bool          `json:"disabled_devices,omitempty"`
	RetiredDevices  map[string]bool          `json:"retired_devices,omitempty"`
	DeviceRecords   map[string]DeviceRecord  `json:"device_records,omitempty"`
	Sessions        map[string]sessionRecord `json:"sessions"`
	Invites         map[string]inviteRecord  `json:"invites,omitempty"`
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
	ID              string `json:"id"`
	DisplayName     string `json:"display_name"`
	OwnerID         string `json:"owner_id"`
	DevicePublicKey string `json:"device_public_key,omitempty"`
	CreatedAt       int64  `json:"created_at"`
	LastSeenAt      int64  `json:"last_seen_at,omitempty"`
	Disabled        bool   `json:"disabled,omitempty"`
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
	cfg                             Config
	base                            *url.URL
	mu                              sync.Mutex
	clients                         map[string]Client
	access                          map[string]tokenRecord
	refresh                         map[string]tokenRecord
	refreshUsed                     map[string]tokenRecord
	pending                         map[string]pendingAuth
	codes                           map[string]authCode
	users                           map[string]User
	usernames                       map[string]string
	devices                         map[string]string
	disabledDevices                 map[string]bool
	retiredDevices                  map[string]bool
	deviceRecords                   map[string]DeviceRecord
	sessions                        map[string]sessionRecord
	ephemeralSessions               map[string]struct{}
	invites                         map[string]inviteRecord
	passwordSlots                   chan struct{}
	stateFile                       string
	registrationEnabled             bool
	dcrEnabled                      bool
	mcpEnabled                      bool
	agentEnabled                    bool
	killSwitch                      bool
	trustedProxies                  []*net.IPNet
	rateMu                          sync.Mutex
	rates                           map[string]rateWindow
	consumedRegistrationChallenges  map[string]map[string]int64
	registrationChallengeKey        [32]byte
	consumedAuthorizationChallenges map[string]map[string]int64
	authorizationChallengeKey       [32]byte
	consumedAgentChallenges         map[string]map[string]int64
	agentChallengeKey               [32]byte
	setupTokenHash                  string
	setupTokenPath                  string
	securityEvents                  []SecurityEvent
	statusProvider                  func() map[string]DeviceStatus
	agentSessionResetter            func(device string)
	stateLease                      *stateLease
	stateGuard                      *os.File
	startedAt                       time.Time
	// persistenceFault is a fail-closed latch. Once authorization state cannot
	// be durably written, MCP/Agent access remains frozen until process restart
	// and a clean state load. Availability is preferred over stale authorization.
	persistenceFault bool
}

type DeviceStatus struct {
	Device       string
	Online       bool
	ConnectedAt  time.Time
	LastSeen     time.Time
	InFlight     int
	Capabilities protocol.AgentCapabilities
}

type mutableStateSnapshot struct {
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
	retiredDevices      map[string]bool
	deviceRecords       map[string]DeviceRecord
	sessions            map[string]sessionRecord
	ephemeralSessions   map[string]struct{}
	invites             map[string]inviteRecord
	registrationEnabled bool
	dcrEnabled          bool
	mcpEnabled          bool
	agentEnabled        bool
	killSwitch          bool
	setupTokenHash      string
	securityEvents      []SecurityEvent
	mode                string
}

func cloneMap[K comparable, V any](src map[K]V) map[K]V {
	out := make(map[K]V, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}

func cloneClients(src map[string]Client) map[string]Client {
	out := make(map[string]Client, len(src))
	for key, value := range src {
		value.RedirectURIs = append([]string(nil), value.RedirectURIs...)
		out[key] = value
	}
	return out
}

func (s *Server) snapshotMutableStateLocked() mutableStateSnapshot {
	return mutableStateSnapshot{
		clients: cloneClients(s.clients), access: cloneMap(s.access), refresh: cloneMap(s.refresh), refreshUsed: cloneMap(s.refreshUsed),
		pending: cloneMap(s.pending), codes: cloneMap(s.codes), users: cloneMap(s.users), usernames: cloneMap(s.usernames),
		devices: cloneMap(s.devices), disabledDevices: cloneMap(s.disabledDevices), retiredDevices: cloneMap(s.retiredDevices), deviceRecords: cloneMap(s.deviceRecords), sessions: cloneMap(s.sessions), ephemeralSessions: cloneMap(s.ephemeralSessions), invites: cloneMap(s.invites),
		registrationEnabled: s.registrationEnabled, dcrEnabled: s.dcrEnabled, mcpEnabled: s.mcpEnabled, agentEnabled: s.agentEnabled,
		killSwitch: s.killSwitch, setupTokenHash: s.setupTokenHash, securityEvents: append([]SecurityEvent(nil), s.securityEvents...), mode: s.cfg.Mode,
	}
}

func (s *Server) restoreMutableStateLocked(snapshot mutableStateSnapshot) {
	s.clients, s.access, s.refresh, s.refreshUsed = snapshot.clients, snapshot.access, snapshot.refresh, snapshot.refreshUsed
	s.pending, s.codes, s.users, s.usernames = snapshot.pending, snapshot.codes, snapshot.users, snapshot.usernames
	s.devices, s.disabledDevices, s.retiredDevices, s.deviceRecords, s.sessions, s.ephemeralSessions, s.invites = snapshot.devices, snapshot.disabledDevices, snapshot.retiredDevices, snapshot.deviceRecords, snapshot.sessions, snapshot.ephemeralSessions, snapshot.invites
	s.registrationEnabled, s.dcrEnabled, s.mcpEnabled, s.agentEnabled = snapshot.registrationEnabled, snapshot.dcrEnabled, snapshot.mcpEnabled, snapshot.agentEnabled
	s.killSwitch, s.setupTokenHash, s.securityEvents, s.cfg.Mode = snapshot.killSwitch, snapshot.setupTokenHash, snapshot.securityEvents, snapshot.mode
}

func (s *Server) saveOrRollbackLocked(snapshot mutableStateSnapshot) error {
	if err := s.saveLocked(); err != nil {
		s.restoreMutableStateLocked(snapshot)
		return err
	}
	return nil
}

func (s *Server) saveRecoveryOrRollbackLocked(snapshot mutableStateSnapshot) error {
	if err := s.saveRecoveryLocked(); err != nil {
		s.restoreMutableStateLocked(snapshot)
		return err
	}
	// Keep the process-local recovery markers while the fail-closed latch is
	// active. This lets a freshly authenticated administrator continue to make
	// authority-reducing recovery changes; restart drops the markers and the
	// clean persisted state becomes the source of truth.
	return nil
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
	if err := secureOAuthStateDirectory(cfg.StateDir); err != nil {
		return nil, err
	}
	var lease *stateLease
	if cfg.EnforceSingleWriter {
		lease, err = acquireStateLease(cfg.StateDir)
		if err != nil {
			return nil, fmt.Errorf("acquire OAuth state lease: %w", err)
		}
	}
	guard, guardDirty, err := openStateGuard(cfg.StateDir)
	if err != nil {
		if lease != nil {
			_ = lease.Close()
		}
		return nil, fmt.Errorf("open OAuth state guard: %w", err)
	}
	keepResources := false
	defer func() {
		if !keepResources {
			_ = guard.Close()
			if lease != nil {
				_ = lease.Close()
			}
		}
	}()
	var registrationChallengeKey [32]byte
	if _, err := rand.Read(registrationChallengeKey[:]); err != nil {
		return nil, fmt.Errorf("generate registration challenge key: %w", err)
	}
	var agentChallengeKey [32]byte
	if _, err := rand.Read(agentChallengeKey[:]); err != nil {
		return nil, fmt.Errorf("generate Agent challenge key: %w", err)
	}
	var authorizationChallengeKey [32]byte
	if _, err := rand.Read(authorizationChallengeKey[:]); err != nil {
		return nil, fmt.Errorf("generate authorization challenge key: %w", err)
	}
	s := &Server{
		cfg: cfg, base: base,
		clients: make(map[string]Client), access: make(map[string]tokenRecord),
		refresh: make(map[string]tokenRecord), refreshUsed: make(map[string]tokenRecord), pending: make(map[string]pendingAuth),
		codes: make(map[string]authCode), users: make(map[string]User), usernames: make(map[string]string),
		devices: make(map[string]string), disabledDevices: make(map[string]bool), retiredDevices: make(map[string]bool), deviceRecords: make(map[string]DeviceRecord), sessions: make(map[string]sessionRecord), ephemeralSessions: make(map[string]struct{}), invites: make(map[string]inviteRecord), passwordSlots: make(chan struct{}, 4),
		stateFile:           filepath.Join(cfg.StateDir, "oauth-state.json"),
		registrationEnabled: mode == ModePublic && !cfg.RegistrationDisabled,
		dcrEnabled:          true,
		mcpEnabled:          true, agentEnabled: true, trustedProxies: trustedProxies,
		rates: make(map[string]rateWindow), consumedRegistrationChallenges: make(map[string]map[string]int64), registrationChallengeKey: registrationChallengeKey, consumedAuthorizationChallenges: make(map[string]map[string]int64), authorizationChallengeKey: authorizationChallengeKey, consumedAgentChallenges: make(map[string]map[string]int64), agentChallengeKey: agentChallengeKey, setupTokenPath: cfg.SetupTokenPath,
		stateLease: lease, stateGuard: guard,
		persistenceFault: guardDirty,
		startedAt:        time.Now(),
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
	keepResources = true
	return s, nil
}

// Close releases the production single-writer state lease. It does not alter
// OAuth state or revoke credentials; normal process shutdown simply relinquishes
// the exclusive writer authority for the next Relay process.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	var first error
	if s.stateGuard != nil {
		if err := s.stateGuard.Close(); err != nil {
			first = err
		}
		s.stateGuard = nil
	}
	if s.stateLease != nil {
		if err := s.stateLease.Close(); err != nil && first == nil {
			first = err
		}
		s.stateLease = nil
	}
	return first
}

func validatePublicURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, errors.New("invalid --public-url")
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

func canonicalizeRouteMap[V any](values map[string]V) (map[string]V, error) {
	if values == nil {
		return nil, nil
	}
	out := make(map[string]V, len(values))
	origins := make(map[string]string, len(values))
	for route, value := range values {
		canonical, ok := canonicalDeviceRoute(route)
		if !ok {
			return nil, fmt.Errorf("invalid persisted device route %q", route)
		}
		if previous, exists := origins[canonical]; exists && previous != route {
			return nil, fmt.Errorf("persisted device routes %q and %q alias the same immutable identity", previous, route)
		}
		origins[canonical] = route
		out[canonical] = value
	}
	return out, nil
}

func (s *Server) canonicalizeDiskState(state *diskState) error {
	var err error
	normalizedUsers := make(map[string]string, len(state.Users))
	for mapID, user := range state.Users {
		if mapID == "" || user.ID == "" || user.ID != mapID {
			return fmt.Errorf("persisted user record %s has an inconsistent immutable user ID", shortHandle(mapID))
		}
		normalized, ok := normalizeUsername(user.Username)
		if !ok {
			return fmt.Errorf("persisted user %s has an invalid username", shortHandle(mapID))
		}
		if previous, exists := normalizedUsers[normalized]; exists && previous != mapID {
			return fmt.Errorf("persisted users %s and %s normalize to the same username", shortHandle(previous), shortHandle(mapID))
		}
		normalizedUsers[normalized] = mapID
	}
	for clientID, client := range state.Clients {
		if !clientIDMatches(clientID, client) {
			return fmt.Errorf("persisted OAuth client %s has an inconsistent immutable client ID", shortHandle(clientID))
		}
		hasDeviceIdentity := client.DeviceID != "" || client.DevicePublicKey != "" || client.DeviceKeyVerified
		if !hasDeviceIdentity {
			continue
		}
		canonicalID, ok := protocol.NormalizeDeviceID(client.DeviceID)
		if !ok || client.DevicePublicKey == "" || !client.DeviceKeyVerified {
			return fmt.Errorf("persisted OAuth client %s has incomplete device proof state", shortHandle(clientID))
		}
		pub, err := deviceidentity.DecodePublicKey(client.DevicePublicKey)
		if err != nil {
			return fmt.Errorf("persisted OAuth client %s has invalid device public key", shortHandle(clientID))
		}
		derivedID, _ := deviceidentity.IDFromPublicKey(pub)
		if derivedID != canonicalID {
			return fmt.Errorf("persisted OAuth client %s device key does not match device ID", shortHandle(clientID))
		}
		client.DeviceID = canonicalID
		client.DevicePublicKey = deviceidentity.EncodePublicKey(pub)
		state.Clients[clientID] = client
	}
	state.Devices, err = canonicalizeRouteMap(state.Devices)
	if err != nil {
		return err
	}
	state.DisabledDevices, err = canonicalizeRouteMap(state.DisabledDevices)
	if err != nil {
		return err
	}
	state.RetiredDevices, err = canonicalizeRouteMap(state.RetiredDevices)
	if err != nil {
		return err
	}
	for route, retired := range state.RetiredDevices {
		if !retired {
			delete(state.RetiredDevices, route)
			continue
		}
		if _, active := state.Devices[route]; active {
			return fmt.Errorf("persisted device route %q is both active and permanently retired", route)
		}
	}
	state.DeviceRecords, err = canonicalizeRouteMap(state.DeviceRecords)
	if err != nil {
		return err
	}
	for route, record := range state.DeviceRecords {
		if strings.HasPrefix(route, "id/") {
			record.ID = strings.TrimPrefix(route, "id/")
			if record.DevicePublicKey != "" {
				pub, err := deviceidentity.DecodePublicKey(record.DevicePublicKey)
				if err != nil {
					return fmt.Errorf("persisted device %q has invalid public key", route)
				}
				derivedID, _ := deviceidentity.IDFromPublicKey(pub)
				if derivedID != record.ID {
					return fmt.Errorf("persisted device %q public key does not match immutable ID", route)
				}
				record.DevicePublicKey = deviceidentity.EncodePublicKey(pub)
			}
		} else if record.ID != "" {
			if record.DevicePublicKey != "" {
				return fmt.Errorf("legacy device route %q must not carry an immutable device public key", route)
			}
			id, ok := protocol.NormalizeDeviceID(record.ID)
			if !ok {
				return fmt.Errorf("invalid persisted immutable device ID %q for route %q", record.ID, route)
			}
			record.ID = id
		}
		state.DeviceRecords[route] = record
	}
	for route, ownerID := range state.Devices {
		if ownerID == "" || state.Users[ownerID].ID != ownerID {
			return fmt.Errorf("persisted device route %q references an unknown owner", route)
		}
		if record, exists := state.DeviceRecords[route]; exists && record.OwnerID != "" && record.OwnerID != ownerID {
			return fmt.Errorf("persisted device route %q has conflicting ownership records", route)
		}
	}
	for route, record := range state.DeviceRecords {
		if record.OwnerID != "" && state.Users[record.OwnerID].ID != record.OwnerID {
			return fmt.Errorf("persisted device record %q references an unknown owner", route)
		}
	}
	canonicalizeTokens := func(records map[string]tokenRecord) error {
		for key, record := range records {
			client, clientExists := state.Clients[record.ClientID]
			user, userExists := state.Users[record.UserID]
			if !clientExists || !clientIDMatches(record.ClientID, client) || !client.Approved ||
				!userExists || user.ID != record.UserID || user.Disabled {
				return fmt.Errorf("persisted OAuth token %s has invalid client or user references", shortHandle(key))
			}
			canonical, ok := s.validateResource(record.Resource)
			if !ok {
				return fmt.Errorf("invalid persisted OAuth resource for token %s", shortHandle(key))
			}
			kind, _, _, _ := s.resourceParts(canonical)
			scope, ok := normalizeScope(record.Scope, kind)
			if !ok {
				return fmt.Errorf("invalid persisted OAuth scope for token %s", shortHandle(key))
			}
			record.Resource = canonical
			record.Scope = scope
			records[key] = record
		}
		return nil
	}
	if err := canonicalizeTokens(state.Access); err != nil {
		return err
	}
	if err := canonicalizeTokens(state.Refresh); err != nil {
		return err
	}
	if err := canonicalizeTokens(state.RefreshUsed); err != nil {
		return err
	}
	return nil
}

func (s *Server) load() error {
	return withStateFileLock(s.stateFile, func() error {
		if info, err := os.Lstat(s.stateFile); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return errors.New("OAuth state file must not be a symlink")
			}
			if !info.Mode().IsRegular() {
				return errors.New("OAuth state file must be a regular file")
			}
			if err := securefile.CheckSingleLink(info, "OAuth state file"); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect OAuth state: %w", err)
		}
		data, err := securefile.Read(s.stateFile, "OAuth state file")
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
		if err := s.canonicalizeDiskState(&state); err != nil {
			return fmt.Errorf("canonicalize OAuth state: %w", err)
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
		if state.RetiredDevices != nil {
			s.retiredDevices = state.RetiredDevices
		}
		if state.DeviceRecords != nil {
			s.deviceRecords = state.DeviceRecords
		}
		if state.Sessions != nil {
			s.sessions = state.Sessions
		}
		if state.Settings != nil {
			if !s.cfg.ModeConfigured {
				if persistedMode, err := normalizeMode(state.Settings.Mode); err == nil && state.Settings.Mode != "" {
					s.cfg.Mode = persistedMode
				}
			}
			s.registrationEnabled = state.Settings.RegistrationEnabled && s.cfg.Mode == ModePublic && !s.cfg.RegistrationDisabled
			s.dcrEnabled = state.Settings.DCREnabled
			s.mcpEnabled = state.Settings.MCPEnabled
			s.agentEnabled = state.Settings.AgentEnabled
			s.killSwitch = state.Settings.KillSwitch
		}
		if state.Invites != nil {
			s.invites = cloneMap(state.Invites)
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
		if s.persistenceFault {
			// A dirty guard means a previous authorization mutation may not have
			// reached durable state. Load the last known JSON only for admin
			// recovery; never rewrite it automatically or enable remote access.
			return nil
		}
		return s.saveStateTransactionUnlocked(false)
	})
}

func (s *Server) saveStateTransactionUnlocked(recovery bool) error {
	if s.persistenceFault {
		if !recovery {
			return errAuthorizationRecoveryRequired
		}
		// A recovery write must persist a global stop first. Even after the
		// guard becomes clean, the next process remains fail-closed until an
		// administrator reviews state and explicitly releases the kill switch.
		s.killSwitch = true
	}
	if err := writeStateGuard(s.stateGuard, stateGuardDirty); err != nil {
		return fmt.Errorf("mark OAuth state dirty: %w", err)
	}
	if err := s.saveLockedUnlocked(); err != nil {
		return err
	}
	if err := writeStateGuard(s.stateGuard, stateGuardClean); err != nil {
		return fmt.Errorf("mark OAuth state clean: %w", err)
	}
	return nil
}

func (s *Server) saveLocked() error {
	err := withStateFileLock(s.stateFile, func() error { return s.saveStateTransactionUnlocked(false) })
	if err != nil && !errors.Is(err, errAuthorizationRecoveryRequired) {
		s.persistenceFault = true
	}
	return err
}

func (s *Server) saveRecoveryLocked() error {
	err := withStateFileLock(s.stateFile, func() error { return s.saveStateTransactionUnlocked(true) })
	if err != nil {
		s.persistenceFault = true
	}
	return err
}

func (s *Server) saveLockedUnlocked() error {
	registrationEnabled := s.registrationEnabled && s.cfg.Mode == ModePublic
	state := diskState{
		Clients: s.clients, Access: s.access, Refresh: s.refresh, RefreshUsed: s.refreshUsed,
		Users: s.users, Devices: s.devices, DisabledDevices: s.disabledDevices, RetiredDevices: s.retiredDevices, DeviceRecords: s.deviceRecords, Sessions: s.sessions, Invites: s.invites,
		Settings:       &settingsState{Mode: s.cfg.Mode, RegistrationEnabled: registrationEnabled, DCREnabled: s.dcrEnabled, MCPEnabled: s.mcpEnabled, AgentEnabled: s.agentEnabled, KillSwitch: s.killSwitch},
		SecurityEvents: append([]SecurityEvent(nil), s.securityEvents...),
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if info, err := os.Lstat(s.stateFile); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("OAuth state file must not be a symlink")
		}
		if !info.Mode().IsRegular() {
			return errors.New("OAuth state file must be a regular file")
		}
		if err := securefile.CheckSingleLink(info, "OAuth state file"); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
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
	for key, invite := range s.invites {
		if invite.Expires <= unix || invite.UsesRemaining <= 0 {
			delete(s.invites, key)
		}
	}
	for key, rec := range s.access {
		client, clientExists := s.clients[rec.ClientID]
		if rec.Expires <= unix || !s.activeUserLocked(rec.UserID) || !clientExists || !clientIDMatches(rec.ClientID, client) || !client.Approved || !s.resourceOwnershipIntactLocked(rec.UserID, rec.Resource, s.requiredScopeForResource(rec.Resource)) {
			delete(s.access, key)
		}
	}
	for key, rec := range s.refresh {
		client, clientExists := s.clients[rec.ClientID]
		if rec.Expires <= unix || !s.activeUserLocked(rec.UserID) || !clientExists || !clientIDMatches(rec.ClientID, client) || !client.Approved || !s.resourceOwnershipIntactLocked(rec.UserID, rec.Resource, s.requiredScopeForResource(rec.Resource)) {
			delete(s.refresh, key)
		}
	}
	for key, rec := range s.refreshUsed {
		client, clientExists := s.clients[rec.ClientID]
		if rec.Expires <= unix || !s.activeUserLocked(rec.UserID) || !clientExists || !clientIDMatches(rec.ClientID, client) || !client.Approved || !s.resourceOwnershipIntactLocked(rec.UserID, rec.Resource, s.requiredScopeForResource(rec.Resource)) {
			delete(s.refreshUsed, key)
		}
	}
	for key, rec := range s.sessions {
		if rec.Expires <= unix || !s.activeUserLocked(rec.UserID) {
			delete(s.sessions, key)
			delete(s.ephemeralSessions, key)
		}
	}
	for key := range s.ephemeralSessions {
		if _, exists := s.sessions[key]; !exists {
			delete(s.ephemeralSessions, key)
		}
	}
	for key, p := range s.pending {
		client, clientExists := s.clients[p.ClientID]
		_, device, _, resourceOK := s.resourceParts(p.Resource)
		deviceDisabled := !resourceOK || s.disabledDevices[device] || s.retiredDevices[device]
		if record, exists := s.deviceRecords[device]; exists && record.Disabled {
			deviceDisabled = true
		}
		if now.After(p.Expires) || !clientExists || !clientIDMatches(p.ClientID, client) || (p.UserID != "" && !s.activeUserLocked(p.UserID)) || deviceDisabled {
			delete(s.pending, key)
		}
	}
	for key, code := range s.codes {
		client, clientExists := s.clients[code.ClientID]
		kind, _, _, resourceOK := s.resourceParts(code.Resource)
		requiredScope := "mcp"
		if kind == "agent" {
			requiredScope = "agent:connect"
		}
		if now.After(code.Expires) || !clientExists || !clientIDMatches(code.ClientID, client) || !client.Approved || !s.activeUserLocked(code.UserID) || !resourceOK || !s.resourceOwnershipIntactLocked(code.UserID, code.Resource, requiredScope) {
			delete(s.codes, key)
		}
	}
	for key, client := range s.clients {
		if !client.Approved && now.Sub(time.Unix(client.IssuedAt, 0)) > time.Hour {
			delete(s.clients, key)
			for pendingID, pending := range s.pending {
				if pending.ClientID == key {
					delete(s.pending, pendingID)
				}
			}
			for codeID, code := range s.codes {
				if code.ClientID == key {
					delete(s.codes, codeID)
				}
			}
		}
	}
}

func clientIDMatches(clientID string, client Client) bool {
	return clientID != "" && client.ID == clientID
}

func (s *Server) activeUserLocked(userID string) bool {
	user, exists := s.users[userID]
	return exists && user.ID == userID && !user.Disabled
}

func (s *Server) requiredScopeForResource(resource string) string {
	kind, _, _, ok := s.resourceParts(resource)
	if ok && kind == "agent" {
		return "agent:connect"
	}
	return "mcp"
}

func (s *Server) resourceOwnershipIntactLocked(userID, resource, requiredScope string) bool {
	if !s.activeUserLocked(userID) {
		return false
	}
	kind, device, canonical, ok := s.resourceParts(resource)
	if !ok || canonical != resource ||
		(requiredScope == "mcp" && kind != "mcp") ||
		(requiredScope == "agent:connect" && kind != "agent") {
		return false
	}
	if s.disabledDevices[device] || s.retiredDevices[device] {
		return false
	}
	if record, exists := s.deviceRecords[device]; exists {
		if record.Disabled || (record.OwnerID != "" && record.OwnerID != userID) {
			return false
		}
	}
	return s.devices[device] == userID
}

func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", s.handleLanding)
	mux.HandleFunc("GET /docs", s.handleDocs)
	mux.HandleFunc("GET /connect", s.handleConnect)
	mux.HandleFunc("GET /install.sh", s.handleInstallScript)
	mux.HandleFunc("GET /setup", s.handleSetupGET)
	mux.HandleFunc("POST /setup", s.handleSetupPOST)
	mux.HandleFunc("GET /account", s.handleAccount)
	mux.HandleFunc("POST /account/login", s.handleAccountLogin)
	mux.HandleFunc("POST /account/logout", s.handleAccountLogout)
	mux.HandleFunc("POST /account/action", s.handleAccountAction)
	mux.HandleFunc("GET /admin", s.handleAdmin)
	mux.HandleFunc("GET /admin/reauth", s.handleAdminReauthGET)
	mux.HandleFunc("POST /admin/reauth", s.handleAdminReauthPOST)
	mux.HandleFunc("POST /admin/login", s.handleAdminLogin)
	mux.HandleFunc("POST /admin/logout", s.handleAdminLogout)
	mux.HandleFunc("POST /admin/action", s.handleAdminAction)
	mux.HandleFunc("POST /admin/invite", s.handleAdminInvite)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleAuthorizationMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.handleRootResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp/{device}", s.handleMCPResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp/id/{id}", s.handleMCPResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/agent/{device}", s.handleAgentResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/agent/id/{id}", s.handleAgentResourceMetadata)
	mux.HandleFunc("POST /oauth/register/challenge", s.handleRegistrationChallenge)
	mux.HandleFunc("POST /oauth/register", s.handleRegister)
	mux.HandleFunc("POST /oauth/authorize/challenge", s.handleAuthorizationChallenge)
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
		"issuer":                 s.base.String(),
		"authorization_endpoint": s.absolute("/oauth/authorize"),
		"token_endpoint":         s.absolute("/oauth/token"),
		"registration_endpoint":  s.absolute("/oauth/register"),
		"chat_with_cli_registration_challenge_endpoint":  s.absolute("/oauth/register/challenge"),
		"chat_with_cli_authorization_challenge_endpoint": s.absolute("/oauth/authorize/challenge"),
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
		id, ok := protocol.NormalizeDeviceID(r.PathValue("id"))
		if !ok {
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

func validAgentRedirectURI(raw string) bool {
	if !validRedirectURI(raw) {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "http") {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.IsLoopback()
}

func validOAuthClientName(name string) bool {
	if len(name) > 256 || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func callbackOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	DeviceID                string   `json:"chat_with_cli_device_id,omitempty"`
	DevicePublicKey         string   `json:"chat_with_cli_device_public_key,omitempty"`
	DeviceChallenge         string   `json:"chat_with_cli_device_challenge,omitempty"`
	DeviceProof             string   `json:"chat_with_cli_device_proof,omitempty"`
}

type registrationChallengeRequest struct {
	ClientName      string `json:"client_name"`
	RedirectURI     string `json:"redirect_uri"`
	DeviceID        string `json:"chat_with_cli_device_id"`
	DevicePublicKey string `json:"chat_with_cli_device_public_key"`
}

type authorizationChallengeRequest struct {
	ClientID      string `json:"client_id"`
	RedirectURI   string `json:"redirect_uri"`
	Resource      string `json:"resource"`
	Scope         string `json:"scope"`
	State         string `json:"state"`
	CodeChallenge string `json:"code_challenge"`
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (s *Server) handleRegistrationChallenge(w http.ResponseWriter, r *http.Request) {
	if !s.allowRate(r, "dcr-challenge", 60, time.Minute) {
		rateLimited(w, 60)
		return
	}
	s.mu.Lock()
	dcrEnabled := s.dcrEnabled && !s.persistenceFault
	s.mu.Unlock()
	if !dcrEnabled {
		oauthError(w, http.StatusForbidden, "access_denied", "dynamic client registration is disabled")
		return
	}
	body := http.MaxBytesReader(w, r.Body, 32<<10)
	defer body.Close()
	var req registrationChallengeRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": "invalid JSON registration challenge metadata"})
		return
	}
	clientName := strings.TrimSpace(req.ClientName)
	redirectURI := strings.TrimSpace(req.RedirectURI)
	deviceID, ok := protocol.NormalizeDeviceID(strings.TrimSpace(req.DeviceID))
	if !ok || clientName == "" || !validOAuthClientName(clientName) || !validAgentRedirectURI(redirectURI) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": "Agent registration challenge redirect must use loopback HTTP"})
		return
	}
	pub, err := deviceidentity.DecodePublicKey(strings.TrimSpace(req.DevicePublicKey))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": "chat_with_cli_device_public_key must be an Ed25519 public key"})
		return
	}
	derivedID, _ := deviceidentity.IDFromPublicKey(pub)
	if derivedID != deviceID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": "Agent device ID does not match its public key"})
		return
	}
	encodedPublicKey := deviceidentity.EncodePublicKey(pub)
	s.mu.Lock()
	retired := s.retiredDevices["id/"+deviceID]
	s.mu.Unlock()
	if retired {
		writeJSON(w, http.StatusGone, map[string]string{"error": "invalid_client_metadata", "error_description": "this cryptographic device identity has been permanently retired"})
		return
	}
	challenge, err := s.issueRegistrationChallenge(deviceID, encodedPublicKey, clientName, redirectURI, time.Now().UTC())
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to issue registration challenge")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"challenge": challenge, "expires_in": int(registrationChallengeLifetime.Seconds())})
}

func (s *Server) handleAuthorizationChallenge(w http.ResponseWriter, r *http.Request) {
	if !s.allowRate(r, "authorize-challenge", 60, time.Minute) {
		rateLimited(w, 60)
		return
	}
	body := http.MaxBytesReader(w, r.Body, 32<<10)
	defer body.Close()
	var req authorizationChallengeRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "invalid JSON authorization challenge metadata")
		return
	}
	clientID := strings.TrimSpace(req.ClientID)
	redirectURI := strings.TrimSpace(req.RedirectURI)
	resource := strings.TrimSpace(req.Resource)
	state := strings.TrimSpace(req.State)
	codeChallenge := strings.TrimSpace(req.CodeChallenge)
	if clientID == "" || len(clientID) > 256 || !validAgentRedirectURI(redirectURI) || len(state) == 0 || len(state) > 512 || !validPKCEChallenge(codeChallenge) {
		oauthError(w, http.StatusBadRequest, "invalid_request", "authorization challenge metadata is invalid")
		return
	}
	kind, device, canonical, ok := s.resourceParts(resource)
	if !ok || canonical != resource || kind != "agent" || !strings.HasPrefix(device, "id/") {
		oauthError(w, http.StatusBadRequest, "invalid_target", "authorization challenge requires an immutable Agent resource")
		return
	}
	scope, ok := normalizeScope(strings.TrimSpace(req.Scope), kind)
	if !ok || scope != strings.TrimSpace(req.Scope) {
		oauthError(w, http.StatusBadRequest, "invalid_scope", "authorization challenge scope is invalid")
		return
	}

	s.mu.Lock()
	client, exists := s.clients[clientID]
	validClient := exists && clientIDMatches(clientID, client) && exactRedirect(client, redirectURI)
	if validClient {
		validClient = client.DeviceKeyVerified && client.DeviceID == strings.TrimPrefix(device, "id/") && client.DevicePublicKey != ""
	}
	if validClient {
		_, err := s.validateAgentDeviceKeyLocked(clientID, resource)
		validClient = err == nil && s.resourceEnabledLocked(resource, "agent:connect")
	}
	s.mu.Unlock()
	if !validClient {
		oauthError(w, http.StatusForbidden, "access_denied", "authorization challenge is not valid for this Agent client")
		return
	}

	challenge, err := s.issueAuthorizationChallenge(clientID, redirectURI, resource, scope, state, codeChallenge, time.Now().UTC())
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to issue authorization challenge")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"challenge": challenge, "expires_in": int(authorizationChallengeLifetime.Seconds())})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.allowRate(r, "dcr", 30, time.Minute) {
		rateLimited(w, 60)
		return
	}
	s.mu.Lock()
	dcrEnabled := s.dcrEnabled && !s.persistenceFault
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
	if !validOAuthClientName(req.ClientName) || len(req.Scope) > 512 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": "client metadata is invalid or too large"})
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
	deviceID := strings.TrimSpace(req.DeviceID)
	devicePublicKey := strings.TrimSpace(req.DevicePublicKey)
	deviceChallenge := strings.TrimSpace(req.DeviceChallenge)
	deviceProof := strings.TrimSpace(req.DeviceProof)
	deviceKeyVerified := false
	registrationChallengeHash := ""
	registrationChallengeExpires := int64(0)
	hasDeviceProofFields := deviceID != "" || devicePublicKey != "" || deviceChallenge != "" || deviceProof != ""
	if hasDeviceProofFields {
		if deviceID == "" || devicePublicKey == "" || deviceChallenge == "" || deviceProof == "" || len(req.RedirectURIs) != 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": "incomplete Agent device proof metadata"})
			return
		}
		if !validAgentRedirectURI(req.RedirectURIs[0]) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri", "error_description": "device-bound Agent clients must use a loopback HTTP redirect"})
			return
		}
		canonicalID, ok := protocol.NormalizeDeviceID(deviceID)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": "invalid Agent device ID"})
			return
		}
		pub, err := deviceidentity.DecodePublicKey(devicePublicKey)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": "chat_with_cli_device_public_key must be an Ed25519 public key"})
			return
		}
		derivedID, _ := deviceidentity.IDFromPublicKey(pub)
		devicePublicKey = deviceidentity.EncodePublicKey(pub)
		if canonicalID != derivedID {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": "Agent device ID does not match its public key"})
			return
		}
		registrationChallengeHash, registrationChallengeExpires, ok = s.validateRegistrationChallenge(canonicalID, devicePublicKey, strings.TrimSpace(req.ClientName), req.RedirectURIs[0], deviceChallenge, time.Now().UTC())
		if !ok || !deviceidentity.VerifyRegistrationProof(pub, canonicalID, strings.TrimSpace(req.ClientName), req.RedirectURIs[0], deviceChallenge, deviceProof) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": "invalid or expired Agent registration challenge proof"})
			return
		}
		deviceID = canonicalID
		deviceKeyVerified = true
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
	now := time.Now().UTC()
	s.cleanupLocked(now)
	snapshot := s.snapshotMutableStateLocked()
	if deviceKeyVerified {
		if s.retiredDevices["id/"+deviceID] {
			writeJSON(w, http.StatusGone, map[string]string{"error": "invalid_client_metadata", "error_description": "this cryptographic device identity has been permanently retired"})
			return
		}
		if !s.registrationChallengeAvailableLocked(deviceID, registrationChallengeHash, now) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": "Agent registration challenge was already used"})
			return
		}
	}
	oldestID := ""
	if len(s.clients) >= maxClients {
		oldestAt := now.Unix() + 1
		for id, client := range s.clients {
			if !client.Approved && client.IssuedAt < oldestAt {
				oldestID, oldestAt = id, client.IssuedAt
			}
		}
		if oldestID == "" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable", "error_description": "client registration limit reached"})
			return
		}
	}
	if deviceKeyVerified && !s.consumeRegistrationChallengeLocked(deviceID, registrationChallengeHash, registrationChallengeExpires, now) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": "Agent registration challenge was already used"})
		return
	}
	if oldestID != "" {
		s.revokeClientLocked(oldestID)
	}
	clientID := randomToken(24)
	client := Client{ID: clientID, Name: strings.TrimSpace(req.ClientName), RedirectURIs: append([]string(nil), req.RedirectURIs...), DeviceID: deviceID, DevicePublicKey: devicePublicKey, DeviceKeyVerified: deviceKeyVerified, IssuedAt: time.Now().Unix()}
	s.clients[clientID] = client
	if err := s.saveOrRollbackLocked(snapshot); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to persist client registration")
		return
	}
	registeredScope := "mcp offline_access"
	if client.DeviceKeyVerified {
		registeredScope = "agent:connect offline_access"
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id": clientID, "client_id_issued_at": client.IssuedAt, "client_name": client.Name,
		"redirect_uris": client.RedirectURIs, "token_endpoint_auth_method": "none",
		"chat_with_cli_device_id":           client.DeviceID,
		"chat_with_cli_device_public_key":   client.DevicePublicKey,
		"chat_with_cli_device_key_verified": client.DeviceKeyVerified,
		"grant_types":                       []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
		"scope": registeredScope,
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
		canonicalID, valid := protocol.NormalizeDeviceID(parts[2])
		if parts[1] != "id" || !valid {
			return "", "", "", false
		}
		parts[2] = canonicalID
		device = "id/" + canonicalID
	}
	return parts[0], device, s.absolute("/" + parts[0] + "/" + strings.Join(parts[1:], "/")), true
}

func canonicalDeviceRoute(route string) (string, bool) {
	route = strings.TrimSpace(route)
	if strings.HasPrefix(route, "id/") {
		id, ok := protocol.NormalizeDeviceID(strings.TrimPrefix(route, "id/"))
		if !ok {
			return "", false
		}
		return "id/" + id, true
	}
	if !protocol.ValidDeviceName(route) {
		return "", false
	}
	return route, true
}

func (s *Server) ensureDeviceRecordLocked(route, ownerID string) DeviceRecord {
	if canonical, ok := canonicalDeviceRoute(route); ok {
		route = canonical
	}
	record := s.deviceRecords[route]
	if record.ID == "" {
		if strings.HasPrefix(route, "id/") {
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
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || !validPKCEChallenge(q.Get("code_challenge")) {
		s.oauthPageError(w, http.StatusBadRequest, "OAuth client must use authorization code with PKCE S256")
		return
	}
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	deviceProof := strings.TrimSpace(q.Get("chat_with_cli_device_proof"))
	authorizationChallenge := strings.TrimSpace(q.Get("chat_with_cli_authorization_challenge"))
	if len(clientID) == 0 || len(clientID) > 256 || len(redirectURI) == 0 || len(redirectURI) > 2048 || len(q.Get("state")) > 512 || len(deviceProof) > 256 || len(authorizationChallenge) > 256 {
		s.oauthPageError(w, http.StatusBadRequest, "OAuth authorization request is too large or has invalid PKCE parameters")
		return
	}
	kind, device, resource, ok := s.resourceParts(q.Get("resource"))
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
	authorizationChallengeHash := ""
	authorizationChallengeExpires := int64(0)
	s.mu.Lock()
	s.cleanupLocked(time.Now())
	client, exists := s.clients[clientID]
	if !exists || !clientIDMatches(clientID, client) || !exactRedirect(client, redirectURI) {
		s.mu.Unlock()
		s.oauthPageError(w, http.StatusBadRequest, "unknown client or redirect URI")
		return
	}
	hasDeviceIdentity := client.DeviceKeyVerified || client.DeviceID != "" || client.DevicePublicKey != ""
	if hasDeviceIdentity {
		expected := "id/" + client.DeviceID
		if !client.DeviceKeyVerified || client.DeviceID == "" || client.DevicePublicKey == "" || kind != "agent" || device != expected {
			s.mu.Unlock()
			s.oauthPageError(w, http.StatusForbidden, "this device-bound OAuth client may only authorize its exact Agent resource")
			return
		}
		if _, err := s.validateAgentDeviceKeyLocked(clientID, resource); err != nil {
			s.mu.Unlock()
			s.oauthPageError(w, http.StatusForbidden, "this device-bound OAuth client has invalid device identity metadata")
			return
		}
		pub, err := deviceidentity.DecodePublicKey(client.DevicePublicKey)
		var challengeOK bool
		authorizationChallengeHash, authorizationChallengeExpires, challengeOK = s.validateAuthorizationChallenge(clientID, redirectURI, resource, scope, q.Get("state"), q.Get("code_challenge"), authorizationChallenge, time.Now().UTC())
		if err != nil || !challengeOK || !deviceidentity.VerifyAuthorizationProof(pub, clientID, redirectURI, resource, scope, q.Get("state"), q.Get("code_challenge"), authorizationChallenge, deviceProof) {
			s.mu.Unlock()
			s.oauthPageError(w, http.StatusForbidden, "this device-bound OAuth client must prove possession of its device identity for authorization")
			return
		}
	} else if kind == "agent" && !s.cfg.AllowLegacyUnboundAgents {
		s.mu.Unlock()
		s.oauthPageError(w, http.StatusForbidden, "unbound OAuth clients cannot authorize Agent resources; run current agent setup with a cryptographic device identity")
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
	if hasDeviceIdentity && !s.consumeAuthorizationChallengeLocked(clientID, authorizationChallengeHash, authorizationChallengeExpires, time.Now().UTC()) {
		s.mu.Unlock()
		s.oauthPageError(w, http.StatusForbidden, "this device-bound OAuth authorization challenge was already used or is unavailable")
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
	s.renderAuthorizationWithCSRF(w, requestID, client, resource, scope, redirectURI, csrfToken, user, loggedIn)
}

var authorizationTemplate = template.Must(template.New("authorization").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize chat-with-cli</title><style>:root{color-scheme:light dark}body{font:16px system-ui;max-width:620px;margin:6vh auto;padding:24px;line-height:1.5}input,button{font:inherit;padding:10px;width:100%;box-sizing:border-box}button{margin-top:12px}.meta,form,.identity{border:1px solid #8885;background:#8881;padding:14px;border-radius:10px;margin-top:14px}.secondary{background:#8881}.verified{border-color:#18803888;background:#18803814}.warning{border-color:#b8860b88;background:#b8860b14}.muted{color:#777}code{overflow-wrap:anywhere}</style></head><body>
<h1>Authorize chat-with-cli</h1>{{if .PublicInstance}}<div class="identity warning"><b>Public Relay operator is inside the trust boundary</b><br>This Relay can observe or modify MCP requests and results, and its operator can run modified server code. User-to-user isolation does not protect you from the operator. Do not use any public instance for secrets or high-trust computer access; self-host a private Relay instead.</div>{{end}}<div class="meta"><b>Client name:</b> {{.Client}}<br><b>Client ID:</b> <code>{{.ClientID}}</code><br><b>Callback:</b> <code>{{.Callback}}</code><br><b>Resource:</b> <code>{{.Resource}}</code><br><b>Scope:</b> {{.Scope}}</div>
{{if .UnverifiedClient}}<div class="identity warning"><b>Unverified dynamic OAuth client</b><br>The client name above is self-asserted. Only authorize if the callback origin matches the application you intended to connect.</div>{{end}}
{{if .VerifiedDevice}}<div class="identity verified"><b>Verified device identity</b><br>This Agent proved possession of the Ed25519 private key for device <code>{{.DeviceID}}</code>. The Relay requires a request-bound signed proof for authorization and a fresh signed proof on every Agent connection.</div>{{else if .AgentDevice}}<div class="identity warning"><b>Legacy unbound Agent</b><br>This device has no verified cryptographic identity. OAuth still enforces account/resource ownership, but a stolen Agent bearer could impersonate this legacy device until it is migrated.</div>{{end}}
{{if .LoggedIn}}<form method="post" action="/oauth/authorize"><input type="hidden" name="request_id" value="{{.RequestID}}"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><p>Signed in as <b>{{.Username}}</b>.</p><button name="decision" value="allow" type="submit">Authorize</button><button name="decision" value="deny" type="submit">Deny</button><button name="decision" value="logout" type="submit">Sign out</button></form>
{{else}}<form method="post" action="/oauth/authorize"><input type="hidden" name="request_id" value="{{.RequestID}}"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><h2>Sign in</h2><input name="username" autocomplete="username" placeholder="Username" required><input type="password" name="password" autocomplete="current-password" placeholder="Password" required><button name="decision" value="login" type="submit">Sign in and authorize</button></form>
{{if .RegistrationAvailable}}<form class="secondary" method="post" action="/oauth/authorize"><input type="hidden" name="request_id" value="{{.RequestID}}"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><h2>Create account</h2>{{if .InviteRequired}}<p class="muted">Open registration is disabled. A single-use invite from this instance operator is required.</p><input name="invite_code" autocomplete="off" placeholder="Invite code" required>{{end}}<input name="username" autocomplete="username" placeholder="Username" required><input type="password" name="password" autocomplete="new-password" placeholder="Password (12+ characters)" minlength="12" required><button name="decision" value="register" type="submit">Register and authorize</button></form>{{end}}{{end}}
</body></html>`))

func (s *Server) renderAuthorization(w http.ResponseWriter, requestID string, client Client, resource, scope string, user User, loggedIn bool) {
	redirectURI := ""
	if len(client.RedirectURIs) == 1 {
		redirectURI = client.RedirectURIs[0]
	}
	s.renderAuthorizationWithCSRF(w, requestID, client, resource, scope, redirectURI, "", user, loggedIn)
}

func (s *Server) renderAuthorizationWithCSRF(w http.ResponseWriter, requestID string, client Client, resource, scope, redirectURI, csrfToken string, user User, loggedIn bool) {
	name := strings.TrimSpace(client.Name)
	if name == "" {
		name = client.ID
	}
	kind, route, _, resourceOK := s.resourceParts(resource)
	agentDevice := resourceOK && kind == "agent" && strings.HasPrefix(route, "id/")
	verifiedDevice := agentDevice && client.DeviceKeyVerified && client.DeviceID == strings.TrimPrefix(route, "id/") && client.DevicePublicKey != ""
	deviceID := ""
	if agentDevice {
		deviceID = strings.TrimPrefix(route, "id/")
	}
	s.mu.Lock()
	publicInstance := s.cfg.Mode == ModePublic
	openRegistration, inviteOnly := s.registrationPolicyLocked(time.Now())
	s.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	callback := "unknown"
	if origin := callbackOrigin(redirectURI); origin != "" {
		callback = origin
	}
	_ = authorizationTemplate.Execute(w, map[string]any{
		"RequestID": requestID, "Client": name, "ClientID": client.ID, "Callback": callback, "Resource": resource, "Scope": scope,
		"CSRFToken": csrfToken, "LoggedIn": loggedIn, "Username": user.Username, "PublicInstance": publicInstance,
		"RegistrationAvailable": openRegistration || inviteOnly, "InviteRequired": inviteOnly,
		"AgentDevice": agentDevice, "VerifiedDevice": verifiedDevice, "UnverifiedClient": !verifiedDevice, "DeviceID": deviceID,
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
	pending, ok := s.pending[requestID]
	if ok && time.Now().After(pending.Expires) {
		delete(s.pending, requestID)
		ok = false
	}
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
		s.renderAuthorizationWithCSRF(w, requestID, client, pending.Resource, pending.Scope, pending.RedirectURI, csrfToken, User{}, false)
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
		prepared, err, busy := s.prepareRegistration(r.Form.Get("username"), r.Form.Get("password"))
		if busy {
			s.oauthPageError(w, http.StatusTooManyRequests, err.Error())
			return
		}
		if err != nil {
			s.oauthPageError(w, http.StatusBadRequest, "registration failed: "+err.Error())
			return
		}
		if err := s.registerAndGrantAuthorization(w, r, requestID, prepared, r.Form.Get("invite_code")); err != nil {
			s.oauthPageError(w, http.StatusForbidden, "registration failed: "+err.Error())
		}
		return
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
		session, err := s.createSession(user)
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

func (s *Server) validateAgentDeviceKeyLocked(clientID, resource string) (string, error) {
	kind, device, _, ok := s.resourceParts(resource)
	if !ok || kind != "agent" || !strings.HasPrefix(device, "id/") {
		return "", nil
	}
	id, ok := protocol.NormalizeDeviceID(strings.TrimPrefix(device, "id/"))
	if !ok {
		return "", errors.New("invalid immutable device ID")
	}
	client := s.clients[clientID]
	record := s.deviceRecords[device]
	owner := s.devices[device]
	encoded := strings.TrimSpace(client.DevicePublicKey)
	if encoded != "" && (!client.DeviceKeyVerified || client.DeviceID != id) {
		return "", errors.New("Agent OAuth client did not prove possession of the device identity during registration")
	}
	if encoded == "" {
		if owner == "" {
			return "", errors.New("new immutable devices require an Ed25519 device identity; rerun agent setup/login with a current client")
		}
		if record.DevicePublicKey != "" {
			return "", errors.New("this device is bound to an Ed25519 identity; the authorizing Agent client did not prove that identity")
		}
		// Compatibility for already-owned alpha devices. They remain visibly
		// unbound until the owner reauthorizes with a current Agent client.
		return "", nil
	}
	pub, err := deviceidentity.DecodePublicKey(encoded)
	if err != nil {
		return "", errors.New("invalid Agent device public key")
	}
	derived, err := deviceidentity.IDFromPublicKey(pub)
	if err != nil || derived != id {
		return "", errors.New("Agent device public key does not match the immutable device ID")
	}
	normalized := deviceidentity.EncodePublicKey(pub)
	if record.DevicePublicKey != "" && record.DevicePublicKey != normalized {
		return "", errors.New("this device is already bound to a different cryptographic identity")
	}
	return normalized, nil
}

func (s *Server) authorizeResourceLocked(userID, clientID, resource string) error {
	kind, device, _, ok := s.resourceParts(resource)
	if !ok {
		return errors.New("invalid authorization resource")
	}
	user, exists := s.users[userID]
	if !exists || user.ID == "" {
		return errors.New("unknown authorization user")
	}
	if user.Disabled {
		return errors.New("authorization user is disabled")
	}
	devicePublicKey, err := s.validateAgentDeviceKeyLocked(clientID, resource)
	if err != nil {
		return err
	}
	if s.persistenceFault {
		return errors.New("authorization state persistence failed; Relay access is frozen until restart after storage repair")
	}
	if s.killSwitch || (kind == "mcp" && !s.mcpEnabled) || (kind == "agent" && !s.agentEnabled) {
		return errors.New("this capability is temporarily disabled by the administrator")
	}
	if s.retiredDevices[device] {
		return errors.New("this device identity was permanently revoked; generate a new device identity")
	}
	if s.disabledDevices[device] {
		return errors.New("this device is disabled")
	}
	owner := s.devices[device]
	record := s.deviceRecords[device]
	if record.OwnerID != "" && owner != "" && record.OwnerID != owner {
		return errors.New("device ownership state is inconsistent")
	}
	if owner == "" && record.OwnerID != "" {
		return errors.New("this device has an orphaned ownership record; it must be retired by an administrator")
	}
	if record.Disabled {
		return errors.New("this device is disabled")
	}
	if kind == "agent" {
		if owner == "" {
			if s.cfg.Mode == ModePublic && !strings.HasPrefix(device, "id/") {
				return errors.New("public instances require an immutable device ID for first claim; legacy name routes are compatibility-only")
			}
			owned := 0
			for _, candidate := range s.devices {
				if candidate == userID {
					owned++
				}
			}
			if owned >= maxDevicesUser {
				return errors.New("device quota reached for this account")
			}
			s.devices[device] = userID
			record = s.ensureDeviceRecordLocked(device, userID)
			record.OwnerID = userID
			if devicePublicKey != "" {
				record.DevicePublicKey = devicePublicKey
			}
			s.deviceRecords[device] = record
			return nil
		}
		if owner != userID {
			return errors.New("this device name belongs to another account")
		}
		if devicePublicKey != "" {
			record := s.ensureDeviceRecordLocked(device, userID)
			record.DevicePublicKey = devicePublicKey
			s.deviceRecords[device] = record
		}
		return nil
	}
	if owner != userID {
		return errors.New("this device is not owned by the signed-in account; connect its Agent first")
	}
	return nil
}

func agentDisplayNameHint(client Client) string {
	const prefix = "chat-with-cli agent "
	if !strings.HasPrefix(client.Name, prefix) {
		return ""
	}
	name := strings.TrimSpace(strings.TrimPrefix(client.Name, prefix))
	if !validateDeviceDisplayName(name) {
		return ""
	}
	return name
}

func (s *Server) commitAuthorizationLocked(requestID, userID string) (pendingAuth, string, error) {
	pending, ok := s.pending[requestID]
	if !ok || time.Now().After(pending.Expires) {
		return pendingAuth{}, "", errors.New("authorization request expired")
	}
	client, exists := s.clients[pending.ClientID]
	if !exists || !clientIDMatches(pending.ClientID, client) || !exactRedirect(client, pending.RedirectURI) {
		return pendingAuth{}, "", errAuthorizationClientInvalid
	}
	if err := s.authorizeResourceLocked(userID, pending.ClientID, pending.Resource); err != nil {
		return pendingAuth{}, "", err
	}
	if kind, device, _, ok := s.resourceParts(pending.Resource); ok && kind == "agent" {
		if hint := agentDisplayNameHint(client); hint != "" {
			record := s.ensureDeviceRecordLocked(device, userID)
			defaultName := strings.TrimPrefix(device, "id/")
			if record.DisplayName == "" || record.DisplayName == record.ID || record.DisplayName == defaultName {
				record.DisplayName = hint
				s.deviceRecords[device] = record
			}
		}
	}
	pending.UserID = userID
	code := randomToken(32)
	delete(s.pending, requestID)
	s.codes[tokenKey(code)] = authCode{pendingAuth: pending, Expires: time.Now().Add(codeLifetime)}
	client.Approved = true
	s.clients[pending.ClientID] = client
	return pending, code, nil
}

func (s *Server) redirectAuthorization(w http.ResponseWriter, r *http.Request, pending pendingAuth, code string) {
	u, _ := url.Parse(pending.RedirectURI)
	q := u.Query()
	q.Set("code", code)
	if pending.State != "" {
		q.Set("state", pending.State)
	}
	q.Set("iss", s.base.String())
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) grantAuthorization(w http.ResponseWriter, r *http.Request, requestID, userID string) error {
	s.mu.Lock()
	snapshot := s.snapshotMutableStateLocked()
	pending, code, err := s.commitAuthorizationLocked(requestID, userID)
	if err != nil {
		s.restoreMutableStateLocked(snapshot)
		if errors.Is(err, errAuthorizationClientInvalid) {
			delete(s.pending, requestID)
			_ = s.saveLocked()
		}
		s.mu.Unlock()
		return err
	}
	if err := s.saveOrRollbackLocked(snapshot); err != nil {
		s.mu.Unlock()
		return errors.New("failed to persist authorization")
	}
	s.mu.Unlock()
	s.redirectAuthorization(w, r, pending, code)
	return nil
}

func (s *Server) registerAndGrantAuthorization(w http.ResponseWriter, r *http.Request, requestID string, user User, inviteCode string) error {
	normalized, ok := normalizeUsername(user.Username)
	if !ok || user.ID == "" || user.PasswordHash == "" {
		return errors.New("invalid registration")
	}
	now := time.Now()
	session := randomToken(32)
	s.mu.Lock()
	openRegistration, inviteOnly := s.registrationPolicyLocked(now)
	if !openRegistration && !inviteOnly {
		s.mu.Unlock()
		return errors.New("registration is closed")
	}
	if _, exists := s.usernames[normalized]; exists {
		s.mu.Unlock()
		return errors.New("username is already registered")
	}
	if len(s.users) >= maxUsers {
		s.mu.Unlock()
		return errors.New("user limit reached")
	}
	snapshot := s.snapshotMutableStateLocked()
	s.users[user.ID] = user
	s.usernames[normalized] = user.ID
	if !s.consumeInviteLocked(inviteCode, now) {
		s.restoreMutableStateLocked(snapshot)
		s.mu.Unlock()
		return errors.New("a valid invite is required while open registration is disabled")
	}
	pending, code, err := s.commitAuthorizationLocked(requestID, user.ID)
	if err != nil {
		s.restoreMutableStateLocked(snapshot)
		if errors.Is(err, errAuthorizationClientInvalid) {
			delete(s.pending, requestID)
			_ = s.saveLocked()
		}
		s.mu.Unlock()
		return err
	}
	handle := tokenKey(session)
	nowUnix := now.Unix()
	s.sessions[handle] = sessionRecord{UserID: user.ID, CreatedAt: nowUnix, LastSeenAt: nowUnix, LastReauthAt: nowUnix, Expires: now.Add(sessionLifetime).Unix()}
	s.recordSecurityLocked(SecurityEvent{Event: "self_register", User: user.Username, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
	if err := s.saveOrRollbackLocked(snapshot); err != nil {
		s.mu.Unlock()
		return errors.New("failed to persist registration and authorization")
	}
	s.mu.Unlock()
	s.setSessionCookie(w, session)
	s.redirectAuthorization(w, r, pending, code)
	return nil
}

func pkceMatches(verifier, challenge string) bool {
	if !validPKCEVerifier(verifier) || !validPKCEChallenge(challenge) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return len(got) == len(challenge) && subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}

func validPKCEChallenge(challenge string) bool {
	if len(challenge) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	return err == nil && len(decoded) == sha256.Size
}

func validPKCEVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for _, r := range verifier {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || strings.ContainsRune("-._~", r) {
			continue
		}
		return false
	}
	return true
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
	client, clientExists := s.clients[code.ClientID]
	if !clientExists || !clientIDMatches(code.ClientID, client) || !client.Approved || code.ClientID != clientID || code.RedirectURI != redirectURI || !pkceMatches(verifier, code.CodeChallenge) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code binding check failed")
		return
	}
	if resource == "" || resource != code.Resource {
		oauthError(w, http.StatusBadRequest, "invalid_target", "resource is required and must exactly match the authorization grant")
		return
	}
	kind, _, _, resourceOK := s.resourceParts(code.Resource)
	requiredScope := "mcp"
	if kind == "agent" {
		requiredScope = "agent:connect"
	}
	if !resourceOK || !s.resourceOwnedByUserLocked(code.UserID, code.Resource, requiredScope) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization grant no longer owns the requested resource")
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
	resource := r.Form.Get("resource")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(time.Now())
	key := tokenKey(refreshValue)
	record, ok := s.refresh[key]
	if !ok || record.ClientID != clientID || resource == "" || resource != record.Resource {
		if used, replay := s.refreshUsed[key]; replay && (clientID == "" || used.ClientID == clientID) {
			s.resetAgentSessionForResourceLocked(used.Resource)
			s.revokeFamilyLocked(used.Family)
			_ = s.saveLocked()
		}
		oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid or expired")
		return
	}
	client, clientExists := s.clients[record.ClientID]
	kind, _, _, resourceOK := s.resourceParts(record.Resource)
	requiredScope := "mcp"
	if kind == "agent" {
		requiredScope = "agent:connect"
	}
	if !clientExists || !clientIDMatches(record.ClientID, client) || !client.Approved || !resourceOK || !s.resourceOwnedByUserLocked(record.UserID, record.Resource, requiredScope) {
		delete(s.refresh, key)
		_ = s.saveLocked()
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
	if record, ok := s.access[key]; ok {
		s.resetAgentSessionForResourceLocked(record.Resource)
		s.revokeFamilyLocked(record.Family)
	} else if record, ok := s.refresh[key]; ok {
		s.resetAgentSessionForResourceLocked(record.Resource)
		s.revokeFamilyLocked(record.Family)
	} else if record, ok := s.refreshUsed[key]; ok {
		s.resetAgentSessionForResourceLocked(record.Resource)
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
	return s.verifyAccessKey(tokenKey(token), resource, requiredScope)
}

// VerifyAgentConnection revalidates an already-established Agent WebSocket
// using the one-way bearer fingerprint retained by the Relay broker. It is
// intentionally separate from VerifyAccessScope so callers do not need to
// retain or pass raw bearer values between packages.
func (s *Server) VerifyAgentConnection(credentialHash, device string) bool {
	device = strings.TrimSpace(device)
	if credentialHash == "" || !validateDeviceRoute(device) {
		return false
	}
	return s.verifyAccessKey(credentialHash, s.absolute("/agent/"+device), "agent:connect")
}

func (s *Server) resourceOwnedByUserLocked(userID, resource, requiredScope string) bool {
	user, exists := s.users[userID]
	if requiredScope != "mcp" && requiredScope != "agent:connect" {
		return false
	}
	if !exists || user.ID != userID || user.Disabled || !s.resourceEnabledLocked(resource, requiredScope) {
		return false
	}
	kind, device, _, ok := s.resourceParts(resource)
	if !ok {
		return false
	}
	if (requiredScope == "mcp" && kind != "mcp") || (requiredScope == "agent:connect" && kind != "agent") {
		return false
	}
	if record, exists := s.deviceRecords[device]; exists && (record.Disabled || (record.OwnerID != "" && record.OwnerID != userID)) {
		return false
	}
	return s.devices[device] == userID
}

func (s *Server) verifyAccessKey(credentialHash, resource, requiredScope string) bool {
	if credentialHash == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(time.Now())
	return s.verifyAccessKeyLocked(credentialHash, resource, requiredScope)
}

func (s *Server) verifyAccessKeyLocked(credentialHash, resource, requiredScope string) bool {
	record, ok := s.access[credentialHash]
	if !ok || !s.resourceOwnedByUserLocked(record.UserID, resource, requiredScope) {
		return false
	}
	client, clientExists := s.clients[record.ClientID]
	return clientExists && clientIDMatches(record.ClientID, client) && client.Approved && record.UserID != "" && record.Resource == resource &&
		strings.Contains(" "+record.Scope+" ", " "+requiredScope+" ")
}

func (s *Server) resourceEnabledLocked(resource, requiredScope string) bool {
	if requiredScope != "mcp" && requiredScope != "agent:connect" {
		return false
	}
	if s.persistenceFault || s.killSwitch || (requiredScope == "mcp" && !s.mcpEnabled) || (requiredScope == "agent:connect" && !s.agentEnabled) {
		return false
	}
	kind, device, _, ok := s.resourceParts(resource)
	if !ok || (requiredScope == "mcp" && kind != "mcp") || (requiredScope == "agent:connect" && kind != "agent") {
		return false
	}
	if s.disabledDevices[device] || s.retiredDevices[device] {
		return false
	}
	if record, exists := s.deviceRecords[device]; exists && record.Disabled {
		return false
	}
	return true
}

func registrationChallengeMACInput(payload []byte, deviceID, devicePublicKey, clientName, redirectURI string) []byte {
	const context = "chat-with-cli-registration-challenge-v1"
	out := make([]byte, 0, len(payload)+len(deviceID)+len(devicePublicKey)+len(clientName)+len(redirectURI)+len(context)+5)
	out = append(out, context...)
	out = append(out, '\n')
	out = append(out, payload...)
	out = append(out, '\n')
	out = append(out, deviceID...)
	out = append(out, '\n')
	out = append(out, devicePublicKey...)
	out = append(out, '\n')
	out = append(out, clientName...)
	out = append(out, '\n')
	out = append(out, redirectURI...)
	return out
}

func (s *Server) issueRegistrationChallenge(deviceID, devicePublicKey, clientName, redirectURI string, now time.Time) (string, error) {
	var payload [32]byte
	if _, err := rand.Read(payload[:24]); err != nil {
		return "", err
	}
	expires := now.Add(registrationChallengeLifetime).Unix()
	binary.BigEndian.PutUint64(payload[24:], uint64(expires))
	mac := hmac.New(sha256.New, s.registrationChallengeKey[:])
	_, _ = mac.Write(registrationChallengeMACInput(payload[:], deviceID, devicePublicKey, clientName, redirectURI))
	return base64.RawURLEncoding.EncodeToString(payload[:]) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (s *Server) validateRegistrationChallenge(deviceID, devicePublicKey, clientName, redirectURI, challenge string, now time.Time) (string, int64, bool) {
	parts := strings.Split(challenge, ".")
	if len(parts) != 2 {
		return "", 0, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) != 32 {
		return "", 0, false
	}
	providedMAC, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(providedMAC) != sha256.Size {
		return "", 0, false
	}
	mac := hmac.New(sha256.New, s.registrationChallengeKey[:])
	_, _ = mac.Write(registrationChallengeMACInput(payload, deviceID, devicePublicKey, clientName, redirectURI))
	if !hmac.Equal(providedMAC, mac.Sum(nil)) {
		return "", 0, false
	}
	expires := int64(binary.BigEndian.Uint64(payload[24:]))
	if expires <= now.Unix() || expires > now.Add(registrationChallengeLifetime+5*time.Second).Unix() {
		return "", 0, false
	}
	sum := sha256.Sum256([]byte(challenge))
	return hex.EncodeToString(sum[:]), expires, true
}

func (s *Server) registrationChallengeAvailableLocked(deviceID, challengeHash string, now time.Time) bool {
	bucket := s.consumedRegistrationChallenges[deviceID]
	if bucket == nil {
		return true
	}
	nowUnix := now.Unix()
	for candidate, expiry := range bucket {
		if expiry <= nowUnix {
			delete(bucket, candidate)
		}
	}
	_, replay := bucket[challengeHash]
	return !replay && len(bucket) < maxRegistrationChallengesConsumedDevice
}

func (s *Server) consumeRegistrationChallengeLocked(deviceID, challengeHash string, expires int64, now time.Time) bool {
	if !s.registrationChallengeAvailableLocked(deviceID, challengeHash, now) {
		return false
	}
	bucket := s.consumedRegistrationChallenges[deviceID]
	if bucket == nil {
		bucket = make(map[string]int64)
		s.consumedRegistrationChallenges[deviceID] = bucket
	}
	bucket[challengeHash] = expires
	return true
}

func authorizationChallengeMACInput(payload []byte, clientID, redirectURI, resource, scope, state, codeChallenge string) []byte {
	const context = "chat-with-cli-authorization-challenge-v1"
	out := make([]byte, 0, len(payload)+len(clientID)+len(redirectURI)+len(resource)+len(scope)+len(state)+len(codeChallenge)+len(context)+7)
	out = append(out, context...)
	out = append(out, '\n')
	out = append(out, payload...)
	out = append(out, '\n')
	for _, value := range []string{clientID, redirectURI, resource, scope, state, codeChallenge} {
		out = append(out, value...)
		out = append(out, '\n')
	}
	return out
}

func (s *Server) issueAuthorizationChallenge(clientID, redirectURI, resource, scope, state, codeChallenge string, now time.Time) (string, error) {
	var payload [32]byte
	if _, err := rand.Read(payload[:24]); err != nil {
		return "", err
	}
	expires := now.Add(authorizationChallengeLifetime).Unix()
	binary.BigEndian.PutUint64(payload[24:], uint64(expires))
	mac := hmac.New(sha256.New, s.authorizationChallengeKey[:])
	_, _ = mac.Write(authorizationChallengeMACInput(payload[:], clientID, redirectURI, resource, scope, state, codeChallenge))
	return base64.RawURLEncoding.EncodeToString(payload[:]) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (s *Server) validateAuthorizationChallenge(clientID, redirectURI, resource, scope, state, codeChallenge, challenge string, now time.Time) (string, int64, bool) {
	parts := strings.Split(challenge, ".")
	if len(parts) != 2 {
		return "", 0, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) != 32 {
		return "", 0, false
	}
	providedMAC, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(providedMAC) != sha256.Size {
		return "", 0, false
	}
	mac := hmac.New(sha256.New, s.authorizationChallengeKey[:])
	_, _ = mac.Write(authorizationChallengeMACInput(payload, clientID, redirectURI, resource, scope, state, codeChallenge))
	if !hmac.Equal(providedMAC, mac.Sum(nil)) {
		return "", 0, false
	}
	expires := int64(binary.BigEndian.Uint64(payload[24:]))
	if expires <= now.Unix() || expires > now.Add(authorizationChallengeLifetime+5*time.Second).Unix() {
		return "", 0, false
	}
	sum := sha256.Sum256([]byte(challenge))
	return hex.EncodeToString(sum[:]), expires, true
}

func (s *Server) authorizationChallengeAvailableLocked(clientID, challengeHash string, now time.Time) bool {
	bucket := s.consumedAuthorizationChallenges[clientID]
	if bucket == nil {
		return true
	}
	nowUnix := now.Unix()
	for candidate, expiry := range bucket {
		if expiry <= nowUnix {
			delete(bucket, candidate)
		}
	}
	_, replay := bucket[challengeHash]
	return !replay && len(bucket) < maxAuthorizationChallengesClient
}

func (s *Server) consumeAuthorizationChallengeLocked(clientID, challengeHash string, expires int64, now time.Time) bool {
	if !s.authorizationChallengeAvailableLocked(clientID, challengeHash, now) {
		return false
	}
	bucket := s.consumedAuthorizationChallenges[clientID]
	if bucket == nil {
		bucket = make(map[string]int64)
		s.consumedAuthorizationChallenges[clientID] = bucket
	}
	bucket[challengeHash] = expires
	return true
}

func agentChallengeMACInput(payload []byte, resource, credentialHash string) []byte {
	out := make([]byte, 0, len(payload)+len(resource)+len(credentialHash)+2)
	out = append(out, payload...)
	out = append(out, '\n')
	out = append(out, resource...)
	out = append(out, '\n')
	out = append(out, credentialHash...)
	return out
}

func (s *Server) issueAgentChallenge(resource, credentialHash string, now time.Time) (string, error) {
	var payload [32]byte
	if _, err := rand.Read(payload[:24]); err != nil {
		return "", err
	}
	expires := now.Add(agentChallengeLifetime).Unix()
	binary.BigEndian.PutUint64(payload[24:], uint64(expires))
	mac := hmac.New(sha256.New, s.agentChallengeKey[:])
	_, _ = mac.Write(agentChallengeMACInput(payload[:], resource, credentialHash))
	return base64.RawURLEncoding.EncodeToString(payload[:]) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (s *Server) validateAgentChallenge(resource, credentialHash, challenge string, now time.Time) (string, int64, bool) {
	parts := strings.Split(challenge, ".")
	if len(parts) != 2 {
		return "", 0, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) != 32 {
		return "", 0, false
	}
	providedMAC, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(providedMAC) != sha256.Size {
		return "", 0, false
	}
	mac := hmac.New(sha256.New, s.agentChallengeKey[:])
	_, _ = mac.Write(agentChallengeMACInput(payload, resource, credentialHash))
	if !hmac.Equal(providedMAC, mac.Sum(nil)) {
		return "", 0, false
	}
	expires := int64(binary.BigEndian.Uint64(payload[24:]))
	if expires <= now.Unix() || expires > now.Add(agentChallengeLifetime+5*time.Second).Unix() {
		return "", 0, false
	}
	sum := sha256.Sum256([]byte(challenge))
	return hex.EncodeToString(sum[:]), expires, true
}

func (s *Server) consumeAgentChallengeLocked(device, challengeHash string, expires int64, now time.Time) bool {
	bucket := s.consumedAgentChallenges[device]
	if bucket == nil {
		bucket = make(map[string]int64)
		s.consumedAgentChallenges[device] = bucket
	}
	nowUnix := now.Unix()
	for candidate, expiry := range bucket {
		if expiry <= nowUnix {
			delete(bucket, candidate)
		}
	}
	if _, replay := bucket[challengeHash]; replay || len(bucket) >= maxAgentChallengesConsumedDevice {
		return false
	}
	bucket[challengeHash] = expires
	return true
}

func (s *Server) verifyAgentDeviceProof(r *http.Request, resource, credentialHash string) bool {
	_, device, _, ok := s.resourceParts(resource)
	if !ok {
		return false
	}
	s.mu.Lock()
	record := s.deviceRecords[device]
	encodedPublicKey := record.DevicePublicKey
	s.mu.Unlock()
	if encodedPublicKey == "" {
		// Bearer-only Agent connections are unsafe against token theft and are
		// therefore disabled by default. This flag exists only to migrate old
		// alpha devices onto a newly generated cryptographic identity.
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.cfg.AllowLegacyUnboundAgents && s.verifyAccessKeyLocked(credentialHash, resource, "agent:connect")
	}
	pub, err := deviceidentity.DecodePublicKey(encodedPublicKey)
	if err != nil {
		return false
	}
	challenge := strings.TrimSpace(r.Header.Get(deviceidentity.HeaderChallenge))
	challengeHash, expires, ok := s.validateAgentChallenge(resource, credentialHash, challenge, time.Now().UTC())
	if !ok {
		return false
	}
	proof := strings.TrimSpace(r.Header.Get(deviceidentity.HeaderProof))
	if !deviceidentity.VerifyProof(pub, resource, credentialHash, challenge, proof) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	currentRecord := s.deviceRecords[device]
	if currentRecord.DevicePublicKey == "" || currentRecord.DevicePublicKey != encodedPublicKey ||
		!s.verifyAccessKeyLocked(credentialHash, resource, "agent:connect") {
		return false
	}
	return s.consumeAgentChallengeLocked(device, challengeHash, expires, time.Now().UTC())
}

func (s *Server) AgentChallengeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		basePath := strings.TrimSuffix(r.URL.EscapedPath(), "/challenge")
		resource, ok := s.validateResource(s.absolute(basePath))
		if !ok {
			http.NotFound(w, r)
			return
		}
		kind, device, _, ok := s.resourceParts(resource)
		if !ok || kind != "agent" {
			http.NotFound(w, r)
			return
		}
		s.mu.Lock()
		enabled := s.resourceEnabledLocked(resource, "agent:connect")
		record := s.deviceRecords[device]
		s.mu.Unlock()
		if !enabled {
			http.Error(w, "capability disabled", http.StatusServiceUnavailable)
			return
		}
		token := bearerValue(r.Header.Get("Authorization"))
		if !s.VerifyAccessScope(token, resource, "agent:connect") {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if record.DevicePublicKey == "" {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "legacy device has no cryptographic identity", http.StatusConflict)
			return
		}
		challenge, err := s.issueAgentChallenge(resource, tokenKey(token), time.Now().UTC())
		if err != nil {
			http.Error(w, "failed to issue challenge", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]any{"challenge": challenge, "expires_in": int(agentChallengeLifetime.Seconds())})
	})
}

func (s *Server) ProtectResource(next http.Handler) http.Handler {
	return s.ProtectScopedResource("mcp", next)
}

func (s *Server) ProtectScopedResource(requiredScope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resource, validResource := s.validateResource(s.absolute(r.URL.EscapedPath()))
		if !validResource {
			http.NotFound(w, r)
			return
		}
		s.mu.Lock()
		enabled := s.resourceEnabledLocked(resource, requiredScope)
		s.mu.Unlock()
		if !enabled {
			http.Error(w, "capability disabled", http.StatusServiceUnavailable)
			return
		}
		token := bearerValue(r.Header.Get("Authorization"))
		if s.VerifyAccessScope(token, resource, requiredScope) {
			credentialHash := tokenKey(token)
			if requiredScope == "agent:connect" && !s.verifyAgentDeviceProof(r, resource, credentialHash) {
				w.Header().Set("Cache-Control", "no-store")
				http.Error(w, "device proof required or invalid", http.StatusUnauthorized)
				return
			}
			checker := func() bool { return s.verifyAccessKey(credentialHash, resource, requiredScope) }
			if !checker() {
				w.Header().Set("Cache-Control", "no-store")
				http.Error(w, "authorization revoked", http.StatusUnauthorized)
				return
			}
			ctx, cancel := context.WithCancel(authzctx.WithChecker(r.Context(), checker))
			defer cancel()
			go func() {
				ticker := time.NewTicker(100 * time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						if !checker() {
							cancel()
							return
						}
					}
				}
			}()
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		resourceURL, _ := url.Parse(resource)
		metadataURL := s.ResourceMetadataURL(resourceURL.EscapedPath())
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata=%q, scope=%q`, metadataURL, requiredScope))
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

// SetAgentSessionResetter installs a local Relay callback used to terminate
// device sessions after security-sensitive OAuth revocation. It is configured
// by the Relay before serving requests and never receives bearer credentials.
func (s *Server) SetAgentSessionResetter(resetter func(device string)) {
	s.mu.Lock()
	s.agentSessionResetter = resetter
	s.mu.Unlock()
}

func (s *Server) resetAgentSessionForResourceLocked(resource string) {
	_, device, _, ok := s.resourceParts(resource)
	if ok && s.agentSessionResetter != nil {
		s.agentSessionResetter(device)
	}
}

func (s *Server) agentSessionResetterSafe(device string) {
	if s.agentSessionResetter != nil {
		s.agentSessionResetter(device)
	}
}

func (s *Server) resetOwnedAgentSessionsLocked(userID string) {
	if s.agentSessionResetter == nil {
		return
	}
	for device, owner := range s.devices {
		if owner == userID {
			s.agentSessionResetter(device)
		}
	}
}

func (s *Server) resetAllAgentSessionsLocked() {
	if s.agentSessionResetter == nil {
		return
	}
	for device := range s.devices {
		s.agentSessionResetter(device)
	}
}

// Ready reports whether the Relay can safely authorize MCP and Agent traffic.
// A persistence fault is fail-closed and should surface as an unhealthy
// readiness check instead of pretending the Relay is operational.
func (s *Server) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.persistenceFault
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
