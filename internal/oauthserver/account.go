package oauthserver

import (
	"crypto/subtle"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ifloppy/chat-with-cli/internal/protocol"
)

const accountCSRFCookie = "cwc_account_csrf"

type accountDeviceView struct {
	Route        string
	ID           string
	Name         string
	Disabled     bool
	Online       bool
	LastSeen     time.Time
	Capabilities protocol.AgentCapabilities
	MCPURL       string
	ProofBound   bool
}

type accountSessionView struct {
	Handle   string
	Label    string
	Current  bool
	Created  time.Time
	LastSeen time.Time
	Expires  time.Time
}

type accountGrantView struct {
	FamilyHandle string
	Label        string
	ClientName   string
	Resource     string
	Expires      time.Time
}

type accountPageData struct {
	Username       string
	PublicURL      string
	PublicInstance bool
	Devices        []accountDeviceView
	Sessions       []accountSessionView
	Grants         []accountGrantView
	CSRFToken      string
}

var accountLoginTemplate = template.Must(template.New("account-login").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Account · Chat with CLI</title>
<style>:root{color-scheme:light dark}body{font:16px system-ui,sans-serif;max-width:500px;margin:9vh auto;padding:24px;line-height:1.5}form,.warning{border:1px solid #8885;border-radius:12px;padding:18px}.warning{border-color:#b8860b88;background:#b8860b18;margin-bottom:16px}label{display:block;margin-top:12px}input,button{font:inherit;width:100%;padding:10px;box-sizing:border-box;margin-top:5px}</style></head>
<body><h1>Chat with CLI account</h1>{{if .PublicInstance}}<div class="warning"><b>Do not trust a public Relay with sensitive access.</b><br>The operator controls the server code and can observe or alter MCP traffic. This service isolates users from each other, not from its operator. Self-host a private Relay for high-trust use.</div>{{end}}<form method="post" action="/account/login"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><label>Username<input name="username" autocomplete="username" required></label><label>Password<input type="password" name="password" autocomplete="current-password" required></label><button type="submit">Sign in</button></form><p><a href="/">Back to home</a></p></body></html>`))

var accountTemplate = template.Must(template.New("account").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>My account · Chat with CLI</title>
<style>:root{color-scheme:light dark}*{box-sizing:border-box}body{font:14px system-ui,sans-serif;max-width:1100px;margin:0 auto;padding:30px 20px 70px;line-height:1.45}h1{font-size:30px;margin:0}h2{margin-top:28px}.toolbar{display:flex;justify-content:space-between;gap:14px;align-items:center;flex-wrap:wrap}.nav{display:flex;gap:10px;align-items:center}section,.warning{border:1px solid #8885;border-radius:12px;padding:15px;margin:10px 0;background:#8881}.warning{border-color:#b8860b88;background:#b8860b18}.warning b{display:block;margin-bottom:3px}table{width:100%;border-collapse:collapse;display:block;overflow:auto}th,td{text-align:left;padding:8px;border-bottom:1px solid #8884;vertical-align:top}input,button{font:inherit;padding:7px;border-radius:6px;border:1px solid #8888}form.inline{display:inline-flex;gap:5px;align-items:center;flex-wrap:wrap;margin:2px}.danger{background:#b3261e;color:#fff}.muted{color:#777}.ok{color:#188038}.bad{color:#b3261e}code{overflow-wrap:anywhere}</style></head>
<body><div class="toolbar"><div><h1>My Chat with CLI</h1><span class="muted">Signed in as {{.Username}}</span></div><div class="nav"><a href="/">Home</a><a href="/docs">Docs</a><form class="inline" method="post" action="/account/logout"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><button type="submit">Sign out</button></form></div></div>
{{if .PublicInstance}}<div class="warning"><b>Public Relay operator is trusted by design.</b>This page can prove that other normal users are isolated from your devices. It cannot prove that the operator is harmless: the operator can run modified Relay code and observe or alter MCP traffic. Do not grant sensitive computer access to any public instance, including one operated by the software author; self-host when trust matters.</div>{{end}}
<h2>My devices</h2><section><p class="muted">Only devices owned by your account are shown. Disabling immediately revokes current device tokens; permanent revocation retires the cryptographic identity.</p><table><tr><th>Device</th><th>Status</th><th>Capabilities</th><th>MCP URL</th><th>Actions</th></tr>{{range .Devices}}<tr><td><b>{{.Name}}</b><br><code>{{.ID}}</code><br>{{if .ProofBound}}<span class="ok">PoP bound</span>{{else}}<span class="bad">legacy unbound</span>{{end}}</td><td>{{if .Online}}<span class="ok">online</span>{{else}}offline{{end}}{{if .Disabled}} · <span class="bad">disabled</span>{{end}}{{if not .LastSeen.IsZero}}<br><small>last seen {{.LastSeen}}</small>{{end}}</td><td><small>{{if .Capabilities.FilesystemRead}}filesystem read<br>{{end}}{{if .Capabilities.FilesystemWrite}}filesystem write<br>{{end}}{{if .Capabilities.Exec}}exec{{if .Capabilities.ExecSandbox}} ({{.Capabilities.ExecSandbox}}){{end}}<br>{{end}}{{if .Capabilities.ScreenRead}}screen read<br>{{end}}{{if .Capabilities.AccessibilityRead}}accessibility read<br>{{end}}{{if .Capabilities.ComputerInput}}computer input{{end}}</small></td><td><code>{{.MCPURL}}</code></td><td><form class="inline" method="post" action="/account/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="rename-device"><input type="hidden" name="target" value="{{.Route}}"><input name="value" placeholder="new name" required><button>Rename</button></form><form class="inline" method="post" action="/account/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="disable-device"><input type="hidden" name="target" value="{{.Route}}"><input type="hidden" name="value" value="{{if .Disabled}}off{{else}}on{{end}}">{{if .Disabled}}<input type="password" name="password" placeholder="password to enable" required>{{end}}<button>{{if .Disabled}}Enable{{else}}Disable{{end}}</button></form><form class="inline" method="post" action="/account/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="revoke-device"><input type="hidden" name="target" value="{{.Route}}"><input name="confirm" placeholder="REVOKE" required><button class="danger">Revoke permanently</button></form></td></tr>{{else}}<tr><td colspan="5" class="muted">No devices are owned by this account yet. Pair an Agent first.</td></tr>{{end}}</table></section>
<h2>Connected authorizations</h2><section><p class="muted">These are your token families, not globally shared OAuth client registrations. Revoking one cannot revoke another user's access.</p><table><tr><th>Client</th><th>Resource</th><th>Expires</th><th>Action</th></tr>{{range .Grants}}<tr><td>{{.ClientName}}<br><code>{{.Label}}</code></td><td><code>{{.Resource}}</code></td><td>{{.Expires}}</td><td><form class="inline" method="post" action="/account/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="revoke-family"><input type="hidden" name="target" value="{{.FamilyHandle}}"><button>Revoke my authorization</button></form></td></tr>{{else}}<tr><td colspan="4" class="muted">No active OAuth token families.</td></tr>{{end}}</table></section>
<h2>Browser sessions</h2><section><form class="inline" method="post" action="/account/action"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="action" value="logout-others"><button>Sign out all other sessions</button></form><table><tr><th>Session</th><th>Created</th><th>Last seen</th><th>Expires</th><th>Action</th></tr>{{range .Sessions}}<tr><td><code>{{.Label}}</code>{{if .Current}} · current{{end}}</td><td>{{.Created}}</td><td>{{.LastSeen}}</td><td>{{.Expires}}</td><td>{{if not .Current}}<form class="inline" method="post" action="/account/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="logout-session"><input type="hidden" name="target" value="{{.Handle}}"><button>Sign out</button></form>{{end}}</td></tr>{{end}}</table></section>
<h2>Change password</h2><section><p class="muted">Changing your password revokes all OAuth credentials and browser sessions for this account. Reconnect devices and apps afterward.</p><form method="post" action="/account/action"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="action" value="change-password"><input type="password" name="password" autocomplete="current-password" placeholder="current password" required> <input type="password" name="value" autocomplete="new-password" minlength="12" placeholder="new password" required> <button class="danger">Change password and revoke credentials</button></form></section>
</body></html>`))

func (s *Server) setAccountCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: accountCSRFCookie, Value: token, Path: "/account", MaxAge: int(sessionLifetime.Seconds()), HttpOnly: true, Secure: s.base.Scheme == "https", SameSite: http.SameSiteStrictMode})
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessionUser(r)
	csrf := randomToken(24)
	s.setAccountCSRFCookie(w, csrf)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if !ok {
		s.mu.Lock()
		public := s.cfg.Mode == ModePublic
		s.mu.Unlock()
		_ = accountLoginTemplate.Execute(w, map[string]any{"CSRFToken": csrf, "PublicInstance": public})
		return
	}
	data := s.accountData(r, user)
	data.CSRFToken = csrf
	_ = accountTemplate.Execute(w, data)
}

func (s *Server) handleAccountLogin(w http.ResponseWriter, r *http.Request) {
	if !s.allowRate(r, "account-login", 15, time.Minute) {
		rateLimited(w, 60)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil || !doubleSubmitMatches(r, accountCSRFCookie) {
		http.Error(w, "invalid account form", http.StatusForbidden)
		return
	}
	user, ok, busy := s.authenticate(r.Form.Get("username"), r.Form.Get("password"))
	if busy {
		http.Error(w, "login capacity is busy; retry shortly", http.StatusTooManyRequests)
		return
	}
	if !ok {
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}
	session, err := s.createSession(user)
	if err != nil {
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}
	s.setSessionCookie(w, session)
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func (s *Server) handleAccountLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !doubleSubmitMatches(r, accountCSRFCookie) {
		http.Error(w, "invalid account form", http.StatusForbidden)
		return
	}
	s.clearSession(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) accountData(r *http.Request, current User) accountPageData {
	currentHandle := ""
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		currentHandle = tokenKey(cookie.Value)
	}
	s.mu.Lock()
	s.cleanupLocked(time.Now())
	data := accountPageData{Username: current.Username, PublicURL: strings.TrimRight(s.base.String(), "/"), PublicInstance: s.cfg.Mode == ModePublic}
	provider := s.statusProvider
	for route, owner := range s.devices {
		if owner != current.ID {
			continue
		}
		record := s.ensureDeviceRecordLocked(route, owner)
		data.Devices = append(data.Devices, accountDeviceView{Route: route, ID: record.ID, Name: record.DisplayName, Disabled: s.disabledDevices[route] || record.Disabled, MCPURL: s.absolute("/mcp/" + route), ProofBound: record.DevicePublicKey != ""})
	}
	for handle, record := range s.sessions {
		if record.UserID == current.ID {
			data.Sessions = append(data.Sessions, accountSessionView{Handle: handle, Label: shortHandle(handle), Current: handle == currentHandle, Created: time.Unix(record.CreatedAt, 0), LastSeen: time.Unix(record.LastSeenAt, 0), Expires: time.Unix(record.Expires, 0)})
		}
	}
	grants := map[string]accountGrantView{}
	addGrant := func(record tokenRecord) {
		if record.UserID != current.ID || record.Family == "" {
			return
		}
		handle := tokenKey(record.Family)
		view := grants[handle]
		clientName := record.ClientID
		if client, ok := s.clients[record.ClientID]; ok && strings.TrimSpace(client.Name) != "" {
			clientName = client.Name
		}
		if view.FamilyHandle == "" || record.Expires > view.Expires.Unix() {
			grants[handle] = accountGrantView{FamilyHandle: handle, Label: shortHandle(handle), ClientName: clientName, Resource: record.Resource, Expires: time.Unix(record.Expires, 0)}
		}
	}
	for _, record := range s.access {
		addGrant(record)
	}
	for _, record := range s.refresh {
		addGrant(record)
	}
	for _, view := range grants {
		data.Grants = append(data.Grants, view)
	}
	s.mu.Unlock()
	if provider != nil {
		statuses := provider()
		for i := range data.Devices {
			if status, ok := statuses[data.Devices[i].Route]; ok {
				data.Devices[i].Online = status.Online
				data.Devices[i].LastSeen = status.LastSeen
				data.Devices[i].Capabilities = status.Capabilities
			}
		}
	}
	sort.Slice(data.Devices, func(i, j int) bool { return data.Devices[i].Name < data.Devices[j].Name })
	sort.Slice(data.Sessions, func(i, j int) bool { return data.Sessions[i].LastSeen.After(data.Sessions[j].LastSeen) })
	sort.Slice(data.Grants, func(i, j int) bool { return data.Grants[i].Expires.After(data.Grants[j].Expires) })
	return data
}

func (s *Server) verifyAccountPassword(current User, password string) bool {
	verified, ok, busy := s.authenticate(current.Username, password)
	return !busy && ok && verified.ID == current.ID && verified.PasswordHash == current.PasswordHash
}

func (s *Server) handleAccountAction(w http.ResponseWriter, r *http.Request) {
	if !s.allowRate(r, "account-action", 60, time.Minute) {
		rateLimited(w, 60)
		return
	}
	current, ok := s.sessionUser(r)
	if !ok {
		http.Error(w, "account authentication required", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil || !doubleSubmitMatches(r, accountCSRFCookie) {
		http.Error(w, "invalid account form", http.StatusForbidden)
		return
	}
	action, target, value := strings.TrimSpace(r.Form.Get("action")), strings.TrimSpace(r.Form.Get("target")), r.Form.Get("value")
	if action == "change-password" && !s.allowRate(r, "account-password", 10, time.Hour) {
		rateLimited(w, 300)
		return
	}
	if action == "change-password" {
		s.changeOwnPassword(w, r, current, r.Form.Get("password"), value)
		return
	}
	needsPassword := action == "disable-device" && strings.EqualFold(value, "off")
	if needsPassword && !s.verifyAccountPassword(current, r.Form.Get("password")) {
		http.Error(w, "current password is required", http.StatusUnauthorized)
		return
	}
	if action == "revoke-device" && subtle.ConstantTimeCompare([]byte(r.Form.Get("confirm")), []byte("REVOKE")) != 1 {
		http.Error(w, "type REVOKE to permanently retire this device", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	if s.persistenceFault {
		s.mu.Unlock()
		http.Error(w, "authorization state is frozen; contact the Relay operator", http.StatusServiceUnavailable)
		return
	}
	snapshot := s.snapshotMutableStateLocked()
	err := s.applyAccountActionLocked(action, target, value, current, r)
	if err == nil {
		err = s.saveOrRollbackLocked(snapshot)
	} else {
		s.restoreMutableStateLocked(snapshot)
	}
	s.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func (s *Server) applyAccountActionLocked(action, target, value string, current User, r *http.Request) error {
	live, exists := s.users[current.ID]
	if !exists || live.Disabled || live.PasswordHash != current.PasswordHash {
		return errUnknownUser
	}
	switch action {
	case "rename-device":
		if s.devices[target] != current.ID || !validateDeviceRoute(target) || !validateDeviceDisplayName(value) {
			return errUnknownDevice
		}
		record := s.ensureDeviceRecordLocked(target, current.ID)
		record.DisplayName = strings.TrimSpace(value)
		s.deviceRecords[target] = record
	case "disable-device":
		if s.devices[target] != current.ID {
			return errUnknownDevice
		}
		state, valid := parseToggle(value)
		if !valid {
			return errInvalidAdminAction
		}
		s.disabledDevices[target] = state
		record := s.ensureDeviceRecordLocked(target, current.ID)
		record.Disabled = state
		s.deviceRecords[target] = record
		if state {
			s.agentSessionResetterSafe(target)
			s.revokeDeviceTokensLocked(target)
		}
	case "revoke-device":
		if s.devices[target] != current.ID {
			return errUnknownDevice
		}
		s.agentSessionResetterSafe(target)
		s.retiredDevices[target] = true
		delete(s.devices, target)
		delete(s.disabledDevices, target)
		delete(s.deviceRecords, target)
		s.revokeDeviceTokensLocked(target)
		s.revokeDeviceClientsLocked(target)
	case "revoke-family":
		family := ""
		resource := ""
		find := func(record tokenRecord) {
			if family == "" && record.UserID == current.ID && record.Family != "" && tokenKey(record.Family) == target {
				family, resource = record.Family, record.Resource
			}
		}
		for _, rec := range s.access {
			find(rec)
		}
		for _, rec := range s.refresh {
			find(rec)
		}
		if family == "" {
			return errUnknownToken
		}
		s.resetAgentSessionForResourceLocked(resource)
		s.revokeFamilyLocked(family)
	case "logout-session":
		record, ok := s.sessions[target]
		if !ok || record.UserID != current.ID {
			return errUnknownSession
		}
		delete(s.sessions, target)
		delete(s.ephemeralSessions, target)
	case "logout-others":
		currentHandle := ""
		if cookie, err := r.Cookie(sessionCookie); err == nil {
			currentHandle = tokenKey(cookie.Value)
		}
		for handle, rec := range s.sessions {
			if rec.UserID == current.ID && handle != currentHandle {
				delete(s.sessions, handle)
				delete(s.ephemeralSessions, handle)
			}
		}
	default:
		return errInvalidAdminAction
	}
	s.recordSecurityLocked(SecurityEvent{Event: "account_" + action, User: current.Username, Device: target, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
	return nil
}

func (s *Server) changeOwnPassword(w http.ResponseWriter, r *http.Request, current User, oldPassword, newPassword string) {
	if !s.verifyAccountPassword(current, oldPassword) {
		http.Error(w, "current password is incorrect", http.StatusUnauthorized)
		return
	}
	if err := validatePassword(newPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hash, err := hashPassword(newPassword)
	if err != nil {
		http.Error(w, "failed to hash new password", http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	if s.persistenceFault {
		s.mu.Unlock()
		http.Error(w, "authorization state is frozen; contact the Relay operator", http.StatusServiceUnavailable)
		return
	}
	live, exists := s.users[current.ID]
	if !exists || live.Disabled || live.PasswordHash != current.PasswordHash {
		s.mu.Unlock()
		http.Error(w, "account changed; sign in again", http.StatusUnauthorized)
		return
	}
	snapshot := s.snapshotMutableStateLocked()
	live.PasswordHash = hash
	s.users[current.ID] = live
	s.resetOwnedAgentSessionsLocked(current.ID)
	s.revokeUserCredentialsLocked(current.ID)
	s.recordSecurityLocked(SecurityEvent{Event: "account_change_password", User: current.Username, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
	if err := s.saveOrRollbackLocked(snapshot); err != nil {
		s.mu.Unlock()
		http.Error(w, "failed to persist password change", http.StatusInternalServerError)
		return
	}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.base.Scheme == "https", SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}
