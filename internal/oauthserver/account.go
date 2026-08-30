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
	Username             string
	Admin                bool
	PublicURL            string
	PublicInstance       bool
	UsageMeteringEnabled bool
	UsageQuotaBytes      int64
	UsageUsedBytes       int64
	UsageRemainingBytes  int64
	Devices              []accountDeviceView
	Sessions             []accountSessionView
	Grants               []accountGrantView
	CSRFToken            string
}

var accountLoginTemplate = template.Must(template.New("account-login").Parse(`<!doctype html>
<html lang="en" data-admin="false"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Account · Chat with CLI</title></head>
<body><div class="page compact"><header class="topbar"><a class="brand" href="/"><span class="brand-mark" aria-hidden="true">⌁</span><span class="brand-name">Chat with CLI</span></a><nav class="nav"><a href="/" data-i18n="Home">Home</a><div class="ui-controls" data-ui-controls></div></nav></header>
<main><div class="page-header"><span class="eyebrow" data-i18n="Account">Account</span><h1 data-i18n="Chat with CLI account">Chat with CLI account</h1><p data-i18n="Sign in to manage your connected workstations and authorizations.">Sign in to manage your connected workstations and authorizations.</p></div>
{{if .PublicInstance}}<div class="warning"><b data-i18n="Do not trust a public Relay with sensitive access.">Do not trust a public Relay with sensitive access.</b><span data-i18n="The operator controls the server code and can observe or alter MCP traffic. This service isolates users from each other, not from its operator. Self-host a private Relay for high-trust use.">The operator controls the server code and can observe or alter MCP traffic. This service isolates users from each other, not from its operator. Self-host a private Relay for high-trust use.</span></div>{{end}}
<section class="auth-card"><form class="auth-form" method="post" action="/account/login"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><label><span data-i18n="Username">Username</span><input name="username" autocomplete="username" required></label><label><span data-i18n="Password">Password</span><input type="password" name="password" autocomplete="current-password" required></label><button class="primary" type="submit" data-i18n="Sign in">Sign in</button></form></section>
<p class="auth-footer"><a href="/" data-i18n="Back to home">Back to home</a></p></main></div></body></html>`))

var accountTemplate = template.Must(template.New("account").Funcs(template.FuncMap{"formatBytes": formatUsageBytes}).Parse(`<!doctype html>
<html lang="en" data-admin="{{.Admin}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>My account · Chat with CLI</title></head>
<body><div class="page"><header class="topbar"><a class="brand" href="/"><span class="brand-mark" aria-hidden="true">⌁</span><span class="brand-name">Chat with CLI</span></a><nav class="nav"><a href="/" data-i18n="Home">Home</a><a href="/docs" data-i18n="Docs">Docs</a><form class="inline" method="post" action="/account/logout"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><button class="text" type="submit" data-i18n="Sign out">Sign out</button></form><div class="ui-controls" data-ui-controls></div></nav></header>
<main><div class="page-header"><span class="eyebrow" data-i18n="Account">Account</span><h1 data-i18n="My Chat with CLI">My Chat with CLI</h1><p><span data-i18n="Signed in as">Signed in as</span> <strong>{{.Username}}</strong></p></div>
{{if .PublicInstance}}<div class="warning"><b data-i18n="Public Relay operator is trusted by design.">Public Relay operator is trusted by design.</b><span data-i18n="This page can prove that other normal users are isolated from your devices. It cannot prove that the operator is harmless: the operator can run modified Relay code and observe or alter MCP traffic. Do not grant sensitive computer access to any public instance, including one operated by the software author; self-host when trust matters.">This page can prove that other normal users are isolated from your devices. It cannot prove that the operator is harmless: the operator can run modified Relay code and observe or alter MCP traffic. Do not grant sensitive computer access to any public instance, including one operated by the software author; self-host when trust matters.</span></div>{{end}}
<section class="surface"><div class="section-heading"><div><span class="eyebrow" data-i18n="ChatGPT / MCP">ChatGPT / MCP</span><h2 data-i18n="Account MCP endpoint">Account MCP endpoint</h2></div><p data-i18n="Use this stable URL in ChatGPT. OAuth grants access only to this account, and each tool call selects one currently owned device.">Use this stable URL in ChatGPT. OAuth grants access only to this account, and each tool call selects one currently owned device.</p></div><div class="copy-row"><code class="command" id="account-mcp-endpoint">{{.PublicURL}}/mcp</code><button class="copy-button" type="button" data-copy-target="account-mcp-endpoint" data-i18n="Copy">Copy</button></div></section>
<section class="surface table-card"><div class="section-heading table-intro"><div><span class="eyebrow" data-i18n="Devices">Devices</span><h2 data-i18n="My devices">My devices</h2></div><p data-i18n="Only devices owned by your account are shown. Disabling immediately revokes current device tokens; permanent revocation retires the cryptographic identity.">Only devices owned by your account are shown. Disabling immediately revokes current device tokens; permanent revocation retires the cryptographic identity.</p></div><div class="table-wrap"><table><thead><tr><th data-i18n="Device">Device</th><th data-i18n="Status">Status</th><th data-i18n="Capabilities">Capabilities</th><th data-i18n="MCP URL">MCP URL</th><th data-i18n="Actions">Actions</th></tr></thead><tbody>{{range .Devices}}<tr><td><b>{{.Name}}</b><br><code>{{.ID}}</code><br>{{if .ProofBound}}<span class="status ok" data-i18n="PoP bound">PoP bound</span>{{else}}<span class="status bad" data-i18n="legacy unbound">legacy unbound</span>{{end}}</td><td>{{if .Online}}<span class="status ok" data-i18n="online">online</span>{{else}}<span data-i18n="offline">offline</span>{{end}}{{if .Disabled}}<br><span class="status bad" data-i18n="disabled">disabled</span>{{end}}{{if not .LastSeen.IsZero}}<br><small><span data-i18n="last seen">last seen</span> {{.LastSeen}}</small>{{end}}</td><td><small>{{if .Capabilities.FilesystemRead}}<span data-i18n="filesystem read">filesystem read</span><br>{{end}}{{if .Capabilities.FilesystemWrite}}<span data-i18n="filesystem write">filesystem write</span><br>{{end}}{{if .Capabilities.Exec}}<span data-i18n="exec">exec</span>{{if .Capabilities.ExecSandbox}} ({{.Capabilities.ExecSandbox}}){{end}}<br>{{end}}{{if .Capabilities.ScreenRead}}<span data-i18n="screen read">screen read</span><br>{{end}}{{if .Capabilities.AccessibilityRead}}<span data-i18n="accessibility read">accessibility read</span><br>{{end}}{{if .Capabilities.ComputerInput}}<span data-i18n="computer input">computer input</span>{{end}}</small></td><td><code>{{.MCPURL}}</code></td><td class="table-actions"><form class="inline" method="post" action="/account/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="rename-device"><input type="hidden" name="target" value="{{.Route}}"><input name="value" data-i18n-placeholder="new name" placeholder="new name" required><button type="submit" data-i18n="Rename">Rename</button></form><form class="inline" method="post" action="/account/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="disable-device"><input type="hidden" name="target" value="{{.Route}}"><input type="hidden" name="value" value="{{if .Disabled}}off{{else}}on{{end}}">{{if .Disabled}}<input type="password" name="password" data-i18n-placeholder="password to enable" placeholder="password to enable" required>{{end}}<button type="submit">{{if .Disabled}}<span data-i18n="Enable">Enable</span>{{else}}<span data-i18n="Disable">Disable</span>{{end}}</button></form><form class="inline" method="post" action="/account/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="revoke-device"><input type="hidden" name="target" value="{{.Route}}"><input name="confirm" data-i18n-placeholder="REVOKE" placeholder="REVOKE" required><button class="danger" type="submit" data-i18n="Revoke permanently">Revoke permanently</button></form></td></tr>{{else}}<tr><td colspan="5" class="muted" data-i18n="No devices are owned by this account yet. Pair an Agent first.">No devices are owned by this account yet. Pair an Agent first.</td></tr>{{end}}</tbody></table></div></section>
{{if .UsageMeteringEnabled}}<section class="surface usage-card" id="relay-usage"><div class="section-heading"><div><span class="eyebrow" data-i18n="Relay usage">Relay usage</span><h2 data-i18n="Support the maintainer">Support the maintainer</h2></div><p data-i18n="MCP and Agent request/response payload bytes are counted at the Relay. Add quota with an activation code.">MCP and Agent request/response payload bytes are counted at the Relay. Add quota with an activation code.</p></div><div class="usage-meter"><div><span data-i18n="Remaining traffic">Remaining traffic</span><strong>{{formatBytes .UsageRemainingBytes}}</strong></div><div><span data-i18n="Used">Used</span><strong>{{formatBytes .UsageUsedBytes}}</strong></div><div><span data-i18n="Granted">Granted</span><strong>{{formatBytes .UsageQuotaBytes}}</strong></div></div><div class="usage-actions"><form class="setting-form" method="post" action="/account/action"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="action" value="redeem-activation-code"><input name="value" autocomplete="one-time-code" data-i18n-placeholder="activation code" placeholder="activation code" required><button class="tonal" type="submit" data-i18n="Redeem activation code">Redeem activation code</button></form></div></section>{{end}}
<section class="surface table-card"><div class="section-heading table-intro"><div><span class="eyebrow" data-i18n="Authorizations">Authorizations</span><h2 data-i18n="Connected authorizations">Connected authorizations</h2></div><p data-i18n="These are your token families, not globally shared OAuth client registrations. Revoking one cannot revoke another user's access.">These are your token families, not globally shared OAuth client registrations. Revoking one cannot revoke another user's access.</p></div><div class="table-wrap"><table><thead><tr><th data-i18n="Client">Client</th><th data-i18n="Resource">Resource</th><th data-i18n="Expires">Expires</th><th data-i18n="Action">Action</th></tr></thead><tbody>{{range .Grants}}<tr><td>{{.ClientName}}<br><code>{{.Label}}</code></td><td><code>{{.Resource}}</code></td><td>{{.Expires}}</td><td><form class="inline" method="post" action="/account/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="revoke-family"><input type="hidden" name="target" value="{{.FamilyHandle}}"><button type="submit" data-i18n="Revoke my authorization">Revoke my authorization</button></form></td></tr>{{else}}<tr><td colspan="4" class="muted" data-i18n="No active OAuth token families.">No active OAuth token families.</td></tr>{{end}}</tbody></table></div></section>
<section class="surface table-card"><div class="section-heading table-intro"><div><span class="eyebrow" data-i18n="Sessions">Sessions</span><h2 data-i18n="Browser sessions">Browser sessions</h2></div><form class="inline" method="post" action="/account/action"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="action" value="logout-others"><button type="submit" data-i18n="Sign out all other sessions">Sign out all other sessions</button></form></div><div class="table-wrap"><table><thead><tr><th data-i18n="Session">Session</th><th data-i18n="Created">Created</th><th data-i18n="Last seen">Last seen</th><th data-i18n="Expires">Expires</th><th data-i18n="Action">Action</th></tr></thead><tbody>{{range .Sessions}}<tr><td><code>{{.Label}}</code>{{if .Current}}<br><span class="status" data-i18n="current">current</span>{{end}}</td><td>{{.Created}}</td><td>{{.LastSeen}}</td><td>{{.Expires}}</td><td>{{if not .Current}}<form class="inline" method="post" action="/account/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="logout-session"><input type="hidden" name="target" value="{{.Handle}}"><button type="submit" data-i18n="Sign out">Sign out</button></form>{{end}}</td></tr>{{end}}</tbody></table></div></section>
<section class="surface"><div class="section-heading"><div><span class="eyebrow" data-i18n="Security">Security</span><h2 data-i18n="Change password">Change password</h2></div><p data-i18n="Changing your password revokes all OAuth credentials and browser sessions for this account. Reconnect devices and apps afterward.">Changing your password revokes all OAuth credentials and browser sessions for this account. Reconnect devices and apps afterward.</p></div><form class="setting-form" method="post" action="/account/action"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="action" value="change-password"><input type="password" name="password" autocomplete="current-password" data-i18n-placeholder="current password" placeholder="current password" required><input type="password" name="value" autocomplete="new-password" minlength="12" data-i18n-placeholder="new password" placeholder="new password" required><button class="danger" type="submit" data-i18n="Change password and revoke credentials">Change password and revoke credentials</button></form></section>
</main><footer class="footer"><a href="/" data-i18n="Back to home">Back to home</a></footer></div></body></html>`))

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
		_ = executeUITemplate(w, r, accountLoginTemplate, map[string]any{"CSRFToken": csrf, "PublicInstance": public, "Admin": false})
		return
	}
	data := s.accountData(r, user)
	data.CSRFToken = csrf
	_ = executeUITemplate(w, r, accountTemplate, data)
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
	data := accountPageData{Username: current.Username, Admin: current.Admin, PublicURL: strings.TrimRight(s.base.String(), "/"), PublicInstance: s.cfg.Mode == ModePublic}
	data.UsageMeteringEnabled = s.usageMeteringEnabled
	if data.UsageMeteringEnabled {
		usage := s.ensureUsageRecordLocked(current.ID)
		data.UsageQuotaBytes, data.UsageUsedBytes, data.UsageRemainingBytes = usage.QuotaBytes, usage.UsedBytes, usageRemaining(usage)
	}
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
	if action == "redeem-activation-code" && !s.allowRate(r, "account-activation", 12, time.Hour) {
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
	if action == "redeem-activation-code" {
		s.mu.Lock()
		if s.persistenceFault {
			s.mu.Unlock()
			http.Error(w, "authorization state is frozen; contact the Relay operator", http.StatusServiceUnavailable)
			return
		}
		live, exists := s.users[current.ID]
		if !exists || live.Disabled || live.PasswordHash != current.PasswordHash {
			s.mu.Unlock()
			http.Error(w, errUnknownUser.Error(), http.StatusBadRequest)
			return
		}
		snapshot := s.snapshotUsageStateLocked()
		err := s.redeemActivationCodeLocked(value, current.ID, time.Now())
		if err == nil {
			err = s.saveUsageOrRollbackLocked(snapshot)
		}
		if err == nil {
			s.recordSecurityLocked(SecurityEvent{Event: "account_redeem-activation-code", User: current.Username, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
		}
		s.mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "/account", http.StatusSeeOther)
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
