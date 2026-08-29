package oauthserver

import (
	"crypto/subtle"
	"encoding/hex"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ifloppy/chat-with-cli/internal/protocol"
)

const adminCSRFCookie = "cwc_admin_csrf"

func (s *Server) SetDeviceStatusProvider(provider func() map[string]DeviceStatus) {
	s.mu.Lock()
	s.statusProvider = provider
	s.mu.Unlock()
}

type adminDeviceView struct {
	Route        string
	ID           string
	Name         string
	Owner        string
	Disabled     bool
	Online       bool
	ConnectedAt  time.Time
	LastSeen     time.Time
	InFlight     int
	Capabilities protocol.AgentCapabilities
	ProofBound   bool
}

type adminUserView struct {
	ID          string
	Username    string
	Admin       bool
	Disabled    bool
	CreatedAt   time.Time
	LastLoginAt time.Time
	Devices     int
}

type adminTokenView struct {
	Handle   string
	Label    string
	Kind     string
	ClientID string
	Username string
	Resource string
	Expires  time.Time
}

type adminSessionView struct {
	Handle   string
	Label    string
	Username string
	Created  time.Time
	LastSeen time.Time
	Expires  time.Time
}

type adminPageData struct {
	Version             string
	Mode                string
	PublicURL           string
	PersistenceFault    bool
	RegistrationEnabled bool
	DCREnabled          bool
	MCPEnabled          bool
	AgentEnabled        bool
	KillSwitch          bool
	LegacyUnboundAgents bool
	Uptime              string
	OnlineAgents        int
	RegisteredDevices   int
	RetiredDevices      int
	Users               int
	OAuthClients        int
	Sessions            int
	Devices             []adminDeviceView
	UserList            []adminUserView
	Clients             []Client
	Tokens              []adminTokenView
	SessionList         []adminSessionView
	Events              []SecurityEvent
	CSRFToken           string
	Username            string
}

var adminLoginTemplate = template.Must(template.New("admin-login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin sign in · Chat with CLI</title>
<style>body{font:16px system-ui,sans-serif;max-width:460px;margin:10vh auto;padding:24px}label{display:block;margin-top:14px}input,button{font:inherit;padding:10px;width:100%;box-sizing:border-box;margin-top:5px}button{margin-top:20px}.note{color:#666}</style></head>
<body><h1>Chat with CLI admin</h1><p class="note">Sign in to manage devices, users, sessions, and emergency capability switches.</p>
<form method="post" action="/admin/login"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><label>Username<input name="username" autocomplete="username" required></label><label>Password<input type="password" name="password" autocomplete="current-password" required></label><button type="submit">Sign in</button></form>
<p><a href="/">Back to home</a></p></body></html>`))

var adminReauthTemplate = template.Must(template.New("admin-reauth").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Re-authenticate · Chat with CLI</title>
<style>:root{color-scheme:light dark}*{box-sizing:border-box}body{font:16px system-ui,sans-serif;max-width:500px;margin:0 auto;padding:64px 24px;line-height:1.5}form{border:1px solid #8885;border-radius:14px;padding:22px}label{display:block;font-weight:650}input,button{font:inherit;width:100%;padding:11px;margin-top:7px;border-radius:8px;border:1px solid #8888}button{margin-top:18px;background:#1769e0;color:#fff;border-color:#1769e0}.muted{color:#777}.actions{margin-top:18px}</style></head>
<body><h1>Confirm it’s you</h1><p class="muted">High-risk administration actions require a password check within the last 15 minutes. This refreshes only the current browser session.</p>
<form method="post" action="/admin/reauth"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><label>Password for {{.Username}}<input type="password" name="password" autocomplete="current-password" required autofocus></label><button type="submit">Re-authenticate</button></form><p class="actions"><a href="/admin">Cancel and return to admin</a></p></body></html>`))

var adminTemplate = template.Must(template.New("admin").Funcs(template.FuncMap{"join": strings.Join}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin · Chat with CLI</title>
<style>:root{color-scheme:light dark}*{box-sizing:border-box}body{font:14px system-ui,sans-serif;max-width:1240px;margin:0 auto;padding:28px 20px 70px;line-height:1.45}h1{font-size:30px;margin:0}h2{margin:30px 0 10px;font-size:20px}a{color:inherit}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}.card,section,details{border:1px solid #8885;border-radius:12px;padding:15px;margin:10px 0;background:#8881}.card b{display:block;font-size:25px}.ok{color:#188038}.bad{color:#b3261e}.warning{border-color:#b8860b88;background:#b8860b18}.critical{border-color:#b3261e88;background:#b3261e14}.banner{padding:14px 16px;border-radius:10px;margin:12px 0}.banner b{display:block;margin-bottom:3px}table{width:100%;border-collapse:collapse;display:block;overflow:auto}th,td{text-align:left;padding:8px;border-bottom:1px solid #8884;vertical-align:top}input,select,button{font:inherit;padding:7px;max-width:100%;border-radius:6px;border:1px solid #8888}button{cursor:pointer}form.inline{display:inline-flex;gap:5px;align-items:center;flex-wrap:wrap;margin:2px}.danger{background:#b3261e;color:#fff;border-color:#b3261e}.muted{color:#777}.pill{padding:3px 7px;border-radius:999px;background:#8883}.toolbar{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap}.toolbar .nav{display:flex;gap:12px;align-items:center}.onboarding{border-color:#1769e066}.steps{display:grid;gap:10px}.step{border-left:3px solid #1769e0;padding-left:12px}.step code{display:block;background:#8882;padding:9px;border-radius:8px;margin-top:5px;overflow-wrap:anywhere}summary{cursor:pointer;font-size:18px;font-weight:650}details>summary{margin:-3px 0}code{overflow-wrap:anywhere}</style></head>
<body><div class="toolbar"><div><h1>Chat with CLI admin</h1><span class="muted">{{.PublicURL}}</span></div><div class="nav"><a href="/">Home</a><a href="/docs">Docs</a><a href="/admin/reauth">Re-authenticate</a><form method="post" action="/admin/logout"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><button type="submit">Sign out</button></form></div></div>
<p>Signed in as <b>{{.Username}}</b> · version <b>{{.Version}}</b> · <b>{{.Mode}}</b> instance · uptime <b>{{.Uptime}}</b>.</p>
{{if .PersistenceFault}}<div class="banner critical"><b>Authorization is frozen</b>The Relay detected an incomplete authorization-state transaction. MCP and Agent access remain fail-closed across restarts. Repair storage, repeat the intended revoke/disable action, and persist it successfully; recovery writes force the emergency kill switch on. Restart, verify the security state, then explicitly release the kill switch. Do not delete <code>oauth-state.guard</code> to bypass recovery.</div>{{end}}
{{if .KillSwitch}}<div class="banner critical"><b>Emergency kill switch is active</b>MCP and Agent authorization is globally blocked. Releasing it requires recent administrator authentication.</div>{{end}}
{{if .LegacyUnboundAgents}}<div class="banner critical"><b>Legacy bearer-only Agent migration mode is ENABLED</b>Unbound alpha Agents can connect using only an Agent bearer token. This weakens device impersonation resistance and must be used only long enough to migrate old devices to new Ed25519 identities, then disabled in the Relay configuration.</div>{{end}}
<div class="grid"><div class="card"><b>{{.OnlineAgents}}</b>online agents</div><div class="card"><b>{{.RegisteredDevices}}</b>registered devices</div><div class="card"><b>{{.RetiredDevices}}</b>retired identities</div><div class="card"><b>{{.Users}}</b>users</div><div class="card"><b>{{.OAuthClients}}</b>OAuth clients</div><div class="card"><b>{{.Sessions}}</b>sessions</div></div>

<h2>Security controls</h2><section><p>Registration: <span class="pill">{{if .RegistrationEnabled}}enabled{{else}}disabled{{end}}</span> · DCR: <span class="pill">{{if .DCREnabled}}enabled{{else}}disabled{{end}}</span> · MCP: <span class="pill">{{if .MCPEnabled}}enabled{{else}}disabled{{end}}</span> · Agent: <span class="pill">{{if .AgentEnabled}}enabled{{else}}disabled{{end}}</span> · Kill switch: <span class="pill">{{if .KillSwitch}}ACTIVE{{else}}off{{end}}</span></p>
{{if eq .Mode "public"}}<form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="action" value="set-registration"><input type="hidden" name="value" value="{{if .RegistrationEnabled}}off{{else}}on{{end}}"><button type="submit">{{if .RegistrationEnabled}}Disable{{else}}Enable{{end}} registration</button></form>{{end}}
<form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="action" value="set-dcr"><input type="hidden" name="value" value="{{if .DCREnabled}}off{{else}}on{{end}}"><button type="submit">{{if .DCREnabled}}Disable{{else}}Enable{{end}} DCR</button></form>
<form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="action" value="set-mcp"><input type="hidden" name="value" value="{{if .MCPEnabled}}off{{else}}on{{end}}"><button type="submit">{{if .MCPEnabled}}Disable{{else}}Enable{{end}} MCP</button></form>
<form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="action" value="set-agent"><input type="hidden" name="value" value="{{if .AgentEnabled}}off{{else}}on{{end}}"><button type="submit">{{if .AgentEnabled}}Disable{{else}}Enable{{end}} Agent</button></form>
<form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="action" value="set-kill-switch"><input type="hidden" name="value" value="{{if .KillSwitch}}off{{else}}on{{end}}">{{if .KillSwitch}}<input name="confirm" placeholder="type RELEASE" size="11" required>{{end}}<button class="danger" type="submit">{{if .KillSwitch}}Release kill switch{{else}}Emergency disable now{{end}}</button></form>
</section>

{{if eq .RegisteredDevices 0}}<h2>Connect your first workstation</h2><section class="onboarding"><p>No device is registered yet. Start with the read-only profile; nothing is started automatically.</p><div class="steps"><div class="step"><b>1. On the workstation</b><code>chat-with-cli agent setup --relay {{.PublicURL}} --root /path/to/workspace --profile read-only --install-systemd</code></div><div class="step"><b>2. Authorize the immutable device ID</b>The setup command prints the exact <code>chat-with-cli login</code> command. Complete browser OAuth as the intended owner.</div><div class="step"><b>3. Review, then start</b>Review the generated config/unit and explicitly enable the Agent only when its capabilities are acceptable.</div></div></section>{{end}}

<h2>Devices</h2><section><p class="muted"><b>Disable</b> is reversible. <b>Revoke permanently</b> retires the device identity so the same private key can never claim this ID again; reconnecting requires a newly generated device identity.</p><table><tr><th>Display name</th><th>Immutable ID / route</th><th>Owner</th><th>Connection</th><th>Capabilities</th><th>Actions</th></tr>{{range .Devices}}<tr><td><b>{{.Name}}</b></td><td><code>{{.ID}}</code><br><small>{{.Route}}</small><br>{{if .ProofBound}}<span class="ok">PoP bound</span>{{else}}<span class="bad">legacy unbound</span>{{end}}</td><td>{{.Owner}}</td><td>{{if .Online}}<span class="ok">online</span>{{else}}<span class="muted">offline</span>{{end}}{{if .Disabled}} · <span class="bad">disabled</span>{{end}}{{if not .LastSeen.IsZero}}<br><small>last seen {{.LastSeen}}</small>{{end}}{{if .InFlight}}<br><small>in flight {{.InFlight}}</small>{{end}}</td><td>{{if .Online}}<small>{{if .Capabilities.FilesystemRead}}filesystem read<br>{{end}}{{if .Capabilities.FilesystemWrite}}filesystem write<br>{{end}}{{if .Capabilities.Exec}}exec{{if .Capabilities.ExecSandbox}} ({{.Capabilities.ExecSandbox}}){{end}}<br>{{end}}{{if .Capabilities.ScreenRead}}screen read<br>{{end}}{{if .Capabilities.AccessibilityRead}}accessibility read<br>{{end}}{{if .Capabilities.ComputerInput}}computer input{{end}}</small>{{else}}<span class="muted">not reported</span>{{end}}</td><td><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="rename-device"><input type="hidden" name="target" value="{{.Route}}"><input name="value" placeholder="new display name" size="14" required><button type="submit">Rename</button></form><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="disable-device"><input type="hidden" name="target" value="{{.Route}}"><input type="hidden" name="value" value="{{if .Disabled}}off{{else}}on{{end}}"><button type="submit">{{if .Disabled}}Enable{{else}}Disable{{end}}</button></form><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="revoke-device"><input type="hidden" name="target" value="{{.Route}}"><input name="confirm" placeholder="REVOKE" size="8" required><button class="danger" type="submit">Revoke permanently</button></form></td></tr>{{else}}<tr><td colspan="6" class="muted">No devices have been claimed.</td></tr>{{end}}</table></section>

<h2>Users</h2><section><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="action" value="create-user"><input name="target" autocomplete="username" placeholder="new username" minlength="3" maxlength="64" required><input name="value" type="password" autocomplete="new-password" minlength="12" placeholder="temporary password" required><button type="submit">Create user</button></form><table><tr><th>Username</th><th>Role / state</th><th>Created / last login</th><th>Actions</th></tr>{{range .UserList}}<tr><td><b>{{.Username}}</b></td><td>{{if .Admin}}admin {{end}}{{if .Disabled}}<span class="bad">disabled</span>{{else}}<span class="ok">active</span>{{end}}<br>{{.Devices}} device(s)</td><td>{{.CreatedAt}}<br>{{if not .LastLoginAt.IsZero}}{{.LastLoginAt}}{{else}}<span class="muted">never</span>{{end}}</td><td><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="disable-user"><input type="hidden" name="target" value="{{.ID}}"><input type="hidden" name="value" value="{{if .Disabled}}off{{else}}on{{end}}"><button type="submit">{{if .Disabled}}Enable{{else}}Disable{{end}}</button></form><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="logout-user"><input type="hidden" name="target" value="{{.ID}}"><button type="submit">Logout all</button></form><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="rotate-password"><input type="hidden" name="target" value="{{.ID}}"><input name="value" type="password" minlength="12" placeholder="new password" required><button type="submit">Rotate password</button></form><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="delete-user"><input type="hidden" name="target" value="{{.ID}}"><input name="confirm" placeholder="DELETE" size="8" required><button class="danger" type="submit">Delete</button></form></td></tr>{{end}}</table></section>

<details><summary>Browser sessions · {{.Sessions}}</summary><p>Session handles are one-way identifiers; browser cookie values are never displayed.</p><table><tr><th>Handle</th><th>User</th><th>Created</th><th>Last seen</th><th>Expires</th><th>Action</th></tr>{{range .SessionList}}<tr><td><code>{{.Label}}</code></td><td>{{.Username}}</td><td>{{.Created}}</td><td>{{.LastSeen}}</td><td>{{.Expires}}</td><td><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="logout-session"><input type="hidden" name="target" value="{{.Handle}}"><button type="submit">Log out</button></form></td></tr>{{else}}<tr><td colspan="6" class="muted">No active browser sessions.</td></tr>{{end}}</table></details>

<details><summary>OAuth clients and token metadata · {{.OAuthClients}} clients / {{len .Tokens}} token records</summary><table><tr><th>Client</th><th>Name / redirects</th><th>Actions</th></tr>{{range .Clients}}<tr><td><code>{{.ID}}</code><br><small>{{.IssuedAt}}</small></td><td>{{.Name}}<br><small>{{join .RedirectURIs ", "}}</small></td><td><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="revoke-client"><input type="hidden" name="target" value="{{.ID}}"><input name="confirm" placeholder="REVOKE" size="8" required><button class="danger" type="submit">Revoke client</button></form></td></tr>{{else}}<tr><td colspan="3" class="muted">No approved clients.</td></tr>{{end}}</table>
<p><b>{{len .Tokens}}</b> active token records (metadata only; bearer values are never displayed).</p><table><tr><th>Handle</th><th>Kind</th><th>User</th><th>Resource</th><th>Expires</th><th>Action</th></tr>{{range .Tokens}}<tr><td><code>{{.Label}}</code></td><td>{{.Kind}}</td><td>{{.Username}}</td><td><code>{{.Resource}}</code></td><td>{{.Expires}}</td><td><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="revoke-token"><input type="hidden" name="target" value="{{.Handle}}"><input name="confirm" placeholder="REVOKE" size="8" required><button class="danger" type="submit">Revoke</button></form></td></tr>{{else}}<tr><td colspan="6" class="muted">No active tokens.</td></tr>{{end}}</table></details>

<details><summary>Recent security events · {{len .Events}}</summary><table><tr><th>Time</th><th>Event</th><th>User / device</th><th>Result</th></tr>{{range .Events}}<tr><td>{{.Time}}</td><td>{{.Event}}</td><td>{{.User}}{{if .Device}} / {{.Device}}{{end}}</td><td>{{if .Success}}success{{else}}failure{{end}}</td></tr>{{else}}<tr><td colspan="4" class="muted">No events recorded.</td></tr>{{end}}</table></details>
<p><a href="/">Back to home</a></p></body></html>`))

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := s.sessionUser(r)
	if !ok || !user.Admin {
		token := randomToken(24)
		http.SetCookie(w, &http.Cookie{Name: adminCSRFCookie, Value: token, Path: "/admin", MaxAge: int(sessionLifetime.Seconds()), HttpOnly: true, Secure: s.base.Scheme == "https", SameSite: http.SameSiteStrictMode})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = adminLoginTemplate.Execute(w, map[string]string{"CSRFToken": token})
		return
	}
	s.renderAdmin(w, user)
}

func (s *Server) handleAdminReauthGET(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessionUser(r)
	if !ok || !user.Admin {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	csrf := randomToken(24)
	http.SetCookie(w, &http.Cookie{Name: adminCSRFCookie, Value: csrf, Path: "/admin", MaxAge: int(sessionLifetime.Seconds()), HttpOnly: true, Secure: s.base.Scheme == "https", SameSite: http.SameSiteStrictMode})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = adminReauthTemplate.Execute(w, map[string]string{"CSRFToken": csrf, "Username": user.Username})
}

func (s *Server) handleAdminReauthPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allowRate(r, "admin-reauth", 10, time.Minute) {
		rateLimited(w, 60)
		return
	}
	current, ok := s.sessionUser(r)
	if !ok || !current.Admin {
		http.Error(w, "administrator authentication required", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil || !doubleSubmitMatches(r, adminCSRFCookie) {
		http.Error(w, "invalid admin form", http.StatusForbidden)
		return
	}
	verified, authenticated, busy := s.authenticate(current.Username, r.Form.Get("password"))
	if busy {
		http.Error(w, "login capacity is busy; retry shortly", http.StatusTooManyRequests)
		return
	}
	if !authenticated || verified.ID != current.ID || !verified.Admin {
		s.recordSecurity(SecurityEvent{Event: "admin_reauth", User: current.Username, RemoteIP: requestIP(r, s.trustedProxies), Success: false})
		http.Error(w, "invalid administrator password", http.StatusUnauthorized)
		return
	}
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		http.Error(w, "administrator session expired", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	recovering := s.persistenceFault
	snapshot := s.snapshotMutableStateLocked()
	handle := tokenKey(cookie.Value)
	record, exists := s.sessions[handle]
	if !exists || record.UserID != current.ID {
		s.mu.Unlock()
		http.Error(w, "administrator session expired", http.StatusUnauthorized)
		return
	}
	record.LastReauthAt = time.Now().Unix()
	s.sessions[handle] = record
	s.recordSecurityLocked(SecurityEvent{Event: "admin_reauth", User: current.Username, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
	if recovering {
		// Fresh authentication is kept process-local during recovery. It may
		// authorize a subsequent authority-reducing recovery action, but must
		// not consume the dirty authorization-state guard by itself.
		err = nil
	} else {
		err = s.saveOrRollbackLocked(snapshot)
	}
	s.mu.Unlock()
	if err != nil {
		http.Error(w, "failed to persist re-authentication", http.StatusServiceUnavailable)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if !s.allowRate(r, "admin-login", 15, time.Minute) {
		rateLimited(w, 60)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil || !doubleSubmitMatches(r, adminCSRFCookie) {
		http.Error(w, "invalid admin form", http.StatusForbidden)
		return
	}
	user, authenticated, busy := s.authenticate(r.Form.Get("username"), r.Form.Get("password"))
	if busy {
		http.Error(w, "login capacity is busy; retry shortly", http.StatusTooManyRequests)
		return
	}
	if !authenticated || !user.Admin {
		s.recordSecurity(SecurityEvent{Event: "admin_login", User: r.Form.Get("username"), RemoteIP: requestIP(r, s.trustedProxies), Success: false})
		http.Error(w, "invalid administrator credentials", http.StatusUnauthorized)
		return
	}
	session, err := s.createSession(user.ID)
	if err != nil {
		http.Error(w, "failed to persist login session", http.StatusInternalServerError)
		return
	}
	s.recordSecurity(SecurityEvent{Event: "admin_login", User: user.Username, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
	s.setSessionCookie(w, session)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !doubleSubmitMatches(r, adminCSRFCookie) {
		http.Error(w, "invalid admin form", http.StatusForbidden)
		return
	}
	s.clearSession(w, r)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) renderAdmin(w http.ResponseWriter, current User) {
	data := s.adminData(current)
	csrf := randomToken(24)
	http.SetCookie(w, &http.Cookie{Name: adminCSRFCookie, Value: csrf, Path: "/admin", MaxAge: int(sessionLifetime.Seconds()), HttpOnly: true, Secure: s.base.Scheme == "https", SameSite: http.SameSiteStrictMode})
	data.CSRFToken = csrf
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = adminTemplate.Execute(w, data)
}

func (s *Server) adminData(current User) adminPageData {
	s.mu.Lock()
	s.cleanupLocked(time.Now())
	uptime := time.Since(s.startedAt)
	if uptime < 0 {
		uptime = 0
	}
	data := adminPageData{Version: s.cfg.Version, Mode: s.cfg.Mode, PublicURL: strings.TrimRight(s.base.String(), "/"), PersistenceFault: s.persistenceFault, Uptime: uptime.Round(time.Second).String(), RegistrationEnabled: s.registrationEnabled, DCREnabled: s.dcrEnabled, MCPEnabled: s.mcpEnabled, AgentEnabled: s.agentEnabled, KillSwitch: s.killSwitch, LegacyUnboundAgents: s.cfg.AllowLegacyUnboundAgents, RetiredDevices: len(s.retiredDevices), Users: len(s.users), OAuthClients: len(s.clients), Sessions: len(s.sessions), Username: current.Username, Events: append([]SecurityEvent(nil), s.securityEvents...)}
	provider := s.statusProvider
	devices := make(map[string]string, len(s.devices))
	for name, userID := range s.devices {
		devices[name] = userID
	}
	for name, userID := range devices {
		user := s.users[userID]
		record := s.ensureDeviceRecordLocked(name, userID)
		data.Devices = append(data.Devices, adminDeviceView{Route: name, ID: record.ID, Name: record.DisplayName, Owner: user.Username, Disabled: s.disabledDevices[name] || record.Disabled, ProofBound: record.DevicePublicKey != ""})
	}
	for _, user := range s.users {
		count := 0
		for _, owner := range s.devices {
			if owner == user.ID {
				count++
			}
		}
		view := adminUserView{ID: user.ID, Username: user.Username, Admin: user.Admin, Disabled: user.Disabled, Devices: count}
		if user.CreatedAt > 0 {
			view.CreatedAt = time.Unix(user.CreatedAt, 0)
		}
		if user.LastLoginAt > 0 {
			view.LastLoginAt = time.Unix(user.LastLoginAt, 0)
		}
		data.UserList = append(data.UserList, view)
	}
	for _, client := range s.clients {
		if client.Approved {
			data.Clients = append(data.Clients, client)
		}
	}
	for handle, record := range s.access {
		user := s.users[record.UserID]
		data.Tokens = append(data.Tokens, adminTokenView{Handle: handle, Label: shortHandle(handle), Kind: "access", ClientID: record.ClientID, Username: user.Username, Resource: record.Resource, Expires: time.Unix(record.Expires, 0)})
	}
	for handle, record := range s.refresh {
		user := s.users[record.UserID]
		data.Tokens = append(data.Tokens, adminTokenView{Handle: handle, Label: shortHandle(handle), Kind: "refresh", ClientID: record.ClientID, Username: user.Username, Resource: record.Resource, Expires: time.Unix(record.Expires, 0)})
	}
	for handle, record := range s.sessions {
		user := s.users[record.UserID]
		data.SessionList = append(data.SessionList, adminSessionView{Handle: handle, Label: shortHandle(handle), Username: user.Username, Created: time.Unix(record.CreatedAt, 0), LastSeen: time.Unix(record.LastSeenAt, 0), Expires: time.Unix(record.Expires, 0)})
	}
	data.RegisteredDevices = len(data.Devices)
	s.mu.Unlock()
	if provider != nil {
		statuses := provider()
		for i := range data.Devices {
			if status, ok := statuses[data.Devices[i].Route]; ok {
				data.Devices[i].Online, data.Devices[i].ConnectedAt, data.Devices[i].LastSeen, data.Devices[i].InFlight, data.Devices[i].Capabilities = status.Online, status.ConnectedAt, status.LastSeen, status.InFlight, status.Capabilities
				if status.Online {
					data.OnlineAgents++
				}
			}
		}
	}
	sort.Slice(data.Devices, func(i, j int) bool { return data.Devices[i].Name < data.Devices[j].Name })
	sort.Slice(data.UserList, func(i, j int) bool { return data.UserList[i].Username < data.UserList[j].Username })
	sort.Slice(data.Clients, func(i, j int) bool { return data.Clients[i].IssuedAt > data.Clients[j].IssuedAt })
	sort.Slice(data.Tokens, func(i, j int) bool { return data.Tokens[i].Expires.Before(data.Tokens[j].Expires) })
	sort.Slice(data.SessionList, func(i, j int) bool { return data.SessionList[i].LastSeen.After(data.SessionList[j].LastSeen) })
	if len(data.Events) > 50 {
		data.Events = data.Events[len(data.Events)-50:]
	}
	return data
}

func shortHandle(handle string) string {
	if len(handle) <= 16 {
		return handle
	}
	return handle[:16] + "…"
}

func (s *Server) handleAdminAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := s.sessionUser(r)
	if !ok || !user.Admin {
		http.Error(w, "administrator authentication required", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil || !doubleSubmitMatches(r, adminCSRFCookie) {
		http.Error(w, "invalid admin form", http.StatusForbidden)
		return
	}
	action := strings.TrimSpace(r.Form.Get("action"))
	if requiresFreshAdminAuth(action, r.Form.Get("value")) && !adminSessionFresh(s, r) {
		http.Redirect(w, r, "/admin/reauth", http.StatusSeeOther)
		return
	}
	if isConfirmRequired(action, r.Form.Get("value")) && !validConfirmation(action, r.Form.Get("value"), r.Form.Get("confirm")) {
		http.Error(w, "confirmation text is required", http.StatusBadRequest)
		return
	}
	if err := s.applyAdminAction(action, r.Form.Get("target"), r.Form.Get("value"), user, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func requiresFreshAdminAuth(action, value string) bool {
	switch action {
	case "revoke-device", "delete-user", "revoke-client", "revoke-token", "rotate-password", "rename-device", "create-user":
		return true
	case "disable-device", "disable-user":
		disabled, valid := parseToggle(value)
		return valid && !disabled
	case "set-registration", "set-dcr", "set-mcp", "set-agent":
		enabled, valid := parseToggle(value)
		return valid && enabled
	case "set-kill-switch":
		// Emergency disable must remain available to any authenticated admin;
		// releasing the global kill switch expands authority and requires a
		// recently authenticated session.
		enabled, valid := parseToggle(value)
		return valid && !enabled
	default:
		return false
	}
}

func isConfirmRequired(action, value string) bool {
	switch action {
	case "revoke-device", "delete-user", "revoke-client", "revoke-token":
		return true
	case "set-kill-switch":
		enabled, valid := parseToggle(value)
		return valid && !enabled
	default:
		return false
	}
}

func validConfirmation(action, value, confirmation string) bool {
	want := "REVOKE"
	if action == "set-kill-switch" {
		enabled, valid := parseToggle(value)
		if !valid || enabled {
			return false
		}
		want = "RELEASE"
	}
	if action == "delete-user" {
		want = "DELETE"
	}
	return len(confirmation) == len(want) && subtle.ConstantTimeCompare([]byte(confirmation), []byte(want)) == 1
}

func adminSessionFresh(s *Server, r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		return false
	}
	s.mu.Lock()
	record := s.sessions[tokenKey(cookie.Value)]
	s.mu.Unlock()
	if record.LastReauthAt <= 0 {
		return false
	}
	age := time.Since(time.Unix(record.LastReauthAt, 0))
	return age >= 0 && age <= 15*time.Minute
}

func parseToggle(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "on", "true", "1":
		return true, true
	case "off", "false", "0":
		return false, true
	default:
		return false, false
	}
}

func persistenceRecoveryActionAllowed(action, value string) bool {
	switch action {
	case "rotate-password", "revoke-device", "delete-user", "logout-user", "logout-all", "logout-session", "revoke-client", "revoke-token":
		return true
	case "disable-device", "disable-user":
		disabled, valid := parseToggle(value)
		return valid && disabled
	case "set-registration", "set-dcr", "set-mcp", "set-agent":
		enabled, valid := parseToggle(value)
		return valid && !enabled
	case "set-kill-switch":
		enabled, valid := parseToggle(value)
		return valid && enabled
	default:
		return false
	}
}

func (s *Server) applyAdminAction(action, target, value string, current User, r *http.Request) error {
	if action == "create-user" {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.persistenceFault {
			return errPersistenceRecoveryOnly
		}
		snapshot := s.snapshotMutableStateLocked()
		user, err := s.createUserLocked(target, value)
		if err != nil {
			return err
		}
		s.recordSecurityLocked(SecurityEvent{Event: action, User: user.Username, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
		return s.saveOrRollbackLocked(snapshot)
	}
	if action == "rotate-password" {
		if err := validatePassword(value); err != nil {
			return err
		}
		hash, err := hashPassword(value)
		if err != nil {
			return err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		recovering := s.persistenceFault
		if recovering && !persistenceRecoveryActionAllowed(action, value) {
			return errPersistenceRecoveryOnly
		}
		snapshot := s.snapshotMutableStateLocked()
		user, exists := s.users[target]
		if !exists || user.Disabled {
			return errUnknownUser
		}
		user.PasswordHash = hash
		s.users[target] = user
		// Password rotation is a credential-compromise recovery action, not just
		// a browser logout. Revoke every token family so already-connected Agents
		// fail their next per-RPC revalidation as well.
		s.resetOwnedAgentSessionsLocked(target)
		s.revokeUserCredentialsLocked(target)
		s.recordSecurityLocked(SecurityEvent{Event: action, User: user.Username, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
		if recovering {
			return s.saveRecoveryOrRollbackLocked(snapshot)
		}
		return s.saveOrRollbackLocked(snapshot)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	recovering := s.persistenceFault
	if recovering && !persistenceRecoveryActionAllowed(action, value) {
		return errPersistenceRecoveryOnly
	}
	snapshot := s.snapshotMutableStateLocked()
	changed := true
	switch action {
	case "set-registration":
		state, valid := parseToggle(value)
		if !valid || s.cfg.Mode != ModePublic {
			return errInvalidAdminAction
		}
		s.registrationEnabled = state
	case "set-dcr":
		state, valid := parseToggle(value)
		if !valid {
			return errInvalidAdminAction
		}
		s.dcrEnabled = state
	case "set-mcp":
		state, valid := parseToggle(value)
		if !valid {
			return errInvalidAdminAction
		}
		s.mcpEnabled = state
		if !state {
			s.resetAllAgentSessionsLocked()
		}
	case "set-agent":
		state, valid := parseToggle(value)
		if !valid {
			return errInvalidAdminAction
		}
		s.agentEnabled = state
		if !state {
			s.resetAllAgentSessionsLocked()
		}
	case "set-kill-switch":
		state, valid := parseToggle(value)
		if !valid {
			return errInvalidAdminAction
		}
		s.killSwitch = state
		if state {
			s.resetAllAgentSessionsLocked()
		}
	case "disable-device":
		if _, exists := s.devices[target]; !exists {
			return errUnknownDevice
		}
		state, valid := parseToggle(value)
		if !valid {
			return errInvalidAdminAction
		}
		s.disabledDevices[target] = state
		record := s.ensureDeviceRecordLocked(target, s.devices[target])
		record.Disabled = state
		s.deviceRecords[target] = record
		if state {
			s.agentSessionResetterSafe(target)
			s.revokeDeviceTokensLocked(target)
		}
	case "revoke-device":
		if _, exists := s.devices[target]; !exists {
			return errUnknownDevice
		}
		s.agentSessionResetterSafe(target)
		// Revocation retires the cryptographic route permanently. If the
		// device private key was compromised, deleting the record would let
		// the holder immediately reclaim the same immutable identity.
		s.retiredDevices[target] = true
		delete(s.devices, target)
		delete(s.disabledDevices, target)
		delete(s.deviceRecords, target)
		s.revokeDeviceTokensLocked(target)
		s.revokeDeviceClientsLocked(target)
	case "rename-device":
		if !validateDeviceRoute(target) || !validateDeviceDisplayName(value) {
			return errInvalidAdminAction
		}
		owner, exists := s.devices[target]
		if !exists {
			return errUnknownDevice
		}
		record := s.ensureDeviceRecordLocked(target, owner)
		record.DisplayName = strings.TrimSpace(value)
		s.deviceRecords[target] = record
	case "disable-user":
		user, exists := s.users[target]
		if !exists || user.ID == current.ID {
			return errUnknownUser
		}
		state, valid := parseToggle(value)
		if !valid {
			return errInvalidAdminAction
		}
		user.Disabled = state
		s.users[target] = user
		if user.Disabled {
			s.resetOwnedAgentSessionsLocked(target)
			s.revokeUserCredentialsLocked(target)
		}
	case "delete-user":
		if target == current.ID {
			return errCannotDeleteSelf
		}
		if _, exists := s.users[target]; !exists {
			return errUnknownUser
		}
		s.resetOwnedAgentSessionsLocked(target)
		delete(s.users, target)
		for normalized, id := range s.usernames {
			if id == target {
				delete(s.usernames, normalized)
			}
		}
		for device, owner := range s.devices {
			if owner == target {
				// Deleting an account must not make its old device identities
				// claimable by whoever still holds a device private key.
				s.retiredDevices[device] = true
				s.revokeDeviceClientsLocked(device)
				delete(s.devices, device)
				delete(s.disabledDevices, device)
				delete(s.deviceRecords, device)
			}
		}
		s.revokeUserCredentialsLocked(target)
	case "logout-user":
		if _, exists := s.users[target]; !exists {
			return errUnknownUser
		}
		s.deleteUserSessionsLocked(target)
	case "logout-all":
		if _, exists := s.users[target]; !exists {
			return errUnknownUser
		}
		s.deleteUserSessionsLocked(target)
	case "logout-session":
		if !validOpaqueHandle(target) {
			return errUnknownSession
		}
		if _, exists := s.sessions[target]; !exists {
			return errUnknownSession
		}
		delete(s.sessions, target)
	case "revoke-client":
		if _, exists := s.clients[target]; !exists {
			return errUnknownClient
		}
		s.revokeClientLocked(target)
	case "revoke-token":
		if !validOpaqueHandle(target) {
			return errUnknownToken
		}
		if record, exists := s.refresh[target]; exists {
			s.resetAgentSessionForResourceLocked(record.Resource)
			s.revokeFamilyLocked(record.Family)
			break
		}
		if record, exists := s.refreshUsed[target]; exists {
			s.resetAgentSessionForResourceLocked(record.Resource)
			s.revokeFamilyLocked(record.Family)
			break
		}
		if record, exists := s.access[target]; exists {
			s.resetAgentSessionForResourceLocked(record.Resource)
			s.revokeFamilyLocked(record.Family)
			break
		}
		return errUnknownToken
	default:
		changed = false
	}
	if !changed {
		return errInvalidAdminAction
	}
	eventTarget := target
	if action == "revoke-token" || action == "logout-session" {
		eventTarget = shortHandle(target)
	}
	s.recordSecurityLocked(SecurityEvent{Event: action, User: current.Username, Device: eventTarget, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
	if recovering {
		return s.saveRecoveryOrRollbackLocked(snapshot)
	}
	return s.saveOrRollbackLocked(snapshot)
}

func validOpaqueHandle(handle string) bool {
	if len(handle) != 64 {
		return false
	}
	_, err := hex.DecodeString(handle)
	return err == nil
}

func (s *Server) recordSecurity(event SecurityEvent) {
	s.mu.Lock()
	s.recordSecurityLocked(event)
	_ = s.saveLocked()
	s.mu.Unlock()
}

func validateDeviceDisplayName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 256 || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validateDeviceName(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func validateDeviceRoute(route string) bool {
	if strings.HasPrefix(route, "id/") {
		return protocol.ValidDeviceID(strings.TrimPrefix(route, "id/"))
	}
	return validateDeviceName(route)
}

func (s *Server) deleteUserSessionsLocked(userID string) {
	for key, record := range s.sessions {
		if record.UserID == userID {
			delete(s.sessions, key)
		}
	}
}

func (s *Server) revokeClientLocked(clientID string) {
	for _, record := range s.access {
		if record.ClientID == clientID {
			s.resetAgentSessionForResourceLocked(record.Resource)
		}
	}
	for _, record := range s.refresh {
		if record.ClientID == clientID {
			s.resetAgentSessionForResourceLocked(record.Resource)
		}
	}
	delete(s.clients, clientID)
	for key, record := range s.access {
		if record.ClientID == clientID {
			delete(s.access, key)
		}
	}
	for key, record := range s.refresh {
		if record.ClientID == clientID {
			delete(s.refresh, key)
		}
	}
	for key, record := range s.refreshUsed {
		if record.ClientID == clientID {
			delete(s.refreshUsed, key)
		}
	}
	for key, pending := range s.pending {
		if pending.ClientID == clientID {
			delete(s.pending, key)
		}
	}
	for key, code := range s.codes {
		if code.ClientID == clientID {
			delete(s.codes, key)
		}
	}
}

func (s *Server) revokeDeviceClientsLocked(device string) {
	if !strings.HasPrefix(device, "id/") {
		return
	}
	deviceID := strings.TrimPrefix(device, "id/")
	for clientID, client := range s.clients {
		if client.DeviceKeyVerified && client.DeviceID == deviceID {
			s.revokeClientLocked(clientID)
		}
	}
}

func (s *Server) revokeUserCredentialsLocked(userID string) {
	s.deleteUserSessionsLocked(userID)
	for key, code := range s.codes {
		if code.UserID == userID {
			delete(s.codes, key)
		}
	}
	for key, pending := range s.pending {
		if pending.UserID == userID {
			delete(s.pending, key)
		}
	}
	for key, record := range s.access {
		if record.UserID == userID {
			delete(s.access, key)
		}
	}
	for key, record := range s.refresh {
		if record.UserID == userID {
			delete(s.refresh, key)
		}
	}
	for key, record := range s.refreshUsed {
		if record.UserID == userID {
			delete(s.refreshUsed, key)
		}
	}
}

func (s *Server) revokeDeviceTokensLocked(device string) {
	for key, pending := range s.pending {
		if s.resourceUsesDevice(pending.Resource, device) {
			delete(s.pending, key)
		}
	}
	for key, code := range s.codes {
		if s.resourceUsesDevice(code.Resource, device) {
			delete(s.codes, key)
		}
	}
	for key, record := range s.access {
		if s.resourceUsesDevice(record.Resource, device) {
			delete(s.access, key)
		}
	}
	for key, record := range s.refresh {
		if s.resourceUsesDevice(record.Resource, device) {
			delete(s.refresh, key)
		}
	}
	for key, record := range s.refreshUsed {
		if s.resourceUsesDevice(record.Resource, device) {
			delete(s.refreshUsed, key)
		}
	}
}

func (s *Server) resourceUsesDevice(resource, device string) bool {
	_, resourceDevice, _, ok := s.resourceParts(resource)
	return ok && resourceDevice == device
}

func (s *Server) renameDeviceTokensLocked(old, new string) {
	for key, record := range s.access {
		record.Resource = strings.Replace(record.Resource, s.absolute("/mcp/"+old), s.absolute("/mcp/"+new), 1)
		record.Resource = strings.Replace(record.Resource, s.absolute("/agent/"+old), s.absolute("/agent/"+new), 1)
		s.access[key] = record
	}
	for key, record := range s.refresh {
		record.Resource = strings.Replace(record.Resource, s.absolute("/mcp/"+old), s.absolute("/mcp/"+new), 1)
		record.Resource = strings.Replace(record.Resource, s.absolute("/agent/"+old), s.absolute("/agent/"+new), 1)
		s.refresh[key] = record
	}
	for key, record := range s.refreshUsed {
		record.Resource = strings.Replace(record.Resource, s.absolute("/mcp/"+old), s.absolute("/mcp/"+new), 1)
		record.Resource = strings.Replace(record.Resource, s.absolute("/agent/"+old), s.absolute("/agent/"+new), 1)
		s.refreshUsed[key] = record
	}
}

var (
	errInvalidAdminAction      = &adminError{"invalid administrator action"}
	errUnknownUser             = &adminError{"unknown user"}
	errUnknownDevice           = &adminError{"unknown device"}
	errUnknownClient           = &adminError{"unknown OAuth client"}
	errUnknownToken            = &adminError{"unknown token record"}
	errUnknownSession          = &adminError{"unknown browser session"}
	errDeviceNameTaken         = &adminError{"device name is already in use"}
	errCannotDeleteSelf        = &adminError{"cannot delete the current administrator"}
	errPersistenceRecoveryOnly = &adminError{"authorization recovery mode only permits authority-reducing actions; complete recovery and restart before expanding access"}
)

type adminError struct{ message string }

func (e *adminError) Error() string { return e.message }
