package oauthserver

import (
	"crypto/subtle"
	"html/template"
	"net/http"
	"os"
	"strings"
	"time"
)

const setupCSRFCookie = "cwc_setup_csrf"

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'")
		next.ServeHTTP(w, r)
	})
}

type landingPageData struct {
	Version        string
	Mode           string
	GitHubURL      string
	PublicURL      string
	SetupAvailable bool
	Degraded       bool
}

var landingTemplate = template.Must(template.New("landing").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Chat with CLI</title><style>
:root{color-scheme:light dark}*{box-sizing:border-box}body{font:16px system-ui,sans-serif;max-width:980px;margin:0 auto;padding:56px 24px 80px;line-height:1.55}h1{font-size:clamp(34px,7vw,58px);line-height:1.02;margin:.25em 0}.lead{max-width:720px;font-size:19px;color:#777}.badge,.status{display:inline-flex;align-items:center;border:1px solid #8886;border-radius:999px;padding:5px 10px;font-size:13px}.status.ok{color:#188038}.status.bad{color:#b3261e}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin:28px 0}.card{border:1px solid #8885;border-radius:16px;padding:20px;background:#8881}.card h2{font-size:18px;margin:0 0 8px}.meta{display:grid;grid-template-columns:7rem 1fr;gap:7px 12px}.muted{color:#777}.actions{display:flex;gap:10px;flex-wrap:wrap;margin:22px 0}.button{border:1px solid #8888;border-radius:10px;padding:10px 14px;text-decoration:none;color:inherit}.primary{background:#1769e0;color:white;border-color:#1769e0}.steps{counter-reset:step;display:grid;gap:12px}.step{border-left:3px solid #8885;padding-left:14px}.step b{display:block;margin-bottom:3px}code{font:14px ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}.command{display:block;padding:10px 12px;border-radius:9px;background:#8882;margin-top:8px}</style></head>
<body><span class="badge">{{.Mode}} relay</span><h1>Chat with CLI</h1><p class="lead">Connect an MCP client to a workstation through a private, outbound Agent connection. Capabilities stay disabled until the workstation explicitly enables them.</p>
<div class="actions">{{if .SetupAvailable}}<a class="button primary" href="/setup">Finish first-run setup</a>{{else}}<a class="button primary" href="/admin">Open admin console</a>{{end}}<a class="button" href="/docs">Documentation</a><a class="button" href="{{.GitHubURL}}" rel="noreferrer">GitHub</a></div>
<div class="grid"><div class="card"><h2>Relay</h2><div class="meta"><span>Version</span><b>{{.Version}}</b><span>Instance</span><b>{{.Mode}}</b><span>Status</span>{{if .Degraded}}<b class="status bad">authorization frozen</b>{{else}}<b class="status ok">ready</b>{{end}}</div></div>
<div class="card"><h2>{{if .SetupAvailable}}Setup required{{else}}Relay configured{{end}}</h2>{{if .SetupAvailable}}<p>The Relay has not created its owner account yet. Use the one-time token stored locally on the Relay host.</p>{{else}}<p>Owner setup is complete. Devices and credentials are visible only after administrator sign-in.</p>{{end}}</div>
<div class="card"><h2>Security model</h2><p>OAuth credentials are bound to one user, exact device resource, and scope. New public devices use random immutable IDs.</p></div></div>
{{if not .SetupAvailable}}<div class="card"><h2>Add a workstation</h2><div class="steps"><div class="step"><b>1. Create a safe local Agent config</b><span class="muted">Read-only is the default profile.</span><code class="command">chat-with-cli agent setup --relay {{.PublicURL}} --root /path/to/workspace --profile read-only --install-systemd</code></div><div class="step"><b>2. Authorize the generated device ID</b><span class="muted">The setup command prints the exact browser-login command. The service remains disabled until you explicitly start it.</span></div><div class="step"><b>3. Connect your MCP client</b><code class="command">{{.PublicURL}}/mcp/id/&lt;device-id&gt;</code></div></div></div>{{end}}
<p class="muted">Health endpoint: <code>/health</code>. No device inventory or host information is exposed on this public page.</p>
</body></html>`))
var docsTemplate = template.Must(template.New("docs").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Documentation · Chat with CLI</title><style>body{font:16px system-ui,sans-serif;max-width:760px;margin:8vh auto;padding:24px;line-height:1.5}li{margin:9px 0}a{color:#69a7ff}.note{border:1px solid #8885;border-radius:10px;padding:14px}</style></head>
<body><h1>Chat with CLI documentation</h1><p class="note">The binary ships with a small navigation page. The full operator documentation is maintained with the open-source project.</p>
<ul><li><a href="{{.Base}}/blob/main/docs/quick-start.md">Quick start</a></li><li><a href="{{.Base}}/blob/main/docs/private-instance.md">Private Relay</a></li><li><a href="{{.Base}}/blob/main/docs/public-instance.md">Public Relay</a></li><li><a href="{{.Base}}/blob/main/docs/agent.md">Agent configuration</a></li><li><a href="{{.Base}}/blob/main/docs/computer-use.md">Computer Use</a></li><li><a href="{{.Base}}/blob/main/docs/security.md">Security</a> · <a href="{{.Base}}/blob/main/docs/threat-model.md">Threat model</a></li><li><a href="{{.Base}}/blob/main/docs/reverse-proxy.md">Reverse proxy</a> · <a href="{{.Base}}/blob/main/docs/cloudflare.md">Cloudflare</a></li><li><a href="{{.Base}}/blob/main/docs/admin.md">Administration</a> · <a href="{{.Base}}/blob/main/docs/upgrade.md">Upgrade and rollback</a></li><li><a href="{{.Base}}/blob/main/docs/troubleshooting.md">Troubleshooting</a> · <a href="{{.Base}}/blob/main/docs/backup-restore.md">Backup and restore</a></li></ul>
<p><a href="/">Back to home</a></p></body></html>`))

var setupTemplate = template.Must(template.New("setup").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Set up Chat with CLI</title>
<style>:root{color-scheme:light dark}*{box-sizing:border-box}body{font:16px system-ui,sans-serif;max-width:720px;margin:0 auto;padding:48px 24px 72px;line-height:1.5}h1{font-size:36px;margin-bottom:8px}.lead{color:#777}.steps{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:26px 0}.step{border:1px solid #8885;border-radius:12px;padding:12px}.step b{display:block}form{border:1px solid #8885;border-radius:16px;padding:22px}label{display:block;margin-top:16px;font-weight:600}input,select,button{font:inherit;padding:11px;width:100%;box-sizing:border-box;margin-top:6px;border-radius:8px;border:1px solid #8888}button{margin-top:22px;background:#1769e0;color:#fff;border-color:#1769e0;font-weight:650}.note,.warning{padding:14px;border-radius:10px;margin:16px 0}.note{background:#8882}.warning{border:1px solid #b8860b88;background:#b8860b18}.check{display:flex;gap:9px;align-items:flex-start;font-weight:400}.check input{width:auto;margin-top:5px}.muted{color:#777}@media(max-width:620px){.steps{grid-template-columns:1fr}}</style></head>
<body><h1>First-run setup</h1><p class="lead">Create the first administrator and choose how this Relay accepts users. This page permanently disappears after successful setup.</p>
<div class="steps"><div class="step"><b>1 · Local token</b><span class="muted">Read the protected setup-token file on the Relay host.</span></div><div class="step"><b>2 · Owner account</b><span class="muted">Create a strong administrator password.</span></div><div class="step"><b>3 · Add devices</b><span class="muted">Sign in, then pair workstations with immutable IDs.</span></div></div>
<div class="warning"><b>Keep the setup token local.</b> Do not paste it into chat, logs, tickets, or command arguments. It is single-use and removed after successful initialization.</div>
<form method="post" action="/setup"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<label>One-time setup token<input name="setup_token" autocomplete="one-time-code" required></label>
<label>Owner username<input name="username" autocomplete="username" value="owner" minlength="3" maxlength="64" required></label>
<label>Owner password<input type="password" name="password" autocomplete="new-password" minlength="12" maxlength="1024" required><small class="muted">Minimum 12 characters. The Relay stores an Argon2id hash, not this password.</small></label>
<label>Instance mode<select name="mode"><option value="private">Private — recommended</option><option value="public">Public — multi-user</option></select></label>
<label class="check"><input type="checkbox" name="registration" value="open"><span>Enable public self-registration immediately. Leave this off unless you intentionally operate a public multi-user Relay.</span></label>
<button type="submit">Create owner and finish setup</button></form><p class="muted">After setup, sign in to <code>/admin</code> to review security controls before connecting a workstation.</p></body></html>`))

func (s *Server) setupAvailable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.setupTokenHash != "" && len(s.users) == 0
}

func (s *Server) handleLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	version, mode, github := s.cfg.Version, s.cfg.Mode, s.cfg.GitHubURL
	degraded := s.persistenceFault
	s.mu.Unlock()
	if version == "" {
		version = "development"
	}
	if github == "" {
		github = "https://github.com/ifloppy/chat-with-cli"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = landingTemplate.Execute(w, landingPageData{Version: version, Mode: mode, GitHubURL: github, PublicURL: strings.TrimRight(s.base.String(), "/"), SetupAvailable: s.setupAvailable(), Degraded: degraded})
}

func (s *Server) handleDocs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	github := s.cfg.GitHubURL
	s.mu.Unlock()
	if github == "" {
		github = "https://github.com/ifloppy/chat-with-cli"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = docsTemplate.Execute(w, map[string]string{"Base": strings.TrimRight(github, "/")})
}

func (s *Server) setSetupCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: setupCSRFCookie, Value: token, Path: "/setup", MaxAge: int(pendingLifetime.Seconds()), HttpOnly: true, Secure: s.base.Scheme == "https", SameSite: http.SameSiteStrictMode})
}

func doubleSubmitMatches(r *http.Request, cookieName string) bool {
	cookie, err := r.Cookie(cookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	value := r.FormValue("csrf_token")
	return value != "" && len(cookie.Value) == len(value) && subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(value)) == 1
}

func (s *Server) handleSetupGET(w http.ResponseWriter, r *http.Request) {
	if !s.setupAvailable() {
		http.NotFound(w, r)
		return
	}
	token := randomToken(24)
	s.setSetupCSRFCookie(w, token)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = setupTemplate.Execute(w, map[string]string{"CSRFToken": token})
}

func (s *Server) handleSetupPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allowRate(r, "setup", 10, time.Minute) {
		rateLimited(w, 60)
		return
	}
	if !s.setupAvailable() {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil || !doubleSubmitMatches(r, setupCSRFCookie) {
		http.Error(w, "invalid setup form", http.StatusForbidden)
		return
	}
	provided := r.Form.Get("setup_token")
	mode, err := normalizeMode(r.Form.Get("mode"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.cfg.ModeConfigured && mode != s.cfg.Mode {
		http.Error(w, "instance mode is fixed by the Relay configuration; update the configured instance mode before setup", http.StatusBadRequest)
		return
	}
	if len(provided) < 16 || len(provided) > 256 {
		http.Error(w, "invalid setup token", http.StatusForbidden)
		return
	}
	if err := validatePassword(r.Form.Get("password")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	registrationOpen := r.Form.Get("registration") == "open"
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.users) != 0 || s.setupTokenHash == "" || subtle.ConstantTimeCompare([]byte(s.setupTokenHash), []byte(tokenKey(provided))) != 1 {
		http.Error(w, "invalid or expired setup token", http.StatusForbidden)
		return
	}
	snapshot := s.snapshotMutableStateLocked()
	user, err := s.createUserLocked(r.Form.Get("username"), r.Form.Get("password"), true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.cfg.Mode = mode
	s.registrationEnabled = mode == ModePublic && registrationOpen
	s.setupTokenHash = ""
	s.recordSecurityLocked(SecurityEvent{Event: "setup_completed", User: user.Username, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
	if err := s.saveOrRollbackLocked(snapshot); err != nil {
		http.Error(w, "failed to persist setup", http.StatusInternalServerError)
		return
	}
	if s.setupTokenPath != "" {
		if info, err := os.Lstat(s.setupTokenPath); err == nil && info.Mode().IsRegular() {
			_ = os.Remove(s.setupTokenPath)
		}
	}
	// The owner is intentionally not issued a bearer credential in the setup
	// response. The browser signs in through the normal admin session flow.
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) recordSecurityLocked(event SecurityEvent) {
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	if len(event.User) > 128 {
		event.User = event.User[:128]
	}
	if len(event.Device) > 128 {
		event.Device = event.Device[:128]
	}
	if len(s.securityEvents) >= 200 {
		copy(s.securityEvents, s.securityEvents[len(s.securityEvents)-199:])
		s.securityEvents = s.securityEvents[:199]
	}
	s.securityEvents = append(s.securityEvents, event)
}
