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

var landingTemplate = template.Must(template.New("landing").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Chat with CLI</title><style>
:root{color-scheme:light dark}body{font:16px system-ui,sans-serif;max-width:760px;margin:10vh auto;padding:24px;line-height:1.5}a{color:#69a7ff}.card{border:1px solid #8885;border-radius:12px;padding:20px;margin:18px 0}.meta{display:grid;grid-template-columns:8rem 1fr;gap:6px;color:#bbb}.actions{display:flex;gap:14px;flex-wrap:wrap}a.button{border:1px solid #8888;border-radius:8px;padding:10px 14px;text-decoration:none}</style></head>
<body><h1>Chat with CLI</h1><p>Secure, outbound-connected remote development tools for an MCP-compatible client.</p>
<div class="card"><div class="meta"><span>Version</span><span>{{.Version}}</span><span>Instance</span><span>{{.Mode}}</span><span>Relay health</span><span>available</span></div></div>
<div class="actions"><a class="button" href="/admin">Sign in / Admin</a><a class="button" href="/setup">Setup</a><a class="button" href="/docs">Documentation</a><a class="button" href="{{.GitHubURL}}" rel="noreferrer">GitHub</a></div>
</body></html>`))

var docsTemplate = template.Must(template.New("docs").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Documentation · Chat with CLI</title><style>body{font:16px system-ui,sans-serif;max-width:760px;margin:8vh auto;padding:24px;line-height:1.5}li{margin:9px 0}a{color:#69a7ff}.note{border:1px solid #8885;border-radius:10px;padding:14px}</style></head>
<body><h1>Chat with CLI documentation</h1><p class="note">The binary ships with a small navigation page. The full operator documentation is maintained with the open-source project.</p>
<ul><li><a href="{{.Base}}/blob/main/docs/quick-start.md">Quick start</a></li><li><a href="{{.Base}}/blob/main/docs/private-instance.md">Private Relay</a></li><li><a href="{{.Base}}/blob/main/docs/public-instance.md">Public Relay</a></li><li><a href="{{.Base}}/blob/main/docs/agent.md">Agent configuration</a></li><li><a href="{{.Base}}/blob/main/docs/computer-use.md">Computer Use</a></li><li><a href="{{.Base}}/blob/main/docs/security.md">Security</a> · <a href="{{.Base}}/blob/main/docs/threat-model.md">Threat model</a></li><li><a href="{{.Base}}/blob/main/docs/reverse-proxy.md">Reverse proxy</a> · <a href="{{.Base}}/blob/main/docs/cloudflare.md">Cloudflare</a></li><li><a href="{{.Base}}/blob/main/docs/admin.md">Administration</a> · <a href="{{.Base}}/blob/main/docs/upgrade.md">Upgrade and rollback</a></li><li><a href="{{.Base}}/blob/main/docs/troubleshooting.md">Troubleshooting</a> · <a href="{{.Base}}/blob/main/docs/backup-restore.md">Backup and restore</a></li></ul>
<p><a href="/">Back to home</a></p></body></html>`))

var setupTemplate = template.Must(template.New("setup").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Set up Chat with CLI</title>
<style>body{font:16px system-ui,sans-serif;max-width:620px;margin:6vh auto;padding:24px}label{display:block;margin-top:14px}input,select,button{font:inherit;padding:10px;width:100%;box-sizing:border-box;margin-top:5px}button{margin-top:20px}.note{background:#f3f3f3;padding:14px;border-radius:8px}</style></head>
<body><h1>First-run setup</h1><p class="note">This page is available only before the first administrator account is created. Obtain the one-time setup token from the Relay host’s protected setup-token file.</p>
<form method="post" action="/setup"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<label>One-time setup token<input name="setup_token" autocomplete="one-time-code" required></label>
<label>Owner username<input name="username" autocomplete="username" value="owner" minlength="3" maxlength="64" required></label>
<label>Owner password<input type="password" name="password" autocomplete="new-password" minlength="12" maxlength="1024" required></label>
<label>Instance mode<select name="mode"><option value="private">Private (recommended)</option><option value="public">Public</option></select></label>
<label><input type="checkbox" name="registration" value="open"> Enable public account registration</label>
<button type="submit">Complete setup</button></form></body></html>`))

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
	s.mu.Unlock()
	if version == "" {
		version = "development"
	}
	if github == "" {
		github = "https://github.com/ifloppy/chat-with-cli"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = landingTemplate.Execute(w, map[string]string{"Version": version, "Mode": mode, "GitHubURL": github})
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
	user, err := s.createUserLocked(r.Form.Get("username"), r.Form.Get("password"), true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	previousMode, previousRegistration, previousToken := s.cfg.Mode, s.registrationEnabled, s.setupTokenHash
	s.cfg.Mode = mode
	s.registrationEnabled = mode == ModePublic && registrationOpen
	s.setupTokenHash = ""
	s.recordSecurityLocked(SecurityEvent{Event: "setup_completed", User: user.Username, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
	if err := s.saveLocked(); err != nil {
		delete(s.users, user.ID)
		if normalized, ok := normalizeUsername(user.Username); ok {
			delete(s.usernames, normalized)
		}
		s.cfg.Mode, s.registrationEnabled, s.setupTokenHash = previousMode, previousRegistration, previousToken
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
