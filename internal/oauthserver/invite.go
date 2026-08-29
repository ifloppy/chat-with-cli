package oauthserver

import (
	"html/template"
	"net/http"
	"strings"
	"time"
)

const (
	maxInvites     = 1024
	inviteLifetime = 24 * time.Hour
)

func (s *Server) registrationPolicyLocked(now time.Time) (open, inviteOnly bool) {
	if s.cfg.Mode != ModePublic || s.setupTokenHash != "" {
		return false, false
	}
	if s.registrationEnabled {
		return true, false
	}
	unix := now.Unix()
	for _, invite := range s.invites {
		if invite.Expires > unix && invite.UsesRemaining > 0 {
			return false, true
		}
	}
	return false, false
}

func (s *Server) consumeInviteLocked(code string, now time.Time) bool {
	if s.cfg.Mode != ModePublic {
		return false
	}
	if s.registrationEnabled {
		return true
	}
	code = strings.TrimSpace(code)
	if len(code) < 16 || len(code) > 256 {
		return false
	}
	key := tokenKey(code)
	record, ok := s.invites[key]
	if !ok || record.Expires <= now.Unix() || record.UsesRemaining <= 0 {
		return false
	}
	record.UsesRemaining--
	if record.UsesRemaining <= 0 {
		delete(s.invites, key)
	} else {
		s.invites[key] = record
	}
	return true
}

var inviteCreatedTemplate = template.Must(template.New("invite-created").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Invite created · Chat with CLI</title>
<style>:root{color-scheme:light dark}body{font:16px system-ui,sans-serif;max-width:680px;margin:8vh auto;padding:24px;line-height:1.5}.card{border:1px solid #8885;border-radius:14px;padding:20px}.code{display:block;padding:14px;background:#8882;border-radius:9px;font:15px ui-monospace,monospace;overflow-wrap:anywhere}.warning{border:1px solid #b8860b88;background:#b8860b18;padding:12px;border-radius:9px;margin:14px 0}</style></head>
<body><h1>Invite created</h1><div class="card"><p>This invite can be used once and expires at <b>{{.Expires}}</b>.</p><code class="code">{{.Code}}</code><div class="warning"><b>Shown once.</b> The Relay stores only a one-way hash of this code. Copy it now.</div><a href="/admin">Return to admin</a></div></body></html>`))

func (s *Server) handleAdminInvite(w http.ResponseWriter, r *http.Request) {
	if !s.allowRate(r, "admin-invite", 20, time.Hour) {
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
	if !adminSessionFresh(s, r) {
		http.Redirect(w, r, "/admin/reauth", http.StatusSeeOther)
		return
	}
	code := randomToken(24)
	now := time.Now()
	expires := now.Add(inviteLifetime)
	s.mu.Lock()
	if !s.liveAdminLocked(current) || s.cfg.Mode != ModePublic || s.persistenceFault {
		s.mu.Unlock()
		http.Error(w, "public invite creation is unavailable", http.StatusForbidden)
		return
	}
	s.cleanupLocked(now)
	if len(s.invites) >= maxInvites {
		s.mu.Unlock()
		http.Error(w, "invite limit reached", http.StatusTooManyRequests)
		return
	}
	snapshot := s.snapshotMutableStateLocked()
	s.invites[tokenKey(code)] = inviteRecord{CreatedAt: now.Unix(), Expires: expires.Unix(), UsesRemaining: 1, CreatedBy: current.Username}
	s.recordSecurityLocked(SecurityEvent{Event: "create_invite", User: current.Username, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
	if err := s.saveOrRollbackLocked(snapshot); err != nil {
		s.mu.Unlock()
		http.Error(w, "failed to persist invite", http.StatusInternalServerError)
		return
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = inviteCreatedTemplate.Execute(w, map[string]any{"Code": code, "Expires": expires.UTC().Format(time.RFC3339)})
}
