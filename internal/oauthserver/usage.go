package oauthserver

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ifloppy/chat-with-cli/internal/securefile"
)

const (
	defaultUsageQuotaBytes  = int64(100 << 20)
	maxUsageQuotaBytes      = int64(1 << 50)
	activationCodeLifetime  = 365 * 24 * time.Hour
	maxActivationCodes      = 4096
	maxActivationCodeUses   = 1
	maxRewardIDLength       = 128
	maxRewardLifetime       = 24 * time.Hour
	usageCheckpointInterval = 2 * time.Second
)

// usageState is deliberately independent from OAuth/device/token state. Usage
// write failures affect accounting availability, never authorization safety.
type usageState struct {
	Usage           map[string]usageRecord          `json:"usage,omitempty"`
	ActivationCodes map[string]activationCodeRecord `json:"activation_codes,omitempty"`
	RedeemedRewards map[string]int64                `json:"redeemed_rewards,omitempty"`
}

type usageStateSnapshot struct {
	usage           map[string]usageRecord
	activationCodes map[string]activationCodeRecord
	redeemedRewards map[string]int64
	dirty           bool
}

func (s *Server) snapshotUsageStateLocked() usageStateSnapshot {
	return usageStateSnapshot{
		usage:           cloneMap(s.usage),
		activationCodes: cloneMap(s.activationCodes),
		redeemedRewards: cloneMap(s.redeemedRewards),
		dirty:           s.usageDirty,
	}
}

func (s *Server) restoreUsageStateLocked(snapshot usageStateSnapshot) {
	s.usage = snapshot.usage
	s.activationCodes = snapshot.activationCodes
	s.redeemedRewards = snapshot.redeemedRewards
	s.usageDirty = snapshot.dirty
}

func inspectUsageStateFile(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect usage state: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("usage state file must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("usage state file must be a regular file")
	}
	if info.Mode().Perm() != 0o600 {
		return false, errors.New("usage state file must have mode 0600")
	}
	if err := securefile.CheckSingleLink(info, "usage state file"); err != nil {
		return false, err
	}
	return true, nil
}

func validateUsageState(state *usageState, users map[string]User) (bool, error) {
	pruned := false
	if state.Usage == nil {
		state.Usage = make(map[string]usageRecord)
	}
	if state.ActivationCodes == nil {
		state.ActivationCodes = make(map[string]activationCodeRecord)
	}
	if state.RedeemedRewards == nil {
		state.RedeemedRewards = make(map[string]int64)
	}
	for userID, record := range state.Usage {
		if record.QuotaBytes < 0 || record.UsedBytes < 0 || record.QuotaBytes > maxUsageQuotaBytes || record.UsedBytes > maxUsageQuotaBytes {
			return false, fmt.Errorf("persisted usage record for user %s is invalid", shortHandle(userID))
		}
		user, exists := users[userID]
		if !exists || user.ID != userID {
			delete(state.Usage, userID)
			pruned = true
		}
	}
	for key, record := range state.ActivationCodes {
		if !validOpaqueHandle(key) || record.CreatedAt <= 0 || record.Expires <= 0 || record.QuotaBytes <= 0 || record.QuotaBytes > maxUsageQuotaBytes || record.UsesRemaining <= 0 || record.UsesRemaining > maxActivationCodeUses {
			return false, fmt.Errorf("persisted activation code %s is invalid", shortHandle(key))
		}
	}
	for key, expires := range state.RedeemedRewards {
		if len(key) == 0 || len(key) > maxRewardIDLength || expires <= 0 {
			return false, fmt.Errorf("persisted reward claim %s is invalid", shortHandle(key))
		}
	}
	return pruned, nil
}

func (s *Server) loadUsageLocked(legacyUsage map[string]usageRecord, legacyCodes map[string]activationCodeRecord, legacyRewards map[string]int64) error {
	exists, err := inspectUsageStateFile(s.usageFile)
	if err != nil {
		return err
	}
	state := usageState{}
	if exists {
		data, err := securefile.Read(s.usageFile, "usage state file")
		if err != nil {
			return fmt.Errorf("read usage state: %w", err)
		}
		if err := json.Unmarshal(data, &state); err != nil {
			return fmt.Errorf("decode usage state: %w", err)
		}
	} else if len(legacyUsage) > 0 || len(legacyCodes) > 0 || len(legacyRewards) > 0 {
		state.Usage = cloneMap(legacyUsage)
		state.ActivationCodes = cloneMap(legacyCodes)
		state.RedeemedRewards = cloneMap(legacyRewards)
		s.usageDirty = true
	}
	pruned, err := validateUsageState(&state, s.users)
	if err != nil {
		return fmt.Errorf("validate usage state: %w", err)
	}
	s.usage, s.activationCodes, s.redeemedRewards = state.Usage, state.ActivationCodes, state.RedeemedRewards
	s.usageDirty = s.usageDirty || pruned
	if !exists && s.usageDirty {
		if err := s.checkpointUsageLocked(); err != nil {
			return fmt.Errorf("migrate usage state: %w", err)
		}
	}
	return nil
}

func (s *Server) writeUsageStateLocked() error {
	state := usageState{Usage: s.usage, ActivationCodes: s.activationCodes, RedeemedRewards: s.redeemedRewards}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return withStateFileLock(s.usageFile, func() error {
		if _, err := inspectUsageStateFile(s.usageFile); err != nil {
			return err
		}
		tmpFile, err := os.CreateTemp(filepath.Dir(s.usageFile), ".usage-state-*")
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
		if _, err := inspectUsageStateFile(s.usageFile); err != nil {
			return err
		}
		if err := os.Rename(tmp, s.usageFile); err != nil {
			return err
		}
		dir, err := os.Open(filepath.Dir(s.usageFile))
		if err != nil {
			return err
		}
		err = dir.Sync()
		_ = dir.Close()
		return err
	})
}

func (s *Server) checkpointUsageLocked() error {
	if !s.usageDirty {
		return nil
	}
	if err := s.writeUsageStateLocked(); err != nil {
		return err
	}
	s.usageDirty = false
	return nil
}

func (s *Server) saveUsageOrRollbackLocked(snapshot usageStateSnapshot) error {
	s.usageDirty = true
	if err := s.checkpointUsageLocked(); err != nil {
		s.restoreUsageStateLocked(snapshot)
		return err
	}
	return nil
}

func (s *Server) usageCheckpointLoop() {
	ticker := time.NewTicker(usageCheckpointInterval)
	defer ticker.Stop()
	defer close(s.usageDone)
	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			_ = s.checkpointUsageLocked()
			s.mu.Unlock()
		case <-s.usageStop:
			return
		}
	}
}

func formatUsageBytes(value int64) string {
	if value < 0 {
		value = 0
	}
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}
	n := float64(value)
	unit := 0
	for n >= 1024 && unit < len(units)-1 {
		n /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d %s", value, units[unit])
	}
	if n >= 10 || n == float64(int64(n)) {
		return fmt.Sprintf("%.0f %s", n, units[unit])
	}
	return fmt.Sprintf("%.1f %s", n, units[unit])
}

func parseUsageQuota(value string) (int64, error) {
	quota, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || quota <= 0 || quota > maxUsageQuotaBytes {
		return 0, fmt.Errorf("quota must be between 1 and %d bytes", maxUsageQuotaBytes)
	}
	return quota, nil
}

func (s *Server) ensureUsageRecordLocked(userID string) usageRecord {
	if record, ok := s.usage[userID]; ok {
		return record
	}
	quota := s.usageDefaultQuotaBytes
	if quota <= 0 {
		quota = defaultUsageQuotaBytes
	}
	record := usageRecord{QuotaBytes: quota}
	s.usage[userID] = record
	s.usageDirty = true
	return record
}

const legacyAdMobRewardedUsageEnabled = false

func (s *Server) rewardedUsageEnabledLocked() bool {
	// The native AdMob companion reward path is intentionally parked while the
	// web product focuses on AdSense. Keep the verifier and redemption code for
	// backward compatibility, but do not advertise or enable the flow.
	return legacyAdMobRewardedUsageEnabled && s.usageMeteringEnabled && s.cfg.UsageUnlockEnabled
}

func (s *Server) rewardedUsageReadyLocked() bool {
	return s.rewardedUsageEnabledLocked() &&
		strings.TrimSpace(s.cfg.AdMobAppID) != "" &&
		strings.TrimSpace(s.cfg.AdMobRewardUnitID) != "" &&
		strings.TrimSpace(s.cfg.UsageUnlockEndpoint) != "" &&
		strings.TrimSpace(s.cfg.AdMobVerifierSecret) != ""
}

func usageRemaining(record usageRecord) int64 {
	if record.QuotaBytes <= record.UsedBytes {
		return 0
	}
	return record.QuotaBytes - record.UsedBytes
}

func (s *Server) grantQuotaLocked(userID string, quota int64) error {
	if quota <= 0 || quota > maxUsageQuotaBytes {
		return fmt.Errorf("quota grant must be between 1 and %d bytes", maxUsageQuotaBytes)
	}
	if !s.activeUserLocked(userID) {
		return errUnknownUser
	}
	record := s.ensureUsageRecordLocked(userID)
	if record.QuotaBytes > maxUsageQuotaBytes-quota {
		return errors.New("user quota would exceed the maximum")
	}
	record.QuotaBytes += quota
	s.usage[userID] = record
	s.usageDirty = true
	return nil
}

func (s *Server) recordUsageBytesLocked(userID string, bytes int64) {
	if !s.usageMeteringEnabled || bytes <= 0 || !s.activeUserLocked(userID) {
		return
	}
	record := s.ensureUsageRecordLocked(userID)
	if bytes > maxUsageQuotaBytes-record.UsedBytes {
		record.UsedBytes = maxUsageQuotaBytes
	} else {
		record.UsedBytes += bytes
	}
	s.usage[userID] = record
	s.usageDirty = true
}

func (s *Server) recordUsageBytes(userID string, bytes int64) {
	if bytes <= 0 {
		return
	}
	s.mu.Lock()
	if s.usageMeteringEnabled && s.activeUserLocked(userID) {
		s.recordUsageBytesLocked(userID, bytes)
	}
	s.mu.Unlock()
}

// RecordRelayTraffic accounts the Agent-side leg of a brokered request. The
// main Relay wires this callback to the WebSocket broker so long-lived Agent
// connections are included in the same user quota as MCP HTTP traffic.
func (s *Server) RecordRelayTraffic(device string, bytes int64) {
	if bytes <= 0 {
		return
	}
	s.mu.Lock()
	userID := s.devices[device]
	if !s.usageMeteringEnabled || userID == "" || !s.activeUserLocked(userID) {
		s.mu.Unlock()
		return
	}
	s.recordUsageBytesLocked(userID, bytes)
	s.mu.Unlock()
}

func (s *Server) usageForCredential(credentialHash, resource, requiredScope string) (string, usageRecord, bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.verifyAccessKeyLocked(credentialHash, resource, requiredScope) {
		return "", usageRecord{}, false, false
	}
	userID := s.access[credentialHash].UserID
	if !s.usageMeteringEnabled {
		return userID, usageRecord{}, false, true
	}
	record := s.ensureUsageRecordLocked(userID)
	return userID, record, true, true
}

func (s *Server) acquireUsageRequest(credentialHash, resource, requiredScope string) (string, usageRecord, bool, bool, func()) {
	s.mu.Lock()
	if !s.verifyAccessKeyLocked(credentialHash, resource, requiredScope) {
		s.mu.Unlock()
		return "", usageRecord{}, false, false, nil
	}
	userID := s.access[credentialHash].UserID
	if !s.usageMeteringEnabled {
		s.mu.Unlock()
		return userID, usageRecord{}, false, true, nil
	}
	gate := s.usageGates[userID]
	if gate == nil {
		gate = &sync.Mutex{}
		s.usageGates[userID] = gate
	}
	s.mu.Unlock()

	// Never wait on a per-user gate while holding Server.mu: broker traffic and
	// authorization revocation both need that mutex while a request is running.
	gate.Lock()
	s.mu.Lock()
	if !s.verifyAccessKeyLocked(credentialHash, resource, requiredScope) {
		s.mu.Unlock()
		gate.Unlock()
		return "", usageRecord{}, false, false, nil
	}
	if !s.usageMeteringEnabled {
		s.mu.Unlock()
		gate.Unlock()
		return userID, usageRecord{}, false, true, nil
	}
	record := s.ensureUsageRecordLocked(userID)
	s.mu.Unlock()
	return userID, record, true, true, gate.Unlock
}

type usageReadCloser struct {
	io.ReadCloser
	bytes int64
}

func (r *usageReadCloser) Read(data []byte) (int, error) {
	n, err := r.ReadCloser.Read(data)
	r.bytes += int64(n)
	return n, err
}

type usageResponseWriter struct {
	http.ResponseWriter
	bytes  int64
	status int
}

func (w *usageResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *usageResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *usageResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(data)
	w.bytes += int64(n)
	return n, err
}

func (w *usageResponseWriter) Flush() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *usageResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer does not support hijacking")
	}
	return hijacker.Hijack()
}

func (w *usageResponseWriter) Push(target string, options *http.PushOptions) error {
	pusher, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, options)
}

// usageEntitlement is signed by a trusted companion app after it verifies the
// AdMob reward server-side. The browser never gets to choose quota or subject.
type usageEntitlement struct {
	Subject    string `json:"sub"`
	QuotaBytes int64  `json:"quota_bytes"`
	Expires    int64  `json:"exp"`
	ID         string `json:"jti"`
}

func signUsageEntitlement(secret string, claim usageEntitlement) (string, error) {
	if strings.TrimSpace(secret) == "" {
		return "", errors.New("reward verifier secret is empty")
	}
	payload, err := json.Marshal(claim)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (s *Server) verifyUsageEntitlement(raw string, now time.Time) (usageEntitlement, error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 2 || len(parts[0]) > 8192 || len(parts[1]) > 256 || strings.TrimSpace(s.cfg.AdMobVerifierSecret) == "" {
		return usageEntitlement{}, errors.New("invalid reward entitlement")
	}
	provided, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return usageEntitlement{}, errors.New("invalid reward entitlement")
	}
	mac := hmac.New(sha256.New, []byte(s.cfg.AdMobVerifierSecret))
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return usageEntitlement{}, errors.New("invalid reward entitlement")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) > 4096 {
		return usageEntitlement{}, errors.New("invalid reward entitlement")
	}
	var claim usageEntitlement
	if err := json.Unmarshal(payload, &claim); err != nil || claim.Subject == "" || len(claim.ID) == 0 || len(claim.ID) > maxRewardIDLength || claim.QuotaBytes <= 0 || claim.QuotaBytes > maxUsageQuotaBytes || claim.Expires <= now.Unix() || claim.Expires > now.Add(maxRewardLifetime).Unix() {
		return usageEntitlement{}, errors.New("invalid reward entitlement")
	}
	return claim, nil
}

func (s *Server) redeemUsageEntitlementLocked(raw, userID string, now time.Time) error {
	claim, err := s.verifyUsageEntitlement(raw, now)
	if err != nil {
		return err
	}
	if claim.Subject != userID {
		return errors.New("reward entitlement belongs to another account")
	}
	if _, used := s.redeemedRewards[claim.ID]; used {
		return errors.New("reward entitlement has already been redeemed")
	}
	if err := s.grantQuotaLocked(userID, claim.QuotaBytes); err != nil {
		return err
	}
	s.redeemedRewards[claim.ID] = claim.Expires
	return nil
}

func (s *Server) activationCodeLocked(quota int64, createdBy string, now time.Time) (string, error) {
	if quota <= 0 || quota > maxUsageQuotaBytes {
		return "", fmt.Errorf("activation quota must be between 1 and %d bytes", maxUsageQuotaBytes)
	}
	if len(s.activationCodes) >= maxActivationCodes {
		return "", errors.New("activation code limit reached")
	}
	code := "cwc-" + randomToken(24)
	s.activationCodes[tokenKey(code)] = activationCodeRecord{CreatedAt: now.Unix(), Expires: now.Add(activationCodeLifetime).Unix(), QuotaBytes: quota, UsesRemaining: maxActivationCodeUses, CreatedBy: createdBy}
	s.usageDirty = true
	return code, nil
}

func (s *Server) redeemActivationCodeLocked(raw, userID string, now time.Time) error {
	raw = strings.TrimSpace(raw)
	if len(raw) < 8 || len(raw) > 256 {
		return errors.New("invalid activation code")
	}
	key := tokenKey(raw)
	record, ok := s.activationCodes[key]
	if !ok || record.Expires <= now.Unix() || record.UsesRemaining <= 0 {
		return errors.New("invalid or expired activation code")
	}
	if err := s.grantQuotaLocked(userID, record.QuotaBytes); err != nil {
		return err
	}
	record.UsesRemaining--
	if record.UsesRemaining <= 0 {
		delete(s.activationCodes, key)
	} else {
		s.activationCodes[key] = record
	}
	return nil
}

func normalizeUsageUnlockEndpoint(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", errors.New("endpoint must be an HTTPS URL")
	}
	if u.User != nil || u.Fragment != "" {
		return "", errors.New("endpoint must not contain credentials or a fragment")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func normalizeAdIdentifier(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if len(value) > 160 || strings.ContainsAny(value, " \t\r\n<>\"'") {
		return "", errors.New("advertising identifier contains invalid characters")
	}
	return value, nil
}

func (s *Server) usageUnlockURL(userID string) string {
	endpoint := strings.TrimSpace(s.cfg.UsageUnlockEndpoint)
	if endpoint == "" {
		return ""
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	query := u.Query()
	query.Set("relay", strings.TrimRight(s.base.String(), "/"))
	query.Set("subject", userID)
	query.Set("return_to", s.absolute("/account/admob/redeem"))
	u.RawQuery = query.Encode()
	return u.String()
}

var activationCodeCreatedTemplate = template.Must(template.New("activation-code-created").Funcs(template.FuncMap{"formatBytes": formatUsageBytes}).Parse(`<!doctype html>
<html lang="en" data-locale="auto"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title data-i18n="Activation code created">Activation code created</title><link rel="stylesheet" href="/assets/app.css?v=content"><script src="/assets/app.js?v=content" defer></script></head>
<body><div class="page compact"><header class="topbar"><a class="brand" href="/" data-i18n="Chat with CLI">Chat with CLI</a><nav class="nav"><a href="/admin" data-i18n="Return to admin">Return to admin</a><div class="ui-controls" data-ui-controls></div></nav></header><main><div class="page-header"><span class="eyebrow" data-i18n="Support">Support</span><h1 data-i18n="Activation code created">Activation code created</h1><p data-i18n="This code is shown once. Share it with the intended user and keep it private until then.">This code is shown once. Share it with the intended user and keep it private until then.</p></div><section class="surface"><p><span data-i18n="Quota">Quota</span>: <strong>{{formatBytes .QuotaBytes}}</strong></p><code class="command" id="activation-code">{{.Code}}</code><button class="copy-button" type="button" data-copy-target="activation-code" data-i18n="Copy">Copy</button><p class="muted"><span data-i18n="Expires">Expires</span>: {{.Expires}}</p></section></main><footer class="footer"><a href="/admin" data-i18n="Return to admin">Return to admin</a></footer></div></body></html>`))

var usageRedeemTemplate = template.Must(template.New("usage-redeem").Parse(`<!doctype html>
<html lang="en" data-locale="auto"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title data-i18n="Claim rewarded usage">Claim rewarded usage</title><link rel="stylesheet" href="/assets/app.css?v=content"><script src="/assets/app.js?v=content" defer></script></head>
<body><div class="page compact"><header class="topbar"><a class="brand" href="/" data-i18n="Chat with CLI">Chat with CLI</a><nav class="nav"><a href="/account" data-i18n="My account">My account</a><div class="ui-controls" data-ui-controls></div></nav></header><main><div class="page-header"><span class="eyebrow" data-i18n="Support">Support</span><h1 data-i18n="Claim rewarded usage">Claim rewarded usage</h1><p data-i18n="The companion app returned a server-verified reward. Confirm below to add it to this account.">The companion app returned a server-verified reward. Confirm below to add it to this account.</p></div><form class="surface" method="post" action="/account/admob/redeem"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="token" value="{{.Token}}"><button class="primary" type="submit" data-i18n="Add rewarded quota">Add rewarded quota</button></form><p class="auth-footer"><a href="/account" data-i18n="Cancel">Cancel</a></p></main></div></body></html>`))

func (s *Server) handleAdminActivationCode(w http.ResponseWriter, r *http.Request) {
	current, ok := s.sessionUser(r)
	if r.Method != http.MethodPost || !ok || !current.Admin {
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
	quota, err := parseUsageQuota(r.Form.Get("value"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	now := time.Now()
	s.mu.Lock()
	if s.persistenceFault || !s.liveAdminLocked(current) {
		s.mu.Unlock()
		http.Error(w, "activation code creation is unavailable during authorization recovery", http.StatusServiceUnavailable)
		return
	}
	usageSnapshot := s.snapshotUsageStateLocked()
	code, err := s.activationCodeLocked(quota, current.Username, now)
	if err == nil {
		err = s.saveUsageOrRollbackLocked(usageSnapshot)
	}
	if err == nil {
		s.recordSecurityLocked(SecurityEvent{Event: "create_activation_code", User: current.Username, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
	}
	s.mu.Unlock()
	if err != nil {
		http.Error(w, "failed to persist activation code", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = executeUITemplate(w, r, activationCodeCreatedTemplate, map[string]any{"Code": code, "QuotaBytes": quota, "Expires": now.Add(activationCodeLifetime).UTC().Format(time.RFC3339)})
}

func (s *Server) handleAdminMonetization(w http.ResponseWriter, r *http.Request) {
	current, ok := s.sessionUser(r)
	if r.Method != http.MethodPost || !ok || !current.Admin {
		http.Error(w, "administrator authentication required", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil || !doubleSubmitMatches(r, adminCSRFCookie) {
		http.Error(w, "invalid admin form", http.StatusForbidden)
		return
	}
	if !adminSessionFresh(s, r) {
		http.Redirect(w, r, "/admin/reauth", http.StatusSeeOther)
		return
	}
	quota, err := parseUsageQuota(r.Form.Get("default_quota_bytes"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	adsenseClient, err := normalizeAdIdentifier(r.Form.Get("adsense_client_id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	adsenseSlot, err := normalizeAdIdentifier(r.Form.Get("adsense_slot"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if (adsenseClient == "") != (adsenseSlot == "") {
		http.Error(w, "AdSense client ID and slot must be configured together", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	if s.persistenceFault || !s.liveAdminLocked(current) {
		s.mu.Unlock()
		http.Error(w, "monetization settings are unavailable during authorization recovery", http.StatusServiceUnavailable)
		return
	}
	snapshot := s.snapshotMutableStateLocked()
	s.cfg.AdSenseClientID, s.cfg.AdSenseSlot = adsenseClient, adsenseSlot
	s.usageDefaultQuotaBytes = quota
	s.usageConfigured = true
	s.monetizationConfigured = true
	s.recordSecurityLocked(SecurityEvent{Event: "set_monetization", User: current.Username, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
	err = s.saveOrRollbackLocked(snapshot)
	s.mu.Unlock()
	if err != nil {
		http.Error(w, "failed to persist monetization settings", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleAccountAdMobRedeem(w http.ResponseWriter, r *http.Request) {
	current, ok := s.sessionUser(r)
	if !ok {
		http.Error(w, "account authentication required", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	rewardedUsageEnabled := s.rewardedUsageEnabledLocked()
	s.mu.Unlock()
	if !rewardedUsageEnabled {
		http.Error(w, "rewarded usage is disabled", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodGet {
		token := strings.TrimSpace(r.URL.Query().Get("token"))
		if token == "" || len(token) > 9000 {
			http.Error(w, "invalid reward entitlement", http.StatusBadRequest)
			return
		}
		csrf := randomToken(24)
		s.setAccountCSRFCookie(w, csrf)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = executeUITemplate(w, r, usageRedeemTemplate, map[string]any{"CSRFToken": csrf, "Token": token})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil || !doubleSubmitMatches(r, accountCSRFCookie) {
		http.Error(w, "invalid account form", http.StatusForbidden)
		return
	}
	token := strings.TrimSpace(r.Form.Get("token"))
	s.mu.Lock()
	if !s.rewardedUsageEnabledLocked() {
		s.mu.Unlock()
		http.Error(w, "rewarded usage is disabled", http.StatusForbidden)
		return
	}
	if s.persistenceFault {
		s.mu.Unlock()
		http.Error(w, "authorization state is frozen; contact the Relay operator", http.StatusServiceUnavailable)
		return
	}
	snapshot := s.snapshotUsageStateLocked()
	err := s.redeemUsageEntitlementLocked(token, current.ID, time.Now())
	if err == nil {
		err = s.saveUsageOrRollbackLocked(snapshot)
	}
	if err == nil {
		s.recordSecurityLocked(SecurityEvent{Event: "account_redeem_admob_reward", User: current.Username, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
	}
	s.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}
