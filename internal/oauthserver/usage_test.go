package oauthserver

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestUsageActivationCodeAndRewardEntitlement(t *testing.T) {
	s, err := New(Config{
		PublicURL:              "http://127.0.0.1:19311",
		Password:               "usage-test-password-123456",
		StateDir:               t.TempDir(),
		UsageMeteringEnabled:   true,
		UsageDefaultQuotaBytes: 10,
		AdMobVerifierSecret:    "test-reward-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now()
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	code, err := s.activationCodeLocked(20, "owner", now)
	if err == nil {
		err = s.redeemActivationCodeLocked(code, ownerID, now)
	}
	if err == nil {
		err = s.redeemActivationCodeLocked(code, ownerID, now)
	}
	if err == nil || !strings.Contains(err.Error(), "invalid or expired") {
		s.mu.Unlock()
		t.Fatalf("second activation-code redemption err=%v", err)
	}
	claim := usageEntitlement{Subject: ownerID, QuotaBytes: 30, Expires: now.Add(time.Hour).Unix(), ID: "reward-1"}
	token, signErr := signUsageEntitlement(s.cfg.AdMobVerifierSecret, claim)
	if signErr == nil {
		s.redeemedRewards = make(map[string]int64)
		err = s.redeemUsageEntitlementLocked(token, ownerID, now)
	}
	if err == nil {
		err = s.redeemUsageEntitlementLocked(token, ownerID, now)
	}
	s.mu.Unlock()
	if signErr != nil {
		t.Fatal(signErr)
	}
	if err == nil || !strings.Contains(err.Error(), "already been redeemed") {
		t.Fatalf("second reward redemption err=%v", err)
	}

	s.mu.Lock()
	record := s.usage[ownerID]
	_, activationCodeStillStored := s.activationCodes[tokenKey(code)]
	_, rewardStillStored := s.redeemedRewards[claim.ID]
	s.mu.Unlock()
	if record.QuotaBytes != 60 || record.UsedBytes != 0 {
		t.Fatalf("unexpected granted quota: %+v", record)
	}
	if activationCodeStillStored || !rewardStillStored {
		t.Fatalf("unexpected redemption state: activation=%v reward=%v", activationCodeStillStored, rewardStillStored)
	}
}

func TestProtectedResourceChargesRelayPayloadBytes(t *testing.T) {
	s, err := New(Config{
		PublicURL:              "http://127.0.0.1:19312",
		Password:               "usage-protect-test-password-123456",
		StateDir:               t.TempDir(),
		UsageMeteringEnabled:   true,
		UsageDefaultQuotaBytes: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.clients["usage-client"] = Client{ID: "usage-client", Approved: true}
	s.devices["usage-device"] = ownerID
	access, _, _, err := s.issueTokensLocked("usage-client", ownerID, s.absolute("/mcp/usage-device"), "mcp offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	handler := s.ProtectScopedResource("mcp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Errorf("read request body: %v", err)
			return
		}
		_, _ = w.Write([]byte("response"))
	}))
	request := httptest.NewRequest(http.MethodPost, s.absolute("/mcp/usage-device"), strings.NewReader("request"))
	request.Header.Set("Authorization", "Bearer "+access)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "response" {
		t.Fatalf("first protected request status=%d body=%q", response.Code, response.Body.String())
	}

	s.mu.Lock()
	record := s.usage[ownerID]
	record.QuotaBytes = record.UsedBytes
	s.usage[ownerID] = record
	s.mu.Unlock()
	if record.UsedBytes != int64(len("request")+len("response")) {
		t.Fatalf("unexpected measured payload bytes: %+v", record)
	}

	exhausted := httptest.NewRecorder()
	second := httptest.NewRequest(http.MethodPost, s.absolute("/mcp/usage-device"), strings.NewReader("next"))
	second.Header.Set("Authorization", "Bearer "+access)
	handler.ServeHTTP(exhausted, second)
	if exhausted.Code != http.StatusPaymentRequired || !strings.Contains(exhausted.Body.String(), "quota exhausted") {
		t.Fatalf("exhausted request status=%d body=%q", exhausted.Code, exhausted.Body.String())
	}

	s.RecordRelayTraffic("usage-device", 7)
	s.mu.Lock()
	record = s.usage[ownerID]
	s.mu.Unlock()
	if record.UsedBytes != int64(len("request")+len("response"))+7 {
		t.Fatalf("Agent-side traffic was not recorded: %+v", record)
	}
}

func TestUsageMeteringDisabledDoesNotCreateUsageRecord(t *testing.T) {
	s, err := New(Config{
		PublicURL: "http://127.0.0.1:19313",
		Password:  "usage-disabled-test-password-123456",
		StateDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.mu.Unlock()
	s.recordUsageBytes(ownerID, 100)
	s.mu.Lock()
	_, exists := s.usage[ownerID]
	s.mu.Unlock()
	if exists {
		t.Fatal("disabled usage metering created a usage record")
	}
}

func TestUsageIncrementIsBatchedSeparatelyAndCloseFlushes(t *testing.T) {
	stateDir := t.TempDir()
	s, err := New(Config{PublicURL: "http://127.0.0.1:19314", Password: "usage-close-test-password-123456", StateDir: stateDir, UsageMeteringEnabled: true, UsageDefaultQuotaBytes: 1000})
	if err != nil {
		t.Fatal(err)
	}
	oauthPath := filepath.Join(stateDir, "oauth-state.json")
	usagePath := filepath.Join(stateDir, "usage-state.json")
	before, err := os.ReadFile(oauthPath)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.mu.Unlock()
	s.recordUsageBytes(ownerID, 123)
	if _, err := os.Stat(usagePath); !os.IsNotExist(err) {
		t.Fatalf("ordinary increment was synchronously persisted: %v", err)
	}
	after, err := os.ReadFile(oauthPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("ordinary usage increment rewrote oauth-state.json")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(usagePath)
	if err != nil {
		t.Fatal(err)
	}
	var persisted usageState
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatal(err)
	}
	if got := persisted.Usage[ownerID].UsedBytes; got != 123 {
		t.Fatalf("Close-flushed used bytes=%d", got)
	}
	info, err := os.Stat(usagePath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("usage state mode=%v err=%v", info.Mode().Perm(), err)
	}
}

func TestLegacyOAuthUsageMigratesOnce(t *testing.T) {
	stateDir := t.TempDir()
	cfg := Config{PublicURL: "http://127.0.0.1:19315", Password: "usage-migration-test-password-123456", StateDir: stateDir, UsageMeteringEnabled: true, UsageDefaultQuotaBytes: 1000}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.mu.Unlock()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Simulate the short-lived legacy layout, which had metering data only in
	// oauth-state.json and therefore no separate usage-state.json yet.
	if err := os.Remove(filepath.Join(stateDir, "usage-state.json")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	oauthPath := filepath.Join(stateDir, "oauth-state.json")
	data, err := os.ReadFile(oauthPath)
	if err != nil {
		t.Fatal(err)
	}
	var legacy diskState
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatal(err)
	}
	legacy.Usage = map[string]usageRecord{ownerID: {QuotaBytes: 1000, UsedBytes: 321}}
	legacy.ActivationCodes = map[string]activationCodeRecord{tokenKey("legacy-code"): {CreatedAt: time.Now().Unix(), Expires: time.Now().Add(time.Hour).Unix(), QuotaBytes: 50, UsesRemaining: 1}}
	legacy.RedeemedRewards = map[string]int64{"legacy-reward": time.Now().Add(time.Hour).Unix()}
	data, err = json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oauthPath, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restarted.mu.Lock()
	record := restarted.usage[ownerID]
	_, hasCode := restarted.activationCodes[tokenKey("legacy-code")]
	_, hasReward := restarted.redeemedRewards["legacy-reward"]
	restarted.mu.Unlock()
	if record.UsedBytes != 321 || !hasCode || !hasReward {
		t.Fatalf("legacy usage not migrated: record=%+v code=%v reward=%v", record, hasCode, hasReward)
	}
	oauthAfter, err := os.ReadFile(oauthPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(oauthAfter, []byte(`"usage"`)) || bytes.Contains(oauthAfter, []byte(`"activation_codes"`)) || bytes.Contains(oauthAfter, []byte(`"redeemed_rewards"`)) {
		t.Fatal("migrated usage data remained in oauth-state.json")
	}
}

func TestUsagePersistenceFailureRollsBackWithoutOAuthFault(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19316", Password: "usage-failure-test-password-123456", StateDir: t.TempDir(), UsageMeteringEnabled: true, UsageDefaultQuotaBytes: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	code, err := s.activationCodeLocked(20, "owner", now)
	if err == nil {
		err = s.saveUsageOrRollbackLocked(usageStateSnapshot{usage: make(map[string]usageRecord), activationCodes: make(map[string]activationCodeRecord), redeemedRewards: make(map[string]int64)})
	}
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	claim := usageEntitlement{Subject: ownerID, QuotaBytes: 30, Expires: now.Add(time.Hour).Unix(), ID: "failure-reward"}
	token, err := signUsageEntitlement(s.cfg.AdMobVerifierSecret, claim)
	if err != nil {
		// The verifier is intentionally configured only for this failure path.
		s.cfg.AdMobVerifierSecret = "failure-test-secret"
		token, err = signUsageEntitlement(s.cfg.AdMobVerifierSecret, claim)
	}
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	originalUsageFile := s.usageFile
	s.usageFile = filepath.Join(t.TempDir(), "missing", "usage-state.json")
	baseline := s.ensureUsageRecordLocked(ownerID)

	grantSnapshot := s.snapshotUsageStateLocked()
	err = s.grantQuotaLocked(ownerID, 10)
	if err == nil {
		err = s.saveUsageOrRollbackLocked(grantSnapshot)
	}
	if err == nil || s.usage[ownerID] != baseline {
		s.mu.Unlock()
		t.Fatalf("failed grant was not rolled back: err=%v usage=%+v", err, s.usage[ownerID])
	}

	activationSnapshot := s.snapshotUsageStateLocked()
	err = s.redeemActivationCodeLocked(code, ownerID, now)
	if err == nil {
		err = s.saveUsageOrRollbackLocked(activationSnapshot)
	}
	_, codeStillAvailable := s.activationCodes[tokenKey(code)]
	if err == nil || !codeStillAvailable || s.usage[ownerID] != baseline {
		s.mu.Unlock()
		t.Fatalf("failed activation redemption was not rolled back: err=%v code=%v usage=%+v", err, codeStillAvailable, s.usage[ownerID])
	}

	rewardSnapshot := s.snapshotUsageStateLocked()
	err = s.redeemUsageEntitlementLocked(token, ownerID, now)
	if err == nil {
		err = s.saveUsageOrRollbackLocked(rewardSnapshot)
	}
	_, rewardConsumed := s.redeemedRewards[claim.ID]
	fault := s.persistenceFault
	s.usageFile = originalUsageFile
	s.mu.Unlock()
	if err == nil || rewardConsumed || fault {
		t.Fatalf("failed reward rollback err=%v consumed=%v OAuth fault=%v", err, rewardConsumed, fault)
	}
}

func TestActivationAndRewardRemainSingleUseAfterRestart(t *testing.T) {
	stateDir := t.TempDir()
	cfg := Config{PublicURL: "http://127.0.0.1:19317", Password: "usage-durable-test-password-123456", StateDir: stateDir, UsageMeteringEnabled: true, UsageDefaultQuotaBytes: 100, AdMobVerifierSecret: "durable-reward-secret"}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	createSnapshot := s.snapshotUsageStateLocked()
	code, err := s.activationCodeLocked(20, "owner", now)
	if err == nil {
		err = s.saveUsageOrRollbackLocked(createSnapshot)
	}
	redeemSnapshot := s.snapshotUsageStateLocked()
	if err == nil {
		err = s.redeemActivationCodeLocked(code, ownerID, now)
	}
	if err == nil {
		err = s.saveUsageOrRollbackLocked(redeemSnapshot)
	}
	claim := usageEntitlement{Subject: ownerID, QuotaBytes: 30, Expires: now.Add(time.Hour).Unix(), ID: "durable-reward"}
	token, signErr := signUsageEntitlement(cfg.AdMobVerifierSecret, claim)
	rewardSnapshot := s.snapshotUsageStateLocked()
	if err == nil && signErr == nil {
		err = s.redeemUsageEntitlementLocked(token, ownerID, now)
	}
	if err == nil && signErr == nil {
		err = s.saveUsageOrRollbackLocked(rewardSnapshot)
	}
	s.mu.Unlock()
	if err != nil || signErr != nil {
		t.Fatalf("initial durable redemption: err=%v sign=%v", err, signErr)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restarted.mu.Lock()
	activationErr := restarted.redeemActivationCodeLocked(code, ownerID, time.Now())
	rewardErr := restarted.redeemUsageEntitlementLocked(token, ownerID, time.Now())
	restarted.mu.Unlock()
	if activationErr == nil || rewardErr == nil {
		t.Fatalf("single-use records were not durable: activation=%v reward=%v", activationErr, rewardErr)
	}
}

func TestMeteredRequestGateSerializesOnlySameUser(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19318", Password: "usage-gate-test-password-123456", StateDir: t.TempDir(), UsageMeteringEnabled: true, UsageDefaultQuotaBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.mu.Lock()
	ownerID := s.usernames["owner"]
	other, err := s.createUserLocked("other-user", "other-user-test-password-123456")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	issue := func(clientID, device, userID string) string {
		s.clients[clientID] = Client{ID: clientID, Approved: true}
		s.devices[device] = userID
		token, _, _, issueErr := s.issueTokensLocked(clientID, userID, s.absolute("/mcp/"+device), "mcp offline_access")
		if issueErr != nil {
			t.Fatalf("issue token: %v", issueErr)
		}
		return token
	}
	ownerToken := issue("gate-owner-client", "gate-owner-device", ownerID)
	otherToken := issue("gate-other-client", "gate-other-device", other.ID)
	s.mu.Unlock()

	var active atomic.Int64
	var maxActive atomic.Int64
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	handler := s.ProtectScopedResource("mcp", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		current := active.Add(1)
		for {
			maximum := maxActive.Load()
			if current <= maximum || maxActive.CompareAndSwap(maximum, current) {
				break
			}
		}
		entered <- struct{}{}
		<-release
		active.Add(-1)
		_, _ = w.Write([]byte("ok"))
	}))
	serve := func(device, token string) <-chan struct{} {
		done := make(chan struct{})
		go func() {
			req := httptest.NewRequest(http.MethodPost, s.absolute("/mcp/"+device), strings.NewReader("x"))
			req.Header.Set("Authorization", "Bearer "+token)
			handler.ServeHTTP(httptest.NewRecorder(), req)
			close(done)
		}()
		return done
	}

	first := serve("gate-owner-device", ownerToken)
	<-entered
	second := serve("gate-owner-device", ownerToken)
	select {
	case <-entered:
		t.Fatal("same-user requests executed concurrently")
	case <-time.After(100 * time.Millisecond):
	}
	release <- struct{}{}
	<-entered
	release <- struct{}{}
	<-first
	<-second
	if maxActive.Load() != 1 {
		t.Fatalf("same-user max concurrency=%d", maxActive.Load())
	}

	maxActive.Store(0)
	ownerDone := serve("gate-owner-device", ownerToken)
	<-entered
	otherDone := serve("gate-other-device", otherToken)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("different users shared a request gate")
	}
	release <- struct{}{}
	release <- struct{}{}
	<-ownerDone
	<-otherDone
	if maxActive.Load() < 2 {
		t.Fatalf("different-user max concurrency=%d", maxActive.Load())
	}
}

func TestNewUserKeepsCreationTimeDefaultQuota(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19321", Password: "usage-new-user-test-password-123456", StateDir: t.TempDir(), UsageMeteringEnabled: true, UsageDefaultQuotaBytes: 111})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.mu.Lock()
	user, err := s.createUserLocked("quota-user", "quota-user-test-password-123456")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	if got := s.usage[user.ID].QuotaBytes; got != 111 {
		s.mu.Unlock()
		t.Fatalf("creation quota=%d want=111", got)
	}
	s.usageDefaultQuotaBytes = 222
	got := s.ensureUsageRecordLocked(user.ID).QuotaBytes
	s.mu.Unlock()
	if got != 111 {
		t.Fatalf("existing account quota changed with default: got=%d want=111", got)
	}
}

func TestAgentCredentialStillObservesExhaustedQuotaWithoutRequestGate(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19322", Password: "usage-agent-quota-test-password-123456", StateDir: t.TempDir(), UsageMeteringEnabled: true, UsageDefaultQuotaBytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.clients["agent-quota-client"] = Client{ID: "agent-quota-client", Approved: true}
	s.devices["agent-quota-device"] = ownerID
	access, _, _, err := s.issueTokensLocked("agent-quota-client", ownerID, s.absolute("/agent/agent-quota-device"), "agent:connect offline_access")
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	record := s.ensureUsageRecordLocked(ownerID)
	record.UsedBytes = record.QuotaBytes
	s.usage[ownerID] = record
	s.mu.Unlock()
	_, usage, enabled, authorized := s.usageForCredential(tokenKey(access), s.absolute("/agent/agent-quota-device"), "agent:connect")
	if !authorized || !enabled || usageRemaining(usage) != 0 {
		t.Fatalf("agent quota check authorized=%v enabled=%v usage=%+v", authorized, enabled, usage)
	}
}

func TestDisabledMeteringDoesNotGateSameUserRequests(t *testing.T) {
	s, err := New(Config{PublicURL: "http://127.0.0.1:19319", Password: "usage-no-gate-test-password-123456", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.mu.Lock()
	ownerID := s.usernames["owner"]
	s.clients["no-gate-client"] = Client{ID: "no-gate-client", Approved: true}
	s.devices["no-gate-device"] = ownerID
	access, _, _, err := s.issueTokensLocked("no-gate-client", ownerID, s.absolute("/mcp/no-gate-device"), "mcp offline_access")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	handler := s.ProtectScopedResource("mcp", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	serve := func() <-chan struct{} {
		done := make(chan struct{})
		go func() {
			req := httptest.NewRequest(http.MethodGet, s.absolute("/mcp/no-gate-device"), nil)
			req.Header.Set("Authorization", "Bearer "+access)
			handler.ServeHTTP(httptest.NewRecorder(), req)
			close(done)
		}()
		return done
	}
	first, second := serve(), serve()
	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("disabled metering serialized same-user requests")
		}
	}
	close(release)
	<-first
	<-second
}

func TestUsageStateRejectsSymlinkAndHardlink(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			stateDir := t.TempDir()
			cfg := Config{PublicURL: "http://127.0.0.1:19320", Password: "usage-link-test-password-123456", StateDir: stateDir, UsageMeteringEnabled: true}
			s, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "target.json")
			if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			usagePath := filepath.Join(stateDir, "usage-state.json")
			if err := os.Remove(usagePath); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if kind == "symlink" {
				err = os.Symlink(target, usagePath)
			} else {
				err = os.Link(target, usagePath)
			}
			if err != nil {
				t.Fatal(err)
			}
			restarted, err := New(cfg)
			if err == nil {
				_ = restarted.Close()
				t.Fatalf("%s usage state was accepted", kind)
			}
		})
	}
}
