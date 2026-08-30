package main

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ifloppy/chat-with-cli/internal/config"
	"github.com/ifloppy/chat-with-cli/internal/deviceidentity"
)

func TestDefaultRelayAndRewardEndpointValidation(t *testing.T) {
	if defaultPublicRelayURL != "https://chat-with-cli.iruanp.com" {
		t.Fatalf("default public Relay=%q", defaultPublicRelayURL)
	}
	for _, raw := range []string{"http://rewards.example/unlock", "https://user:pass@rewards.example/unlock", "https://rewards.example/unlock#fragment"} {
		if _, err := normalizeUsageUnlockEndpoint(raw); err == nil {
			t.Fatalf("unsafe reward endpoint %q was accepted", raw)
		}
	}
	if got, err := normalizeUsageUnlockEndpoint("https://rewards.example/unlock/"); err != nil || got != "https://rewards.example/unlock" {
		t.Fatalf("normalized reward endpoint=%q err=%v", got, err)
	}
}

func TestRelayMalformedUsageDefaultQuotaTOMLFailsFast(t *testing.T) {
	t.Setenv("CHAT_WITH_CLI_USAGE_DEFAULT_QUOTA_BYTES", "")
	path := filepath.Join(t.TempDir(), "relay.toml")
	if err := os.WriteFile(path, []byte("[relay]\nusage_default_quota_bytes = nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runRelay([]string{"--config", path})
	if err == nil || !strings.Contains(err.Error(), "invalid relay.usage_default_quota_bytes") {
		t.Fatalf("malformed quota error=%v", err)
	}
}

func TestCapabilityProfileAliasesAndSingleLetters(t *testing.T) {
	cases := map[string]string{
		"R": "read-only", "read-only": "read-only",
		"W": "read-write", "read-write": "read-write", "developer": "read-write",
		"D": "desktop-computer-use", "desktop": "desktop-computer-use", "computer-use": "desktop-computer-use",
		"A": "all", "full": "all",
		"C": "custom",
	}
	for input, want := range cases {
		got, ok := canonicalCapabilityProfile(input)
		if !ok || got != want {
			t.Fatalf("profile %q canonical=%q ok=%v, want %q", input, got, ok, want)
		}
	}
	if _, ok := canonicalCapabilityProfile("mystery"); ok {
		t.Fatal("unknown profile was accepted")
	}
}

func TestPromptCapabilityProfileAllAndCustom(t *testing.T) {
	var out bytes.Buffer
	profile, flags, err := promptCapabilityProfile(bufio.NewReader(strings.NewReader("a\n")), &out, "read-only", config.Values{})
	if err != nil || profile != "all" || len(flags) != 0 {
		t.Fatalf("all profile=%q flags=%v err=%v", profile, flags, err)
	}
	for _, marker := range []string{"[R] Read-only", "[W] Read-write", "[D] Desktop-computer-use", "[A] All", "[C] Custom"} {
		if !strings.Contains(out.String(), marker) {
			t.Fatalf("profile menu missing %q: %s", marker, out.String())
		}
	}

	out.Reset()
	profile, flags, err = promptCapabilityProfile(bufio.NewReader(strings.NewReader("c\ny\ny\nn\ny\ny\n")), &out, "read-only", config.Values{})
	if err != nil || profile != "custom" {
		t.Fatalf("custom profile=%q err=%v", profile, err)
	}
	want := []string{"--allow-file-write", "--allow-exec", "--allow-accessibility", "--allow-computer-use"}
	if strings.Join(flags, ",") != strings.Join(want, ",") {
		t.Fatalf("custom flags=%v want=%v", flags, want)
	}
}

func TestAgentSetupAllProfileEnablesEveryCapability(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	stateDir := filepath.Join(dir, "state")
	if err := runAgentSetup([]string{
		"--config", configPath,
		"--state-dir", stateDir,
		"--relay", "https://relay.example.test",
		"--root", dir,
		"--device", "test-device",
		"--profile", "A",
	}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, expected := range []string{
		`profile = "all"`,
		`allow_file_write = true`,
		`allow_exec = true`,
		`allow_screen = true`,
		`allow_accessibility = true`,
		`allow_computer_use = true`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("all profile config missing %q:\n%s", expected, text)
		}
	}
}

func TestRotateRetiredAgentIdentityPreservesOldKeyAndUpdatesConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	stateDir := filepath.Join(dir, "state")
	credentials := filepath.Join(dir, "credentials.json")
	if err := runAgentSetup([]string{
		"--config", configPath, "--state-dir", stateDir, "--credentials", credentials,
		"--relay", "https://relay.example.test", "--root", dir,
		"--device", "rotate-device", "--profile", "A",
	}); err != nil {
		t.Fatal(err)
	}
	before, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	oldPath := before.String("", "agent.identity")
	oldIdentity, err := deviceidentity.Load(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	oldID := oldIdentity.ID()
	gotOld, newID, err := rotateConfiguredAgentIdentity(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if gotOld != oldID || newID == "" || newID == oldID {
		t.Fatalf("rotation old=%q new=%q want old=%q and a fresh ID", gotOld, newID, oldID)
	}
	if preserved, err := deviceidentity.Load(oldPath); err != nil || preserved.ID() != oldID {
		t.Fatalf("retired key was not preserved: identity=%v err=%v", preserved, err)
	}
	after, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.String("", "agent.device_id") != newID {
		t.Fatalf("config device_id=%q want=%q", after.String("", "agent.device_id"), newID)
	}
	newPath := after.String("", "agent.identity")
	if newPath == oldPath {
		t.Fatal("rotation reused the permanently retired identity path")
	}
	newIdentity, err := deviceidentity.Load(newPath)
	if err != nil || newIdentity.ID() != newID {
		t.Fatalf("replacement identity invalid: id=%v err=%v", newIdentity, err)
	}
	for _, key := range []string{"agent.allow_file_write", "agent.allow_exec", "agent.allow_screen", "agent.allow_accessibility", "agent.allow_computer_use"} {
		if !after.Bool(false, key) {
			t.Fatalf("rotation lost capability %s", key)
		}
	}
}

func TestInteractiveSetupUpdatesExistingConfigInsteadOfFailing(t *testing.T) {
	configHome := t.TempDir()
	stateHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("XDG_STATE_HOME", stateHome)
	configPath := filepath.Join(configHome, "chat-with-cli", "config.toml")
	root := t.TempDir()
	if err := runAgentSetup([]string{
		"--config", configPath,
		"--state-dir", filepath.Join(stateHome, "chat-with-cli"),
		"--relay", "https://relay.example.test",
		"--root", root,
		"--device", "existing-device",
		"--profile", "A",
	}); err != nil {
		t.Fatal(err)
	}
	before, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	oldID := before.String("", "agent.device_id")
	var out bytes.Buffer
	// Keep every existing default and decline systemd generation.
	if err := interactiveAgentSetup(bufio.NewReader(strings.NewReader("\n\n\n\n\n")), &out); err != nil {
		t.Fatalf("interactive update failed: %v\n%s", err, out.String())
	}
	after, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.String("", "agent.device_id") != oldID {
		t.Fatalf("settings update unexpectedly rotated identity: before=%q after=%q", oldID, after.String("", "agent.device_id"))
	}
	if after.String("", "agent.profile") != "all" || !after.Bool(false, "agent.allow_computer_use") {
		t.Fatalf("settings update lost profile/capabilities: %#v", after)
	}
}

func TestMissingConfiguredIdentityIsRecoverableAndAccountDoesNotFail(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	stateDir := filepath.Join(dir, "state")
	credentials := filepath.Join(dir, "credentials.json")
	if err := runAgentSetup([]string{
		"--config", configPath, "--state-dir", stateDir, "--credentials", credentials,
		"--relay", "https://relay.example.test", "--root", dir,
		"--device", "missing-key-device", "--profile", "A",
	}); err != nil {
		t.Fatal(err)
	}
	before, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	oldID := before.String("", "agent.device_id")
	oldPath := before.String("", "agent.identity")
	if err := os.Remove(oldPath); err != nil {
		t.Fatal(err)
	}
	auth, err := configuredOAuthFromFile(configPath)
	if err != nil {
		t.Fatalf("account context should tolerate a missing key: %v", err)
	}
	if !auth.IdentityMissing || auth.DeviceID != oldID {
		t.Fatalf("missing identity state=%v deviceID=%q want %q", auth.IdentityMissing, auth.DeviceID, oldID)
	}
	status := accountSessionStatus(context.Background(), auth)
	if !strings.Contains(status, "identity is missing") || !strings.Contains(status, "OAuth") {
		t.Fatalf("missing identity account status=%q", status)
	}
	gotOld, newID, recovered, err := recoverMissingConfiguredIdentity(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !recovered || gotOld != oldID || newID == "" || newID == oldID {
		t.Fatalf("recovery recovered=%v old=%q new=%q want old=%q and a fresh ID", recovered, gotOld, newID, oldID)
	}
	after, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.String("", "agent.device_id") != newID {
		t.Fatalf("config device_id=%q want %q", after.String("", "agent.device_id"), newID)
	}
	newPath := after.String("", "agent.identity")
	if newPath == oldPath {
		t.Fatal("missing-key recovery reused the vanished identity path")
	}
	identity, err := deviceidentity.Load(newPath)
	if err != nil || identity.ID() != newID {
		t.Fatalf("replacement identity invalid: id=%v err=%v", identity, err)
	}
	for _, key := range []string{"agent.allow_file_write", "agent.allow_exec", "agent.allow_screen", "agent.allow_accessibility", "agent.allow_computer_use"} {
		if !after.Bool(false, key) {
			t.Fatalf("missing-key recovery lost capability %s", key)
		}
	}
}

func TestCorruptConfiguredIdentityDoesNotAutoRotate(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	stateDir := filepath.Join(dir, "state")
	if err := runAgentSetup([]string{
		"--config", configPath, "--state-dir", stateDir,
		"--relay", "https://relay.example.test", "--root", dir,
		"--device", "corrupt-key-device", "--profile", "R",
	}); err != nil {
		t.Fatal(err)
	}
	values, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	identityPath := values.String("", "agent.identity")
	if err := os.WriteFile(identityPath, []byte("not-an-ed25519-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, recovered, err := recoverMissingConfiguredIdentity(configPath)
	if err == nil || recovered {
		t.Fatalf("corrupt identity was silently recovered: recovered=%v err=%v", recovered, err)
	}
}

func TestAccountSessionStatusExplainsPermanentlyRevokedIdentity(t *testing.T) {
	status := accountSessionDescriptionForHTTPStatus(http.StatusGone)
	if !strings.Contains(status, "permanently revoked") || !strings.Contains(status, "OAuth") {
		t.Fatalf("revoked account status=%q", status)
	}
}
