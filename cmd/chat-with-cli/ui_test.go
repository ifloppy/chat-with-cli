package main

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ifloppy/chat-with-cli/internal/config"
	"github.com/ifloppy/chat-with-cli/internal/deviceidentity"
	"github.com/ifloppy/chat-with-cli/internal/oauthclient"
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

func TestPromptExecSandboxAllowsExplicitFullUserAccess(t *testing.T) {
	var out bytes.Buffer
	got, err := promptExecSandbox(bufio.NewReader(strings.NewReader("f\n")), &out, "landlock")
	if runtime.GOOS != "linux" {
		if err != nil || got != "none" {
			t.Fatalf("non-Linux shell mode=%q err=%v", got, err)
		}
		return
	}
	if err != nil || got != "none" {
		t.Fatalf("full shell mode=%q err=%v", got, err)
	}
	if !strings.Contains(out.String(), "Full user access") || !strings.Contains(out.String(), "Landlock") || !strings.Contains(out.String(), "Protected-path filter") {
		t.Fatalf("shell boundary menu missing operator choices: %s", out.String())
	}
	out.Reset()
	got, err = promptExecSandbox(bufio.NewReader(strings.NewReader("p\n")), &out, "none")
	if err != nil || got != "protected" {
		t.Fatalf("protected shell mode=%q err=%v", got, err)
	}
}

func TestInteractiveSetupLetsOperatorKeepBroadRootWithProtectedPaths(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("protected shell choice is Linux-specific")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap is unavailable")
	}
	base := t.TempDir()
	t.Setenv("HOME", base)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, ".config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(base, ".state"))
	configPath := oauthclient.DefaultConfigPath()
	var out bytes.Buffer
	// relay, root, device, profile=A, shell=L, conflict resolution=P, systemd=n
	input := strings.Join([]string{"", base, "", "a", "l", "p", "n", ""}, "\n")
	if err := interactiveAgentSetup(bufio.NewReader(strings.NewReader(input)), &out); err != nil {
		t.Fatalf("explicit protected-path setup failed: %v\n%s", err, out.String())
	}
	values, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := values.String("", "agent.exec_sandbox"); got != "protected" {
		t.Fatalf("exec_sandbox=%q want protected", got)
	}
	roots := values.Strings("agent.root")
	if len(roots) != 1 || filepath.Clean(roots[0]) != filepath.Clean(base) {
		t.Fatalf("roots=%v want broad root %q", roots, base)
	}
	if !values.Bool(false, "agent.allow_exec") || !values.Bool(false, "agent.allow_file_write") {
		t.Fatalf("full-access profile lost coding capabilities: %#v", values)
	}
	if !strings.Contains(out.String(), "Keep this root and mask Chat with CLI private paths") {
		t.Fatalf("protected-path overlap resolution was not shown: %s", out.String())
	}
}

func TestAgentSetupPersistsAdditionalProtectedPaths(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	custom := filepath.Join(root, ".sensitive")
	configPath := filepath.Join(base, "config.toml")
	stateDir := filepath.Join(base, "state")
	if err := runAgentSetup([]string{
		"--config", configPath, "--state-dir", stateDir,
		"--relay", "https://relay.example.test", "--root", root,
		"--device", "protected-path-device", "--profile", "R",
		"--protected-path", custom,
	}); err != nil {
		t.Fatal(err)
	}
	values, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	got := values.Strings("agent.protected_paths")
	if len(got) != 1 || filepath.Clean(got[0]) != filepath.Clean(custom) {
		t.Fatalf("protected_paths=%v want %q", got, custom)
	}
	found := false
	for _, path := range configuredPrivatePaths(values, configPath) {
		if filepath.Clean(path) == filepath.Clean(custom) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("configured private paths did not include %q", custom)
	}
}

func TestAgentSetupPersistsAndValidatesRedactLineTerms(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(base, "config.toml")
	if err := runAgentSetup([]string{
		"--config", configPath, "--state-dir", filepath.Join(base, "state"),
		"--relay", "https://relay.example.test", "--root", root,
		"--device", "redact-term-device", "--profile", "R",
		"--redact-line-term", " API_KEY ", "--redact-line-term", "api_key",
	}); err != nil {
		t.Fatal(err)
	}
	values, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	terms := values.Strings("agent.redact_line_terms")
	if len(terms) != 1 || terms[0] != "api_key" {
		t.Fatalf("redact_line_terms=%v want [api_key]", terms)
	}
	badConfig := filepath.Join(base, "bad.toml")
	err = runAgentSetup([]string{
		"--config", badConfig, "--state-dir", filepath.Join(base, "bad-state"),
		"--relay", "https://relay.example.test", "--root", root,
		"--device", "bad-redact-device", "--profile", "R",
		"--redact-line-term", "bad\nterm",
	})
	if err == nil || !strings.Contains(err.Error(), "redact-line term") {
		t.Fatalf("invalid redact term error=%v", err)
	}
}

func TestAgentSetupRejectsLandlockRootOverlappingPrivateState(t *testing.T) {
	base := t.TempDir()
	workspace := filepath.Join(base, "workspace")
	if err := os.Mkdir(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(base, "config.toml")
	credentials := filepath.Join(base, "credentials.json")
	stateDir := filepath.Join(workspace, ".agent-state")
	err := runAgentSetup([]string{
		"--config", configPath, "--state-dir", stateDir, "--credentials", credentials,
		"--relay", "https://relay.example.test", "--root", workspace,
		"--device", "landlock-overlap-device", "--profile", "A",
	})
	if err == nil || !strings.Contains(err.Error(), "cannot create a Landlock coding configuration") {
		t.Fatalf("overlapping Landlock setup was accepted: %v", err)
	}
	if _, statErr := os.Lstat(configPath); !os.IsNotExist(statErr) {
		t.Fatalf("rejected setup wrote config: %v", statErr)
	}
}

func TestCodingCapabilityDefaultsNeverSelectTheEntireHomeDirectory(t *testing.T) {
	var roots stringList
	applyCodingRootDefault(&roots, true, true)
	if len(roots) != 1 {
		t.Fatalf("coding default roots=%v", roots)
	}
	home, err := os.UserHomeDir()
	if err == nil && filepath.Clean(roots[0]) == filepath.Clean(home) {
		t.Fatalf("coding default selected the entire home directory: %q", roots[0])
	}
	var readOnlyRoots stringList
	applyCodingRootDefault(&readOnlyRoots, false, false)
	if len(readOnlyRoots) != 0 {
		t.Fatalf("read-only default unexpectedly selected a root: %v", readOnlyRoots)
	}
}

func TestNewEngineRejectsUnusableLandlockConfiguration(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Landlock is Linux-only")
	}
	base := t.TempDir()
	workspace := filepath.Join(base, "workspace")
	if err := os.Mkdir(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(workspace, ".agent-state")
	if _, err := newEngine([]string{workspace}, true, true, "landlock", false, false, false, "process", stateDir, "", nil, nil, 1); err == nil || !strings.Contains(err.Error(), "contains chat-with-cli private state") {
		t.Fatalf("unusable Landlock configuration was accepted: %v", err)
	}
}

func TestAgentSetupAllProfileEnablesEveryCapability(t *testing.T) {
	dir := t.TempDir()
	workspace := filepath.Join(dir, "workspace")
	if err := os.Mkdir(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.toml")
	stateDir := filepath.Join(dir, "state")
	if err := runAgentSetup([]string{
		"--config", configPath,
		"--state-dir", stateDir,
		"--relay", "https://relay.example.test",
		"--root", workspace,
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
	if runtime.GOOS == "linux" && !strings.Contains(text, `exec_sandbox = "landlock"`) {
		t.Fatalf("coding profile did not select the Landlock default:\n%s", text)
	}
}

func TestRotateRetiredAgentIdentityPreservesOldKeyAndUpdatesConfig(t *testing.T) {
	dir := t.TempDir()
	workspace := filepath.Join(dir, "workspace")
	if err := os.Mkdir(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.toml")
	stateDir := filepath.Join(dir, "state")
	credentials := filepath.Join(dir, "credentials.json")
	if err := runAgentSetup([]string{
		"--config", configPath, "--state-dir", stateDir, "--credentials", credentials,
		"--relay", "https://relay.example.test", "--root", workspace,
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
	if err := interactiveAgentSetup(bufio.NewReader(strings.NewReader("\n\n\n\n\n\n")), &out); err != nil {
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
	workspace := filepath.Join(dir, "workspace")
	if err := os.Mkdir(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.toml")
	stateDir := filepath.Join(dir, "state")
	credentials := filepath.Join(dir, "credentials.json")
	if err := runAgentSetup([]string{
		"--config", configPath, "--state-dir", stateDir, "--credentials", credentials,
		"--relay", "https://relay.example.test", "--root", workspace,
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
