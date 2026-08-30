package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	profile, flags, err := promptCapabilityProfile(bufio.NewReader(strings.NewReader("a\n")), &out)
	if err != nil || profile != "all" || len(flags) != 0 {
		t.Fatalf("all profile=%q flags=%v err=%v", profile, flags, err)
	}
	for _, marker := range []string{"[R] Read-only", "[W] Read-write", "[D] Desktop-computer-use", "[A] All", "[C] Custom"} {
		if !strings.Contains(out.String(), marker) {
			t.Fatalf("profile menu missing %q: %s", marker, out.String())
		}
	}

	out.Reset()
	profile, flags, err = promptCapabilityProfile(bufio.NewReader(strings.NewReader("c\ny\ny\nn\ny\ny\n")), &out)
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
