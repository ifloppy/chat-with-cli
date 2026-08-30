package main

import (
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
