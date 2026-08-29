package main

import "testing"

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
