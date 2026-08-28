package oauthclient

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSavedRelayForDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store := credentialStore{Version: 1, Profiles: map[string]Credential{
		"https://relay.example/agent/laptop-a": {Resource: "https://relay.example/agent/laptop-a"},
		"https://relay.example/mcp/laptop-a":   {Resource: "https://relay.example/mcp/laptop-a"},
	}}
	if err := saveStore(path, store); err != nil {
		t.Fatal(err)
	}
	relay, ok, err := SavedRelayForDevice(path, "laptop-a")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || relay != "https://relay.example" {
		t.Fatalf("relay=%q ok=%v", relay, ok)
	}
}

func TestSavedRelayForDeviceAmbiguous(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store := credentialStore{Version: 1, Profiles: map[string]Credential{
		"https://relay-a.example/agent/laptop-a": {Resource: "https://relay-a.example/agent/laptop-a"},
		"https://relay-b.example/agent/laptop-a": {Resource: "https://relay-b.example/agent/laptop-a"},
	}}
	if err := saveStore(path, store); err != nil {
		t.Fatal(err)
	}
	_, ok, err := SavedRelayForDevice(path, "laptop-a")
	if err == nil || ok || !strings.Contains(err.Error(), "multiple saved relays") {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}
