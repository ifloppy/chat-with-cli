package oauthclient

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialStoreRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	link := filepath.Join(dir, "link.json")
	if err := os.WriteFile(target, []byte(`{"version":1,"profiles":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skip("symlinks are unavailable")
		}
		t.Fatal(err)
	}
	if _, err := loadStore(link); err == nil {
		t.Fatal("loadStore followed a credential-store symlink")
	}
	if err := saveStore(link, credentialStore{Version: 1, Profiles: map[string]Credential{}}); err == nil {
		t.Fatal("saveStore replaced a credential-store symlink")
	}
}

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

func TestSavedRelayForDeviceIDCanonicalizesCase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	resource := "https://relay.example/agent/id/abcdef0123456789abcdef0123456789"
	store := credentialStore{Version: 1, Profiles: map[string]Credential{resource: {Issuer: "https://relay.example", Resource: resource}}}
	if err := saveStore(path, store); err != nil {
		t.Fatal(err)
	}
	relay, ok, err := SavedRelayForDeviceID(path, "ABCDEF0123456789ABCDEF0123456789")
	if err != nil || !ok || relay != "https://relay.example" {
		t.Fatalf("relay=%q ok=%v err=%v", relay, ok, err)
	}
}
