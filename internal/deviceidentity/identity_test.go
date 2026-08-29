package deviceidentity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityRoundTripAndProof(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.key")
	identity, created, err := LoadOrCreate(path)
	if err != nil || !created {
		t.Fatalf("create identity: created=%v err=%v", created, err)
	}
	loaded, created, err := LoadOrCreate(path)
	if err != nil || created || loaded.ID() != identity.ID() {
		t.Fatalf("reload identity: created=%v err=%v ids=%q/%q", created, err, loaded.ID(), identity.ID())
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("identity permissions: info=%v err=%v", info, err)
	}
	challenge := "relay-issued-challenge-for-test"
	sig, err := identity.SignProof("https://relay.example/agent/id/"+identity.ID(), "token", challenge)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyProof(identity.PublicKey(), "https://relay.example/agent/id/"+identity.ID(), TokenFingerprint("token"), challenge, sig) {
		t.Fatal("valid proof rejected")
	}
	if VerifyProof(identity.PublicKey(), "https://relay.example/agent/id/"+identity.ID(), TokenFingerprint("other"), challenge, sig) {
		t.Fatal("proof accepted for another token")
	}
	if VerifyProof(identity.PublicKey(), "https://relay.example/agent/id/"+identity.ID(), TokenFingerprint("token"), challenge+"-other", sig) {
		t.Fatal("proof accepted for another Relay challenge")
	}
}

func TestDeviceIDIsBoundToPublicKey(t *testing.T) {
	a, _ := Generate()
	b, _ := Generate()
	if a.ID() == "" || b.ID() == "" || a.ID() == b.ID() {
		t.Fatalf("unexpected IDs: %q %q", a.ID(), b.ID())
	}
	decoded, err := DecodePublicKey(EncodePublicKey(a.PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	id, err := IDFromPublicKey(decoded)
	if err != nil || id != a.ID() {
		t.Fatalf("public-key ID mismatch: %q err=%v", id, err)
	}
}

func TestRegistrationProofBindsDeviceAndRedirect(t *testing.T) {
	identity, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	challenge := "relay-registration-challenge"
	proof, err := identity.SignRegistrationProof("chat-with-cli agent workstation", "http://127.0.0.1:4321/callback", challenge)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyRegistrationProof(identity.PublicKey(), identity.ID(), "chat-with-cli agent workstation", "http://127.0.0.1:4321/callback", challenge, proof) {
		t.Fatal("valid registration proof rejected")
	}
	if VerifyRegistrationProof(identity.PublicKey(), identity.ID(), "chat-with-cli agent workstation", "http://127.0.0.1:9999/callback", challenge, proof) {
		t.Fatal("registration proof accepted for another redirect")
	}
	if VerifyRegistrationProof(identity.PublicKey(), identity.ID(), "chat-with-cli agent workstation", "http://127.0.0.1:4321/callback", "other-challenge", proof) {
		t.Fatal("registration proof accepted for another Relay challenge")
	}
}

func TestAuthorizationProofBindsOAuthRequest(t *testing.T) {
	identity, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	const (
		clientID               = "client-id"
		redirectURI            = "http://127.0.0.1:4321/callback"
		resource               = "http://127.0.0.1:4321/agent/id/0123456789abcdef0123456789abcdef"
		scope                  = "agent:connect offline_access"
		state                  = "fresh-state"
		codeChallenge          = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012"
		authorizationChallenge = "relay-issued-authorization-challenge"
	)
	proof, err := identity.SignAuthorizationProof(clientID, redirectURI, resource, scope, state, codeChallenge, authorizationChallenge)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyAuthorizationProof(identity.PublicKey(), clientID, redirectURI, resource, scope, state, codeChallenge, authorizationChallenge, proof) {
		t.Fatal("authorization proof was rejected")
	}
	if VerifyAuthorizationProof(identity.PublicKey(), clientID, redirectURI, resource, scope, "other-state", codeChallenge, authorizationChallenge, proof) {
		t.Fatal("authorization proof was accepted for another OAuth state")
	}
	if VerifyAuthorizationProof(identity.PublicKey(), clientID, redirectURI, resource, scope, state, "other-challenge", authorizationChallenge, proof) {
		t.Fatal("authorization proof was accepted for another PKCE challenge")
	}
	if VerifyAuthorizationProof(identity.PublicKey(), "other-client", redirectURI, resource, scope, state, codeChallenge, authorizationChallenge, proof) {
		t.Fatal("authorization proof was accepted for another client")
	}
	if VerifyAuthorizationProof(identity.PublicKey(), clientID, redirectURI, resource, scope, state, codeChallenge, "other-authorization-challenge", proof) {
		t.Fatal("authorization proof was accepted for another Relay authorization challenge")
	}
}
