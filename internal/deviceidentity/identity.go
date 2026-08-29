package deviceidentity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	HeaderChallenge = "X-Chat-With-CLI-Device-Challenge"
	HeaderProof     = "X-Chat-With-CLI-Device-Proof"
	proofContext    = "chat-with-cli-agent-challenge-v1"
)

type Identity struct {
	private ed25519.PrivateKey
}

func Generate() (*Identity, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{private: private}, nil
}

func DefaultPath(stateDir string) string {
	return filepath.Join(stateDir, "device-identity.key")
}

func LoadOrCreate(path string) (*Identity, bool, error) {
	identity, err := Load(path)
	if err == nil {
		return identity, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	identity, err = Generate()
	if err != nil {
		return nil, false, err
	}
	if err := identity.Save(path); err != nil {
		return nil, false, err
	}
	return identity, true, nil
}

func Load(path string) (*Identity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("device identity must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("device identity %s must not be accessible by group/other", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	private, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 device identity")
	}
	return &Identity{private: ed25519.PrivateKey(append([]byte(nil), private...))}, nil
}

func (i *Identity) Save(path string) error {
	if i == nil || len(i.private) != ed25519.PrivateKeySize {
		return errors.New("invalid device identity")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("refusing to replace non-regular device identity")
		}
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".device-identity-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(base64.RawURLEncoding.EncodeToString(i.private) + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (i *Identity) PublicKey() ed25519.PublicKey {
	if i == nil || len(i.private) != ed25519.PrivateKeySize {
		return nil
	}
	pub := i.private.Public().(ed25519.PublicKey)
	return append(ed25519.PublicKey(nil), pub...)
}

func EncodePublicKey(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}

func DecodePublicKey(encoded string) (ed25519.PublicKey, error) {
	pub, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key")
	}
	return ed25519.PublicKey(pub), nil
}

func IDFromPublicKey(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", errors.New("invalid Ed25519 public key")
	}
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16]), nil
}

func (i *Identity) ID() string {
	id, _ := IDFromPublicKey(i.PublicKey())
	return id
}

func TokenFingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func proofMessage(resource, tokenFingerprint, challenge string) []byte {
	return []byte(proofContext + "\n" + resource + "\n" + tokenFingerprint + "\n" + challenge)
}

func (i *Identity) SignProof(resource, token, challenge string) (string, error) {
	if i == nil || len(i.private) != ed25519.PrivateKeySize {
		return "", errors.New("device identity is unavailable")
	}
	if challenge == "" {
		return "", errors.New("Relay challenge is required")
	}
	sig := ed25519.Sign(i.private, proofMessage(resource, TokenFingerprint(token), challenge))
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func VerifyProof(pub ed25519.PublicKey, resource, tokenFingerprint, challenge, encodedSignature string) bool {
	if len(pub) != ed25519.PublicKeySize || challenge == "" {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, proofMessage(resource, tokenFingerprint, challenge), sig)
}

const registrationProofContext = "chat-with-cli-agent-registration-challenge-v1"

func registrationProofMessage(deviceID, clientName, redirectURI, challenge string) []byte {
	return []byte(registrationProofContext + "\n" + deviceID + "\n" + clientName + "\n" + redirectURI + "\n" + challenge)
}

func (i *Identity) SignRegistrationProof(clientName, redirectURI, challenge string) (string, error) {
	if i == nil || len(i.private) != ed25519.PrivateKeySize {
		return "", errors.New("device identity is unavailable")
	}
	if challenge == "" {
		return "", errors.New("Relay registration challenge is required")
	}
	sig := ed25519.Sign(i.private, registrationProofMessage(i.ID(), clientName, redirectURI, challenge))
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func VerifyRegistrationProof(pub ed25519.PublicKey, deviceID, clientName, redirectURI, challenge, encodedSignature string) bool {
	if len(pub) != ed25519.PublicKeySize || challenge == "" {
		return false
	}
	derived, err := IDFromPublicKey(pub)
	if err != nil || derived != deviceID {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, registrationProofMessage(deviceID, clientName, redirectURI, challenge), sig)
}
