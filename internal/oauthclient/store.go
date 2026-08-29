package oauthclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/ifloppy/chat-with-cli/internal/protocol"
)

type Credential struct {
	Issuer       string `json:"issuer"`
	Resource     string `json:"resource"`
	ClientID     string `json:"client_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

type credentialStore struct {
	Version  int                   `json:"version"`
	Profiles map[string]Credential `json:"profiles"`
}

func DefaultCredentialsPath() string {
	if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
		return filepath.Join(xdg, "chat-with-cli", "credentials.json")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "chat-with-cli", "credentials.json")
}

func DefaultConfigPath() string {
	if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
		return filepath.Join(xdg, "chat-with-cli", "config.toml")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "chat-with-cli", "config.toml")
}

func loadStore(path string) (credentialStore, error) {
	store := credentialStore{Version: 1, Profiles: map[string]Credential{}}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return store, errors.New("credential store must not be a symlink")
		}
		if !info.Mode().IsRegular() {
			return store, errors.New("credential store must be a regular file")
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return store, fmt.Errorf("secure credentials %s: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return store, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return store, err
	}
	if err := json.Unmarshal(data, &store); err != nil {
		return store, fmt.Errorf("decode credentials %s: %w", path, err)
	}
	if store.Profiles == nil {
		store.Profiles = map[string]Credential{}
	}
	return store, nil
}

func saveStore(path string, store credentialStore) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("credential store must not be a symlink")
		}
		if !info.Mode().IsRegular() {
			return errors.New("credential store must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".credentials-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
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
	if err := os.Rename(name, path); err != nil {
		return err
	}
	dirFile, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = dirFile.Sync()
	_ = dirFile.Close()
	return err
}

func SavedRelayForDevice(path, device string) (string, bool, error) {
	if path == "" {
		path = DefaultCredentialsPath()
	}
	store, err := loadStore(path)
	if err != nil {
		return "", false, err
	}
	suffix := "/agent/" + url.PathEscape(strings.TrimSpace(device))
	match := ""
	for resource := range store.Profiles {
		if !strings.HasSuffix(resource, suffix) {
			continue
		}
		base := strings.TrimSuffix(resource, suffix)
		if match != "" && match != base {
			return "", false, fmt.Errorf("multiple saved relays match device %q; specify --relay", device)
		}
		match = base
	}
	return match, match != "", nil
}

func SavedRelayForDeviceID(path, deviceID string) (string, bool, error) {
	if path == "" {
		path = DefaultCredentialsPath()
	}
	canonicalID, ok := protocol.NormalizeDeviceID(deviceID)
	if !ok {
		return "", false, fmt.Errorf("invalid immutable device ID")
	}
	store, err := loadStore(path)
	if err != nil {
		return "", false, err
	}
	suffix := "/agent/id/" + url.PathEscape(canonicalID)
	match := ""
	for resource := range store.Profiles {
		if !strings.HasSuffix(resource, suffix) {
			continue
		}
		base := strings.TrimSuffix(resource, suffix)
		if match != "" && match != base {
			return "", false, fmt.Errorf("multiple saved relays match device ID %q; specify --relay", deviceID)
		}
		match = base
	}
	return match, match != "", nil
}

// LoadCredential returns the locally saved credential for one exact resource.
// It is used by diagnostics to test an existing session without opening a
// browser or printing bearer values.
func LoadCredential(path, resource string) (Credential, bool, error) {
	if path == "" {
		path = DefaultCredentialsPath()
	}
	store, err := loadStore(path)
	if err != nil {
		return Credential{}, false, err
	}
	credential, ok := store.Profiles[resource]
	return credential, ok, nil
}
