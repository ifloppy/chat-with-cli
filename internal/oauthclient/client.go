package oauthclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ifloppy/chat-with-cli/internal/protocol"
)

type Manager struct {
	RelayURL        string
	Device          string
	DeviceID        string
	CredentialsPath string
	HTTPClient      *http.Client
	OpenBrowser     func(string) error
	mu              sync.Mutex
}

type authMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
}

type registrationResponse struct {
	ClientID string `json:"client_id"`
}
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

func normalizeRelay(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid relay URL %q", raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return "", errors.New("relay OAuth requires https except for loopback testing")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("relay URL must not contain credentials, query, or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return "", errors.New("relay URL must be an origin without a path")
	}
	u.Path = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func (m *Manager) Resource() (string, error) {
	base, err := normalizeRelay(m.RelayURL)
	if err != nil {
		return "", err
	}
	device := strings.TrimSpace(m.Device)
	deviceID := strings.TrimSpace(m.DeviceID)
	if device == "" && deviceID == "" {
		return "", errors.New("device or immutable device ID is required")
	}
	if deviceID != "" {
		canonicalID, ok := protocol.NormalizeDeviceID(deviceID)
		if !ok {
			return "", errors.New("invalid immutable device ID")
		}
		return base + "/agent/id/" + url.PathEscape(canonicalID), nil
	}
	if !protocol.ValidDeviceName(device) {
		return "", errors.New("invalid device name")
	}
	return base + "/agent/" + url.PathEscape(device), nil
}

func (m *Manager) Token(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	resource, err := m.Resource()
	if err != nil {
		return "", err
	}
	path := m.CredentialsPath
	if path == "" {
		path = DefaultCredentialsPath()
	}
	var token string
	err = withCredentialStoreLock(path, func() error {
		token, err = m.tokenLocked(ctx, resource, path)
		return err
	})
	return token, err
}

func (m *Manager) tokenLocked(ctx context.Context, resource, path string) (string, error) {
	store, err := loadStore(path)
	if err != nil {
		return "", err
	}
	cred := store.Profiles[resource]
	if cred.AccessToken != "" && cred.ExpiresAt > time.Now().Add(time.Minute).Unix() {
		return cred.AccessToken, nil
	}
	client := m.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	issuer, issuerErr := normalizeRelay(cred.Issuer)
	base, _ := normalizeRelay(m.RelayURL)
	if issuerErr == nil && issuer == base && cred.RefreshToken != "" && cred.ClientID != "" {
		if refreshed, err := refresh(ctx, client, cred); err == nil {
			store.Profiles[resource] = refreshed
			if err := saveStore(path, store); err != nil {
				return "", err
			}
			return refreshed.AccessToken, nil
		}
	}
	cred, err = m.browserAuthorize(ctx, client, resource)
	if err != nil {
		return "", err
	}
	store.Profiles[resource] = cred
	if err := saveStore(path, store); err != nil {
		return "", err
	}
	return cred.AccessToken, nil
}

func refresh(ctx context.Context, client *http.Client, cred Credential) (Credential, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {cred.RefreshToken},
		"client_id":     {cred.ClientID},
		"resource":      {cred.Resource},
	}
	var token tokenResponse
	if err := postFormJSON(ctx, client, strings.TrimRight(cred.Issuer, "/")+"/oauth/token", form, &token); err != nil {
		return Credential{}, err
	}
	if token.AccessToken == "" || token.RefreshToken == "" {
		return Credential{}, errors.New("refresh response is missing tokens")
	}
	cred.AccessToken = token.AccessToken
	cred.RefreshToken = token.RefreshToken
	cred.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second).Unix()
	return cred, nil
}
