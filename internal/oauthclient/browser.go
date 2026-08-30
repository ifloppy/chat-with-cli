package oauthclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/ifloppy/chat-with-cli/internal/deviceidentity"
)

type callbackResult struct {
	code string
	err  error
}

func (m *Manager) browserAuthorize(ctx context.Context, client *http.Client, resource string) (Credential, error) {
	base, err := normalizeRelay(m.RelayURL)
	if err != nil {
		return Credential{}, err
	}
	var meta authMetadata
	if err := getJSON(ctx, client, base+"/.well-known/oauth-authorization-server", &meta); err != nil {
		return Credential{}, err
	}
	if meta.Issuer == "" || meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" || meta.RegistrationEndpoint == "" {
		return Credential{}, errors.New("relay OAuth metadata is incomplete")
	}
	issuer, err := normalizeRelay(meta.Issuer)
	if err != nil || issuer != base {
		return Credential{}, errors.New("relay OAuth issuer does not match the configured Relay")
	}
	authorizationEndpoint, err := sameOriginEndpoint(base, meta.AuthorizationEndpoint, "authorization endpoint")
	if err != nil {
		return Credential{}, err
	}
	tokenEndpoint, err := sameOriginEndpoint(base, meta.TokenEndpoint, "token endpoint")
	if err != nil {
		return Credential{}, err
	}
	registrationEndpoint, err := sameOriginEndpoint(base, meta.RegistrationEndpoint, "registration endpoint")
	if err != nil {
		return Credential{}, err
	}
	registrationChallengeEndpoint := ""
	authorizationChallengeEndpoint := ""
	if m.DeviceIdentity != nil {
		registrationChallengeEndpoint, err = sameOriginEndpoint(base, meta.RegistrationChallengeEndpoint, "registration challenge endpoint")
		if err != nil {
			return Credential{}, err
		}
		authorizationChallengeEndpoint, err = sameOriginEndpoint(base, meta.AuthorizationChallengeEndpoint, "authorization challenge endpoint")
		if err != nil {
			return Credential{}, err
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return Credential{}, err
	}
	defer ln.Close()
	redirect := "http://" + ln.Addr().String() + "/callback"
	clientName := "chat-with-cli agent " + m.Device
	regBody := map[string]any{
		"redirect_uris":              []string{redirect},
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"client_name":                clientName,
		"scope":                      "agent:connect offline_access",
	}
	if m.DeviceIdentity != nil {
		deviceID := m.DeviceIdentity.ID()
		devicePublicKey := deviceidentity.EncodePublicKey(m.DeviceIdentity.PublicKey())
		challengeBody := map[string]any{
			"client_name": clientName, "redirect_uri": redirect,
			"chat_with_cli_device_id": deviceID, "chat_with_cli_device_public_key": devicePublicKey,
		}
		var challengeResponse struct {
			Challenge string `json:"challenge"`
		}
		if err := postJSON(ctx, client, registrationChallengeEndpoint, challengeBody, &challengeResponse); err != nil {
			return Credential{}, fmt.Errorf("obtain device registration challenge: %w", err)
		}
		challenge := strings.TrimSpace(challengeResponse.Challenge)
		if challenge == "" {
			return Credential{}, errors.New("dynamic registration challenge returned no challenge")
		}
		proof, err := m.DeviceIdentity.SignRegistrationProof(clientName, redirect, challenge)
		if err != nil {
			return Credential{}, fmt.Errorf("sign device registration proof: %w", err)
		}
		regBody["chat_with_cli_device_id"] = deviceID
		regBody["chat_with_cli_device_public_key"] = devicePublicKey
		regBody["chat_with_cli_device_challenge"] = challenge
		regBody["chat_with_cli_device_proof"] = proof
	}
	var reg registrationResponse
	if err := postJSON(ctx, client, registrationEndpoint, regBody, &reg); err != nil {
		return Credential{}, err
	}
	if reg.ClientID == "" {
		return Credential{}, errors.New("dynamic registration returned no client_id")
	}
	verifier := randomURLToken(32)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := randomURLToken(24)
	u, err := url.Parse(authorizationEndpoint)
	if err != nil {
		return Credential{}, err
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", reg.ClientID)
	q.Set("redirect_uri", redirect)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("scope", "agent:connect offline_access")
	q.Set("resource", resource)
	q.Set("state", state)
	if m.DeviceIdentity != nil {
		challengeBody := map[string]any{
			"client_id": reg.ClientID, "redirect_uri": redirect, "resource": resource,
			"scope": "agent:connect offline_access", "state": state, "code_challenge": challenge,
		}
		var challengeResponse struct {
			Challenge string `json:"challenge"`
		}
		if err := postJSON(ctx, client, authorizationChallengeEndpoint, challengeBody, &challengeResponse); err != nil {
			return Credential{}, fmt.Errorf("obtain device authorization challenge: %w", err)
		}
		authorizationChallenge := strings.TrimSpace(challengeResponse.Challenge)
		if authorizationChallenge == "" {
			return Credential{}, errors.New("device authorization challenge returned no challenge")
		}
		proof, err := m.DeviceIdentity.SignAuthorizationProof(reg.ClientID, redirect, resource, "agent:connect offline_access", state, challenge, authorizationChallenge)
		if err != nil {
			return Credential{}, fmt.Errorf("sign device authorization proof: %w", err)
		}
		q.Set("chat_with_cli_authorization_challenge", authorizationChallenge)
		q.Set("chat_with_cli_device_proof", proof)
	}
	u.RawQuery = q.Encode()

	result := make(chan callbackResult, 1)
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second}
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "OAuth state mismatch", http.StatusBadRequest)
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "OAuth authorization failed", http.StatusBadRequest)
			select {
			case result <- callbackResult{err: errors.New("OAuth authorization denied")}:
			default:
			}
			return
		}
		_, _ = w.Write([]byte("chat-with-cli authorization complete. You can return to the terminal.\n"))
		select {
		case result <- callbackResult{code: code}:
		default:
		}
	})
	server.Handler = mux
	go func() { _ = server.Serve(ln) }()

	manual := m.ForceManual
	if !manual {
		opener := m.OpenBrowser
		if opener == nil {
			opener = openBrowser
		}
		if err := opener(u.String()); err != nil {
			manual = true
		}
	}

	var cb callbackResult
	if manual {
		cb = m.readManualCallback(ctx, u.String(), redirect, state)
	} else {
		select {
		case cb = <-result:
		case <-ctx.Done():
			_ = server.Close()
			return Credential{}, ctx.Err()
		}
	}
	_ = server.Close()
	if cb.err != nil {
		return Credential{}, cb.err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {cb.code},
		"client_id":     {reg.ClientID},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
		"resource":      {resource},
	}
	var token tokenResponse
	if err := postFormJSON(ctx, client, tokenEndpoint, form, &token); err != nil {
		return Credential{}, err
	}
	if token.AccessToken == "" || token.RefreshToken == "" {
		return Credential{}, errors.New("token response is missing access or refresh token")
	}
	return Credential{Issuer: meta.Issuer, Resource: resource, ClientID: reg.ClientID,
		AccessToken: token.AccessToken, RefreshToken: token.RefreshToken,
		ExpiresAt: time.Now().Add(time.Duration(token.ExpiresIn) * time.Second).Unix()}, nil
}

func (m *Manager) readManualCallback(ctx context.Context, authorizationURL, redirectURI, state string) callbackResult {
	manualPath, err := saveManualAuthorizationURL(authorizationURL)
	if err != nil {
		return callbackResult{err: errors.New("could not save the OAuth authorization URL for manual login")}
	}
	defer os.Remove(manualPath)
	if m.ManualCallback == nil {
		return callbackResult{err: errors.New("no graphical browser is available and manual OAuth callback input is not configured")}
	}
	raw, err := m.ManualCallback(ctx, ManualAuthorization{AuthorizationURLFile: manualPath, RedirectURI: redirectURI})
	if err != nil {
		return callbackResult{err: err}
	}
	code, err := parseManualCallbackURL(raw, redirectURI, state)
	return callbackResult{code: code, err: err}
}

func parseManualCallbackURL(raw, redirectURI, expectedState string) (string, error) {
	callback, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !callback.IsAbs() || callback.Host == "" || callback.User != nil || callback.Fragment != "" {
		return "", errors.New("invalid OAuth callback URL")
	}
	expected, err := url.Parse(redirectURI)
	if err != nil {
		return "", errors.New("invalid expected OAuth callback URL")
	}
	if !strings.EqualFold(callback.Scheme, expected.Scheme) || !strings.EqualFold(callback.Host, expected.Host) || callback.EscapedPath() != expected.EscapedPath() {
		return "", errors.New("OAuth callback URL does not match this login attempt")
	}
	query := callback.Query()
	states := query["state"]
	if len(states) != 1 || states[0] != expectedState {
		return "", errors.New("OAuth state mismatch")
	}
	if values := query["error"]; len(values) != 0 {
		return "", errors.New("OAuth authorization denied")
	}
	codes := query["code"]
	if len(codes) != 1 || strings.TrimSpace(codes[0]) == "" {
		return "", errors.New("OAuth callback URL is missing a single authorization code")
	}
	return codes[0], nil
}

func saveManualAuthorizationURL(target string) (string, error) {
	file, err := os.CreateTemp("", ".chat-with-cli-oauth-url-*")
	if err != nil {
		return "", err
	}
	path := file.Name()
	cleanup := func(err error) (string, error) {
		_ = file.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := file.Chmod(0o600); err != nil {
		return cleanup(err)
	}
	if _, err := file.WriteString(target + "\n"); err != nil {
		return cleanup(err)
	}
	if err := file.Sync(); err != nil {
		return cleanup(err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func sameOriginEndpoint(base, raw, name string) (string, error) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	target, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !target.IsAbs() || target.Host == "" || target.User != nil || target.RawQuery != "" || target.Fragment != "" {
		return "", fmt.Errorf("invalid OAuth %s", name)
	}
	if !strings.EqualFold(target.Scheme, baseURL.Scheme) || !strings.EqualFold(target.Host, baseURL.Host) {
		return "", fmt.Errorf("OAuth %s must use the configured Relay origin", name)
	}
	return target.String(), nil
}

func randomURLToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func openBrowser(target string) error {
	if runtime.GOOS == "linux" && strings.TrimSpace(os.Getenv("DISPLAY")) == "" && strings.TrimSpace(os.Getenv("WAYLAND_DISPLAY")) == "" {
		return errors.New("no graphical session is available")
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", target)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		cmd = exec.Command("xdg-open", target)
	}
	return cmd.Start()
}
