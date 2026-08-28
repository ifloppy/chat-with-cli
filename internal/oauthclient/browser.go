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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return Credential{}, err
	}
	defer ln.Close()
	redirect := "http://" + ln.Addr().String() + "/callback"
	regBody := map[string]any{
		"redirect_uris":              []string{redirect},
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"client_name":                "chat-with-cli agent " + m.Device,
		"scope":                      "agent:connect offline_access",
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

	opener := m.OpenBrowser
	if opener == nil {
		opener = openBrowser
	}
	if err := opener(u.String()); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Could not open a browser automatically (%v). Open this URL manually:\n%s\n", err, u.String())
	}
	var cb callbackResult
	select {
	case cb = <-result:
	case <-ctx.Done():
		_ = server.Close()
		return Credential{}, ctx.Err()
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
