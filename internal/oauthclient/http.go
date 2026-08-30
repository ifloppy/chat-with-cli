package oauthclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type HTTPStatusError struct {
	StatusCode int
}

func (e *HTTPStatusError) Error() string {
	if e == nil {
		return "OAuth endpoint returned an HTTP error"
	}
	return fmt.Sprintf("OAuth endpoint returned %d %s", e.StatusCode, http.StatusText(e.StatusCode))
}

func IsHTTPStatus(err error, status int) bool {
	var target *HTTPStatusError
	return errors.As(err, &target) && target.StatusCode == status
}

func getJSON(ctx context.Context, client *http.Client, target string, out any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return safeHTTPError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return &HTTPStatusError{StatusCode: resp.StatusCode}
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

func postJSON(ctx context.Context, client *http.Client, target string, body any, out any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return doJSON(client, req, out)
}

func postForm(ctx context.Context, client *http.Client, target string, form url.Values) error {
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return safeHTTPError(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return &HTTPStatusError{StatusCode: resp.StatusCode}
	}
	return nil
}

func postFormJSON(ctx context.Context, client *http.Client, target string, form url.Values, out any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return doJSON(client, req, out)
}

func doJSON(client *http.Client, req *http.Request, out any) error {
	resp, err := client.Do(req)
	if err != nil {
		return safeHTTPError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		// Error bodies are controlled by the remote endpoint and may echo the
		// OAuth request. Never include them in an error that can reach CLI logs:
		// token, authorization-code, PKCE, and other credential fields are sent
		// in the request body.
		return &HTTPStatusError{StatusCode: resp.StatusCode}
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

func safeHTTPError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return errors.New("OAuth HTTP request failed")
}
