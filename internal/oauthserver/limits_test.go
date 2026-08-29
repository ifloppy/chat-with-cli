package oauthserver

import (
	"net/http/httptest"
	"testing"
)

func TestRequestIPIgnoresForwardedHeadersFromUntrustedPeer(t *testing.T) {
	r := httptest.NewRequest("GET", "https://relay.example/", nil)
	r.RemoteAddr = "198.51.100.9:443"
	r.Header.Set("X-Forwarded-For", "203.0.113.77")
	if got := requestIP(r, nil); got != "198.51.100.9" {
		t.Fatalf("requestIP=%q", got)
	}
}

func TestRequestIPWalksTrustedProxyChainRightToLeft(t *testing.T) {
	trusted, err := parseTrustedProxyCIDRs([]string{"127.0.0.1/32", "172.64.0.0/13"})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "https://relay.example/", nil)
	r.RemoteAddr = "127.0.0.1:39100"
	// A malicious client prepended 192.0.2.55. The nearest trusted Cloudflare
	// hop is right-most, so the actual client is the first untrusted hop to its left.
	r.Header.Set("X-Forwarded-For", "192.0.2.55, 203.0.113.42, 172.70.10.20")
	if got := requestIP(r, trusted); got != "203.0.113.42" {
		t.Fatalf("requestIP=%q want client 203.0.113.42", got)
	}
}
