package oauthserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLocalUIAssetsAndMonetizationContract(t *testing.T) {
	s, err := New(Config{
		PublicURL:           "http://127.0.0.1:19301",
		StateDir:            t.TempDir(),
		Mode:                ModePublic,
		AdSenseClientID:     "ca-pub-test",
		AdSenseSlot:         "1234567890",
		AdMobAppID:          "ca-app-pub-test~123",
		AdMobRewardUnitID:   "ca-app-pub-test/456",
		UsageUnlockEnabled:  true,
		UsageUnlockEndpoint: "https://rewards.example/unlock",
		Version:             "test-version",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	mux := http.NewServeMux()
	s.RegisterRoutes(mux)
	h := SecurityHeaders(mux)
	for _, tc := range []struct {
		path, contentType, contains string
	}{
		{"/assets/app.css", "text/css", "--md-primary"},
		{"/assets/app.js", "application/javascript", "data-i18n"},
	} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, s.absolute(tc.path), nil))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Header().Get("Content-Type"), tc.contentType) || !strings.Contains(rr.Body.String(), tc.contains) {
			t.Fatalf("asset %s status=%d type=%q body contains %q=%v", tc.path, rr.Code, rr.Header().Get("Content-Type"), tc.contains, strings.Contains(rr.Body.String(), tc.contains))
		}
	}

	configResponse := httptest.NewRecorder()
	h.ServeHTTP(configResponse, httptest.NewRequest(http.MethodGet, s.absolute("/api/monetization/config"), nil))
	if configResponse.Code != http.StatusOK {
		t.Fatalf("monetization config status=%d body=%s", configResponse.Code, configResponse.Body.String())
	}
	var contract struct {
		AdSense struct {
			Enabled bool   `json:"enabled"`
			Client  string `json:"client_id"`
		} `json:"adsense"`
		AdMob struct {
			Enabled bool `json:"enabled"`
		} `json:"admob"`
		UsageUnlock struct {
			Enabled      bool   `json:"enabled"`
			Endpoint     string `json:"endpoint"`
			Verification string `json:"verification"`
		} `json:"usage_unlock"`
	}
	if err := json.Unmarshal(configResponse.Body.Bytes(), &contract); err != nil {
		t.Fatal(err)
	}
	if !contract.AdSense.Enabled || contract.AdSense.Client != "ca-pub-test" || !contract.AdMob.Enabled || !contract.UsageUnlock.Enabled || contract.UsageUnlock.Endpoint != "https://rewards.example/unlock" || contract.UsageUnlock.Verification == "" {
		t.Fatalf("unexpected monetization contract: %+v", contract)
	}

	landing := httptest.NewRecorder()
	h.ServeHTTP(landing, httptest.NewRequest(http.MethodGet, s.absolute("/?lang=zh-CN"), nil))
	body := landing.Body.String()
	for _, expected := range []string{"data-locale=\"zh-CN\"", "data-i18n", "data-adsense-client=\"ca-pub-test\"", "data-admob-app-id=\"ca-app-pub-test~123\"", "https://rewards.example/unlock"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("landing page is missing %q: %s", expected, body)
		}
	}
	if strings.Contains(body, "<style") || !strings.Contains(body, "/assets/app.css") || !strings.Contains(body, "/assets/app.js") {
		t.Fatalf("landing page did not use the shared local UI assets")
	}
	if strings.Contains(landing.Header().Get("Content-Security-Policy"), "unsafe-inline") {
		t.Fatalf("UI CSP unexpectedly permits inline code: %s", landing.Header().Get("Content-Security-Policy"))
	}
}
