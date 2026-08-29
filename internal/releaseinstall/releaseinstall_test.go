package releaseinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFetchVerifiedRelease(t *testing.T) {
	binary := []byte("verified-binary")
	sum := sha256.Sum256(binary)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/SHA256SUMS":
			_, _ = w.Write([]byte(hex.EncodeToString(sum[:]) + "  chat-with-cli-linux-amd64\n"))
		case "/binary":
			_, _ = w.Write(binary)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	got, digest, err := FetchVerified(context.Background(), server.Client(), server.URL+"/SHA256SUMS", server.URL+"/binary", "chat-with-cli-linux-amd64")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(binary) || digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("unexpected verified result: %q %q", got, digest)
	}
}

func TestFetchVerifiedRejectsChecksumMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "SHA256") {
			_, _ = w.Write([]byte(strings.Repeat("0", 64) + "  chat-with-cli-linux-amd64\n"))
			return
		}
		_, _ = w.Write([]byte("not-the-published-binary"))
	}))
	defer server.Close()
	_, _, err := FetchVerified(context.Background(), server.Client(), server.URL+"/SHA256SUMS", server.URL+"/binary", "chat-with-cli-linux-amd64")
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("checksum mismatch was not rejected: %v", err)
	}
}

func TestInstallCreatesVerifiedRollbackBackup(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "chat-with-cli")
	backup := destination + ".previous"
	if err := os.WriteFile(destination, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Install(destination, backup, []byte("new-binary")); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(destination)
	if string(got) != "new-binary" {
		t.Fatalf("installed=%q", got)
	}
	if err := RestoreVerifiedBackup(destination, backup); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(destination)
	if string(got) != "old-binary" {
		t.Fatalf("restored=%q", got)
	}
}

func TestInstallRejectsSymlinkDestination(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "chat-with-cli")
	if err := os.WriteFile(target, []byte("keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := Install(link, link+".previous", []byte("evil")); err == nil {
		t.Fatal("symlink destination was replaced")
	}
	got, _ := os.ReadFile(target)
	if string(got) != "keep" {
		t.Fatalf("symlink target changed: %q", got)
	}
}

func TestRollbackRejectsTamperedBackup(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "chat-with-cli")
	backup := destination + ".previous"
	_ = os.WriteFile(destination, []byte("old"), 0o755)
	if err := Install(destination, backup, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := RestoreVerifiedBackup(destination, backup); err == nil {
		t.Fatal("tampered rollback backup was accepted")
	}
	got, _ := os.ReadFile(destination)
	if string(got) != "new" {
		t.Fatalf("destination changed after rejected rollback: %q", got)
	}
}

func TestResolveLatestIncludesPrereleaseAndSkipsDraft(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
  {"tag_name":"v9.9.9-draft","draft":true},
  {"tag_name":"v0.2.0-alpha.1","draft":false},
  {"tag_name":"v0.1.0","draft":false}
]`))
	}))
	defer server.Close()
	tag, err := resolveGitHubVersion(context.Background(), server.Client(), server.URL, "latest")
	if err != nil {
		t.Fatal(err)
	}
	if tag != "v0.2.0-alpha.1" {
		t.Fatalf("resolved tag=%q", tag)
	}
}

func TestGitHubReleaseURLsRejectsUnresolvedLatest(t *testing.T) {
	if _, _, _, err := GitHubReleaseURLs("latest", "amd64"); err == nil {
		t.Fatal("unresolved latest release URL was accepted")
	}
}
