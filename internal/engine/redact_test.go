package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeRedactLineTerms(t *testing.T) {
	got, err := NormalizeRedactLineTerms([]string{" API_KEY ", "api_key", "Token"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "api_key,token" {
		t.Fatalf("normalized terms=%v", got)
	}
	if _, err := NormalizeRedactLineTerms([]string{"bad\nterm"}); err == nil {
		t.Fatal("multiline redact term was accepted")
	}
	if _, err := NormalizeRedactLineTerms([]string{strings.Repeat("x", maxRedactTermBytes+1)}); err == nil {
		t.Fatal("oversized redact term was accepted")
	}
}
func TestRedactTextPreservesLineEndings(t *testing.T) {
	e := &Engine{cfg: Config{RedactLineTerms: []string{"api_key", "token"}}}
	input := "visible\nAPI_KEY=value\r\nToken: value\nno-final-newline"
	want := "visible\n[REDACTED LINE]\r\n[REDACTED LINE]\nno-final-newline"
	if got := e.redactText(input); got != want {
		t.Fatalf("redacted text=%q want=%q", got, want)
	}
	if got := e.redactText("plain text"); got != "plain text" {
		t.Fatalf("plain text changed: %q", got)
	}
}

func TestFileReadRedactsReturnedContentButKeepsSourceSnapshot(t *testing.T) {
	root := t.TempDir()
	state := t.TempDir()
	path := filepath.Join(root, "config.txt")
	raw := []byte("visible\nAPI_KEY=super-secret\r\nfinal")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := New(Config{Roots: []string{root}, StateDir: state, RedactLineTerms: []string{"api_key"}})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	read, err := eng.ReadFile(FileReadInput{Path: path, Limit: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if read.Content != "visible\n[REDACTED LINE]\r\nfinal" {
		t.Fatalf("redacted file content=%q", read.Content)
	}
	sum := sha256.Sum256(raw)
	wantSHA := hex.EncodeToString(sum[:])
	if read.SHA256 != wantSHA {
		t.Fatalf("snapshot sha=%q want source sha=%q", read.SHA256, wantSHA)
	}
	if strings.Contains(read.Content, "super-secret") {
		t.Fatal("redacted fs_read leaked source value")
	}
}

func TestTaskMetadataIsRedactedOnlyOnReturn(t *testing.T) {
	e := &Engine{cfg: Config{RedactLineTerms: []string{"api_key"}}}
	original := TaskInfo{Name: "API_KEY maintenance", Command: "printf API_KEY=secret", State: "completed"}
	got := e.redactTaskInfo(original)
	if got.Name != "[REDACTED LINE]" || got.Command != "[REDACTED LINE]" {
		t.Fatalf("redacted task=%+v", got)
	}
	if original.Name != "API_KEY maintenance" || original.Command != "printf API_KEY=secret" {
		t.Fatal("redaction mutated stored task metadata")
	}
}
