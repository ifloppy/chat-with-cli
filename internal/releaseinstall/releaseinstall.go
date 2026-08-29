package releaseinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxBinaryBytes   = 64 << 20
	maxSumsBytes     = 1 << 20
	maxMetadataBytes = 2 << 20
)

func AssetName(arch string) (string, error) {
	switch arch {
	case "amd64", "arm64":
		return "chat-with-cli-linux-" + arch, nil
	default:
		return "", fmt.Errorf("unsupported Linux architecture %q", arch)
	}
}

type githubRelease struct {
	TagName string `json:"tag_name"`
	Draft   bool   `json:"draft"`
}

func resolveGitHubVersion(ctx context.Context, client *http.Client, apiURL, version string) (string, error) {
	version = strings.TrimSpace(version)
	if version != "" && version != "latest" {
		_, _, _, err := GitHubReleaseURLs(version, "amd64")
		return version, err
	}
	if client == nil {
		client = SecureHTTPClient()
	}
	data, err := fetch(ctx, client, apiURL, maxMetadataBytes)
	if err != nil {
		return "", fmt.Errorf("resolve latest GitHub release: %w", err)
	}
	var releases []githubRelease
	if err := json.Unmarshal(data, &releases); err != nil {
		return "", fmt.Errorf("decode GitHub releases: %w", err)
	}
	for _, release := range releases {
		if release.Draft || strings.TrimSpace(release.TagName) == "" {
			continue
		}
		if _, _, _, err := GitHubReleaseURLs(release.TagName, "amd64"); err != nil {
			continue
		}
		return release.TagName, nil
	}
	return "", errors.New("GitHub returned no installable release")
}

func ResolveGitHubVersion(ctx context.Context, client *http.Client, version string) (string, error) {
	return resolveGitHubVersion(ctx, client, "https://api.github.com/repos/ifloppy/chat-with-cli/releases?per_page=20", version)
}

func GitHubReleaseURLs(version, arch string) (assetName, sumsURL, assetURL string, err error) {
	assetName, err = AssetName(arch)
	if err != nil {
		return "", "", "", err
	}
	version = strings.TrimSpace(version)
	if version == "" || version == "latest" {
		return "", "", "", errors.New("latest must be resolved to a concrete tag first")
	}
	if len(version) > 96 {
		return "", "", "", errors.New("release version is too long")
	}
	for _, r := range version {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return "", "", "", fmt.Errorf("invalid release version %q", version)
	}
	base := "https://github.com/ifloppy/chat-with-cli/releases/download/" + url.PathEscape(version) + "/"
	return assetName, base + "SHA256SUMS", base + assetName, nil
}

func readBounded(resp *http.Response, limit int64) ([]byte, error) {
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("download exceeded size limit")
	}
	return data, nil
}

func fetch(ctx context.Context, client *http.Client, target string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return readBounded(resp, limit)
}

func SecureHTTPClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many release download redirects")
			}
			if req.URL.Scheme != "https" || req.URL.User != nil {
				return errors.New("release download redirect must remain HTTPS without credentials")
			}
			return nil
		},
	}
}

func checksumFor(data []byte, assetName string) (string, error) {
	var found string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name != assetName {
			continue
		}

		if len(fields[0]) != 64 {
			return "", fmt.Errorf("invalid checksum length for %s", assetName)
		}
		if _, err := hex.DecodeString(fields[0]); err != nil {
			return "", fmt.Errorf("invalid checksum for %s", assetName)
		}
		if found != "" {
			return "", fmt.Errorf("duplicate checksum entry for %s", assetName)
		}
		found = strings.ToLower(fields[0])
	}
	if found == "" {
		return "", fmt.Errorf("SHA256SUMS has no entry for %s", assetName)
	}
	return found, nil
}

func FetchVerified(ctx context.Context, client *http.Client, sumsURL, assetURL, assetName string) ([]byte, string, error) {
	if client == nil {
		client = SecureHTTPClient()
	}
	sums, err := fetch(ctx, client, sumsURL, maxSumsBytes)
	if err != nil {
		return nil, "", fmt.Errorf("download SHA256SUMS: %w", err)
	}
	expected, err := checksumFor(sums, assetName)
	if err != nil {
		return nil, "", err
	}
	binary, err := fetch(ctx, client, assetURL, maxBinaryBytes)
	if err != nil {
		return nil, "", fmt.Errorf("download %s: %w", assetName, err)
	}
	digest := sha256.Sum256(binary)
	got := hex.EncodeToString(digest[:])
	if got != expected {
		return nil, "", fmt.Errorf("checksum mismatch for %s: got %s want %s", assetName, got, expected)
	}
	return binary, got, nil
}

func fsyncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to replace symlink %s", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".chat-with-cli-install-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return fsyncDir(dir)
}

func digestHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func readRegularFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds size limit", path)
	}
	return data, nil
}

func BackupCurrent(destination, backup string) error {
	data, err := readRegularFile(destination, maxBinaryBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := writeAtomic(backup, data, 0o755); err != nil {
		return fmt.Errorf("backup current binary: %w", err)
	}
	return writeAtomic(backup+".sha256", []byte(digestHex(data)+"\n"), 0o600)
}

func Preflight(destination, backup string) error {
	if !filepath.IsAbs(destination) || !filepath.IsAbs(backup) {
		return errors.New("installation and backup paths must be absolute")
	}
	if destination == backup {
		return errors.New("installation and backup paths must differ")
	}
	for _, path := range []string{destination, backup, backup + ".sha256"} {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("refusing unsafe install path %s", path)
		}
	}
	return nil
}

func Install(destination, backup string, data []byte) error {
	if err := Preflight(destination, backup); err != nil {
		return err
	}
	if err := BackupCurrent(destination, backup); err != nil {
		return err
	}
	if err := writeAtomic(destination, data, 0o755); err != nil {
		return fmt.Errorf("install new binary: %w", err)
	}
	return nil
}

func RestoreVerifiedBackup(destination, backup string) error {
	data, err := readRegularFile(backup, maxBinaryBytes)
	if err != nil {
		return fmt.Errorf("read backup: %w", err)
	}
	sumData, err := readRegularFile(backup+".sha256", 4096)
	if err != nil {
		return fmt.Errorf("read backup checksum: %w", err)
	}
	expected := strings.TrimSpace(string(sumData))
	if len(expected) != 64 {
		return errors.New("backup checksum has invalid length")
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return errors.New("backup checksum is invalid")
	}
	if got := digestHex(data); got != strings.ToLower(expected) {
		return fmt.Errorf("backup checksum mismatch: got %s want %s", got, expected)
	}
	if err := writeAtomic(destination, data, 0o755); err != nil {
		return fmt.Errorf("restore backup: %w", err)
	}
	return nil
}
