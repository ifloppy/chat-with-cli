package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ifloppy/chat-with-cli/internal/config"
	"github.com/ifloppy/chat-with-cli/internal/oauthclient"
	"github.com/ifloppy/chat-with-cli/internal/oauthserver"
	"github.com/ifloppy/chat-with-cli/internal/protocol"
)

func runAgentSetup(args []string) error {
	fs := flag.NewFlagSet("agent setup", flag.ContinueOnError)
	configPath := fs.String("config", oauthclient.DefaultConfigPath(), "agent TOML configuration path")
	relayURL := fs.String("relay", "", "relay base URL")
	deviceDefault, _ := os.Hostname()
	device := fs.String("device", deviceDefault, "human-readable device name")
	deviceID := fs.String("device-id", "", "immutable device ID; generated when omitted")
	profile := fs.String("profile", "read-only", "read-only, developer, computer-use, or custom")
	roots := new(stringList)
	fs.Var(roots, "root", "allowed filesystem root (repeatable)")
	stateDir := fs.String("state-dir", "", "agent state directory")
	allowFileWrite := fs.Bool("allow-file-write", false, "allow filesystem/checkpoint writes")
	allowExec := fs.Bool("allow-exec", false, "allow PTY shell execution")
	execSandbox := fs.String("exec-sandbox", "none", "none or landlock")
	allowScreen := fs.Bool("allow-screen", false, "allow read-only screen inspection")
	allowComputer := fs.Bool("allow-computer-use", false, "allow computer input/control")
	computerPersist := fs.String("computer-persist", "process", "none, process, or persistent")
	killSwitchPath := fs.String("kill-switch-file", "", "local emergency kill-switch file")
	maxActiveTasks := fs.Int("max-active-tasks", 32, "maximum concurrent PTY tasks")
	installSystemd := fs.Bool("install-systemd", false, "write a systemd user unit; never enables or starts it")
	unitPath := fs.String("unit", "", "systemd user unit path")
	force := fs.Bool("force", false, "replace an existing config/unit after symlink checks")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !protocol.ValidDeviceName(strings.TrimSpace(*device)) {
		return errors.New("--device must be 1-128 ASCII letters, digits, dot, underscore, or hyphen")
	}
	if strings.TrimSpace(*deviceID) == "" {
		*deviceID = protocol.NewID()
	}
	if !protocol.ValidDeviceID(strings.TrimSpace(*deviceID)) {
		return errors.New("--device-id must be 32 hexadecimal characters")
	}
	if !validCapabilityProfile(*profile) {
		return fmt.Errorf("invalid capability profile %q", *profile)
	}
	switch strings.ToLower(strings.TrimSpace(*profile)) {
	case "read-only":
		*allowFileWrite, *allowExec, *allowScreen, *allowComputer = false, false, false, false
	case "developer":
		*allowFileWrite, *allowExec, *allowScreen, *allowComputer = true, true, false, false
	case "computer-use":
		*allowFileWrite, *allowExec, *allowScreen, *allowComputer = false, false, true, true
	}
	if !*allowExec {
		*execSandbox = "none"
	}
	if strings.ToLower(strings.TrimSpace(*execSandbox)) != "none" && strings.ToLower(strings.TrimSpace(*execSandbox)) != "landlock" {
		return fmt.Errorf("invalid exec sandbox %q", *execSandbox)
	}
	if len(*roots) == 0 {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		*roots = append(*roots, cwd)
	}
	values := map[string]any{
		"agent.relay_url":          strings.TrimSpace(*relayURL),
		"agent.device":             strings.TrimSpace(*device),
		"agent.device_id":          strings.TrimSpace(*deviceID),
		"agent.root":               append([]string(nil), *roots...),
		"agent.profile":            strings.ToLower(strings.TrimSpace(*profile)),
		"agent.state_dir":          strings.TrimSpace(*stateDir),
		"agent.allow_file_write":   *allowFileWrite,
		"agent.allow_exec":         *allowExec,
		"agent.exec_sandbox":       strings.ToLower(strings.TrimSpace(*execSandbox)),
		"agent.allow_screen":       *allowScreen,
		"agent.allow_computer_use": *allowComputer,
		"agent.computer_persist":   strings.TrimSpace(*computerPersist),
		"agent.max_active_tasks":   *maxActiveTasks,
		"agent.kill_switch_file":   strings.TrimSpace(*killSwitchPath),
		"agent.credentials":        oauthclient.DefaultCredentialsPath(),
	}
	if err := writeConfigFile(*configPath, values, *force); err != nil {
		return fmt.Errorf("write agent config: %w", err)
	}
	fmt.Printf("agent config written to %s\nimmutable device ID: %s\nMCP endpoint: %s/mcp/id/%s\n", *configPath, *deviceID, strings.TrimRight(*relayURL, "/"), *deviceID)
	if *installSystemd {
		if *unitPath == "" {
			*unitPath = filepath.Join(userConfigDir(), "systemd", "user", "chat-with-cli-agent.service")
		}
		unit := fmt.Sprintf(`[Unit]
Description=Chat with CLI Agent
After=graphical-session.target

[Service]
ExecStart=/usr/local/bin/chat-with-cli agent --config %s
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=default.target
`, *configPath)
		if err := writeTextFile(*unitPath, unit, 0o600, *force); err != nil {
			return fmt.Errorf("write systemd user unit: %w", err)
		}
		fmt.Printf("systemd user unit written to %s; it remains inactive until you explicitly enable it after review\n", *unitPath)
	}
	return nil
}

func validCapabilityProfile(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "read-only", "developer", "computer-use", "custom":
		return true
	default:
		return false
	}
}

func runRelaySetup(args []string) error {
	fs := flag.NewFlagSet("relay setup", flag.ContinueOnError)
	configPath := fs.String("config", defaultRelayConfigPath(), "relay TOML configuration path")
	publicURL := fs.String("public-url", "", "public HTTPS origin")
	listen := fs.String("listen", ":8765", "HTTP listen address")
	mode := fs.String("instance-mode", "private", "private or public")
	stateDir := fs.String("state-dir", defaultRelayStateDir(), "relay state directory")
	setupTokenFile := fs.String("setup-token-file", "", "one-time setup token path")
	force := fs.Bool("force", false, "replace existing config/token after symlink checks")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*setupTokenFile) == "" {
		*setupTokenFile = defaultSetupTokenPath(*stateDir)
	}
	if strings.EqualFold(strings.TrimSpace(*mode), oauthserver.ModePublic) {
		*mode = oauthserver.ModePublic
	} else if strings.EqualFold(strings.TrimSpace(*mode), oauthserver.ModePrivate) {
		*mode = oauthserver.ModePrivate
	} else {
		return fmt.Errorf("invalid instance mode %q", *mode)
	}
	if strings.TrimSpace(readTrimmedFile(*setupTokenFile)) == "" {
		if err := writeTextFile(*setupTokenFile, protocol.NewID()+protocol.NewID()+"\n", 0o600, *force); err != nil {
			return fmt.Errorf("write setup token: %w", err)
		}
	}
	values := map[string]any{
		"relay.public_url":           strings.TrimSpace(*publicURL),
		"relay.listen":               strings.TrimSpace(*listen),
		"relay.instance_mode":        strings.TrimSpace(*mode),
		"relay.state_dir":            strings.TrimSpace(*stateDir),
		"relay.setup_token_file":     strings.TrimSpace(*setupTokenFile),
		"relay.disable_registration": false,
	}
	if err := writeConfigFile(*configPath, values, *force); err != nil {
		return fmt.Errorf("write relay config: %w", err)
	}
	fmt.Printf("relay config written to %s\none-time setup token: %s\n", *configPath, *setupTokenFile)
	fmt.Println("Start the Relay manually, then open /setup from the configured public origin.")
	return nil
}

func runRelayInstall(args []string) error {
	fs := flag.NewFlagSet("relay install", flag.ContinueOnError)
	version := fs.String("version", "latest", "release version to install")
	prefix := fs.String("prefix", "/usr/local", "binary installation prefix")
	if err := fs.Parse(args); err != nil {
		return err
	}
	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		return fmt.Errorf("release installer currently supports amd64 and arm64; detected %s", arch)
	}
	fmt.Printf("verified installation plan for %s on linux/%s:\n", *version, arch)
	fmt.Printf("1. Download chat-with-cli_%s_linux_%s.tar.gz and its .sha256 file from the GitHub release.\n", *version, arch)
	fmt.Println("2. Inspect the archive and checksum before extraction (never pipe an unverified response to a shell).")
	fmt.Printf("3. Install the binary as %s/bin/chat-with-cli, then run `chat-with-cli relay setup`.\n", strings.TrimRight(*prefix, "/"))
	fmt.Println("4. Create a dedicated system user/state directory and review the hardened systemd unit before starting.")
	return nil
}

func runUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Println("No update was applied. Download a signed release, verify its published SHA256 checksum, retain the previous binary, and restart only after review.")
	return nil
}

func runRollback(args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Println("No rollback was applied. Restore the previous checksum-verified binary, keep the state directory unchanged, and validate with `chat-with-cli doctor` before starting.")
	return nil
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	configPath := fs.String("config", oauthclient.DefaultConfigPath(), "agent TOML configuration path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	values, err := config.LoadOptional(*configPath)
	if err != nil {
		return err
	}
	active, enabled := systemdUserState("chat-with-cli-agent.service")
	status := map[string]any{"config": *configPath, "relay": values.String("", "agent.relay_url"), "device": values.String("", "agent.device"), "device_id": values.String("", "agent.device_id"), "profile": values.String("read-only", "agent.profile"), "systemd_active": active, "systemd_enabled": enabled}
	data, _ := json.MarshalIndent(status, "", "  ")
	fmt.Println(string(data))
	return nil
}

func systemdUserState(unit string) (bool, bool) {
	active := exec.Command("systemctl", "--user", "is-active", "--quiet", unit).Run() == nil
	enabled := exec.Command("systemctl", "--user", "is-enabled", "--quiet", unit).Run() == nil
	return active, enabled
}

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	relayURL := fs.String("relay", "", "Relay URL to inspect")
	device := fs.String("device", "", "legacy display-name route to inspect")
	deviceID := fs.String("device-id", "", "immutable device ID route to inspect")
	configPath := fs.String("config", oauthclient.DefaultConfigPath(), "agent TOML configuration path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	values, err := config.LoadOptional(*configPath)
	if err != nil {
		return err
	}
	if *relayURL == "" {
		*relayURL = values.String(*relayURL, "agent.relay_url")
	}
	if *device == "" {
		*device = values.String(*device, "agent.device")
	}
	if *deviceID == "" {
		*deviceID = values.String(*deviceID, "agent.device_id")
	}
	if strings.TrimSpace(*relayURL) == "" {
		return errors.New("doctor needs --relay or agent.relay_url")
	}
	base, err := normalizeDiagnosticURL(*relayURL)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	checks := []doctorCheck{}
	checks = append(checks, doctorHTTPCheck(context.Background(), client, "DNS/TLS and health", base+"/health", func(resp *http.Response) bool { return resp.StatusCode == http.StatusOK }))
	checks = append(checks, doctorHTTPCheck(context.Background(), client, "OAuth metadata", base+"/.well-known/oauth-authorization-server", func(resp *http.Response) bool {
		return resp.StatusCode == http.StatusOK && strings.Contains(resp.Header.Get("Content-Type"), "json")
	}))
	checks = append(checks, doctorHTTPCheck(context.Background(), client, "DCR endpoint", base+"/oauth/register", func(resp *http.Response) bool {
		return resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusCreated
	}))
	route := strings.TrimSpace(*device)
	if strings.TrimSpace(*deviceID) != "" {
		if !protocol.ValidDeviceID(strings.TrimSpace(*deviceID)) {
			return errors.New("invalid --device-id")
		}
		route = "id/" + strings.TrimSpace(*deviceID)
	}
	if route != "" {
		checks = append(checks, doctorHTTPCheck(context.Background(), client, "protected resource metadata", base+"/.well-known/oauth-protected-resource/agent/"+route, func(resp *http.Response) bool { return resp.StatusCode == http.StatusOK }))
		checks = append(checks, doctorHTTPCheck(context.Background(), client, "MCP challenge", base+"/mcp/"+route, func(resp *http.Response) bool {
			return resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusServiceUnavailable
		}))
	}
	failed := 0
	for _, check := range checks {
		if check.OK {
			fmt.Printf("PASS  %s%s\n", check.Name, check.Detail)
		} else {
			failed++
			fmt.Printf("FAIL  %s%s\n", check.Name, check.Detail)
		}
	}
	if failed > 0 {
		return fmt.Errorf("doctor found %d failing check(s)", failed)
	}
	return nil
}

type doctorCheck struct {
	Name   string
	OK     bool
	Detail string
}

func doctorHTTPCheck(ctx context.Context, client *http.Client, name, target string, predicate func(*http.Response) bool) doctorCheck {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return doctorCheck{Name: name, Detail: ": " + err.Error()}
	}
	response, err := client.Do(request)
	if err != nil {
		return doctorCheck{Name: name, Detail: ": " + redactDiagnosticError(err)}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.Header.Get("cf-mitigated") == "challenge" {
		return doctorCheck{Name: name, Detail: ": Cloudflare Managed Challenge (review Browser Integrity Check/Bot Fight Mode/Super Bot Fight Mode)", OK: false}
	}
	return doctorCheck{Name: name, OK: predicate(response), Detail: fmt.Sprintf(" (HTTP %d)", response.StatusCode)}
}

func normalizeDiagnosticURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1"))) {
		return "", fmt.Errorf("invalid relay URL %q; use HTTPS or loopback HTTP without a path/query", raw)
	}
	if u.Path != "" && u.Path != "/" {
		return "", errors.New("relay URL must be an origin without a path")
	}
	u.Path = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func redactDiagnosticError(err error) string {
	return strings.ReplaceAll(err.Error(), "?", "")
}

func writeConfigFile(path string, values map[string]any, force bool) error {
	if !force {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("file already exists (use --force to replace): %s", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return config.Write(path, values)
}

func writeTextFile(path, content string, mode os.FileMode, force bool) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing to write through symlink")
		}
		if !force {
			return fmt.Errorf("file already exists: %s", path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".chat-with-cli-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func defaultRelayConfigPath() string {
	if os.Geteuid() == 0 {
		return "/etc/chat-with-cli/config.toml"
	}
	return filepath.Join(userConfigDir(), "chat-with-cli", "relay-config.toml")
}

func userConfigDir() string {
	if value := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); value != "" {
		return value
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config")
}
