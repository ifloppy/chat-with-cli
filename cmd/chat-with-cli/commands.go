package main

import (
	"bufio"
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
	"github.com/ifloppy/chat-with-cli/internal/deviceidentity"
	"github.com/ifloppy/chat-with-cli/internal/mcpserver"
	"github.com/ifloppy/chat-with-cli/internal/oauthclient"
	"github.com/ifloppy/chat-with-cli/internal/oauthserver"
	"github.com/ifloppy/chat-with-cli/internal/protocol"
	"github.com/ifloppy/chat-with-cli/internal/releaseinstall"
)

func runInteractiveUI(args []string) error {
	if len(args) != 0 {
		return errors.New("the interactive UI does not accept arguments; choose an action from the menu")
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errors.New("interactive UI requires a local terminal; use `chat-with-cli ui` from a TTY or run a subcommand directly")
	}
	defer tty.Close()
	reader := bufio.NewReader(tty)
	for {
		fmt.Fprintln(tty, "\n┌─ Chat with CLI ─────────────────────────────────────┐")
		fmt.Fprintln(tty, "│  A small, safe control centre for your workstation.  │")
		fmt.Fprintln(tty, "└─────────────────────────────────────────────────────┘")
		fmt.Fprintln(tty, "  1  Set up a workstation")
		fmt.Fprintln(tty, "  2  Connect this workstation")
		fmt.Fprintln(tty, "  3  Run diagnostics")
		fmt.Fprintln(tty, "  4  Show current status")
		fmt.Fprintln(tty, "  q  Quit")
		choice, err := uiPrompt(reader, tty, "Choose an action", "1")
		if err != nil {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(choice)) {
		case "1", "setup", "s":
			if err := interactiveAgentSetup(reader, tty); err != nil {
				fmt.Fprintf(tty, "\nSetup failed: %v\n", err)
			} else {
				fmt.Fprintln(tty, "\nSetup complete. Choose connect when you are ready to start the foreground Agent.")
			}
		case "2", "connect", "c":
			return runConnect(nil)
		case "3", "doctor", "d":
			if err := runDoctor(nil); err != nil {
				fmt.Fprintf(tty, "\nDiagnostics failed: %v\n", err)
			}
			_, _ = uiPrompt(reader, tty, "Press Enter to return to the menu", "")
		case "4", "status":
			if err := runStatus(nil); err != nil {
				fmt.Fprintf(tty, "\nStatus failed: %v\n", err)
			}
			_, _ = uiPrompt(reader, tty, "Press Enter to return to the menu", "")
		case "q", "quit", "exit", "0":
			fmt.Fprintln(tty, "Goodbye.")
			return nil
		default:
			fmt.Fprintln(tty, "Please choose 1, 2, 3, 4, or q.")
		}
	}
}

func uiPrompt(reader *bufio.Reader, writer io.Writer, label, defaultValue string) (string, error) {
	if defaultValue != "" {
		fmt.Fprintf(writer, "  %s [%s]: ", label, defaultValue)
	} else {
		fmt.Fprintf(writer, "  %s: ", label)
	}
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultValue, nil
	}
	return line, nil
}

func promptCapabilityProfile(reader *bufio.Reader, writer io.Writer) (string, []string, error) {
	fmt.Fprintln(writer, "  [R] Read-only             Filesystem read only")
	fmt.Fprintln(writer, "  [W] Read-write            Filesystem read/write + shell/exec")
	fmt.Fprintln(writer, "  [D] Desktop-computer-use  Screenshot + accessibility + mouse/keyboard")
	fmt.Fprintln(writer, "  [A] All                   Read-write + desktop-computer-use")
	fmt.Fprintln(writer, "  [C] Custom                Choose capabilities individually")
	selected, err := uiPrompt(reader, writer, "Capability profile [R/W/D/A/C]", "R")
	if err != nil {
		return "", nil, err
	}
	profile, ok := canonicalCapabilityProfile(selected)
	if !ok {
		return "", nil, fmt.Errorf("invalid capability profile %q", selected)
	}
	if profile != "custom" {
		return profile, nil, nil
	}

	flags := make([]string, 0, 5)
	choices := []struct {
		label string
		flag  string
	}{
		{"Allow filesystem/checkpoint writes? (y/N)", "--allow-file-write"},
		{"Allow PTY shell execution? (y/N)", "--allow-exec"},
		{"Allow screenshot capture? (y/N)", "--allow-screen"},
		{"Allow accessibility inspection? (y/N)", "--allow-accessibility"},
		{"Allow mouse/keyboard and semantic UI control? (y/N)", "--allow-computer-use"},
	}
	for _, choice := range choices {
		answer, err := uiPrompt(reader, writer, choice.label, "n")
		if err != nil {
			return "", nil, err
		}
		if strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes") {
			flags = append(flags, choice.flag)
		}
	}
	return profile, flags, nil
}

func interactiveAgentSetup(reader *bufio.Reader, writer io.Writer) error {
	hostname, _ := os.Hostname()
	root, err := os.Getwd()
	if err != nil {
		root = "."
	}
	relay, err := uiPrompt(reader, writer, "Relay URL", defaultPublicRelayURL)
	if err != nil {
		return err
	}
	root, err = uiPrompt(reader, writer, "Workspace root", root)
	if err != nil {
		return err
	}
	device, err := uiPrompt(reader, writer, "Device name", hostname)
	if err != nil {
		return err
	}
	profile, capabilityFlags, err := promptCapabilityProfile(reader, writer)
	if err != nil {
		return err
	}
	installSystemd, err := uiPrompt(reader, writer, "Write an inactive systemd user unit? (y/N)", "n")
	if err != nil {
		return err
	}
	setupArgs := []string{"--relay", relay, "--root", root, "--device", device, "--profile", profile}
	setupArgs = append(setupArgs, capabilityFlags...)
	if strings.EqualFold(installSystemd, "y") || strings.EqualFold(installSystemd, "yes") {
		setupArgs = append(setupArgs, "--install-systemd")
	}
	return runAgentSetup(setupArgs)
}

func runAgentSetup(args []string) error {
	fs := flag.NewFlagSet("agent setup", flag.ContinueOnError)
	configPath := fs.String("config", oauthclient.DefaultConfigPath(), "agent TOML configuration path")
	relayURL := fs.String("relay", defaultPublicRelayURL, "relay base URL (defaults to the community public Relay)")
	deviceDefault, _ := os.Hostname()
	device := fs.String("device", deviceDefault, "human-readable device name")
	deviceID := fs.String("device-id", "", "immutable device ID; generated when omitted")
	profile := fs.String("profile", "read-only", "read-only, read-write, desktop-computer-use, all, or custom (legacy developer/computer-use aliases accepted)")
	roots := new(stringList)
	fs.Var(roots, "root", "allowed filesystem root (repeatable)")
	stateDir := fs.String("state-dir", defaultAgentStateDir(), "agent state directory")
	identityPath := fs.String("identity", "", "Ed25519 device identity path; generated under the state directory when omitted")
	allowFileWrite := fs.Bool("allow-file-write", false, "allow filesystem/checkpoint writes")
	allowExec := fs.Bool("allow-exec", false, "allow PTY shell execution")
	execSandbox := fs.String("exec-sandbox", "none", "none or landlock")
	allowScreen := fs.Bool("allow-screen", false, "allow read-only screenshot capture")
	allowAccessibility := fs.Bool("allow-accessibility", false, "allow read-only AT-SPI accessibility inspection")
	allowComputer := fs.Bool("allow-computer-use", false, "allow computer input/control")
	computerPersist := fs.String("computer-persist", "process", "none, process, or persistent")
	killSwitchPath := fs.String("kill-switch-file", "", "local emergency kill-switch file")
	maxActiveTasks := fs.Int("max-active-tasks", 32, "maximum concurrent PTY tasks")
	installSystemd := fs.Bool("install-systemd", false, "write a systemd user unit; never enables or starts it")
	binaryPath := fs.String("binary", "", "chat-with-cli binary path for the generated systemd unit; defaults to the currently running executable")
	unitPath := fs.String("unit", "", "systemd user unit path")
	force := fs.Bool("force", false, "replace an existing config/unit after symlink checks")
	if err := fs.Parse(args); err != nil {
		return err
	}
	applyKillSwitchDefault(stateDir, killSwitchPath)
	if !protocol.ValidDeviceName(strings.TrimSpace(*device)) {
		return errors.New("--device must be 1-128 ASCII letters, digits, dot, underscore, or hyphen")
	}
	requestedDeviceID := strings.TrimSpace(*deviceID)
	if requestedDeviceID != "" {
		canonicalID, ok := protocol.NormalizeDeviceID(requestedDeviceID)
		if !ok {
			return errors.New("--device-id must be 32 hexadecimal characters")
		}
		requestedDeviceID = canonicalID
	}
	if strings.TrimSpace(*relayURL) == "" {
		return errors.New("--relay is required, for example https://relay.example.com")
	}
	canonicalProfile, ok := canonicalCapabilityProfile(*profile)
	if !ok {
		return fmt.Errorf("invalid capability profile %q", *profile)
	}
	*profile = canonicalProfile
	explicitFileWrite, explicitExec := *allowFileWrite, *allowExec
	explicitScreen, explicitAccessibility, explicitComputer := *allowScreen, *allowAccessibility, *allowComputer
	switch *profile {
	case "read-only":
		*allowFileWrite, *allowExec, *allowScreen, *allowAccessibility, *allowComputer = false, false, false, false, false
	case "read-write":
		*allowFileWrite, *allowExec, *allowScreen, *allowAccessibility, *allowComputer = true, true, false, false, false
	case "desktop-computer-use":
		*allowFileWrite, *allowExec, *allowScreen, *allowAccessibility, *allowComputer = false, false, true, true, true
	case "all":
		*allowFileWrite, *allowExec, *allowScreen, *allowAccessibility, *allowComputer = true, true, true, true, true
	}
	// Profiles provide a baseline; capability flags explicitly supplied to
	// setup remain the final operator choice.
	if flagWasSet(fs, "allow-file-write") {
		*allowFileWrite = explicitFileWrite
	}
	if flagWasSet(fs, "allow-exec") {
		*allowExec = explicitExec
	}
	if flagWasSet(fs, "allow-screen") {
		*allowScreen = explicitScreen
	}
	if flagWasSet(fs, "allow-accessibility") {
		*allowAccessibility = explicitAccessibility
	}
	if flagWasSet(fs, "allow-computer-use") {
		*allowComputer = explicitComputer
	}
	if *allowComputer {
		*allowScreen, *allowAccessibility = true, true
	}
	if *allowExec && (*profile == "read-write" || *profile == "all") && runtime.GOOS == "linux" && !flagWasSet(fs, "exec-sandbox") && strings.EqualFold(strings.TrimSpace(*execSandbox), "none") {
		*execSandbox = "landlock"
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
	for i, root := range *roots {
		normalized, err := normalizeExistingDirectory(root)
		if err != nil {
			return fmt.Errorf("invalid --root %q: %w", root, err)
		}
		(*roots)[i] = normalized
	}
	var err error
	*stateDir, err = normalizeUserPath(*stateDir)
	if err != nil {
		return fmt.Errorf("invalid --state-dir: %w", err)
	}
	if strings.TrimSpace(*identityPath) == "" {
		*identityPath = deviceidentity.DefaultPath(*stateDir)
	}
	*identityPath, err = normalizeUserPath(*identityPath)
	if err != nil {
		return fmt.Errorf("invalid --identity: %w", err)
	}
	identity, createdIdentity, err := deviceidentity.LoadOrCreate(*identityPath)
	if err != nil {
		return fmt.Errorf("load or create device identity: %w", err)
	}
	derivedDeviceID := identity.ID()
	if requestedDeviceID != "" && requestedDeviceID != derivedDeviceID {
		return fmt.Errorf("--device-id %s does not match the Ed25519 device identity %s; device IDs are cryptographically derived and cannot be reassigned", requestedDeviceID, derivedDeviceID)
	}
	*deviceID = derivedDeviceID
	manager := &oauthclient.Manager{RelayURL: strings.TrimSpace(*relayURL), Device: strings.TrimSpace(*device), DeviceID: *deviceID, DeviceIdentity: identity}
	if _, err := manager.Resource(); err != nil {
		return fmt.Errorf("invalid --relay: %w", err)
	}
	*configPath, err = normalizeUserPath(*configPath)
	if err != nil {
		return fmt.Errorf("invalid --config: %w", err)
	}
	if strings.TrimSpace(*killSwitchPath) != "" {
		*killSwitchPath, err = normalizeUserPath(*killSwitchPath)
		if err != nil {
			return fmt.Errorf("invalid --kill-switch-file: %w", err)
		}
	}
	values := map[string]any{
		"agent.relay_url":           strings.TrimSpace(*relayURL),
		"agent.device":              strings.TrimSpace(*device),
		"agent.device_id":           strings.TrimSpace(*deviceID),
		"agent.root":                append([]string(nil), *roots...),
		"agent.profile":             strings.ToLower(strings.TrimSpace(*profile)),
		"agent.state_dir":           strings.TrimSpace(*stateDir),
		"agent.identity":            strings.TrimSpace(*identityPath),
		"agent.allow_file_write":    *allowFileWrite,
		"agent.allow_exec":          *allowExec,
		"agent.exec_sandbox":        strings.ToLower(strings.TrimSpace(*execSandbox)),
		"agent.allow_screen":        *allowScreen,
		"agent.allow_accessibility": *allowAccessibility,
		"agent.allow_computer_use":  *allowComputer,
		"agent.computer_persist":    strings.TrimSpace(*computerPersist),
		"agent.max_active_tasks":    *maxActiveTasks,
		"agent.kill_switch_file":    strings.TrimSpace(*killSwitchPath),
		"agent.credentials":         oauthclient.DefaultCredentialsPath(),
	}
	if err := writeConfigFile(*configPath, values, *force); err != nil {
		return fmt.Errorf("write agent config: %w", err)
	}
	base := strings.TrimRight(*relayURL, "/")
	fmt.Printf("Agent configuration written to %s\n\n", *configPath)
	fmt.Printf("Device name: %s\nImmutable device ID: %s\nDevice identity: %s%s\nAccount MCP endpoint: %s/mcp\nDevice-pinned MCP endpoint: %s/mcp/id/%s\n", *device, *deviceID, *identityPath, map[bool]string{true: " (created)", false: ""}[createdIdentity], base, base, *deviceID)
	fmt.Println("Filesystem roots exposed to MCP read tools:")
	home, _ := os.UserHomeDir()
	for _, root := range *roots {
		fmt.Printf("  - %s\n", root)
		if root == string(filepath.Separator) || (home != "" && filepath.Clean(root) == filepath.Clean(home)) {
			fmt.Fprintln(os.Stderr, "WARNING: this root exposes a broad filesystem area. Prefer a dedicated workspace directory unless broad read access is intentional.")
		}
	}
	fmt.Printf("\nNext step:\n  Connect this workstation (OAuth opens automatically when needed):\n     chat-with-cli connect --config %s\n", *configPath)
	if *installSystemd {
		if *unitPath == "" {
			*unitPath = filepath.Join(userConfigDir(), "systemd", "user", "chat-with-cli-agent.service")
		}
		*unitPath, err = normalizeUserPath(*unitPath)
		if err != nil {
			return fmt.Errorf("invalid --unit: %w", err)
		}
		if strings.TrimSpace(*binaryPath) == "" {
			*binaryPath, err = os.Executable()
			if err != nil {
				return fmt.Errorf("resolve current chat-with-cli binary: %w", err)
			}
		}
		*binaryPath, err = normalizeExistingFile(*binaryPath)
		if err != nil {
			return fmt.Errorf("invalid --binary: %w", err)
		}
		readWritePaths := []string{*stateDir, filepath.Dir(oauthclient.DefaultCredentialsPath())}
		if *allowFileWrite {
			readWritePaths = append(readWritePaths, (*roots)...)
		}
		seenPaths := map[string]bool{}
		var writable strings.Builder
		for _, path := range readWritePaths {
			path = strings.TrimSpace(path)
			if path == "" || seenPaths[path] {
				continue
			}
			seenPaths[path] = true
			fmt.Fprintf(&writable, "ReadWritePaths=%s\n", systemdQuote(path))
		}
		memoryHardening := "MemoryDenyWriteExecute=true\n"
		if *allowExec {
			// JIT runtimes and development toolchains commonly need executable
			// mappings. Landlock remains the filesystem boundary for Developer.
			memoryHardening = ""
		}
		unit := fmt.Sprintf(`[Unit]
Description=Chat with CLI Agent
After=graphical-session.target

[Service]
ExecStart=%s agent --config %s
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
%sRestrictSUIDSGID=true
LockPersonality=true
%s
[Install]
WantedBy=default.target
`, systemdQuote(*binaryPath), systemdQuote(*configPath), writable.String(), memoryHardening)
		if err := writeTextFile(*unitPath, unit, 0o600, *force); err != nil {
			return fmt.Errorf("write systemd user unit: %w", err)
		}
		fmt.Printf("  2. Review the generated systemd user unit:\n     %s\n", *unitPath)
		fmt.Println("  3. After OAuth and review, start it explicitly:")
		fmt.Println("     systemctl --user daemon-reload && systemctl --user enable --now chat-with-cli-agent.service")
	} else {
		fmt.Printf("  The interactive connect command runs in the foreground; Ctrl+C disconnects it.\n")
	}
	fmt.Println("\nRun `chat-with-cli doctor` after the Agent is connected. Setup never starts the Agent automatically.")
	return nil
}

func normalizeUserPath(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("path must not be empty")
	}
	if value == "~" || strings.HasPrefix(value, "~/") {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", errors.New("cannot resolve home directory")
		}
		if value == "~" {
			value = home
		} else {
			value = filepath.Join(home, strings.TrimPrefix(value, "~/"))
		}
	}
	return filepath.Abs(value)
}

func normalizeExistingDirectory(value string) (string, error) {
	path, err := normalizeUserPath(value)
	if err != nil {
		return "", err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("path is not a directory")
	}
	return filepath.Clean(path), nil
}

func normalizeExistingFile(value string) (string, error) {
	path, err := normalizeUserPath(value)
	if err != nil {
		return "", err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("path is not a regular file")
	}
	if info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("file is not executable")
	}
	return filepath.Clean(path), nil
}

func systemdQuote(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	value = strings.ReplaceAll(value, "%", "%%")
	return "\"" + value + "\""
}

func canonicalCapabilityProfile(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "r", "read-only", "readonly":
		return "read-only", true
	case "w", "read-write", "readwrite", "workspace", "developer":
		return "read-write", true
	case "d", "desktop", "desktop-computer-use", "computer-use":
		return "desktop-computer-use", true
	case "a", "all", "full":
		return "all", true
	case "c", "custom":
		return "custom", true
	default:
		return "", false
	}
}

func validCapabilityProfile(value string) bool {
	_, ok := canonicalCapabilityProfile(value)
	return ok
}

func runRelaySetup(args []string) error {
	fs := flag.NewFlagSet("relay setup", flag.ContinueOnError)
	configPath := fs.String("config", defaultRelayConfigPath(), "relay TOML configuration path")
	publicURL := fs.String("public-url", "", "public HTTPS origin")
	listen := fs.String("listen", "127.0.0.1:8765", "HTTP listen address")
	mode := fs.String("instance-mode", "private", "private or public")
	stateDir := fs.String("state-dir", defaultRelayStateDir(), "relay state directory")
	setupTokenFile := fs.String("setup-token-file", "", "one-time setup token path")
	adsenseClientID := fs.String("adsense-client-id", "", "optional Google AdSense publisher client ID")
	adsenseSlot := fs.String("adsense-slot", "", "optional Google AdSense responsive slot ID")
	admobAppID := fs.String("admob-app-id", "", "optional companion-app AdMob application ID")
	admobRewardUnitID := fs.String("admob-reward-unit-id", "", "optional companion-app AdMob rewarded-ad unit ID")
	usageUnlockEnabled := fs.Bool("usage-unlock-enabled", false, "enable the signed rewarded usage entitlement link")
	usageUnlockEndpoint := fs.String("usage-unlock-endpoint", "", "HTTPS companion-app/backend URL for verified usage entitlements")
	usageMeteringEnabled := fs.Bool("usage-metering-enabled", false, "enable per-account Relay payload quota metering")
	usageDefaultQuotaBytes := fs.Int64("usage-default-quota-bytes", 100<<20, "default per-account Relay quota in payload bytes")
	force := fs.Bool("force", false, "replace existing config/token after symlink checks")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var endpointErr error
	*usageUnlockEndpoint, endpointErr = normalizeUsageUnlockEndpoint(*usageUnlockEndpoint)
	if endpointErr != nil {
		return fmt.Errorf("invalid usage unlock endpoint: %w", endpointErr)
	}
	if *usageUnlockEnabled && *usageUnlockEndpoint == "" {
		return errors.New("--usage-unlock-enabled requires --usage-unlock-endpoint")
	}
	if *usageDefaultQuotaBytes < 0 {
		return errors.New("--usage-default-quota-bytes must not be negative")
	}
	if strings.TrimSpace(*publicURL) == "" {
		return errors.New("--public-url is required, for example https://relay.example.com")
	}
	base, err := normalizeDiagnosticURL(*publicURL)
	if err != nil {
		return fmt.Errorf("invalid --public-url: %w", err)
	}
	*publicURL = base
	if strings.EqualFold(strings.TrimSpace(*mode), oauthserver.ModePublic) {
		*mode = oauthserver.ModePublic
	} else if strings.EqualFold(strings.TrimSpace(*mode), oauthserver.ModePrivate) {
		*mode = oauthserver.ModePrivate
	} else {
		return fmt.Errorf("invalid instance mode %q", *mode)
	}
	*stateDir, err = normalizeUserPath(*stateDir)
	if err != nil {
		return fmt.Errorf("invalid --state-dir: %w", err)
	}
	*configPath, err = normalizeUserPath(*configPath)
	if err != nil {
		return fmt.Errorf("invalid --config: %w", err)
	}
	if strings.TrimSpace(*setupTokenFile) == "" {
		*setupTokenFile = defaultSetupTokenPath(*stateDir)
	}
	*setupTokenFile, err = normalizeUserPath(*setupTokenFile)
	if err != nil {
		return fmt.Errorf("invalid --setup-token-file: %w", err)
	}
	existingToken, err := readPrivateCredential(*setupTokenFile)
	if err != nil {
		return fmt.Errorf("read setup token: %w", err)
	}
	if existingToken == "" {
		if err := writeTextFile(*setupTokenFile, protocol.NewID()+protocol.NewID()+"\n", 0o600, *force); err != nil {
			return fmt.Errorf("write setup token: %w", err)
		}
	}
	values := map[string]any{
		"relay.public_url":                  *publicURL,
		"relay.listen":                      strings.TrimSpace(*listen),
		"relay.instance_mode":               strings.TrimSpace(*mode),
		"relay.state_dir":                   *stateDir,
		"relay.setup_token_file":            *setupTokenFile,
		"relay.disable_registration":        false,
		"relay.allow_legacy_unbound_agents": false,
		"relay.adsense_client_id":           strings.TrimSpace(*adsenseClientID),
		"relay.adsense_slot":                strings.TrimSpace(*adsenseSlot),
		"relay.admob_app_id":                strings.TrimSpace(*admobAppID),
		"relay.admob_reward_unit_id":        strings.TrimSpace(*admobRewardUnitID),
		"relay.usage_unlock_enabled":        *usageUnlockEnabled,
		"relay.usage_unlock_endpoint":       strings.TrimSpace(*usageUnlockEndpoint),
		"relay.usage_metering_enabled":      *usageMeteringEnabled,
		"relay.usage_default_quota_bytes":   *usageDefaultQuotaBytes,
	}
	if err := writeConfigFile(*configPath, values, *force); err != nil {
		return fmt.Errorf("write relay config: %w", err)
	}
	fmt.Printf("Relay configuration written to %s\n", *configPath)
	fmt.Printf("One-time setup token file: %s (the token itself is intentionally not printed)\n", *setupTokenFile)
	fmt.Printf("Local listener: %s\nPublic origin: %s\n\n", *listen, *publicURL)
	fmt.Println("Next steps:")
	fmt.Printf("  1. Put Caddy/Nginx/your HTTPS proxy in front of %s.\n", *listen)
	fmt.Printf("  2. Start the Relay: chat-with-cli relay --config %s\n", *configPath)
	fmt.Printf("  3. Read the setup token locally, then open %s/setup in your browser.\n", *publicURL)
	fmt.Printf("  4. After setup, sign in at %s/admin and review security controls before pairing a workstation.\n", *publicURL)
	return nil
}

func relaySystemdUnit(binary, configPath string) string {
	return fmt.Sprintf(`[Unit]
Description=chat-with-cli OAuth relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s relay --config %s
Restart=on-failure
RestartSec=2s
DynamicUser=yes
StateDirectory=chat-with-cli
StateDirectoryMode=0700
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
`, systemdQuote(binary), systemdQuote(configPath))
}

func runRelayInstall(args []string) error {
	fs := flag.NewFlagSet("relay install", flag.ContinueOnError)
	version := fs.String("version", "latest", "GitHub release tag or latest")
	prefix := fs.String("prefix", "/usr/local", "binary installation prefix")
	apply := fs.Bool("apply", false, "download, verify, and atomically install the release")
	writeSystemd := fs.Bool("write-systemd", false, "write a hardened relay systemd unit; never starts or enables it")
	forceSystemd := fs.Bool("force-systemd", false, "replace an existing relay systemd unit")
	unitPath := fs.String("unit", "/etc/systemd/system/chat-with-cli-relay.service", "systemd unit path")
	configPath := fs.String("config", "/etc/chat-with-cli/config.toml", "relay config path referenced by the unit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("relay installer supports Linux; detected %s", runtime.GOOS)
	}
	asset, err := releaseinstall.AssetName(runtime.GOARCH)
	if err != nil {
		return err
	}
	prefixPath, err := normalizeUserPath(*prefix)
	if err != nil {
		return err
	}
	destination := filepath.Join(prefixPath, "bin", "chat-with-cli")
	backup := destination + ".previous"
	if err := releaseinstall.Preflight(destination, backup); err != nil {
		return err
	}
	var unit, configFile string
	if *writeSystemd {
		unit, err = normalizeUserPath(*unitPath)
		if err != nil {
			return err
		}
		configFile, err = normalizeUserPath(*configPath)
		if err != nil {
			return err
		}
		if err := preflightTextFile(unit, *forceSystemd); err != nil {
			return fmt.Errorf("systemd unit preflight: %w", err)
		}
	}
	fmt.Printf("Release: %s\nRelease asset: %s\nDestination: %s\nRollback backup: %s\n", *version, asset, destination, backup)
	if !*apply {
		if strings.TrimSpace(*version) == "" || *version == "latest" {
			fmt.Println("Latest means the newest non-draft GitHub release, including prereleases; the exact tag is resolved only with --apply.")
		} else if _, sumsURL, assetURL, err := releaseinstall.GitHubReleaseURLs(*version, runtime.GOARCH); err == nil {
			fmt.Printf("SHA256SUMS: %s\nBinary URL: %s\n", sumsURL, assetURL)
		}
		fmt.Println("Review only: no network request or file change was made. Re-run with --apply to install.")
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client := releaseinstall.SecureHTTPClient()
	client.Timeout = 90 * time.Second
	resolvedVersion, err := releaseinstall.ResolveGitHubVersion(ctx, client, *version)
	if err != nil {
		return err
	}
	asset, sumsURL, assetURL, err := releaseinstall.GitHubReleaseURLs(resolvedVersion, runtime.GOARCH)
	if err != nil {
		return err
	}
	fmt.Printf("Resolved release: %s\n", resolvedVersion)
	binary, digest, err := releaseinstall.FetchVerified(ctx, client, sumsURL, assetURL, asset)
	if err != nil {
		return err
	}
	if err := releaseinstall.Install(destination, backup, binary); err != nil {
		return err
	}
	fmt.Printf("Installed %s (SHA256 %s).\n", destination, digest)
	if *writeSystemd {
		if err := writeTextFile(unit, relaySystemdUnit(destination, configFile), 0o644, *forceSystemd); err != nil {
			return fmt.Errorf("write relay systemd unit: %w", err)
		}
		fmt.Printf("Wrote %s. It was not enabled or started.\n", unit)
	}
	fmt.Println("Next: run `chat-with-cli relay setup`, review config/unit, then explicitly enable the service when ready.")
	return nil
}

func resolveUpdateBinary(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		path, err := os.Executable()
		if err != nil {
			return "", err
		}
		value = path
	}
	return normalizeExistingFile(value)
}

func runUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	version := fs.String("version", "latest", "GitHub release tag or latest")
	binaryFlag := fs.String("binary", "", "installed binary to replace; defaults to the current executable")
	apply := fs.Bool("apply", false, "download, verify, and atomically replace the binary")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("update supports Linux; detected %s", runtime.GOOS)
	}
	binaryPath, err := resolveUpdateBinary(*binaryFlag)
	if err != nil {
		return err
	}
	asset, err := releaseinstall.AssetName(runtime.GOARCH)
	if err != nil {
		return err
	}
	backup := binaryPath + ".previous"
	fmt.Printf("Update target: %s\nRelease: %s\nVerified asset: %s\nRollback backup: %s\n", binaryPath, *version, asset, backup)
	if !*apply {
		if strings.TrimSpace(*version) == "" || *version == "latest" {
			fmt.Println("Latest is resolved through the GitHub Releases API only when --apply is used.")
		} else if _, sumsURL, assetURL, err := releaseinstall.GitHubReleaseURLs(*version, runtime.GOARCH); err == nil {
			fmt.Printf("SHA256SUMS: %s\nBinary URL: %s\n", sumsURL, assetURL)
		}
		fmt.Println("Review only: no network request or file change was made. Re-run with --apply to update; services are never restarted automatically.")
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client := releaseinstall.SecureHTTPClient()
	client.Timeout = 90 * time.Second
	resolvedVersion, err := releaseinstall.ResolveGitHubVersion(ctx, client, *version)
	if err != nil {
		return err
	}
	asset, sumsURL, assetURL, err := releaseinstall.GitHubReleaseURLs(resolvedVersion, runtime.GOARCH)
	if err != nil {
		return err
	}
	fmt.Printf("Resolved release: %s\n", resolvedVersion)
	data, digest, err := releaseinstall.FetchVerified(ctx, client, sumsURL, assetURL, asset)
	if err != nil {
		return err
	}
	if err := releaseinstall.Install(binaryPath, backup, data); err != nil {
		return err
	}
	fmt.Printf("Updated %s (SHA256 %s). Existing services were not restarted.\n", binaryPath, digest)
	return nil
}

func runRollback(args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	binaryFlag := fs.String("binary", "", "installed binary to restore; defaults to the current executable")
	backupFlag := fs.String("backup", "", "verified local backup; defaults to <binary>.previous")
	apply := fs.Bool("apply", false, "restore the verified local backup")
	if err := fs.Parse(args); err != nil {
		return err
	}
	binaryPath, err := resolveUpdateBinary(*binaryFlag)
	if err != nil {
		return err
	}
	backup := strings.TrimSpace(*backupFlag)
	if backup == "" {
		backup = binaryPath + ".previous"
	} else if backup, err = normalizeUserPath(backup); err != nil {
		return err
	}
	fmt.Printf("Rollback target: %s\nVerified backup: %s\n", binaryPath, backup)
	if !*apply {
		fmt.Println("Review only: no files changed. Re-run with --apply to restore; services are never restarted automatically.")
		return nil
	}
	if err := releaseinstall.RestoreVerifiedBackup(binaryPath, backup); err != nil {
		return err
	}
	fmt.Printf("Restored %s from checksum-verified backup. Existing services were not restarted.\n", binaryPath)
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
	identityPath := values.String("", "agent.identity")
	identityState := "legacy-unbound"
	if identityPath != "" {
		identityState = "unreadable"
		if identity, err := deviceidentity.Load(identityPath); err == nil {
			configuredID, ok := protocol.NormalizeDeviceID(values.String("", "agent.device_id"))
			if ok && configuredID == identity.ID() {
				identityState = "bound"
			} else {
				identityState = "mismatch"
			}
		}
	}
	status := map[string]any{"config": *configPath, "relay": values.String(defaultPublicRelayURL, "agent.relay_url"), "device": values.String("", "agent.device"), "device_id": values.String("", "agent.device_id"), "device_identity": identityPath, "device_proof": identityState, "profile": values.String("read-only", "agent.profile"), "systemd_active": active, "systemd_enabled": enabled}
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
	relayURL := fs.String("relay", defaultPublicRelayURL, "Relay URL to inspect (defaults to the community public Relay)")
	device := fs.String("device", "", "legacy display-name route to inspect")
	deviceID := fs.String("device-id", "", "immutable device ID route to inspect")
	mcpToken := fs.String("mcp-token", "", "existing MCP bearer token for initialize/tools/list checks")
	configPath := fs.String("config", oauthclient.DefaultConfigPath(), "agent TOML configuration path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	values, err := config.LoadOptional(*configPath)
	if err != nil {
		return err
	}
	if !flagWasSet(fs, "relay") {
		*relayURL = values.String(*relayURL, "agent.relay_url")
	}
	if *device == "" {
		*device = values.String(*device, "agent.device")
	}
	if *deviceID == "" {
		*deviceID = values.String(*deviceID, "agent.device_id")
	}
	*mcpToken = envOr(*mcpToken, "CHAT_WITH_CLI_CLIENT_TOKEN")
	checks := localDoctorChecks(values)
	var deviceIdentity *deviceidentity.Identity
	if identityPath := values.String("", "agent.identity"); identityPath != "" {
		deviceIdentity, _ = deviceidentity.Load(identityPath)
	}
	if strings.TrimSpace(*relayURL) == "" {
		checks = append(checks, doctorCheck{Name: "Relay checks", Skip: true, Detail: ": provide --relay or agent.relay_url for network checks"})
		return reportDoctorChecks(checks)
	}
	base, err := normalizeDiagnosticURL(*relayURL)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	checks = append(checks, doctorHTTPCheck(context.Background(), client, "DNS/TLS and health", base+"/health", func(resp *http.Response) bool { return resp.StatusCode == http.StatusOK }))
	checks = append(checks, doctorHTTPCheck(context.Background(), client, "OAuth metadata", base+"/.well-known/oauth-authorization-server", func(resp *http.Response) bool {
		return resp.StatusCode == http.StatusOK && strings.Contains(resp.Header.Get("Content-Type"), "json")
	}))
	checks = append(checks, doctorHTTPCheck(context.Background(), client, "DCR endpoint", base+"/oauth/register", func(resp *http.Response) bool {
		// Probe with GET so doctor never creates a dynamic OAuth client. Go's
		// method-aware mux returns 405 with Allow: POST for a healthy endpoint.
		return resp.StatusCode == http.StatusMethodNotAllowed && strings.Contains(resp.Header.Get("Allow"), http.MethodPost)
	}))
	checks = append(checks, doctorHTTPCheck(context.Background(), client, "DCR device challenge endpoint", base+"/oauth/register/challenge", func(resp *http.Response) bool {
		return resp.StatusCode == http.StatusMethodNotAllowed && strings.Contains(resp.Header.Get("Allow"), http.MethodPost)
	}))
	route := strings.TrimSpace(*device)
	if strings.TrimSpace(*deviceID) != "" {
		canonicalID, ok := protocol.NormalizeDeviceID(*deviceID)
		if !ok {
			return errors.New("invalid --device-id")
		}
		*deviceID = canonicalID
		route = "id/" + canonicalID
	}
	if route != "" {
		checks = append(checks, doctorHTTPCheck(context.Background(), client, "protected resource metadata", base+"/.well-known/oauth-protected-resource/agent/"+route, func(resp *http.Response) bool { return resp.StatusCode == http.StatusOK }))
		checks = append(checks, doctorHTTPCheck(context.Background(), client, "MCP challenge", base+"/mcp/"+route, func(resp *http.Response) bool {
			return resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusServiceUnavailable
		}))
		resource := base + "/agent/" + route
		credentialsPath := values.String(oauthclient.DefaultCredentialsPath(), "agent.credentials")
		credential, found, credentialErr := oauthclient.LoadCredential(credentialsPath, resource)
		if credentialErr != nil {
			checks = append(checks, doctorCheck{Name: "saved Agent credential", Detail: ": " + credentialErr.Error()})
		} else if !found {
			checks = append(checks, doctorCheck{Name: "saved Agent credential", Skip: true, Detail: ": no saved credential for this device; run `chat-with-cli connect` and OAuth will open automatically"})
		} else if credential.AccessToken == "" || credential.ExpiresAt <= time.Now().Unix() {
			checks = append(checks, doctorCheck{Name: "saved Agent credential", Detail: ": access token is missing or expired"})
		} else {
			checks = append(checks, doctorCheck{Name: "saved Agent credential", OK: true, Detail: ": access token is unexpired (bearer value withheld)"})
			checks = append(checks, doctorAgentConnectionCheck(context.Background(), base, route, credential.AccessToken, deviceIdentity))
		}
		if strings.TrimSpace(*mcpToken) != "" {
			checks = append(checks, doctorMCPCheck(context.Background(), client, base+"/mcp/"+route, *mcpToken, "MCP initialize"))
			checks = append(checks, doctorMCPToolsCheck(context.Background(), client, base+"/mcp/"+route, *mcpToken))
		} else {
			checks = append(checks, doctorCheck{Name: "MCP initialize/tools/list", Skip: true, Detail: ": provide --mcp-token; Agent tokens are scoped to /agent, not /mcp"})
		}
	} else {
		checks = append(checks, doctorCheck{Name: "Agent connection", Skip: true, Detail: ": provide --device or --device-id"})
		checks = append(checks, doctorCheck{Name: "MCP initialize/tools/list", Skip: true, Detail: ": provide a device route and --mcp-token"})
	}
	return reportDoctorChecks(checks)
}

func reportDoctorChecks(checks []doctorCheck) error {
	failed := 0
	for _, check := range checks {
		if check.Skip {
			fmt.Printf("SKIP  %s%s\n", check.Name, check.Detail)
		} else if check.OK {
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
	Skip   bool
	Detail string
}

func localDoctorChecks(values config.Values) []doctorCheck {
	checks := make([]doctorCheck, 0, 9)
	roots := values.Strings("agent.root")
	if len(roots) == 0 {
		if cwd, err := os.Getwd(); err == nil {
			roots = []string{cwd}
		}
	}
	if len(roots) == 0 {
		checks = append(checks, doctorCheck{Name: "filesystem root", Detail: ": current directory is unavailable"})
	} else {
		for i, root := range roots {
			info, err := os.Stat(root)
			if err != nil || !info.IsDir() {
				checks = append(checks, doctorCheck{Name: fmt.Sprintf("filesystem root %d", i+1), Detail: fmt.Sprintf(": %s is not a readable directory", root)})
				continue
			}
			checks = append(checks, doctorCheck{Name: fmt.Sprintf("filesystem root %d", i+1), OK: true, Detail: ": " + root})
		}
	}

	identityPath := values.String("", "agent.identity")
	configuredDeviceID := values.String("", "agent.device_id")
	if identityPath == "" {
		checks = append(checks, doctorCheck{Name: "device proof identity", Skip: true, Detail: ": legacy Agent has no Ed25519 identity; rerun agent setup/login to migrate"})
	} else {
		identity, err := deviceidentity.Load(identityPath)
		if err != nil {
			checks = append(checks, doctorCheck{Name: "device proof identity", Detail: ": " + err.Error()})
		} else if canonicalID, ok := protocol.NormalizeDeviceID(configuredDeviceID); !ok || canonicalID != identity.ID() {
			checks = append(checks, doctorCheck{Name: "device proof identity", Detail: ": configured immutable device ID does not match the Ed25519 identity"})
		} else {
			checks = append(checks, doctorCheck{Name: "device proof identity", OK: true, Detail: ": Ed25519 identity matches immutable device ID"})
		}
	}

	screen := values.Bool(false, "agent.allow_screen")
	accessibility := values.Bool(false, "agent.allow_accessibility")
	computer := values.Bool(false, "agent.allow_computer_use")
	gui := screen || accessibility || computer
	if !gui {
		for _, name := range []string{"desktop display", "session D-Bus", "AT-SPI", "screenshot backend"} {
			checks = append(checks, doctorCheck{Name: name, Skip: true, Detail: ": GUI capabilities are disabled"})
		}
	} else {
		display := strings.TrimSpace(os.Getenv("WAYLAND_DISPLAY"))
		if display == "" {
			display = strings.TrimSpace(os.Getenv("DISPLAY"))
		}
		if display == "" {
			checks = append(checks, doctorCheck{Name: "desktop display", Detail: ": WAYLAND_DISPLAY/DISPLAY is unset"})
		} else {
			checks = append(checks, doctorCheck{Name: "desktop display", OK: true, Detail: ": " + display})
		}
		if strings.TrimSpace(os.Getenv("DBUS_SESSION_BUS_ADDRESS")) == "" && strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")) == "" {
			checks = append(checks, doctorCheck{Name: "session D-Bus", Detail: ": DBUS_SESSION_BUS_ADDRESS and XDG_RUNTIME_DIR are unset"})
		} else {
			checks = append(checks, doctorCheck{Name: "session D-Bus", OK: true, Detail: ": session environment detected"})
		}
		if accessibility || computer {
			checks = append(checks, desktopBusDoctorCheck("AT-SPI", "org.a11y.Bus", "/org/a11y/bus"))
		} else {
			checks = append(checks, doctorCheck{Name: "AT-SPI", Skip: true, Detail: ": accessibility reads are disabled"})
		}
		if screen || computer {
			if backend := firstCommand("spectacle", "grim", "gnome-screenshot", "import"); backend == "" {
				checks = append(checks, doctorCheck{Name: "screenshot backend", Detail: ": spectacle, grim, gnome-screenshot, or import not found"})
			} else {
				checks = append(checks, doctorCheck{Name: "screenshot backend", OK: true, Detail: ": " + backend})
			}
		} else {
			checks = append(checks, doctorCheck{Name: "screenshot backend", Skip: true, Detail: ": screenshots are disabled"})
		}
	}
	if computer {
		checks = append(checks, desktopBusDoctorCheck("Desktop portal", "org.freedesktop.portal.Desktop", "/org/freedesktop/portal/desktop"))
		if backend := firstCommand("wdotool", "xdotool"); backend == "" {
			checks = append(checks, doctorCheck{Name: "input fallback", Skip: true, Detail: ": native portal input is preferred; no CLI fallback found"})
		} else {
			checks = append(checks, doctorCheck{Name: "input fallback", OK: true, Detail: ": " + backend})
		}
	} else {
		checks = append(checks, doctorCheck{Name: "Desktop portal", Skip: true, Detail: ": computer input is disabled"})
	}
	unitPath := filepath.Join(userConfigDir(), "systemd", "user", "chat-with-cli-agent.service")
	if info, err := os.Stat(unitPath); err == nil && info.Mode().IsRegular() {
		active, enabled := systemdUserState("chat-with-cli-agent.service")
		checks = append(checks, doctorCheck{Name: "systemd user unit", OK: true, Detail: fmt.Sprintf(": installed (active=%v enabled=%v)", active, enabled)})
	} else {
		checks = append(checks, doctorCheck{Name: "systemd user unit", Skip: true, Detail: ": not installed; setup can write one without enabling it"})
	}
	checks = append(checks, doctorCheck{Name: "version compatibility", Skip: true, Detail: ": remote Agent/MCP versions are checked after a live connection"})
	return checks
}

func firstCommand(names ...string) string {
	for _, name := range names {
		if _, err := exec.LookPath(name); err == nil {
			return name
		}
	}
	return ""
}

func desktopBusDoctorCheck(name, service, objectPath string) doctorCheck {
	if _, err := exec.LookPath("busctl"); err != nil {
		return doctorCheck{Name: name, Detail: ": busctl is unavailable"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "busctl", "--user", "--no-pager", "--timeout=2s", "call", service, objectPath, "org.freedesktop.DBus.Peer", "Ping")
	if err := cmd.Run(); err != nil {
		return doctorCheck{Name: name, Detail: ": session bus ping failed"}
	}
	return doctorCheck{Name: name, OK: true, Detail: ": session bus service responded"}
}

func doctorAgentConnectionCheck(ctx context.Context, base, route, token string, identity *deviceidentity.Identity) doctorCheck {
	resource := strings.TrimRight(base, "/") + "/agent/" + route
	target := resource + "?probe=1"
	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, target, nil)
	if err != nil {
		return doctorCheck{Name: "Agent connection", Detail: ": " + err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if identity != nil {
		challengeReq, err := http.NewRequestWithContext(probeCtx, http.MethodGet, resource+"/challenge", nil)
		if err != nil {
			return doctorCheck{Name: "Agent connection", Detail: ": build device challenge request failed"}
		}
		challengeReq.Header.Set("Authorization", "Bearer "+token)
		challengeResp, err := client.Do(challengeReq)
		if err != nil {
			return doctorCheck{Name: "Agent connection", Detail: ": device challenge failed: " + redactDiagnosticError(err)}
		}
		if challengeResp.Header.Get("cf-mitigated") == "challenge" {
			challengeResp.Body.Close()
			return doctorCheck{Name: "Agent connection", Detail: ": Cloudflare Managed Challenge"}
		}
		if challengeResp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, io.LimitReader(challengeResp.Body, 64<<10))
			challengeResp.Body.Close()
			return doctorCheck{Name: "Agent connection", Detail: fmt.Sprintf(": device challenge returned HTTP %d", challengeResp.StatusCode)}
		}
		var challengePayload struct {
			Challenge string `json:"challenge"`
			ExpiresIn int    `json:"expires_in"`
		}
		err = json.NewDecoder(io.LimitReader(challengeResp.Body, 4096)).Decode(&challengePayload)
		challengeResp.Body.Close()
		if err != nil || challengePayload.Challenge == "" {
			return doctorCheck{Name: "Agent connection", Detail: ": invalid device challenge response"}
		}
		proof, err := identity.SignProof(resource, token, challengePayload.Challenge)
		if err != nil {
			return doctorCheck{Name: "Agent connection", Detail: ": failed to sign device challenge"}
		}
		req.Header.Set(deviceidentity.HeaderChallenge, challengePayload.Challenge)
		req.Header.Set(deviceidentity.HeaderProof, proof)
	}
	resp, err := client.Do(req)
	if err != nil {
		return doctorCheck{Name: "Agent connection", Detail: ": " + redactDiagnosticError(err)}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.Header.Get("cf-mitigated") == "challenge" {
		return doctorCheck{Name: "Agent connection", Detail: ": Cloudflare Managed Challenge"}
	}
	switch resp.StatusCode {
	case http.StatusNoContent:
		return doctorCheck{Name: "Agent connection", OK: true, Detail: ": authorized Agent is online"}
	case http.StatusServiceUnavailable:
		return doctorCheck{Name: "Agent connection", Detail: ": credential accepted but device is offline or disabled"}
	case http.StatusUnauthorized:
		return doctorCheck{Name: "Agent connection", Detail: ": saved Agent credential or device proof is not authorized"}
	default:
		return doctorCheck{Name: "Agent connection", Detail: fmt.Sprintf(": unexpected HTTP %d", resp.StatusCode)}
	}
}

func doctorMCPCheck(ctx context.Context, client *http.Client, target, token, name string) doctorCheck {
	response, err := doctorMCPRequest(ctx, client, target, token, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{
			"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "chat-with-cli-doctor", "version": mcpserver.Version},
		},
	})
	if err != nil {
		return doctorCheck{Name: name, Detail: ": " + err.Error()}
	}
	if _, ok := response["result"]; !ok {
		return doctorCheck{Name: name, Detail: ": initialize response has no result"}
	}
	return doctorCheck{Name: name, OK: true, Detail: ": MCP initialize succeeded"}
}

func doctorMCPToolsCheck(ctx context.Context, client *http.Client, target, token string) doctorCheck {
	response, err := doctorMCPRequest(ctx, client, target, token, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": map[string]any{}})
	if err != nil {
		return doctorCheck{Name: "MCP tools/list", Detail: ": " + err.Error()}
	}
	result, ok := response["result"].(map[string]any)
	if !ok {
		return doctorCheck{Name: "MCP tools/list", Detail: ": tools/list response has no result"}
	}
	tools, ok := result["tools"].([]any)
	if !ok {
		return doctorCheck{Name: "MCP tools/list", Detail: ": response has no tools array"}
	}
	return doctorCheck{Name: "MCP tools/list", OK: true, Detail: fmt.Sprintf(": %d tools advertised", len(tools))}
}

func doctorMCPRequest(ctx context.Context, client *http.Client, target, token string, message map[string]any) (map[string]any, error) {
	body, err := json.Marshal(message)
	if err != nil {
		return nil, errors.New("failed to encode MCP probe")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New(redactDiagnosticError(err))
	}
	defer resp.Body.Close()
	if resp.Header.Get("cf-mitigated") == "challenge" {
		return nil, errors.New("Cloudflare Managed Challenge; review Browser Integrity Check/Bot Fight Mode/Super Bot Fight Mode")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if contentType := resp.Header.Get("Content-Type"); strings.Contains(contentType, "text/event-stream") {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "data:") {
				data = []byte(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
				break
			}
		}
	}
	var response map[string]any
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, errors.New("invalid MCP JSON response")
	}
	if _, ok := response["error"].(map[string]any); ok {
		// The remote endpoint controls this string and may reflect bearer
		// credentials, tool arguments, or file content. Diagnostics must never
		// print a server-supplied JSON-RPC error verbatim.
		return nil, errors.New("MCP returned a JSON-RPC error")
	}
	return response, nil
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
		return "", errors.New("invalid relay URL; use HTTPS or loopback HTTP without a path/query")
	}
	if u.Path != "" && u.Path != "/" {
		return "", errors.New("relay URL must be an origin without a path")
	}
	u.Path = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func redactDiagnosticError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "request timed out"
	}
	if errors.Is(err, context.Canceled) {
		return "request canceled"
	}
	// Network/client errors frequently include the complete request URL. Do
	// not echo that string: diagnostic requests may carry OAuth query values.
	return "network request failed"
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

func preflightTextFile(path string, force bool) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing to write through symlink")
		}
		if !info.Mode().IsRegular() {
			return errors.New("refusing to replace a non-regular file")
		}
		if !force {
			return fmt.Errorf("file already exists: %s", path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func writeTextFile(path, content string, mode os.FileMode, force bool) error {
	if err := preflightTextFile(path, force); err != nil {
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
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = dir.Sync()
	_ = dir.Close()
	return err
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
