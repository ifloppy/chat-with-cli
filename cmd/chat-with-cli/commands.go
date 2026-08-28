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

	"github.com/coder/websocket"
	"github.com/ifloppy/chat-with-cli/internal/config"
	"github.com/ifloppy/chat-with-cli/internal/mcpserver"
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
	mcpToken := fs.String("mcp-token", "", "existing MCP bearer token for initialize/tools/list checks")
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
	*mcpToken = envOr(*mcpToken, "CHAT_WITH_CLI_CLIENT_TOKEN")
	checks := localDoctorChecks(values)
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
		resource := base + "/agent/" + route
		credentialsPath := values.String(oauthclient.DefaultCredentialsPath(), "agent.credentials")
		credential, found, credentialErr := oauthclient.LoadCredential(credentialsPath, resource)
		if credentialErr != nil {
			checks = append(checks, doctorCheck{Name: "saved Agent credential", Detail: ": " + credentialErr.Error()})
		} else if !found {
			checks = append(checks, doctorCheck{Name: "saved Agent credential", Skip: true, Detail: ": no saved credential for this device; run login first"})
		} else if credential.AccessToken == "" || credential.ExpiresAt <= time.Now().Unix() {
			checks = append(checks, doctorCheck{Name: "saved Agent credential", Detail: ": access token is missing or expired"})
		} else {
			checks = append(checks, doctorCheck{Name: "saved Agent credential", OK: true, Detail: ": access token is unexpired (bearer value withheld)"})
			checks = append(checks, doctorAgentConnectionCheck(context.Background(), base, route, credential.AccessToken))
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

	gui := values.Bool(false, "agent.allow_screen") || values.Bool(false, "agent.allow_computer_use")
	computer := values.Bool(false, "agent.allow_computer_use")
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
		checks = append(checks, desktopBusDoctorCheck("AT-SPI", "org.a11y.Bus", "/org/a11y/bus"))
		if backend := firstCommand("spectacle", "grim", "gnome-screenshot", "import"); backend == "" {
			checks = append(checks, doctorCheck{Name: "screenshot backend", Detail: ": spectacle, grim, gnome-screenshot, or import not found"})
		} else {
			checks = append(checks, doctorCheck{Name: "screenshot backend", OK: true, Detail: ": " + backend})
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

func doctorAgentConnectionCheck(ctx context.Context, base, route, token string) doctorCheck {
	u, err := url.Parse(base)
	if err != nil {
		return doctorCheck{Name: "Agent connection", Detail: ": " + err.Error()}
	}
	if u.Scheme == "http" {
		u.Scheme = "ws"
	} else {
		u.Scheme = "wss"
	}
	u.Path = "/agent/" + route
	u.RawQuery = ""
	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(connectCtx, u.String(), &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}}})
	if err != nil {
		return doctorCheck{Name: "Agent connection", Detail: ": " + redactDiagnosticError(err)}
	}
	defer conn.Close(websocket.StatusNormalClosure, "doctor complete")
	conn.SetReadLimit(1 << 20)
	request := protocol.Request{ID: protocol.NewID(), Method: "system_info", Args: json.RawMessage(`{}`)}
	data, err := json.Marshal(request)
	if err != nil {
		return doctorCheck{Name: "Agent connection", Detail: ": failed to encode probe"}
	}
	if err := conn.Write(connectCtx, websocket.MessageText, data); err != nil {
		return doctorCheck{Name: "Agent connection", Detail: ": probe write failed"}
	}
	_, responseData, err := conn.Read(connectCtx)
	if err != nil {
		return doctorCheck{Name: "Agent connection", Detail: ": probe read failed"}
	}
	var response protocol.Response
	if err := json.Unmarshal(responseData, &response); err != nil || response.ID != request.ID {
		return doctorCheck{Name: "Agent connection", Detail: ": invalid Agent probe response"}
	}
	if response.Error != "" {
		return doctorCheck{Name: "Agent connection", Detail: ": Agent probe failed: " + response.Error}
	}
	return doctorCheck{Name: "Agent connection", OK: true, Detail: ": system_info probe succeeded"}
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
	if rpcError, ok := response["error"].(map[string]any); ok {
		if message, ok := rpcError["message"].(string); ok {
			return nil, errors.New(message)
		}
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
		if !info.Mode().IsRegular() {
			return errors.New("refusing to replace a non-regular file")
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
