package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ifloppy/chat-with-cli/internal/agent"
	"github.com/ifloppy/chat-with-cli/internal/config"
	"github.com/ifloppy/chat-with-cli/internal/deviceidentity"
	"github.com/ifloppy/chat-with-cli/internal/engine"
	"github.com/ifloppy/chat-with-cli/internal/execsandbox"
	"github.com/ifloppy/chat-with-cli/internal/mcpserver"
	"github.com/ifloppy/chat-with-cli/internal/oauthclient"
	"github.com/ifloppy/chat-with-cli/internal/oauthserver"
	"github.com/ifloppy/chat-with-cli/internal/protocol"
	"github.com/ifloppy/chat-with-cli/internal/relay"
	"github.com/ifloppy/chat-with-cli/internal/securefile"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "local":
		err = runLocal(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
	case "relay":
		if len(os.Args) > 2 && os.Args[2] == "setup" {
			err = runRelaySetup(os.Args[3:])
		} else if len(os.Args) > 2 && os.Args[2] == "install" {
			err = runRelayInstall(os.Args[3:])
		} else {
			err = runRelay(os.Args[2:])
		}
	case "agent":
		if len(os.Args) > 2 && os.Args[2] == "setup" {
			err = runAgentSetup(os.Args[3:])
		} else {
			err = runAgent(os.Args[2:])
		}
	case "connect":
		err = runConnect(os.Args[2:])
	case "doctor":
		err = runDoctor(os.Args[2:])
	case "status":
		err = runStatus(os.Args[2:])
	case "update":
		err = runUpdate(os.Args[2:])
	case "rollback":
		err = runRollback(os.Args[2:])
	case "login":
		err = runLogin(os.Args[2:])
	case "token":
		fmt.Println(protocol.NewID() + protocol.NewID())
	case "exec-sandbox":
		err = runExecSandbox(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println(mcpserver.Version)
	case "help", "--help", "-h":
		usage()
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		log.Printf("error: %v", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `chat-with-cli - open-source MCP remote development bridge

Usage:
  chat-with-cli local [flags]   Run MCP over stdio on this machine
  chat-with-cli serve [flags]   Run direct Streamable HTTP MCP on this machine
  chat-with-cli relay [flags]   Run the public relay/MCP gateway
  chat-with-cli relay setup     Create relay config and one-time setup token
  chat-with-cli relay install   Review or apply a checksum-verified binary install
  chat-with-cli connect         Recommended interactive connect; OAuth is automatic
  chat-with-cli agent [flags]   Connect this machine outbound to a relay
  chat-with-cli agent setup     Create agent config and optional user unit
  chat-with-cli login [flags]   Explicit browser OAuth login (normally unnecessary)
  chat-with-cli doctor [flags]  Check relay, OAuth, MCP, and local prerequisites
  chat-with-cli status          Show local configuration/service status
  chat-with-cli update          Review or apply a verified atomic binary update
  chat-with-cli rollback        Review or restore the verified previous binary
  chat-with-cli token           Generate a strong random token
  chat-with-cli version         Print version

	Security defaults: filesystem reads are restricted to --root values and all
		filesystem writes, shell execution, screenshots, accessibility reads, and input are disabled unless
		their capability flag is explicitly provided. Desktop screenshots and input are
		separately gated by --allow-screen, --allow-accessibility, and --allow-computer-use.
`)
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func runExecSandbox(args []string) error {
	fs := flag.NewFlagSet("exec-sandbox", flag.ContinueOnError)
	roots := new(stringList)
	fs.Var(roots, "root", "workspace root to expose to the child")
	allowWrite := fs.Bool("allow-write", false, "allow child writes inside workspace roots")
	tempDir := fs.String("temp-dir", "", "private writable temporary directory for write-enabled sandboxes")
	cwd := fs.String("cwd", "", "working directory to enter after applying the sandbox")
	if err := fs.Parse(args); err != nil {
		return err
	}
	command := fs.Args()
	if len(command) == 0 {
		return fmt.Errorf("exec-sandbox requires a command after --")
	}
	if err := execsandbox.Apply(*roots, *allowWrite, *tempDir); err != nil {
		return err
	}
	if strings.TrimSpace(*cwd) != "" {
		if err := os.Chdir(*cwd); err != nil {
			return fmt.Errorf("enter sandbox working directory: %w", err)
		}
		realCWD, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("verify sandbox working directory: %w", err)
		}
		inside := false
		for _, root := range *roots {
			realRoot, resolveErr := filepath.EvalSymlinks(root)
			if resolveErr != nil {
				continue
			}
			rel, relErr := filepath.Rel(realRoot, realCWD)
			if relErr == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				inside = true
				break
			}
		}
		if !inside {
			return fmt.Errorf("sandbox working directory escaped allowed roots")
		}
	}
	child := exec.Command(command[0], command[1:]...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	return child.Run()
}

func addEngineFlags(fs *flag.FlagSet) (*stringList, *string, *bool, *bool, *string, *bool, *bool, *bool, *string, *string, *string, *int) {
	roots := new(stringList)
	fs.Var(roots, "root", "allowed filesystem root (repeatable; defaults to current directory)")
	profile := fs.String("profile", "", "capability profile: read-only, developer, computer-use, or custom (individual flags apply when omitted)")
	allowFileWrite := fs.Bool("allow-file-write", false, "allow filesystem and checkpoint writes inside allowed roots")
	fs.BoolVar(allowFileWrite, "allow-fs-write", false, "alias for --allow-file-write")
	allowExec := fs.Bool("allow-exec", false, "allow arbitrary shell commands in PTY tasks")
	execSandbox := fs.String("exec-sandbox", "none", "exec boundary: none or landlock (Linux; only applies with --allow-exec)")
	allowScreen := fs.Bool("allow-screen", false, "allow read-only desktop screenshots")
	allowAccessibility := fs.Bool("allow-accessibility", false, "allow read-only AT-SPI accessibility inspection")
	allowComputer := fs.Bool("allow-computer-use", false, "allow screenshots, accessibility writes, and keyboard/mouse control")
	computerPersist := fs.String("computer-persist", "process", "portal permission persistence: none, process, or persistent")
	stateDir := fs.String("state-dir", defaultAgentStateDir(), "state directory for task logs and checkpoints")
	killSwitchPath := fs.String("kill-switch-file", "", "disable all Engine tools while this local file exists")
	maxActiveTasks := fs.Int("max-active-tasks", 32, "maximum concurrent PTY tasks")
	return roots, profile, allowFileWrite, allowExec, execSandbox, allowScreen, allowAccessibility, allowComputer, computerPersist, stateDir, killSwitchPath, maxActiveTasks
}

func applyCapabilityProfile(fs *flag.FlagSet, profile string, allowFileWrite, allowExec, allowScreen, allowAccessibility, allowComputer *bool) error {
	if !flagWasSet(fs, "profile") && strings.TrimSpace(profile) == "" {
		return nil
	}
	explicitFileWrite, explicitExec := *allowFileWrite, *allowExec
	explicitScreen, explicitAccessibility, explicitComputer := *allowScreen, *allowAccessibility, *allowComputer
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "read-only":
		*allowFileWrite, *allowExec, *allowScreen, *allowAccessibility, *allowComputer = false, false, false, false, false
	case "developer":
		*allowFileWrite, *allowExec, *allowScreen, *allowAccessibility, *allowComputer = true, true, false, false, false
	case "computer-use":
		*allowFileWrite, *allowExec, *allowScreen, *allowAccessibility, *allowComputer = false, false, true, true, true
	case "custom":
		return nil
	default:
		return fmt.Errorf("unknown capability profile %q", profile)
	}
	// A profile from TOML is a baseline. Any capability flag explicitly given
	// on the command line remains the final override, including an explicit
	// --allow-exec=false or --allow-fs-write=false.
	if flagWasSet(fs, "allow-file-write") || flagWasSet(fs, "allow-fs-write") {
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
	return nil
}

func applyExecSandboxDefault(fs *flag.FlagSet, profile string, allowExec bool, execSandbox *string) {
	if !allowExec || flagWasSet(fs, "exec-sandbox") {
		return
	}
	if strings.EqualFold(strings.TrimSpace(profile), "developer") && runtime.GOOS == "linux" && strings.EqualFold(strings.TrimSpace(*execSandbox), "none") {
		*execSandbox = "landlock"
	}
}

func newEngine(roots []string, allowFileWrite, allowExec bool, execSandbox string, allowScreen, allowAccessibility, allowComputer bool, computerPersist, stateDir, killSwitchPath string, protectedPaths []string, maxActiveTasks int) (*engine.Engine, error) {
	return engine.New(engine.Config{
		Roots: roots, AllowFileWrite: allowFileWrite, AllowExec: allowExec, ExecSandbox: execSandbox, AllowScreen: allowScreen || allowComputer,
		AllowAccessibility:   allowAccessibility || allowComputer,
		AllowComputerControl: allowComputer, ComputerPersistMode: computerPersist,
		StateDir: stateDir, KillSwitchPath: killSwitchPath, ProtectedPaths: protectedPaths, MaxReadBytes: 256 * 1024, MaxActiveTasks: maxActiveTasks,
	})
}

func runLocal(args []string) error {
	fs := flag.NewFlagSet("local", flag.ContinueOnError)
	roots, profile, allowFileWrite, allowExec, execSandbox, allowScreen, allowAccessibility, allowComputer, computerPersist, stateDir, killSwitchPath, maxActiveTasks := addEngineFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	applyKillSwitchDefault(stateDir, killSwitchPath)
	if err := applyCapabilityProfile(fs, *profile, allowFileWrite, allowExec, allowScreen, allowAccessibility, allowComputer); err != nil {
		return err
	}
	applyExecSandboxDefault(fs, *profile, *allowExec, execSandbox)
	eng, err := newEngine(*roots, *allowFileWrite, *allowExec, *execSandbox, *allowScreen, *allowAccessibility, *allowComputer, *computerPersist, *stateDir, *killSwitchPath, nil, *maxActiveTasks)
	if err != nil {
		return err
	}
	defer eng.Close()
	server := mcpserver.New(mcpserver.LocalCaller{Engine: eng})
	ctx, cancel := signalContext()
	defer cancel()
	return server.Run(ctx, &mcp.StdioTransport{})
}

func envOr(value, name string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return os.Getenv(name)
}

func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	roots, profile, allowFileWrite, allowExec, execSandbox, allowScreen, allowAccessibility, allowComputer, computerPersist, stateDir, killSwitchPath, maxActiveTasks := addEngineFlags(fs)
	listen := fs.String("listen", "127.0.0.1:8765", "HTTP listen address")
	token := fs.String("token", "", "optional bearer token (or CHAT_WITH_CLI_CLIENT_TOKEN)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	applyKillSwitchDefault(stateDir, killSwitchPath)
	if err := applyCapabilityProfile(fs, *profile, allowFileWrite, allowExec, allowScreen, allowAccessibility, allowComputer); err != nil {
		return err
	}
	*token = envOr(*token, "CHAT_WITH_CLI_CLIENT_TOKEN")
	if *token == "" && !loopbackListen(*listen) {
		return fmt.Errorf("refusing unauthenticated non-loopback listen %q", *listen)
	}
	applyExecSandboxDefault(fs, *profile, *allowExec, execSandbox)
	eng, err := newEngine(*roots, *allowFileWrite, *allowExec, *execSandbox, *allowScreen, *allowAccessibility, *allowComputer, *computerPersist, *stateDir, *killSwitchPath, nil, *maxActiveTasks)
	if err != nil {
		return err
	}
	defer eng.Close()
	server := mcpserver.New(mcpserver.LocalCaller{Engine: eng})
	var handler http.Handler = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true})
	handler = maxRequestBody(8<<20, handler)
	mux := http.NewServeMux()
	if *token == "" {
		// Unauthenticated direct MCP is an explicit loopback-only mode. Keep
		// this decision at the command boundary instead of teaching the shared
		// bearer middleware that an empty secret means "allow".
		mux.Handle("/mcp", handler)
	} else {
		mux.Handle("/mcp", bearerAuth(*token, handler))
	}
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("ok\n"))
	})
	ctx, cancel := signalContext()
	defer cancel()
	return serveHTTP(ctx, *listen, oauthserver.SecurityHeaders(mux))
}

func loopbackListen(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func envBool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func relayStreamableHTTPOptions(listen, publicURL string) *mcp.StreamableHTTPOptions {
	opts := &mcp.StreamableHTTPOptions{Stateless: true}
	listenHost, _, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil {
		return opts
	}
	listenIP := net.ParseIP(strings.Trim(listenHost, "[]"))
	listenLoopback := strings.EqualFold(listenHost, "localhost") || (listenIP != nil && listenIP.IsLoopback())
	public, err := url.Parse(strings.TrimSpace(publicURL))
	if err != nil || public.Hostname() == "" {
		return opts
	}
	publicHost := public.Hostname()
	publicIP := net.ParseIP(publicHost)
	publicLoopback := strings.EqualFold(publicHost, "localhost") || (publicIP != nil && publicIP.IsLoopback())
	// A loopback listener paired with a non-loopback public URL is the explicit
	// reverse-proxy topology supported by Relay. The SDK's automatic localhost
	// DNS-rebinding check otherwise rejects the proxy-preserved public Host.
	// Direct/local MCP serving paths keep the SDK default protection.
	if listenLoopback && !publicLoopback {
		opts.DisableLocalhostProtection = true
	}
	return opts
}

func mcpDiagnosticHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Body == nil {
			next.ServeHTTP(w, r)
			return
		}

		const inspectBytes = 16 << 10
		prefix, err := io.ReadAll(io.LimitReader(r.Body, inspectBytes))
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), r.Body))
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		var envelope struct {
			Method string `json:"method"`
		}
		if json.Unmarshal(prefix, &envelope) != nil || !diagnosticMCPMethod(envelope.Method) {
			next.ServeHTTP(w, r)
			return
		}

		recorder := &diagnosticResponseWriter{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		log.Printf("MCP discovery request: rpc_method=%s path=%s status=%d", envelope.Method, r.URL.Path, status)
	})
}

type diagnosticResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *diagnosticResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *diagnosticResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *diagnosticResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(data)
}

func diagnosticMCPMethod(method string) bool {
	switch method {
	case "initialize", "tools/list", "server/discover":
		return true
	default:
		return false
	}
}

func relayDeviceRoute(r *http.Request) string {
	if device := strings.TrimSpace(r.PathValue("device")); protocol.ValidDeviceName(device) {
		return device
	}
	if id, ok := protocol.NormalizeDeviceID(r.PathValue("id")); ok {
		return "id/" + id
	}
	return ""
}

func defaultAgentStateDir() string {
	if xdg := strings.TrimSpace(os.Getenv("XDG_STATE_HOME")); xdg != "" {
		return filepath.Join(xdg, "chat-with-cli")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "chat-with-cli")
}

func applyKillSwitchDefault(stateDir, killSwitchPath *string) {
	if strings.TrimSpace(*killSwitchPath) == "" && strings.TrimSpace(*stateDir) != "" {
		*killSwitchPath = filepath.Join(*stateDir, "PANIC")
	}
}

func defaultRelayStateDir() string {
	if xdg := strings.TrimSpace(os.Getenv("XDG_STATE_HOME")); xdg != "" {
		return filepath.Join(xdg, "chat-with-cli", "relay")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "chat-with-cli", "relay")
}

func defaultOwnerPasswordPath() string {
	if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
		return filepath.Join(xdg, "chat-with-cli", "private-owner-password")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "chat-with-cli", "private-owner-password")
}

func defaultSetupTokenPath(stateDir string) string {
	return filepath.Join(stateDir, "setup-token")
}

func readPrivateCredential(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("credential path must be a regular file, not a symlink")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("credential file permissions must not grant group or other access")
	}
	if err := securefile.CheckSingleLink(info, "credential file"); err != nil {
		return "", err
	}
	data, err := securefile.Read(path, "credential file")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func writePrivateCredential(path, value string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("credential path must be a regular file, not a symlink")
		}
		if err := securefile.CheckSingleLink(info, "credential file"); err != nil {
			return err
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".chat-with-cli-credential-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(value + "\n"); err != nil {
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

func runRelay(args []string) error {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8765", "HTTP listen address")
	mode := fs.String("instance-mode", oauthserver.ModePrivate, "instance mode: private or public")
	clientToken := fs.String("client-token", "", "legacy single-tenant MCP bearer token; grants access to every registered legacy device")
	agentToken := fs.String("agent-token", "", "legacy single-tenant Agent bearer token; shared across all legacy devices")
	publicURL := fs.String("public-url", "", "public HTTPS origin used for OAuth, for example https://cli.example.com")
	ownerUsername := fs.String("owner-username", "owner", "private instance owner username")
	ownerPassword := fs.String("owner-password", "", "private instance first-run owner password")
	legacyOAuthPassword := fs.String("oauth-password", "", "deprecated alias for --owner-password")
	ownerPasswordFile := fs.String("owner-password-file", defaultOwnerPasswordPath(), "private first-run owner password file")
	stateDir := fs.String("state-dir", defaultRelayStateDir(), "relay state directory")
	setupTokenFile := fs.String("setup-token-file", "", "local one-time first-run setup token file")
	trustedProxies := new(stringList)
	fs.Var(trustedProxies, "trusted-proxy", "trusted reverse-proxy IP/CIDR (repeatable; never trust proxy headers by default)")
	disableRegistration := fs.Bool("disable-registration", false, "disable public account registration")
	allowLegacyUnboundAgents := fs.Bool("allow-legacy-unbound-agents", false, "MIGRATION ONLY: allow bearer-only legacy Agent connections without Ed25519 proof")
	githubURL := fs.String("github-url", "https://github.com/ifloppy/chat-with-cli", "GitHub project URL shown on the landing page")
	configPath := fs.String("config", defaultRelayConfigPath(), "relay TOML configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	modeConfigured := flagWasSet(fs, "instance-mode")
	values, err := config.LoadOptional(*configPath)
	if err != nil {
		return fmt.Errorf("load relay config: %w", err)
	}
	if !flagWasSet(fs, "listen") {
		*listen = values.String(*listen, "relay.listen")
	}
	if !flagWasSet(fs, "instance-mode") {
		if _, ok := values.Raw("relay.instance_mode"); ok {
			modeConfigured = true
		}
		*mode = values.String(*mode, "relay.instance_mode")
	}
	if !flagWasSet(fs, "public-url") {
		*publicURL = values.String(*publicURL, "relay.public_url")
	}
	if !flagWasSet(fs, "owner-username") {
		*ownerUsername = values.String(*ownerUsername, "relay.owner_username")
	}
	if !flagWasSet(fs, "owner-password-file") {
		*ownerPasswordFile = values.String(*ownerPasswordFile, "relay.owner_password_file")
	}
	if !flagWasSet(fs, "state-dir") {
		*stateDir = values.String(*stateDir, "relay.state_dir")
	}
	if !flagWasSet(fs, "setup-token-file") {
		*setupTokenFile = values.String(*setupTokenFile, "relay.setup_token_file")
	}
	if !flagWasSet(fs, "trusted-proxy") {
		*trustedProxies = values.Strings("relay.trusted_proxy")
	}
	if !flagWasSet(fs, "disable-registration") {
		*disableRegistration = values.Bool(*disableRegistration, "relay.disable_registration")
	}
	if !flagWasSet(fs, "allow-legacy-unbound-agents") {
		*allowLegacyUnboundAgents = values.Bool(*allowLegacyUnboundAgents, "relay.allow_legacy_unbound_agents")
	}
	if !flagWasSet(fs, "github-url") {
		*githubURL = values.String(*githubURL, "relay.github_url")
	}
	*clientToken = envOr(*clientToken, "CHAT_WITH_CLI_CLIENT_TOKEN")
	*agentToken = envOr(*agentToken, "CHAT_WITH_CLI_AGENT_TOKEN")
	*publicURL = envOr(*publicURL, "CHAT_WITH_CLI_PUBLIC_URL")
	if !flagWasSet(fs, "public-url") && strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_PUBLIC_URL")) != "" {
		*publicURL = strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_PUBLIC_URL"))
	}
	if !flagWasSet(fs, "instance-mode") && strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_INSTANCE_MODE")) != "" {
		*mode = strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_INSTANCE_MODE"))
		modeConfigured = true
	}
	if !flagWasSet(fs, "owner-username") && strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_OWNER_USERNAME")) != "" {
		*ownerUsername = strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_OWNER_USERNAME"))
	}
	*ownerPassword = envOr(*ownerPassword, "CHAT_WITH_CLI_OWNER_PASSWORD")
	if *ownerPassword == "" {
		*ownerPassword = envOr(*legacyOAuthPassword, "CHAT_WITH_CLI_OAUTH_PASSWORD")
	}
	if !flagWasSet(fs, "owner-password-file") && strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_OWNER_PASSWORD_FILE")) != "" {
		*ownerPasswordFile = strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_OWNER_PASSWORD_FILE"))
	}
	if !flagWasSet(fs, "state-dir") && strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_RELAY_STATE_DIR")) != "" {
		*stateDir = strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_RELAY_STATE_DIR"))
	}
	if *setupTokenFile == "" {
		*setupTokenFile = defaultSetupTokenPath(*stateDir)
	}
	if !flagWasSet(fs, "setup-token-file") && strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_SETUP_TOKEN_FILE")) != "" {
		*setupTokenFile = strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_SETUP_TOKEN_FILE"))
	}
	if !flagWasSet(fs, "disable-registration") && envBool("CHAT_WITH_CLI_DISABLE_REGISTRATION") {
		*disableRegistration = true
	}
	if !flagWasSet(fs, "allow-legacy-unbound-agents") && envBool("CHAT_WITH_CLI_ALLOW_LEGACY_UNBOUND_AGENTS") {
		*allowLegacyUnboundAgents = true
	}
	if !flagWasSet(fs, "github-url") && strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_GITHUB_URL")) != "" {
		*githubURL = strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_GITHUB_URL"))
	}
	if *ownerPassword == "" {
		*ownerPassword, err = readPrivateCredential(*ownerPasswordFile)
		if err != nil {
			return fmt.Errorf("read owner password file: %w", err)
		}
	}
	oauthEnabled := strings.TrimSpace(*publicURL) != ""
	if !oauthEnabled && *clientToken == "" {
		return fmt.Errorf("relay requires --public-url for OAuth or a legacy --client-token")
	}
	if oauthEnabled && (*clientToken != "" || *agentToken != "") {
		return fmt.Errorf("OAuth mode forbids shared static client/agent tokens because they cannot enforce per-user device ownership; remove the static tokens or run explicit legacy mode without --public-url")
	}
	if !oauthEnabled && *agentToken == "" {
		return fmt.Errorf("legacy relay mode requires --agent-token")
	}
	setupToken := ""
	if oauthEnabled && *ownerPassword == "" {
		setupToken, err = readPrivateCredential(*setupTokenFile)
		if err != nil {
			return fmt.Errorf("read setup token file: %w", err)
		}
		if setupToken == "" {
			statePath := filepath.Join(*stateDir, "oauth-state.json")
			if _, err := os.Stat(statePath); os.IsNotExist(err) {
				setupToken = protocol.NewID() + protocol.NewID()
				if err := writePrivateCredential(*setupTokenFile, setupToken); err != nil {
					return fmt.Errorf("write generated setup token: %w", err)
				}
				log.Printf("first-run setup token generated in %s (mode 0600); read it locally to initialize the Relay", *setupTokenFile)
			}
		}
	}

	broker := relay.NewBroker()
	var pathHandler http.Handler = mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		device := relayDeviceRoute(r)
		if device == "" {
			return nil
		}
		return mcpserver.New(relay.RemoteCaller{Broker: broker, Device: device})
	}, relayStreamableHTTPOptions(*listen, *publicURL))
	pathHandler = maxRequestBody(8<<20, pathHandler)
	var legacyHandler http.Handler = mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		device := strings.TrimSpace(r.URL.Query().Get("device"))
		if !protocol.ValidDeviceName(device) && !(strings.HasPrefix(device, "id/") && protocol.ValidDeviceID(strings.TrimPrefix(device, "id/"))) {
			return nil
		}
		return mcpserver.New(relay.RemoteCaller{Broker: broker, Device: device})
	}, relayStreamableHTTPOptions(*listen, *publicURL))
	legacyHandler = maxRequestBody(8<<20, legacyHandler)
	if envBool("CHAT_WITH_CLI_MCP_DIAGNOSTICS") {
		pathHandler = mcpDiagnosticHandler(pathHandler)
		legacyHandler = mcpDiagnosticHandler(legacyHandler)
		log.Printf("MCP discovery diagnostics enabled (method/path/status only)")
	}

	mux := http.NewServeMux()
	var oauthHealth *oauthserver.Server
	if oauthEnabled {
		cfg := oauthserver.Config{PublicURL: *publicURL, StateDir: *stateDir, Mode: *mode, ModeConfigured: modeConfigured, OwnerUsername: *ownerUsername, OwnerPassword: *ownerPassword, RegistrationDisabled: *disableRegistration, TrustedProxyCIDRs: append([]string(nil), *trustedProxies...), EnforceSingleWriter: true, AllowLegacyUnboundAgents: *allowLegacyUnboundAgents, SetupToken: setupToken, SetupTokenPath: *setupTokenFile, Version: mcpserver.Version, GitHubURL: *githubURL}
		oauth, err := oauthserver.New(cfg)
		if err != nil {
			return err
		}
		defer oauth.Close()
		oauthHealth = oauth
		broker.SetAgentConnectionAuthorizer(func(device, credentialHash string) bool {
			return oauth.VerifyAgentConnection(credentialHash, device)
		})
		oauth.SetAgentSessionResetter(broker.DisconnectDevice)
		oauth.SetDeviceStatusProvider(func() map[string]oauthserver.DeviceStatus {
			status := broker.DeviceStatuses()
			out := make(map[string]oauthserver.DeviceStatus, len(status))
			for name, value := range status {
				out[name] = oauthserver.DeviceStatus{Device: value.Device, Online: value.Online, ConnectedAt: value.ConnectedAt, LastSeen: value.LastSeen, InFlight: value.InFlight, Capabilities: value.Capabilities}
			}
			return out
		})
		oauth.RegisterRoutes(mux)
		mux.Handle("/mcp/{device}", oauth.ProtectScopedResource("mcp", pathHandler))
		mux.Handle("/mcp/id/{id}", oauth.ProtectScopedResource("mcp", pathHandler))
		mux.Handle("/agent/", agentPathMux(
			oauth.AgentChallengeHandler(),
			oauth.ProtectScopedResource("agent:connect", broker.AgentHandler()),
		))
		log.Printf("%s OAuth instance; MCP endpoint: %s/mcp/<device>", strings.ToLower(*mode), strings.TrimRight(*publicURL, "/"))
	} else {
		mux.Handle("/mcp/{device}", bearerAuth(*clientToken, pathHandler))
		mux.Handle("/mcp/id/{id}", bearerAuth(*clientToken, pathHandler))
		mux.Handle("/agent/{device}", bearerAuth(*agentToken, broker.AgentHandler()))
		mux.Handle("/agent/id/{id}", bearerAuth(*agentToken, broker.AgentHandler()))
	}
	if *clientToken != "" {
		mux.Handle("/mcp", bearerAuth(*clientToken, legacyHandler))
		mux.Handle("/devices", bearerAuth(*clientToken, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_ = json.NewEncoder(w).Encode(broker.Devices())
		})))
	}
	if *agentToken != "" {
		mux.Handle("/agent", broker.LegacyAgentHandler(*agentToken))
	}
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if oauthHealth != nil && !oauthHealth.Ready() {
			http.Error(w, "authorization state unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	ctx, cancel := signalContext()
	defer cancel()
	return serveHTTP(ctx, *listen, oauthserver.SecurityHeaders(mux))
}

const (
	approvalConfigured = "configured"
	approvalAsk        = "ask"
	approvalAllowAll   = "allow-all"
)

func runConnect(args []string) error {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" || arg == "--approval-mode" || strings.HasPrefix(arg, "--approval-mode=") {
			return runAgentCommand("connect", args)
		}
	}
	mode, err := chooseConnectApprovalMode()
	if err != nil {
		return err
	}
	return runAgentCommand("connect", append([]string{"--approval-mode=" + mode}, args...))
}

func chooseConnectApprovalMode() (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "No interactive terminal detected; using the configured capability profile.")
		return approvalConfigured, nil
	}
	defer tty.Close()
	fmt.Fprintln(tty, "Chat with CLI permission mode for this session:")
	fmt.Fprintln(tty, "  1. Interactive approvals (recommended; temporary access, confirm locally)")
	fmt.Fprintln(tty, "  2. Allow all operations this session (dangerous)")
	fmt.Fprintln(tty, "  3. Configured profile only (no temporary capability expansion)")
	fmt.Fprint(tty, "Choose [1]: ")
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	switch strings.TrimSpace(line) {
	case "", "1":
		return approvalAsk, nil
	case "2":
		return approvalAllowAll, nil
	case "3":
		return approvalConfigured, nil
	default:
		return "", fmt.Errorf("invalid permission choice %q", strings.TrimSpace(line))
	}
}

type requestApprover struct {
	mu         sync.Mutex
	reader     *bufio.Reader
	writer     io.Writer
	allowAll   bool
	allowedCap map[string]bool
}

func newTTYRequestApprover() (*requestApprover, io.Closer, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, errors.New("interactive approval mode requires a local terminal; use --approval-mode=configured or --approval-mode=allow-all for non-interactive starts")
	}
	return &requestApprover{reader: bufio.NewReader(tty), writer: tty, allowedCap: map[string]bool{}}, tty, nil
}

func approvalCategory(method string) string {
	switch method {
	case "system_info", "computer_info", "audit_recent":
		return "status"
	case "fs_read", "fs_list", "fs_search", "checkpoint_read":
		return "filesystem-read"
	case "fs_write", "fs_patch", "checkpoint_write":
		return "filesystem-write"
	case "task_start", "task_read", "task_wait", "task_list", "task_send", "task_stop":
		return "shell-exec"
	case "computer_screenshot":
		return "screen-read"
	case "computer_observe", "computer_ui_tree", "computer_ui_find", "computer_ui_wait", "computer_ui_get_text":
		return "desktop-read"
	case "computer_ui_focus", "computer_ui_action", "computer_ui_invoke", "computer_ui_set_text", "computer_move", "computer_click", "computer_scroll", "computer_type", "computer_key":
		return "computer-input"
	default:
		return "other"
	}
}

func (a *requestApprover) authorize(ctx context.Context, request protocol.Request) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	category := approvalCategory(request.Method)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.allowAll || a.allowedCap[category] {
		return nil
	}
	for {
		fmt.Fprintf(a.writer, "\nChat with CLI request: %s [%s]\n", request.Method, category)
		fmt.Fprint(a.writer, "Approve? [y] once  [s] this capability for session  [a] all for session  [n] deny: ")
		line, err := a.reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes", "":
			return nil
		case "s", "session":
			a.allowedCap[category] = true
			return nil
		case "a", "all":
			a.allowAll = true
			return nil
		case "n", "no":
			return errors.New("request denied by local user")
		default:
			fmt.Fprintln(a.writer, "Please enter y, s, a, or n.")
		}
	}
}

func runAgent(args []string) error {
	return runAgentCommand("agent", args)
}

func runAgentCommand(command string, args []string) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	roots, profile, allowFileWrite, allowExec, execSandbox, allowScreen, allowAccessibility, allowComputer, computerPersist, stateDir, killSwitchPath, maxActiveTasks := addEngineFlags(fs)
	relayURL := fs.String("relay", "", "relay base URL, for example https://cli.example.com")
	deviceDefault, _ := os.Hostname()
	device := fs.String("device", deviceDefault, "device name exposed to MCP clients")
	deviceID := fs.String("device-id", "", "immutable 128-bit device ID; use with /agent/id/<id> to avoid name squatting")
	token := fs.String("token", "", "legacy private Agent token; omit to use browser OAuth")
	credentials := fs.String("credentials", oauthclient.DefaultCredentialsPath(), "OAuth credential store")
	configPath := fs.String("config", oauthclient.DefaultConfigPath(), "agent TOML configuration file")
	identityPath := fs.String("identity", "", "Ed25519 device identity path")
	approvalMode := fs.String("approval-mode", approvalConfigured, "configured, ask, or allow-all; ask/allow-all temporarily expose all capabilities for this process")
	if err := fs.Parse(args); err != nil {
		return err
	}
	values, err := config.LoadOptional(*configPath)
	if err != nil {
		return fmt.Errorf("load agent config: %w", err)
	}
	if !flagWasSet(fs, "root") {
		*roots = values.Strings("agent.root")
	}
	if !flagWasSet(fs, "profile") {
		*profile = values.String(*profile, "agent.profile")
	}
	if !flagWasSet(fs, "allow-file-write") && !flagWasSet(fs, "allow-fs-write") {
		*allowFileWrite = values.Bool(*allowFileWrite, "agent.allow_file_write")
	}
	if !flagWasSet(fs, "allow-exec") {
		*allowExec = values.Bool(*allowExec, "agent.allow_exec")
	}
	if !flagWasSet(fs, "exec-sandbox") {
		*execSandbox = values.String(*execSandbox, "agent.exec_sandbox")
	}
	if !flagWasSet(fs, "allow-screen") {
		*allowScreen = values.Bool(*allowScreen, "agent.allow_screen")
	}
	if !flagWasSet(fs, "allow-accessibility") {
		*allowAccessibility = values.Bool(*allowAccessibility, "agent.allow_accessibility")
	}
	if !flagWasSet(fs, "allow-computer-use") {
		*allowComputer = values.Bool(*allowComputer, "agent.allow_computer_use")
	}
	if !flagWasSet(fs, "computer-persist") {
		*computerPersist = values.String(*computerPersist, "agent.computer_persist")
	}
	if !flagWasSet(fs, "state-dir") {
		*stateDir = values.String(*stateDir, "agent.state_dir")
	}
	if !flagWasSet(fs, "kill-switch-file") {
		*killSwitchPath = values.String(*killSwitchPath, "agent.kill_switch_file")
	}
	applyKillSwitchDefault(stateDir, killSwitchPath)
	if !flagWasSet(fs, "max-active-tasks") {
		*maxActiveTasks = values.Int(*maxActiveTasks, "agent.max_active_tasks")
	}
	if !flagWasSet(fs, "relay") {
		*relayURL = values.String(*relayURL, "agent.relay_url")
	}
	if !flagWasSet(fs, "device") {
		*device = values.String(*device, "agent.device")
	}
	if !flagWasSet(fs, "device-id") {
		*deviceID = values.String(*deviceID, "agent.device_id")
	}
	if !flagWasSet(fs, "credentials") {
		*credentials = values.String(*credentials, "agent.credentials")
	}
	if !flagWasSet(fs, "identity") {
		*identityPath = values.String(*identityPath, "agent.identity")
	}
	if err := applyCapabilityProfile(fs, *profile, allowFileWrite, allowExec, allowScreen, allowAccessibility, allowComputer); err != nil {
		return err
	}
	*approvalMode = strings.ToLower(strings.TrimSpace(*approvalMode))
	switch *approvalMode {
	case approvalConfigured:
	case approvalAsk, approvalAllowAll:
		*allowFileWrite, *allowExec, *allowScreen, *allowAccessibility, *allowComputer = true, true, true, true, true
		if runtime.GOOS == "linux" && strings.EqualFold(strings.TrimSpace(*execSandbox), "none") {
			*execSandbox = "landlock"
		}
	default:
		return fmt.Errorf("invalid --approval-mode %q; use configured, ask, or allow-all", *approvalMode)
	}
	*token = envOr(*token, "CHAT_WITH_CLI_AGENT_TOKEN")
	if !flagWasSet(fs, "credentials") && strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_CREDENTIALS")) != "" {
		*credentials = strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_CREDENTIALS"))
	}
	if !protocol.ValidDeviceName(strings.TrimSpace(*device)) {
		return fmt.Errorf("--device must be 1-128 ASCII letters, digits, dot, underscore, or hyphen")
	}
	*device = strings.TrimSpace(*device)
	if strings.TrimSpace(*deviceID) != "" {
		canonicalID, ok := protocol.NormalizeDeviceID(*deviceID)
		if !ok {
			return fmt.Errorf("--device-id must be 32 hexadecimal characters")
		}
		*deviceID = canonicalID
	}
	var deviceIdentity *deviceidentity.Identity
	if strings.TrimSpace(*identityPath) != "" {
		*identityPath, err = normalizeUserPath(*identityPath)
		if err != nil {
			return fmt.Errorf("invalid --identity: %w", err)
		}
		deviceIdentity, err = deviceidentity.Load(*identityPath)
		if err != nil {
			return fmt.Errorf("load device identity: %w", err)
		}
		derivedID := deviceIdentity.ID()
		if *deviceID == "" {
			*deviceID = derivedID
		} else if *deviceID != derivedID {
			return fmt.Errorf("configured device ID %s does not match Ed25519 identity %s", *deviceID, derivedID)
		}
	}
	if strings.TrimSpace(*relayURL) == "" && *token == "" {
		saved, ok, err := "", false, error(nil)
		if *deviceID != "" {
			saved, ok, err = oauthclient.SavedRelayForDeviceID(*credentials, *deviceID)
		} else {
			saved, ok, err = oauthclient.SavedRelayForDevice(*credentials, *device)
		}
		if err != nil {
			return err
		}
		if ok {
			*relayURL = saved
			log.Printf("using saved Relay profile %s for device %q", saved, *device)
		}
	}
	if strings.TrimSpace(*relayURL) == "" {
		return fmt.Errorf("--relay is required for first login; later starts can reuse the saved OAuth profile")
	}
	if _, configuredInFile := values.Raw("agent.exec_sandbox"); !configuredInFile {
		applyExecSandboxDefault(fs, *profile, *allowExec, execSandbox)
	}
	protectedPaths := []string{*credentials, *configPath}
	if *identityPath != "" {
		protectedPaths = append(protectedPaths, *identityPath)
	}
	eng, err := newEngine(*roots, *allowFileWrite, *allowExec, *execSandbox, *allowScreen, *allowAccessibility, *allowComputer, *computerPersist, *stateDir, *killSwitchPath, protectedPaths, *maxActiveTasks)
	if err != nil {
		return err
	}
	defer eng.Close()
	ctx, cancel := signalContext()
	defer cancel()
	client := &agent.Client{Engine: eng, URL: *relayURL, Device: *device, DeviceID: *deviceID, Token: *token, Identity: deviceIdentity}
	if *approvalMode == approvalAsk {
		approver, closer, err := newTTYRequestApprover()
		if err != nil {
			return err
		}
		defer closer.Close()
		client.AuthorizeRequest = approver.authorize
		log.Printf("local approval mode: interactive; temporary capabilities require terminal confirmation")
	} else if *approvalMode == approvalAllowAll {
		log.Printf("WARNING: local approval mode allows all capabilities for this process")
	}
	if *token == "" {
		if deviceIdentity == nil && *deviceID != "" {
			log.Printf("WARNING: immutable device %s has no local Ed25519 identity; this is legacy bearer-only compatibility and should be migrated with `agent setup`", *deviceID)
		}
		manager := &oauthclient.Manager{RelayURL: *relayURL, Device: *device, DeviceID: *deviceID, DeviceIdentity: deviceIdentity, CredentialsPath: *credentials}
		client.TokenProvider = manager.Token
		log.Printf("Agent authentication: browser OAuth (credentials: %s)", *credentials)
	}
	log.Printf("agent %q connecting to %s", *device, *relayURL)
	if *deviceID != "" {
		log.Printf("MCP endpoint for this device: %s/mcp/id/%s", strings.TrimRight(*relayURL, "/"), *deviceID)
	} else {
		log.Printf("MCP endpoint for this device: %s/mcp/%s", strings.TrimRight(*relayURL, "/"), *device)
	}
	return client.Run(ctx)
}

func runLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	relayURL := fs.String("relay", "", "relay base URL, for example https://cli.example.com")
	deviceDefault, _ := os.Hostname()
	device := fs.String("device", deviceDefault, "device to authorize")
	deviceID := fs.String("device-id", "", "immutable 128-bit device ID to authorize")
	credentials := fs.String("credentials", oauthclient.DefaultCredentialsPath(), "OAuth credential store")
	configPath := fs.String("config", oauthclient.DefaultConfigPath(), "agent TOML configuration file")
	identityPath := fs.String("identity", "", "Ed25519 device identity path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	values, err := config.LoadOptional(*configPath)
	if err != nil {
		return fmt.Errorf("load agent config: %w", err)
	}
	if !flagWasSet(fs, "relay") {
		*relayURL = values.String(*relayURL, "agent.relay_url")
	}
	if !flagWasSet(fs, "device") {
		*device = values.String(*device, "agent.device")
	}
	if !flagWasSet(fs, "device-id") {
		*deviceID = values.String(*deviceID, "agent.device_id")
	}
	if !flagWasSet(fs, "credentials") {
		*credentials = values.String(*credentials, "agent.credentials")
		if strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_CREDENTIALS")) != "" {
			*credentials = strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_CREDENTIALS"))
		}
	}
	if !flagWasSet(fs, "identity") {
		*identityPath = values.String(*identityPath, "agent.identity")
	}
	if strings.TrimSpace(*relayURL) == "" {
		return fmt.Errorf("Relay URL is missing; run `chat-with-cli agent setup --relay https://...` or provide --relay")
	}
	if !protocol.ValidDeviceName(strings.TrimSpace(*device)) {
		return fmt.Errorf("invalid --device")
	}
	if strings.TrimSpace(*deviceID) != "" {
		canonicalID, ok := protocol.NormalizeDeviceID(*deviceID)
		if !ok {
			return fmt.Errorf("invalid --device-id")
		}
		*deviceID = canonicalID
	}
	var deviceIdentity *deviceidentity.Identity
	if strings.TrimSpace(*identityPath) != "" {
		*identityPath, err = normalizeUserPath(*identityPath)
		if err != nil {
			return fmt.Errorf("invalid --identity: %w", err)
		}
		deviceIdentity, err = deviceidentity.Load(*identityPath)
		if err != nil {
			return fmt.Errorf("load device identity: %w", err)
		}
		derivedID := deviceIdentity.ID()
		if *deviceID == "" {
			*deviceID = derivedID
		} else if *deviceID != derivedID {
			return fmt.Errorf("configured device ID %s does not match Ed25519 identity %s", *deviceID, derivedID)
		}
	}
	manager := &oauthclient.Manager{RelayURL: strings.TrimSpace(*relayURL), Device: strings.TrimSpace(*device), DeviceID: *deviceID, DeviceIdentity: deviceIdentity, CredentialsPath: *credentials}
	resource, err := manager.Resource()
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	if _, err := manager.Token(ctx); err != nil {
		return err
	}
	fmt.Printf("Authorized %s via browser OAuth.\nAgent resource: %s\nCredentials saved to %s\n", *device, resource, *credentials)
	return nil
}

func agentPathMux(challenge, connection http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimSuffix(r.URL.EscapedPath(), "/")
		if strings.HasSuffix(path, "/challenge") {
			challenge.ServeHTTP(w, r)
			return
		}
		connection.ServeHTTP(w, r)
	})
}

func bearerAuth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		header := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(header, prefix) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		provided := strings.TrimSpace(strings.TrimPrefix(header, prefix))
		if len(provided) != len(token) || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func maxRequestBody(limit int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

func serveHTTP(ctx context.Context, listen string, handler http.Handler) error {
	server := &http.Server{
		Addr: listen, Handler: handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Printf("listening on %s", listen)
		errCh <- server.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		err := <-errCh
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}
