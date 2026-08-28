package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ifloppy/chat-with-cli/internal/agent"
	"github.com/ifloppy/chat-with-cli/internal/engine"
	"github.com/ifloppy/chat-with-cli/internal/mcpserver"
	"github.com/ifloppy/chat-with-cli/internal/oauthclient"
	"github.com/ifloppy/chat-with-cli/internal/oauthserver"
	"github.com/ifloppy/chat-with-cli/internal/protocol"
	"github.com/ifloppy/chat-with-cli/internal/relay"
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
		err = runRelay(os.Args[2:])
	case "agent":
		err = runAgent(os.Args[2:])
	case "login":
		err = runLogin(os.Args[2:])
	case "token":
		fmt.Println(protocol.NewID() + protocol.NewID())
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
  chat-with-cli agent [flags]   Connect this machine outbound to a relay
  chat-with-cli login [flags]   Browser OAuth login for an Agent profile
  chat-with-cli token           Generate a strong random token
  chat-with-cli version         Print version

Security defaults: filesystem access is restricted to --root values and shell
execution is disabled unless --allow-exec is explicitly provided. Desktop screenshots
and input are separately gated by --allow-screen / --allow-computer-use.
`)
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func addEngineFlags(fs *flag.FlagSet) (*stringList, *bool, *bool, *bool, *string, *string, *int) {
	roots := new(stringList)
	fs.Var(roots, "root", "allowed filesystem root (repeatable; defaults to current directory)")
	allowExec := fs.Bool("allow-exec", false, "allow arbitrary shell commands in PTY tasks")
	allowScreen := fs.Bool("allow-screen", false, "allow read-only desktop screenshots and accessibility inspection")
	allowComputer := fs.Bool("allow-computer-use", false, "allow screenshots, accessibility writes, and keyboard/mouse control")
	computerPersist := fs.String("computer-persist", "process", "portal permission persistence: none, process, or persistent")
	stateDir := fs.String("state-dir", "", "state directory for task logs and checkpoints")
	maxActiveTasks := fs.Int("max-active-tasks", 32, "maximum concurrent PTY tasks")
	return roots, allowExec, allowScreen, allowComputer, computerPersist, stateDir, maxActiveTasks
}

func newEngine(roots []string, allowExec, allowScreen, allowComputer bool, computerPersist, stateDir string, maxActiveTasks int) (*engine.Engine, error) {
	return engine.New(engine.Config{
		Roots: roots, AllowExec: allowExec, AllowScreen: allowScreen || allowComputer,
		AllowComputerControl: allowComputer, ComputerPersistMode: computerPersist,
		StateDir: stateDir, MaxReadBytes: 256 * 1024, MaxActiveTasks: maxActiveTasks,
	})
}

func runLocal(args []string) error {
	fs := flag.NewFlagSet("local", flag.ContinueOnError)
	roots, allowExec, allowScreen, allowComputer, computerPersist, stateDir, maxActiveTasks := addEngineFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	eng, err := newEngine(*roots, *allowExec, *allowScreen, *allowComputer, *computerPersist, *stateDir, *maxActiveTasks)
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
	roots, allowExec, allowScreen, allowComputer, computerPersist, stateDir, maxActiveTasks := addEngineFlags(fs)
	listen := fs.String("listen", "127.0.0.1:8765", "HTTP listen address")
	token := fs.String("token", "", "optional bearer token (or CHAT_WITH_CLI_CLIENT_TOKEN)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	*token = envOr(*token, "CHAT_WITH_CLI_CLIENT_TOKEN")
	if *token == "" && !loopbackListen(*listen) {
		return fmt.Errorf("refusing unauthenticated non-loopback listen %q", *listen)
	}
	eng, err := newEngine(*roots, *allowExec, *allowScreen, *allowComputer, *computerPersist, *stateDir, *maxActiveTasks)
	if err != nil {
		return err
	}
	defer eng.Close()
	server := mcpserver.New(mcpserver.LocalCaller{Engine: eng})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true})
	mux := http.NewServeMux()
	mux.Handle("/mcp", bearerAuth(*token, handler))
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	ctx, cancel := signalContext()
	defer cancel()
	return serveHTTP(ctx, *listen, mux)
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

func readTrimmedFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func writePrivateCredential(path, value string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func runRelay(args []string) error {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	listen := fs.String("listen", ":8765", "HTTP listen address")
	mode := fs.String("instance-mode", oauthserver.ModePrivate, "instance mode: private or public")
	clientToken := fs.String("client-token", "", "optional private legacy/static MCP bearer token")
	agentToken := fs.String("agent-token", "", "optional private legacy Agent bearer token")
	publicURL := fs.String("public-url", "", "public HTTPS origin used for OAuth, for example https://cli.example.com")
	ownerUsername := fs.String("owner-username", "owner", "private instance owner username")
	ownerPassword := fs.String("owner-password", "", "private instance first-run owner password")
	legacyOAuthPassword := fs.String("oauth-password", "", "deprecated alias for --owner-password")
	ownerPasswordFile := fs.String("owner-password-file", defaultOwnerPasswordPath(), "private first-run owner password file")
	stateDir := fs.String("state-dir", defaultRelayStateDir(), "relay state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	*clientToken = envOr(*clientToken, "CHAT_WITH_CLI_CLIENT_TOKEN")
	*agentToken = envOr(*agentToken, "CHAT_WITH_CLI_AGENT_TOKEN")
	*publicURL = envOr(*publicURL, "CHAT_WITH_CLI_PUBLIC_URL")
	if !flagWasSet(fs, "instance-mode") && strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_INSTANCE_MODE")) != "" {
		*mode = strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_INSTANCE_MODE"))
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
	if *ownerPassword == "" {
		*ownerPassword = readTrimmedFile(*ownerPasswordFile)
	}
	oauthEnabled := strings.TrimSpace(*publicURL) != ""
	if !oauthEnabled && *clientToken == "" {
		return fmt.Errorf("relay requires --public-url for OAuth or a legacy --client-token")
	}
	if strings.EqualFold(*mode, oauthserver.ModePublic) && (*clientToken != "" || *agentToken != "") {
		return fmt.Errorf("public mode forbids shared static client/agent tokens; use browser OAuth")
	}
	if !oauthEnabled && *agentToken == "" {
		return fmt.Errorf("legacy relay mode requires --agent-token")
	}

	broker := relay.NewBroker()
	pathHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		device := strings.TrimSpace(r.PathValue("device"))
		if !protocol.ValidDeviceName(device) {
			return nil
		}
		return mcpserver.New(relay.RemoteCaller{Broker: broker, Device: device})
	}, &mcp.StreamableHTTPOptions{Stateless: true})
	legacyHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		device := strings.TrimSpace(r.URL.Query().Get("device"))
		if !protocol.ValidDeviceName(device) {
			return nil
		}
		return mcpserver.New(relay.RemoteCaller{Broker: broker, Device: device})
	}, &mcp.StreamableHTTPOptions{Stateless: true})

	mux := http.NewServeMux()
	if oauthEnabled {
		cfg := oauthserver.Config{PublicURL: *publicURL, StateDir: *stateDir, Mode: *mode, OwnerUsername: *ownerUsername, OwnerPassword: *ownerPassword}
		oauth, err := oauthserver.New(cfg)
		if err != nil && strings.EqualFold(*mode, oauthserver.ModePrivate) && *ownerPassword == "" && strings.Contains(err.Error(), "no owner") {
			generated := protocol.NewID() + protocol.NewID()
			if err := writePrivateCredential(*ownerPasswordFile, generated); err != nil {
				return fmt.Errorf("write generated owner password: %w", err)
			}
			cfg.OwnerPassword = generated
			oauth, err = oauthserver.New(cfg)
			if err == nil {
				log.Printf("private owner bootstrap password generated at %s (mode 0600)", *ownerPasswordFile)
			}
		}
		if err != nil {
			return err
		}
		oauth.RegisterRoutes(mux)
		mux.Handle("/mcp/{device}", oauth.ProtectScopedResource(*clientToken, "mcp", pathHandler))
		mux.Handle("/agent/{device}", oauth.ProtectScopedResource(*agentToken, "agent:connect", broker.AgentHandler()))
		log.Printf("%s OAuth instance; MCP endpoint: %s/mcp/<device>", strings.ToLower(*mode), strings.TrimRight(*publicURL, "/"))
	} else {
		mux.Handle("/mcp/{device}", bearerAuth(*clientToken, pathHandler))
		mux.Handle("/agent/{device}", bearerAuth(*agentToken, broker.AgentHandler()))
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
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	ctx, cancel := signalContext()
	defer cancel()
	return serveHTTP(ctx, *listen, mux)
}

func runAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	roots, allowExec, allowScreen, allowComputer, computerPersist, stateDir, maxActiveTasks := addEngineFlags(fs)
	relayURL := fs.String("relay", "", "relay base URL, for example https://cli.example.com")
	deviceDefault, _ := os.Hostname()
	device := fs.String("device", deviceDefault, "device name exposed to MCP clients")
	token := fs.String("token", "", "legacy private Agent token; omit to use browser OAuth")
	credentials := fs.String("credentials", oauthclient.DefaultCredentialsPath(), "OAuth credential store")
	if err := fs.Parse(args); err != nil {
		return err
	}
	*token = envOr(*token, "CHAT_WITH_CLI_AGENT_TOKEN")
	if !flagWasSet(fs, "credentials") && strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_CREDENTIALS")) != "" {
		*credentials = strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_CREDENTIALS"))
	}
	if !protocol.ValidDeviceName(strings.TrimSpace(*device)) {
		return fmt.Errorf("--device must be 1-128 ASCII letters, digits, dot, underscore, or hyphen")
	}
	*device = strings.TrimSpace(*device)
	if strings.TrimSpace(*relayURL) == "" && *token == "" {
		saved, ok, err := oauthclient.SavedRelayForDevice(*credentials, *device)
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
	eng, err := newEngine(*roots, *allowExec, *allowScreen, *allowComputer, *computerPersist, *stateDir, *maxActiveTasks)
	if err != nil {
		return err
	}
	defer eng.Close()
	ctx, cancel := signalContext()
	defer cancel()
	client := &agent.Client{Engine: eng, URL: *relayURL, Device: *device, Token: *token}
	if *token == "" {
		manager := &oauthclient.Manager{RelayURL: *relayURL, Device: *device, CredentialsPath: *credentials}
		client.TokenProvider = manager.Token
		log.Printf("Agent authentication: browser OAuth (credentials: %s)", *credentials)
	}
	log.Printf("agent %q connecting to %s", *device, *relayURL)
	log.Printf("MCP endpoint for this device: %s/mcp/%s", strings.TrimRight(*relayURL, "/"), *device)
	return client.Run(ctx)
}

func runLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	relayURL := fs.String("relay", "", "relay base URL, for example https://cli.example.com")
	deviceDefault, _ := os.Hostname()
	device := fs.String("device", deviceDefault, "device to authorize")
	credentials := fs.String("credentials", oauthclient.DefaultCredentialsPath(), "OAuth credential store")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !flagWasSet(fs, "credentials") && strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_CREDENTIALS")) != "" {
		*credentials = strings.TrimSpace(os.Getenv("CHAT_WITH_CLI_CREDENTIALS"))
	}
	if *relayURL == "" {
		return fmt.Errorf("--relay is required")
	}
	if !protocol.ValidDeviceName(strings.TrimSpace(*device)) {
		return fmt.Errorf("invalid --device")
	}
	manager := &oauthclient.Manager{RelayURL: *relayURL, Device: strings.TrimSpace(*device), CredentialsPath: *credentials}
	ctx, cancel := signalContext()
	defer cancel()
	if _, err := manager.Token(ctx); err != nil {
		return err
	}
	fmt.Printf("authorized %s via browser OAuth; credentials saved to %s\n", *device, *credentials)
	return nil
}

func bearerAuth(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
