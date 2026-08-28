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

func runRelay(args []string) error {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	listen := fs.String("listen", ":8765", "HTTP listen address")
	clientToken := fs.String("client-token", "", "optional legacy/static MCP bearer token")
	agentToken := fs.String("agent-token", "", "device agent bearer token")
	publicURL := fs.String("public-url", "", "public HTTPS origin used for OAuth, for example https://cli.example.com")
	oauthPassword := fs.String("oauth-password", "", "single-user OAuth consent password")
	stateDir := fs.String("state-dir", defaultRelayStateDir(), "relay state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	*clientToken = envOr(*clientToken, "CHAT_WITH_CLI_CLIENT_TOKEN")
	*agentToken = envOr(*agentToken, "CHAT_WITH_CLI_AGENT_TOKEN")
	*publicURL = envOr(*publicURL, "CHAT_WITH_CLI_PUBLIC_URL")
	*oauthPassword = envOr(*oauthPassword, "CHAT_WITH_CLI_OAUTH_PASSWORD")
	*stateDir = envOr(*stateDir, "CHAT_WITH_CLI_RELAY_STATE_DIR")
	if *agentToken == "" {
		return fmt.Errorf("relay requires an agent token")
	}
	oauthEnabled := *publicURL != "" || *oauthPassword != ""
	if oauthEnabled && (*publicURL == "" || *oauthPassword == "") {
		return fmt.Errorf("OAuth requires both --public-url and --oauth-password")
	}
	if !oauthEnabled && *clientToken == "" {
		return fmt.Errorf("relay requires OAuth or --client-token for MCP clients")
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
		oauth, err := oauthserver.New(oauthserver.Config{PublicURL: *publicURL, Password: *oauthPassword, StateDir: *stateDir})
		if err != nil {
			return err
		}
		oauth.RegisterRoutes(mux)
		mux.Handle("/mcp/{device}", oauth.ProtectResource(*clientToken, pathHandler))
		log.Printf("OAuth MCP endpoint: %s/mcp/<device>", strings.TrimRight(*publicURL, "/"))
	} else {
		mux.Handle("/mcp/{device}", bearerAuth(*clientToken, pathHandler))
	}
	if *clientToken != "" {
		mux.Handle("/mcp", bearerAuth(*clientToken, legacyHandler))
		mux.Handle("/devices", bearerAuth(*clientToken, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_ = json.NewEncoder(w).Encode(broker.Devices())
		})))
	}
	mux.Handle("/agent", broker.AgentHandler(*agentToken))
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
	token := fs.String("token", "", "agent token (or CHAT_WITH_CLI_AGENT_TOKEN)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	*token = envOr(*token, "CHAT_WITH_CLI_AGENT_TOKEN")
	if strings.TrimSpace(*relayURL) == "" {
		return fmt.Errorf("--relay is required")
	}
	if *token == "" {
		return fmt.Errorf("agent token is required")
	}
	if !protocol.ValidDeviceName(strings.TrimSpace(*device)) {
		return fmt.Errorf("--device must be 1-128 ASCII letters, digits, dot, underscore, or hyphen")
	}
	*device = strings.TrimSpace(*device)
	eng, err := newEngine(*roots, *allowExec, *allowScreen, *allowComputer, *computerPersist, *stateDir, *maxActiveTasks)
	if err != nil {
		return err
	}
	defer eng.Close()
	ctx, cancel := signalContext()
	defer cancel()
	client := &agent.Client{Engine: eng, URL: *relayURL, Device: *device, Token: *token}
	log.Printf("agent %q connecting to %s", *device, *relayURL)
	log.Printf("MCP endpoint for this device: %s/mcp/%s", strings.TrimRight(*relayURL, "/"), *device)
	return client.Run(ctx)
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
