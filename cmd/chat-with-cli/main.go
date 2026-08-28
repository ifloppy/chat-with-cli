package main

import (
	"context"
	"crypto/subtle"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ifloppy/chat-with-cli/internal/agent"
	"github.com/ifloppy/chat-with-cli/internal/engine"
	"github.com/ifloppy/chat-with-cli/internal/mcpserver"
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

func addEngineFlags(fs *flag.FlagSet) (*stringList, *bool, *bool, *bool, *string) {
	roots := new(stringList)
	fs.Var(roots, "root", "allowed filesystem root (repeatable; defaults to current directory)")
	allowExec := fs.Bool("allow-exec", false, "allow arbitrary shell commands in PTY tasks")
	allowScreen := fs.Bool("allow-screen", false, "allow read-only desktop screenshots")
	allowComputer := fs.Bool("allow-computer-use", false, "allow desktop screenshots plus keyboard/mouse control")
	stateDir := fs.String("state-dir", "", "state directory for task logs and checkpoints")
	return roots, allowExec, allowScreen, allowComputer, stateDir
}

func newEngine(roots []string, allowExec, allowScreen, allowComputer bool, stateDir string) (*engine.Engine, error) {
	return engine.New(engine.Config{
		Roots: roots, AllowExec: allowExec, AllowScreen: allowScreen || allowComputer,
		AllowComputerControl: allowComputer, StateDir: stateDir, MaxReadBytes: 256 * 1024,
	})
}

func runLocal(args []string) error {
	fs := flag.NewFlagSet("local", flag.ContinueOnError)
	roots, allowExec, allowScreen, allowComputer, stateDir := addEngineFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	eng, err := newEngine(*roots, *allowExec, *allowScreen, *allowComputer, *stateDir)
	if err != nil {
		return err
	}
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
	roots, allowExec, allowScreen, allowComputer, stateDir := addEngineFlags(fs)
	listen := fs.String("listen", "127.0.0.1:8765", "HTTP listen address")
	token := fs.String("token", "", "optional bearer token (or CHAT_WITH_CLI_CLIENT_TOKEN)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	*token = envOr(*token, "CHAT_WITH_CLI_CLIENT_TOKEN")
	if *token == "" && !loopbackListen(*listen) {
		return fmt.Errorf("refusing unauthenticated non-loopback listen %q", *listen)
	}
	eng, err := newEngine(*roots, *allowExec, *allowScreen, *allowComputer, *stateDir)
	if err != nil {
		return err
	}
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

func runRelay(args []string) error {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	listen := fs.String("listen", ":8765", "HTTP listen address")
	clientToken := fs.String("client-token", "", "MCP client bearer token")
	agentToken := fs.String("agent-token", "", "device agent bearer token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	*clientToken = envOr(*clientToken, "CHAT_WITH_CLI_CLIENT_TOKEN")
	*agentToken = envOr(*agentToken, "CHAT_WITH_CLI_AGENT_TOKEN")
	if *clientToken == "" || *agentToken == "" {
		return fmt.Errorf("relay requires separate client and agent tokens")
	}

	broker := relay.NewBroker()
	mcpHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		device := strings.TrimSpace(r.URL.Query().Get("device"))
		if device == "" {
			return nil
		}
		return mcpserver.New(relay.RemoteCaller{Broker: broker, Device: device})
	}, &mcp.StreamableHTTPOptions{Stateless: true})

	mux := http.NewServeMux()
	mux.Handle("/mcp", bearerAuth(*clientToken, mcpHandler))
	mux.Handle("/agent", broker.AgentHandler(*agentToken))
	mux.Handle("/devices", bearerAuth(*clientToken, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, "%q\n", broker.Devices())
	})))
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	ctx, cancel := signalContext()
	defer cancel()
	return serveHTTP(ctx, *listen, mux)
}

func runAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	roots, allowExec, allowScreen, allowComputer, stateDir := addEngineFlags(fs)
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
	eng, err := newEngine(*roots, *allowExec, *allowScreen, *allowComputer, *stateDir)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	client := &agent.Client{Engine: eng, URL: *relayURL, Device: *device, Token: *token}
	log.Printf("agent %q connecting to %s", *device, *relayURL)
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
