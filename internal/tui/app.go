// Package tui provides a detachable terminal control center.
// The UI never owns the Agent process, so quitting cannot interrupt MCP calls.
package tui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/ifloppy/chat-with-cli/internal/config"
	"github.com/ifloppy/chat-with-cli/internal/mcpgateway"
)

var pages = []string{"Dashboard", "MCP Servers", "Logs", "Settings", "Help"}

type snapshot struct {
	registry         mcpgateway.Registry
	config           config.Values
	service          string
	serviceInstalled bool
	agentProcess     bool
	logs             []string
	auditLogs        []string
	err              error
}

type snapshotMsg snapshot
type tickMsg struct{}
type noticeMsg string
type commandDoneMsg struct {
	action string
	err    error
}

type Model struct {
	path                string
	configPath          string
	page                int
	cursor              int
	width               int
	height              int
	data                snapshot
	notice              string
	input               bool
	inputText           string
	confirmDelete       bool
	confirmServiceStart bool
	logMode             int // 0=runtime, 1=tool audit metadata
	follow              bool
	initialized         bool
}

func New(configPath string) *Model {
	if configPath == "" {
		dir, _ := os.UserConfigDir()
		configPath = filepath.Join(dir, "chat-with-cli", "config.toml")
	}
	return &Model{path: filepath.Join(filepath.Dir(configPath), "mcp.json"), configPath: configPath, width: 80, height: 24, follow: true}
}

func Run(configPath string) error {
	_, err := tea.NewProgram(New(configPath)).Run()
	return err
}

func readSnapshot(configPath, registryPath string) tea.Cmd {
	return func() tea.Msg {
		var s snapshot
		s.registry, s.err = mcpgateway.Load(registryPath)
		values, err := config.LoadOptional(configPath)
		if err == nil {
			s.config = values
		} else if s.err == nil {
			s.err = err
		}
		state := systemdServiceState()
		s.serviceInstalled = state.Installed
		s.service = state.Label
		s.agentProcess = otherAgentProcessPresent()
		if !state.Active && s.agentProcess {
			s.service = "foreground Agent detected (Relay link unverified)"
		}
		if !state.Active && !s.agentProcess && !state.Installed {
			s.service = "Agent not running"
		}
		s.logs = readJournalLines(100)
		dir, _ := os.UserHomeDir()
		defaultState := filepath.Join(dir, ".local", "state", "chat-with-cli")
		if env := os.Getenv("XDG_STATE_HOME"); env != "" {
			defaultState = filepath.Join(env, "chat-with-cli")
		}
		stateDir := values.String(defaultState, "agent.state_dir")
		s.auditLogs = readAuditLines(stateDir, 100)
		return snapshotMsg(s)
	}
}

func refreshCmd() tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m *Model) Init() tea.Cmd {
	return tea.Batch(readSnapshot(m.configPath, m.path), refreshCmd())
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = v.Width, v.Height
	case snapshotMsg:
		if !m.initialized {
			// Foreground Agents cannot be retroactively attached to the
			// journal; show their existing local audit events by default.
			if v.agentProcess && !strings.HasPrefix(v.service, "running (systemd") {
				m.logMode = 1
			}
			m.initialized = true
		}
		if !m.follow {
			v.logs = m.data.logs
			v.auditLogs = m.data.auditLogs
		}
		m.data = snapshot(v)
		if m.cursor >= len(mcpgateway.ServerIDs(m.data.registry)) {
			m.cursor = max(0, len(m.data.registry.Servers)-1)
		}
	case tickMsg:
		return m, tea.Batch(readSnapshot(m.configPath, m.path), refreshCmd())
	case commandDoneMsg:
		if v.err != nil {
			m.notice = v.action + ": " + v.err.Error()
		} else if v.action == "Managed Agent start" {
			m.notice = "Managed Agent launch requested; open Logs to verify authentication and connection."
		} else {
			m.notice = v.action + " finished"
		}
		return m, readSnapshot(m.configPath, m.path)
	case tea.KeyPressMsg:
		key := v.String()
		if m.input {
			switch key {
			case "esc":
				m.input = false
				m.inputText = ""
				m.notice = "Add canceled"
			case "enter":
				m.addServer()
			case "backspace":
				if len(m.inputText) > 0 {
					runes := []rune(m.inputText)
					m.inputText = string(runes[:len(runes)-1])
				}
			default:
				if v.Key().Text != "" {
					m.inputText += v.Key().Text
				}
			}
			return m, nil
		}
		if m.confirmServiceStart {
			m.confirmServiceStart = false
			if key == "y" || key == "Y" {
				return m, func() tea.Msg {
					out, err := exec.Command("systemctl", "--user", "start", "chat-with-cli-agent.service").CombinedOutput()
					if err != nil {
						return commandDoneMsg{action: "Start user service (" + truncate(string(out), 120) + ")", err: err}
					}
					return commandDoneMsg{action: "User service started"}
				}
			}
			m.notice = "Service start canceled"
			return m, nil
		}
		if m.confirmDelete {
			switch key {
			case "y", "Y":
				m.changeSelected("remove")
			default:
				m.notice = "Deletion canceled"
			}
			m.confirmDelete = false
			return m, readSnapshot(m.configPath, m.path)
		}
		switch key {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "tab", "right":
			m.page = (m.page + 1) % len(pages)
			m.cursor = 0
		case "shift+tab", "left":
			m.page = (m.page + len(pages) - 1) % len(pages)
			m.cursor = 0
		case "1", "2", "3", "4", "5":
			m.page = int(key[0] - '1')
			m.cursor = 0
		case "up", "k":
			if m.page == 1 && m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.page == 1 && m.cursor+1 < len(m.data.registry.Servers) {
				m.cursor++
			}
		case "a":
			if m.page == 1 {
				m.input = true
				m.inputText = ""
				m.notice = ""
			}
		case "e":
			if m.page == 1 {
				m.changeSelected("enable")
			}
		case "x":
			if m.page == 1 {
				m.changeSelected("expose")
			}
		case "d":
			if m.page == 1 && len(m.data.registry.Servers) > 0 {
				m.confirmDelete = true
			}
		case "c":
			if m.data.agentProcess || strings.HasPrefix(m.data.service, "running") {
				m.notice = "An Agent is already running. See Logs -> g for recent tool calls."
				return m, nil
			}
			if m.data.config == nil || m.data.config.String("", "agent.identity") == "" {
				m.notice = "Configure a workstation first: press o to open the setup menu."
				return m, nil
			}
			m.notice = "Starting managed Agent in background..."
			return m, func() tea.Msg {
				binary, err := os.Executable()
				if err != nil {
					return commandDoneMsg{action: "Find Agent binary", err: err}
				}
				return commandDoneMsg{action: "Managed Agent start", err: startManagedAgent(binary, m.configPath)}
			}
		case "o":
			return m, tea.ExecProcess(exec.Command(os.Args[0], "menu"), func(err error) tea.Msg { return commandDoneMsg{action: "Setup menu", err: err} })
		case "s":
			if !m.data.serviceInstalled {
				m.notice = "Systemd user service is not installed; press o for setup."
				return m, nil
			}
			if m.data.agentProcess || strings.HasPrefix(m.data.service, "running") {
				m.notice = "An Agent/CLI process is already active."
				return m, nil
			}
			m.confirmServiceStart = true
		case "g":
			if m.page == 2 {
				m.logMode = 1 - m.logMode
			}
		case "f":
			if m.page == 2 {
				m.follow = !m.follow
				if m.follow {
					return m, readSnapshot(m.configPath, m.path)
				}
			}
		case "l":
			m.page = 2
		case "r":
			return m, readSnapshot(m.configPath, m.path)
		}
	}
	return m, nil
}

func (m *Model) selected() (string, mcpgateway.ServerConfig, bool) {
	ids := mcpgateway.ServerIDs(m.data.registry)
	if m.cursor < 0 || m.cursor >= len(ids) {
		return "", mcpgateway.ServerConfig{}, false
	}
	id := ids[m.cursor]
	return id, m.data.registry.Servers[id], true
}

func (m *Model) changeSelected(action string) {
	id, cfg, ok := m.selected()
	if !ok {
		return
	}
	r, err := mcpgateway.Load(m.path)
	if err != nil {
		m.notice = err.Error()
		return
	}
	cfg, ok = r.Servers[id]
	if !ok {
		m.notice = "MCP entry changed; refresh"
		return
	}
	switch action {
	case "enable":
		cfg.Enabled = !cfg.Enabled
	case "expose":
		cfg.Expose = !cfg.Expose
	case "remove":
		delete(r.Servers, id)
	}
	if action != "remove" {
		r.Servers[id] = cfg
	}
	if err := mcpgateway.Save(m.path, r); err != nil {
		m.notice = err.Error()
		return
	}
	m.data.registry = r
	m.notice = "Updated " + id + " (" + action + "); Agent picks up changes on next gateway call"
}

func (m *Model) addServer() {
	// This quick-add intentionally only supports single-token arguments.
	// Complex JSON arrays and secrets can be managed in the registry file.
	parts := strings.Fields(m.inputText)
	if len(parts) < 3 {
		m.notice = "Use: ID stdio COMMAND [ARGS...]  or  ID http URL"
		return
	}
	id := parts[0]
	r, err := mcpgateway.Load(m.path)
	if err != nil {
		m.notice = err.Error()
		return
	}
	if _, exists := r.Servers[id]; exists {
		m.notice = "Server ID already exists"
		return
	}
	cfg := mcpgateway.ServerConfig{Enabled: true, Expose: true}
	switch parts[1] {
	case "stdio":
		cfg.Transport, cfg.Command, cfg.Args = "stdio", parts[2], parts[3:]
	case "http":
		if len(parts) != 3 {
			m.notice = "HTTP requires one URL"
			return
		}
		cfg.Transport, cfg.URL = "streamable-http", parts[2]
	default:
		m.notice = "Transport must be stdio or http"
		return
	}
	r.Servers[id] = cfg
	if err := mcpgateway.Save(m.path, r); err != nil {
		m.notice = err.Error()
		return
	}
	m.data.registry = r
	m.notice = "Added " + id
	m.input = false
	m.inputText = ""
}

func truncate(s string, n int) string {
	r := []rune(s)
	if n < 4 {
		return ""
	}
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func (m *Model) View() tea.View {
	var b strings.Builder
	width := max(45, m.width)
	b.WriteString("\x1b[1;36m CHAT WITH CLI \x1b[0m  Workstation Control Center\n")
	b.WriteString(strings.Repeat("─", min(width, 110)) + "\n")
	for i, p := range pages {
		if i == m.page {
			fmt.Fprintf(&b, "\x1b[7m %d %s \x1b[0m", i+1, p)
		} else {
			fmt.Fprintf(&b, " %d %s ", i+1, p)
		}
	}
	b.WriteString("\n" + strings.Repeat("─", min(width, 110)) + "\n\n")
	if m.data.err != nil {
		fmt.Fprintf(&b, "\x1b[31mConfiguration error: %v\x1b[0m\n", m.data.err)
	}
	switch m.page {
	case 0:
		fmt.Fprintf(&b, "  Agent service     %s\n", m.data.service)
		if m.data.config != nil {
			fmt.Fprintf(&b, "  Relay             %s\n", m.data.config.String("(not configured)", "agent.relay_url"))
			fmt.Fprintf(&b, "  Device            %s\n", m.data.config.String("(not configured)", "agent.device"))
			fmt.Fprintf(&b, "  Capability        %s\n", m.data.config.String("read-only", "agent.profile"))
		}
		fmt.Fprintf(&b, "  Downstream MCPs   %d configured\n", len(m.data.registry.Servers))
		active := 0
		for _, cfg := range m.data.registry.Servers {
			if cfg.Enabled && cfg.Expose {
				active++
			}
		}
		fmt.Fprintf(&b, "  Gateway exposure  %d enabled\n\n", active)
		b.WriteString("  c Start background Agent (TUI stays open)   o Setup menu\n")
		b.WriteString("  s Start installed user service (asks confirmation)\n")
		b.WriteString("  l Logs: runtime + tool audit, refreshes every second\n")
		b.WriteString("  The TUI is detachable: q quits the UI, not the Agent.\n")
		if m.confirmServiceStart {
			b.WriteString("  Start chat-with-cli-agent.service? Press y to confirm.\n")
		}
	case 1:
		b.WriteString("  ID                      TRANSPORT          ENABLED  EXPOSED\n")
		ids := mcpgateway.ServerIDs(m.data.registry)
		if len(ids) == 0 {
			b.WriteString("  No downstream servers. Press a to add one.\n")
		}
		for i, id := range ids {
			cfg := m.data.registry.Servers[id]
			prefix := "  "
			if i == m.cursor {
				prefix = "> "
			}
			fmt.Fprintf(&b, "%s%-23s %-18s %-8t %t\n", prefix, truncate(id, 23), cfg.Transport, cfg.Enabled, cfg.Expose)
		}
		b.WriteString("\n  a Add   e Enable/disable   x Expose/hide   d Remove   j/k Select\n")
		if m.input {
			b.WriteString("\n  Add MCP: ID stdio COMMAND [ARGS...] | ID http URL\n  > " + m.inputText + "█\n  Enter Save   Esc Cancel\n")
		}
		if m.confirmDelete {
			id, _, _ := m.selected()
			b.WriteString("\n  Delete " + id + "? Press y to confirm, any other key to cancel\n")
		}
	case 2:
		source := "Runtime (systemd journal)"
		lines := m.data.logs
		if m.logMode == 1 {
			source = "Tool audit (metadata only)"
			lines = m.data.auditLogs
		}
		followState := "LIVE"
		if !m.follow {
			followState = "PAUSED"
		}
		fmt.Fprintf(&b, "  %s — %s\n", source, followState)
		b.WriteString("  g Toggle runtime/audit   f Pause/resume refresh   r Refresh now\n\n")
		maxLines := max(4, m.height-12)
		if len(lines) > maxLines {
			lines = lines[len(lines)-maxLines:]
		}
		for _, line := range lines {
			fmt.Fprintf(&b, "  %s\n", truncate(sanitizeTerminalLog(line), width-5))
		}
	case 3:
		b.WriteString("  Agent settings are stored in the existing config.toml.\n")
		b.WriteString("  MCP registry: " + m.path + "\n")
		b.WriteString("  Existing advanced setup: chat-with-cli menu\n")
		b.WriteString("  CLI alternative: chat-with-cli mcp list|add|enable|disable|remove\n")
		b.WriteString("  Service management: systemctl --user status chat-with-cli-agent\n")
	case 4:
		b.WriteString("  Tab / arrows  Change page         1-5   Jump to page\n")
		b.WriteString("  j / k         Select server       r     Refresh\n")
		b.WriteString("  q             Quit TUI only       Ctrl+C Quit\n")
		b.WriteString("  a / e / x / d Add / toggle / expose / delete MCP entry\n\n")
		b.WriteString("  c Start background Agent without leaving TUI, o Setup menu\n")
		b.WriteString("  l Logs page, g Switch runtime/audit, f Pause/resume log refresh\n")
		b.WriteString("  s Start installed user service with confirmation\n")
		b.WriteString("  Foreground process detection does NOT verify network connectivity.\n")
	}
	if m.notice != "" {
		b.WriteString("\n\x1b[33m  " + truncate(m.notice, width-4) + "\x1b[0m\n")
	}
	b.WriteString("\n" + strings.Repeat("─", min(width, 110)) + "\n")
	b.WriteString("  q Quit UI   Tab Navigate   l Logs   r Refresh   5 Help")
	view := tea.NewView(b.String())
	view.AltScreen = true
	view.WindowTitle = "Chat With CLI"
	return view
}
