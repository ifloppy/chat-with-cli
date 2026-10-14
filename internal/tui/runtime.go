package tui

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ifloppy/chat-with-cli/internal/config"
)

const agentUnit = "chat-with-cli-agent.service"

type serviceState struct {
	Installed bool
	Active    bool
	Label     string
}

// systemdServiceState distinguishes running units from unmanaged CLI sessions.
// Querying systemd never starts, replaces, or stops a running Agent.
func systemdServiceState() serviceState {
	state := serviceState{Label: "no managed Agent"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "--user", "show", agentUnit, "--property=LoadState,ActiveState", "--no-pager").Output()
	if err != nil {
		return state
	}
	for _, line := range strings.Split(string(out), "\n") {
		if line == "LoadState=loaded" {
			state.Installed = true
		}
		if line == "ActiveState=active" {
			state.Active = true
		}
	}
	if state.Active {
		state.Label = "running (systemd user; Relay link unverified)"
	} else if state.Installed {
		state.Label = "systemd user unit installed but stopped"
	}
	return state
}

// startManagedAgent uses the existing user unit, or launches an ephemeral
// systemd user unit if not installed. Neither path claims the terminal.
// No generated login tokens or environment secrets are placed in argv.
func startManagedAgent(binary, configPath string) error {
	if binary == "" || !filepath.IsAbs(binary) {
		return errors.New("Agent executable must have an absolute path")
	}
	if !filepath.IsAbs(configPath) {
		return errors.New("Agent config must have an absolute path")
	}
	if _, err := config.Load(configPath); err != nil {
		return fmt.Errorf("Agent config: %w", err)
	}
	state := systemdServiceState()
	if state.Active {
		return errors.New("Agent user service is already running")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var command *exec.Cmd
	if state.Installed {
		command = exec.CommandContext(ctx, "systemctl", "--user", "start", agentUnit)
	} else {
		command = exec.CommandContext(ctx, "systemd-run", "--user", "--collect", "--unit=chat-with-cli-agent",
			"--description=Chat With CLI managed Agent",
			"--property=Restart=on-failure", "--property=RestartSec=5s",
			binary, "agent", "--config", configPath, "--approval-mode=configured")
	}
	out, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("start Agent: %w (%s)", err, truncate(strings.TrimSpace(string(out)), 180))
	}
	return nil
}

func readJournalLines(maxLines int) []string {
	if maxLines <= 0 || maxLines > 150 {
		maxLines = 80
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "journalctl", "--user", "-u", agentUnit,
		"-n", fmt.Sprint(maxLines), "--no-pager", "--output=short-iso")
	output, err := cmd.Output()
	if err != nil {
		return []string{"No Agent journal available yet. Start the managed Agent with c."}
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 1 && (lines[0] == "" || strings.Contains(lines[0], "-- No entries --")) {
		return []string{"No managed Agent runtime logs yet. Tool calls are available in the Audit view (g)."}
	}
	return lines
}

// Audit entries are intentionally metadata-only (method, duration and success).
// Read only a bounded tail rather than loading a multi-megabyte audit file
// every time the UI refreshes.
func readAuditLines(stateDir string, limit int) []string {
	if limit <= 0 || limit > 160 {
		limit = 80
	}
	path := filepath.Join(stateDir, "audit", "events.jsonl")
	fileInfo, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return []string{"No tool audit events yet."}
	}
	if err != nil {
		return []string{"Cannot inspect tool audit log: " + err.Error()}
	}
	if !fileInfo.Mode().IsRegular() || fileInfo.Mode()&os.ModeSymlink != 0 || fileInfo.Mode().Perm()&0o077 != 0 {
		return []string{"Unsafe audit log permissions or path; refusing to read."}
	}
	f, err := os.Open(path)
	if err != nil {
		return []string{"Cannot open tool audit log: " + err.Error()}
	}
	defer f.Close()
	// Check the file descriptor as well as lstat; reject replacement races.
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(fileInfo, opened) {
		return []string{"Audit log changed while opening; retrying next refresh."}
	}
	const maxTail int64 = 192 << 10
	start := opened.Size() - maxTail
	if start < 0 {
		start = 0
	}
	if _, err = f.Seek(start, io.SeekStart); err != nil {
		return []string{"Cannot seek tool audit log."}
	}
	reader := bufio.NewReader(io.LimitReader(f, maxTail))
	if start > 0 {
		_, _ = reader.ReadString('\n')
	} // skip partial first JSON line
	result := make([]string, 0, limit)
	for {
		line, err := reader.ReadString('\n')
		if line != "" && strings.HasSuffix(line, "\n") {
			var event struct {
				Time       time.Time `json:"time"`
				Method     string    `json:"method"`
				DurationMS int64     `json:"duration_ms"`
				OK         bool      `json:"ok"`
			}
			if json.Unmarshal([]byte(line), &event) == nil && event.Method != "" {
				status := "OK"
				if !event.OK {
					status = "FAIL"
				}
				result = append(result, fmt.Sprintf("%s   %-4s %-26s %dms", event.Time.Local().Format("15:04:05"), status, event.Method, event.DurationMS))
				if len(result) > limit {
					result = result[1:]
				}
			}
		}
		if err != nil {
			break
		}
	}
	if len(result) == 0 {
		return []string{"No recent tool audit events."}
	}
	return result
}

// Strip terminal control characters from logs before displaying them.
func sanitizeTerminalLog(line string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, line)
}
