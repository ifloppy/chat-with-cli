package tui

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// otherAgentProcessPresent finds local foreground Agent processes without
// confusing other open TUI windows with an Agent. This is not a network check.
func otherAgentProcessPresent() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	self := os.Getpid()
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == self {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil || len(raw) == 0 {
			continue
		}
		parts := strings.Split(string(raw), "\x00")
		if filepath.Base(parts[0]) != "chat-with-cli" {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
		if err != nil || strings.TrimSpace(string(comm)) != "chat-with-cli" {
			continue
		}
		if len(parts) > 1 && (parts[1] == "agent" || parts[1] == "connect") {
			return true
		}
	}
	return false
}
