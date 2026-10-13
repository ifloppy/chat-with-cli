package tui

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// otherCLIProcessPresent only detects likely foreground CLI processes. It is
// deliberately NOT an authenticated Agent health check; show that distinction
// in the UI and do not claim a network connection from a process name alone.
func otherCLIProcessPresent() bool {
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
		first := strings.SplitN(string(raw), "\x00", 2)[0]
		if filepath.Base(first) != "chat-with-cli" {
			continue
		}
		// Self-built test programs may share argv[0]. Use the kernel's process
		// name as a second check to avoid common shell/grep false positives.
		comm, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
		if err == nil && strings.TrimSpace(string(comm)) == "chat-with-cli" {
			return true
		}
	}
	return false
}
