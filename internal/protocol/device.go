package protocol

import "strings"

// ValidDeviceName reports whether name is safe for use in Relay URLs and
// routing keys. Keeping this ASCII-only makes the canonical MCP resource URL
// stable across proxies, OAuth clients, and WebSocket agents.
func ValidDeviceName(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

// ValidDeviceID accepts the immutable 128-bit identifier used by the modern
// device route. Human-readable names remain labels only; callers should use
// this identifier as the authorization/resource key.
func NormalizeDeviceID(id string) (string, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	if len(id) != 32 {
		return "", false
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'f') || (r >= '0' && r <= '9') {
			continue
		}
		return "", false
	}
	return id, true
}

func ValidDeviceID(id string) bool {
	_, ok := NormalizeDeviceID(id)
	return ok
}

// AgentCapabilities is a deliberately small, privacy-preserving capability
// report sent by an Agent after its authenticated WebSocket is established.
// It contains policy state only; roots, hostnames, environment, and tool data
// never cross the Relay boundary through this message.
type AgentCapabilities struct {
	FilesystemRead    bool   `json:"filesystem_read"`
	FilesystemWrite   bool   `json:"filesystem_write"`
	Exec              bool   `json:"exec"`
	ExecSandbox       string `json:"exec_sandbox,omitempty"`
	ScreenRead        bool   `json:"screen_read"`
	AccessibilityRead bool   `json:"accessibility_read"`
	ComputerInput     bool   `json:"computer_input"`
	MaxActiveTasks    int    `json:"max_active_tasks,omitempty"`
}
