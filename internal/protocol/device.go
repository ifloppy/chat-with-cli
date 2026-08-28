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
func ValidDeviceID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, r := range strings.ToLower(id) {
		if (r >= 'a' && r <= 'f') || (r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}
