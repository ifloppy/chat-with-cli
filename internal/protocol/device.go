package protocol

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
