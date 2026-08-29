// Package version owns the single build-time version value used by the CLI,
// MCP metadata, Relay pages, and release tooling. It is a variable so local
// and CI builds can stamp a candidate without editing Go source.
package version

var Value = "0.1.0-alpha.5"
