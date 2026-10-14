# MCP Gateway and terminal UI (early implementation)

## Terminal controls

Run `chat-with-cli` or `chat-with-cli ui` from a real TTY for the new Bubble Tea
dashboard. Use Tab or 1–5 to switch pages, `q` to quit, and `r` to refresh.
In **MCP Servers**, `j/k` selects a server, `a` adds one, `e` toggles enabled,
`x` toggles exposure, and `d` requests deletion confirmation.

The TUI displays foreground Agent process detection, managed service status,
and two live log sources in the Logs tab: **Runtime** (user systemd journal)
and **Tool audit** (recent redacted local `audit/events.jsonl` metadata).
Press `l` to open Logs, `g` to switch sources, `f` to pause/resume updates,
and `r` to refresh. Logs normally refresh every second without leaving TUI.
Existing foreground Agents are visible through their audit events, but their
old terminal stderr cannot be retrospectively captured.

Press `c` to start a background Agent through `systemd-run --user`; the
TUI stays on screen and new Agent runtime logs appear in Logs. If an Agent
user service is already installed, `c` starts that service instead. Existing
foreground Agent processes are detected and block accidental duplicate starts.
The Agent uses the *configured* permission profile; TUI does not silently
escalate permissions. `o` opens the existing interactive setup/OAuth menu,
and `s` starts an installed user unit after confirmation.

The current control center does not yet use a dedicated Agent IPC socket or
allow interactive approval prompts through the TUI itself. If OAuth needs
initial browser approval or a credential must be renewed, use the existing
setup/login flow before starting the background Agent.

Quitting the TUI never stops an already running Agent. The installed systemd
user service is still managed with `systemctl --user`.

## Configure downstream MCPs

The Gateway reads `$XDG_CONFIG_HOME/chat-with-cli/mcp.json` (normally
`~/.config/chat-with-cli/mcp.json`). It is optional, versioned JSON and must be
a regular file. An Agent using `--config` reads `mcp.json` alongside that config.

```sh
chat-with-cli mcp add playwright stdio npx -y @playwright/mcp
chat-with-cli mcp add local-tools http http://127.0.0.1:3000/mcp
chat-with-cli mcp list
chat-with-cli mcp test playwright
chat-with-cli mcp hide playwright
chat-with-cli mcp expose playwright
chat-with-cli mcp disable playwright
chat-with-cli mcp enable playwright
chat-with-cli mcp remove playwright
```

The CLI deliberately passes command arguments as separate argv entries rather
than a shell command. The TUI's current quick-add accepts simple
whitespace-separated arguments; use the CLI or edit JSON for arguments containing
spaces, environment variables, or advanced options. No commands are executed
during add/save; execution starts when the enabled and exposed MCP is queried.

Registry example:

```json
{
  "version": 1,
  "servers": {
    "example": {
      "transport": "stdio",
      "command": "my-mcp-server",
      "args": ["--read-only"],
      "enabled": true,
      "expose": true
    }
  }
}
```

This initial implementation supports MCP **tools** over stdio and Streamable
HTTP, with lazy client connection, schema discovery, and a 1 MiB result limit.
Changes to enabled/exposed/configured servers are reloaded on the next Gateway
tool call; existing sessions are closed when a server is changed or disabled.

On ChatGPT, refresh or scan app actions after the Relay advertises new tool
descriptors. Start with `mcp_servers_list`, then `mcp_tools_search`,
`mcp_tool_inspect`, and finally `mcp_tool_call`. This avoids publishing
hundreds of downstream tools to the model's top-level catalog.

## Security and limitations

- The Gateway executes configured stdio commands **with the Agent process's
  OS permissions**. Existing native file-root/exec-sandbox restrictions are **not**
  inherited by downstream MCP processes. Only enable and expose trusted servers.
- `enabled` controls whether a server can be connected; `expose` controls whether
  remote MCP clients can discover/call it. Both must be true for Gateway access.
- This is a first increment, not the full planned control plane: no per-tool
  allowlist, on-screen approval queue, local IPC API, automatic cross-client
  import, or native MCP resource/prompt forwarding yet.
- The generic `mcp_tool_call` returns JSON-friendly content rather than native
  images as top-level ChatGPT content. Oversized/binary results are rejected.
  Complex multi-round-trip input requests are not handled yet.
- The Relay does not execute downstream tools. The workstation Agent does.
  Old and new Relay/Agent versions interoperate for existing tools. Gateway tools
  appear only after a new Agent negotiates the feature with a new Relay; see
  [compatibility and safe upgrades](compatibility-upgrade.md).
- The Gateway never auto-imports another client's MCP configuration or takes
  over an existing stdio session. Every server must be explicitly configured.

## Development checks

```sh
go test ./...
go test -race ./internal/mcpgateway ./internal/mcpserver ./cmd/chat-with-cli
go vet ./...
go build ./cmd/chat-with-cli
```
