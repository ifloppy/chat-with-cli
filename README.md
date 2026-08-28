# chat-with-cli

Open-source remote development bridge for AI agents.

`chat-with-cli` is a small Go service that lets an MCP client work on an authorized computer through bounded filesystem tools, persistent PTY tasks, durable checkpoints, and optional computer-use controls.

The project is designed for long-running application development rather than one-shot shell execution: commands survive individual MCP calls, logs are incremental, multiple tasks can run concurrently, and another chat/session can resume from a workspace checkpoint.

> Status: early alpha. Linux is the first supported host. The protocol and security model are intentionally kept small enough to audit.

## Design goals

- Fully open source from public MCP endpoint to local agent.
- One small Go binary for relay, agent, local MCP, and direct HTTP MCP modes.
- Long-running tasks that do not die when a tool call ends.
- Efficient incremental output instead of repeatedly returning entire logs.
- Multiple independent workstreams on one machine.
- Explicit capability gates for shell, screenshots, and keyboard/mouse control.
- Filesystem roots that are opt-in and symlink-aware.
- Safe surgical file edits with exact-match validation.
- Simple self-hosting behind Caddy/Nginx without inbound ports on the workstation.

## Architecture

```text
ChatGPT / MCP client
        |
        | HTTPS / MCP Streamable HTTP
        v
+-------------------+
|       Relay       |  public VPS, OAuth + request routing
+-------------------+
        |
        | outbound WebSocket initiated by the workstation
        v
+-------------------+
|       Agent       |  capability policy + task/file/computer engine
+-------------------+
    |       |      |
    |       |      +-- screenshot / keyboard / pointer (optional)
    |       +--------- bounded filesystem + checkpoints
    +----------------- persistent PTY tasks + capped logs
```

The Relay cannot initiate a network connection to the workstation. The Agent establishes the connection outbound and reconnects automatically. Requests carry independent IDs, so unrelated tool calls can be in flight concurrently.

A direct `local` stdio mode and a direct `serve` HTTP mode are also available when a Relay is unnecessary.

## Security defaults

All powerful capabilities are disabled unless explicitly granted:

| Capability | Default | Enable |
| --- | --- | --- |
| Read/write files | only inside `--root` | add one or more `--root` paths |
| Arbitrary shell / PTY | off | `--allow-exec` |
| Screen + read-only accessibility | off | `--allow-screen` |
| GUI writes + keyboard/mouse | off | `--allow-computer-use` |

`--allow-computer-use` also enables screenshots. Computer-control MCP tools are marked destructive/open-world hints because the focused GUI may be a browser, chat client, admin console, or another application with external side effects.

The public Relay supports MCP OAuth 2.1-style authorization with RFC 9728 protected-resource discovery, Dynamic Client Registration, mandatory PKCE S256, rotating refresh tokens, and resource-bound access tokens. OAuth state survives Relay restarts without storing raw access/refresh tokens. A separate high-entropy Agent bearer token authenticates workstation WebSocket connections; an optional static MCP bearer remains available for CLI/debug compatibility. Terminate public traffic with TLS in a trusted reverse proxy.

Task logs are capped at 64 MiB per task by default. After the cap is reached, the PTY continues to be drained so the child process does not deadlock; the task is marked `log_truncated`. Concurrent PTY tasks are capped at 32 by default and can be tuned with `--max-active-tasks`.

See [SECURITY.md](SECURITY.md) for the threat model and residual risks.

## Computer Use

Computer Use is intentionally a backend interface rather than a privileged input hack.

On Linux the current alpha uses:

- **Semantic UI:** pure-Go AT-SPI2 tree/search with roles, names, states, bounds, focus and actions.
- **Screenshot:** KWin ScreenShot2 D-Bus fast path when authorized, with Spectacle/`grim`/GNOME Screenshot fallbacks.
- **Wayland input:** pure-Go XDG RemoteDesktop Portal first; `wdotool` is an optional fallback.
- **X11 input:** `xdotool` fallback.

`ydotool` is deliberately not auto-selected because `/dev/uinput` bypasses the compositor permission boundary. The Portal backend keeps KDE/GNOME consent and revocation in the OS security model while keeping the Agent itself CGO-free.

Screenshots are returned directly as MCP image content, not as base64 text in the model conversation. PNG and JPEG output are supported. If an Agent is launched without GUI environment variables, Linux desktop-session variables are recovered from the logged-in user's runtime directory where possible.

Preferred interaction loop:

1. Start with `computer_observe` when GUI state is unknown. Its default `screenshot=auto` returns bounded visible AT-SPI data and only transfers an image when semantic UI is insufficient.
2. Prefer `computer_ui_invoke` for a unique semantic action. It performs selection and action on one AT-SPI connection, refuses ambiguous selectors, and returns candidates instead of guessing. Set `timeout_ms` when the control may appear asynchronously.
3. Prefer `computer_ui_get_text` / `computer_ui_set_text` for text controls: they uniquely select visible AT-SPI `Text` / `EditableText` elements, enabling bounded reads and direct UTF-8 replacement without OCR, pointer focus, or simulated keystrokes.
4. Use `computer_ui_find` / `computer_ui_wait` for inspection, disambiguation, and state synchronization. Treat returned refs as short-lived handles.
5. Fall back to `computer_screenshot` + pointer coordinates only when semantic UI is unavailable. Verify consequential results with semantic state or a screenshot.

### Agent-friendly call patterns

Keep Computer Use calls narrow and state-driven. A recommended sequence is `computer_observe` -> `computer_ui_invoke`/`computer_ui_get_text`/`computer_ui_set_text` -> `computer_ui_wait`. Both atomic mutation tools can optionally wait for `not_found` selectors, avoiding a separate wait call. Avoid repeated screenshots when a semantic condition can be waited on. For `computer_ui_invoke`, zero matches return `not_found`, multiple matches return `ambiguous` with candidate nodes, and elements with multiple possible semantic actions return `ambiguous_action` unless an action name is supplied. If a bounded search ends before uniqueness can be proven, it returns `search_incomplete` and performs no action.

For pixel-only applications, request JPEG screenshots for routine navigation and PNG only when exact pixels/text rendering matter. Low-level `move`/`click`/`type`/`key` remain deliberate escape hatches for canvas, games, remote desktops, and poorly accessible Electron/WebView interfaces.

Portal consent persistence defaults to `--computer-persist=process`: the live Agent can rotate one-time restore tokens and recover a closed session without turning the machine into permanently unattended remote control. Use `none` to disable restoration, or explicitly choose `persistent` to store the rotating restore token in the Agent state directory with mode `0600`.

## Build

Requires Go 1.26 or newer for the current development branch.

```bash
git clone https://github.com/ifloppy/chat-with-cli.git
cd chat-with-cli
go test ./...
go build -o chat-with-cli ./cmd/chat-with-cli
```

## Local MCP

```bash
./chat-with-cli local \
  --root "$HOME/project" \
  --allow-exec
```

For read-only visual/semantic access, add `--allow-screen`. For full visual control, add `--allow-computer-use`. Portal persistence can be set with `--computer-persist=none|process|persistent`.

## Direct HTTP MCP

```bash
export CHAT_WITH_CLI_CLIENT_TOKEN="$(./chat-with-cli token)"
./chat-with-cli serve --listen 127.0.0.1:8765 --root "$HOME/project"
```

The MCP endpoint is `/mcp`; `/health` is available for health checks.

## Relay + Agent

Generate independent high-entropy secrets for the workstation and OAuth consent:

```bash
./chat-with-cli token   # Agent token
./chat-with-cli token   # OAuth authorization password
```

On the public relay host behind TLS:

```bash
export CHAT_WITH_CLI_AGENT_TOKEN='...'
export CHAT_WITH_CLI_OAUTH_PASSWORD='...'
export CHAT_WITH_CLI_PUBLIC_URL='https://cli.example.com'
./chat-with-cli relay --listen 127.0.0.1:8765
```

`CHAT_WITH_CLI_CLIENT_TOKEN` is optional and only needed for legacy/static-token MCP clients and the `/devices` helper endpoint.

On the workstation:

```bash
export CHAT_WITH_CLI_AGENT_TOKEN='...'
./chat-with-cli agent \
  --relay https://cli.example.com \
  --device workstation \
  --root "$HOME/project" \
  --allow-exec
```

The remote MCP URL for that machine is:

```text
https://cli.example.com/mcp/workstation
```

The workstation needs only outbound HTTPS/WebSocket access. See [docs/deployment.md](docs/deployment.md) for Caddy and systemd examples.

## Connect from ChatGPT Web

Once the Relay is available over public HTTPS and the Agent is connected, create a custom MCP app in ChatGPT developer mode and use the device-specific URL, for example `https://cli.example.com/mcp/workstation`. Select OAuth authentication; ChatGPT discovers the protected-resource and authorization-server metadata, dynamically registers itself, opens the Relay authorization page, and exchanges a PKCE-protected authorization code. Enter `CHAT_WITH_CLI_OAUTH_PASSWORD` only on your own Relay authorization page. No OAuth client ID or secret needs to be preconfigured.

The resulting OAuth access and refresh tokens are bound to that exact MCP resource URL, so authorizing `workstation` does not authorize another device. To revoke every ChatGPT authorization immediately, stop the Relay and remove its OAuth state file before restarting it; changing `CHAT_WITH_CLI_OAUTH_PASSWORD` only affects new authorizations.

ChatGPT product availability is separate from server compatibility. OpenAI currently documents full custom-MCP write/modify actions for Business and Enterprise/Edu workspaces; other plans may expose only a subset of custom-app functionality. See the current OpenAI developer-mode documentation before relying on write actions.

## MCP tools

### Long-running tasks

- `task_start` — start a PTY-backed command and immediately return a task ID.
- `task_read` — read a bounded log slice from a byte offset.
- `task_wait` — long-poll for new output or completion instead of rapid polling.
- `task_send` — send text/control input to an interactive PTY.
- `task_stop` — send TERM/INT/HUP/KILL to the process group.
- `task_list` — recover active and historical task IDs.

### Files and continuity

- `fs_read` — bounded byte-range reads.
- `fs_write` — rewrite or append inside an allowed root.
- `fs_patch` — exact-match surgical replacement with expected-count validation.
- `fs_list` — bounded-depth tree listing with dependency/cache noise skipped.
- `fs_search` — bounded regex search with binary/large-file protection.
- `checkpoint_write` / `checkpoint_read` — durable workspace handoff between chats or agents.

### Computer Use

- `computer_info`, `computer_observe`, `computer_screenshot`
- `computer_ui_tree`, `computer_ui_find`, `computer_ui_wait`
- `computer_ui_invoke` — unique selector + optional wait + semantic action in one call; refuses ambiguity/incomplete searches.
- `computer_ui_get_text` — bounded read from one unique visible AT-SPI Text control, avoiding OCR.
- `computer_ui_set_text` — unique editable selector + direct AT-SPI text replacement, avoiding keyboard injection.
- `computer_ui_focus`, `computer_ui_action` — lower-level short-lived-ref operations.
- `computer_move`, `computer_click`, `computer_scroll`
- `computer_type`, `computer_key`

## Roadmap

- Optional native libei/EIS fast path for very high-frequency input; D-Bus Portal input is already implemented.
- Paired ScreenCast/PipeWire capture for compositor-native multi-monitor coordinates.
- Windows and macOS host backends behind the same capability interface.
- Per-device credentials and key rotation.
- Configurable task-log retention and garbage collection.
- Task groups/dependencies for larger multi-agent workstreams.
- Optional audit event stream with secret redaction.
- Signed release binaries and reproducible release metadata.

## Non-goals

This is not intended to silently bypass OS security boundaries, become an unattended RAT, or hide AI actions from the machine owner. Desktop-control permissions are explicit and should remain visible/revocable at the OS and Agent layers.

## License

Apache-2.0. See [LICENSE](LICENSE).
