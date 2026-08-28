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
|       Relay       |  public VPS, stateless request routing
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
| Desktop screenshots | off | `--allow-screen` |
| Keyboard and mouse | off | `--allow-computer-use` |

`--allow-computer-use` also enables screenshots. Computer-control MCP tools are marked destructive/open-world hints because the focused GUI may be a browser, chat client, admin console, or another application with external side effects.

Relay authentication uses separate client and Agent bearer tokens and constant-time comparisons. For internet deployment, terminate TLS in a trusted reverse proxy. Static bearer tokens are the alpha authentication mechanism; standards-based OAuth support is on the roadmap.

Task logs are capped at 64 MiB per task by default. After the cap is reached, the PTY continues to be drained so the child process does not deadlock; the task is marked `log_truncated`.

See [SECURITY.md](SECURITY.md) for the threat model and residual risks.

## Computer Use

Computer Use is intentionally a backend interface rather than a privileged input hack.

On Linux the current alpha detects:

- **Screenshot:** KDE Spectacle, `grim`, GNOME Screenshot, then ImageMagick on X11.
- **Wayland input:** [`wdotool`](https://github.com/cushycush/wdotool), which uses compositor-supported mechanisms such as XDG RemoteDesktop Portal/libei.
- **X11 input:** `xdotool`.

`ydotool` is deliberately not auto-selected because `/dev/uinput` bypasses the compositor permission boundary. A future native Go Portal/libei backend can remove the optional `wdotool` runtime dependency.

Screenshots are returned directly as MCP image content, not as base64 text in the model conversation. PNG and JPEG output are supported.

Typical visual loop:

1. `computer_screenshot`
2. reason about the visible UI
3. `computer_move` + `computer_click`, or `computer_type` / `computer_key`
4. `computer_screenshot` again to verify the result

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

For read-only visual access, add `--allow-screen`. For full visual control, add `--allow-computer-use`.

## Direct HTTP MCP

```bash
export CHAT_WITH_CLI_CLIENT_TOKEN="$(./chat-with-cli token)"
./chat-with-cli serve --listen 127.0.0.1:8765 --root "$HOME/project"
```

The MCP endpoint is `/mcp`; `/health` is available for health checks.

## Relay + Agent

Generate two different secrets:

```bash
./chat-with-cli token   # MCP client token
./chat-with-cli token   # Agent token
```

On the public relay host:

```bash
export CHAT_WITH_CLI_CLIENT_TOKEN='...'
export CHAT_WITH_CLI_AGENT_TOKEN='...'
./chat-with-cli relay --listen 127.0.0.1:8765
```

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
https://cli.example.com/mcp?device=workstation
```

The workstation needs only outbound HTTPS/WebSocket access. See [docs/deployment.md](docs/deployment.md) for Caddy and systemd examples.

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

- `computer_info`, `computer_screenshot`
- `computer_move`, `computer_click`, `computer_scroll`
- `computer_type`, `computer_key`

## Roadmap

- OAuth 2.1 / MCP authorization for hosted ChatGPT connectors.
- Native Go XDG RemoteDesktop Portal + libei backend.
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
