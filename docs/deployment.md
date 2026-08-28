# Deployment

A typical remote deployment has a tiny public Relay and one or more outbound-connected Agents.

## 1. Build

```bash
go build -trimpath -ldflags='-s -w' -o chat-with-cli ./cmd/chat-with-cli
sudo install -m 0755 chat-with-cli /usr/local/bin/chat-with-cli
```

Generate two independent high-entropy secrets:

```bash
chat-with-cli token   # workstation Agent token
chat-with-cli token   # OAuth authorization password
```

Keep them in root/user-readable environment files rather than command-line arguments where possible. The OAuth password must be at least 32 characters; the generated token is suitable.

## 2. Relay environment

`/etc/chat-with-cli/relay.env`:

```text
CHAT_WITH_CLI_AGENT_TOKEN=<agent secret>
CHAT_WITH_CLI_OAUTH_PASSWORD=<oauth authorization password>
CHAT_WITH_CLI_PUBLIC_URL=https://cli.example.com
# Optional legacy/debug MCP bearer:
# CHAT_WITH_CLI_CLIENT_TOKEN=<client secret>
```

Set mode `0600` and owner `root:root`.

`/etc/systemd/system/chat-with-cli-relay.service`:

```ini
[Unit]
Description=chat-with-cli public relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/chat-with-cli/relay.env
ExecStart=/usr/local/bin/chat-with-cli relay --listen 127.0.0.1:8765 --state-dir /var/lib/chat-with-cli
Restart=on-failure
RestartSec=2s
DynamicUser=yes
StateDirectory=chat-with-cli
StateDirectoryMode=0700
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now chat-with-cli-relay
```

## 3. TLS with Caddy

```caddyfile
cli.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8765
}
```

The Relay intentionally listens on loopback in this example. Caddy owns the public socket and TLS lifecycle.

Useful checks:

```bash
curl -fsS https://cli.example.com/health
curl -fsS https://cli.example.com/.well-known/oauth-authorization-server | jq
# Device-specific resource metadata after choosing a device name:
curl -fsS https://cli.example.com/.well-known/oauth-protected-resource/mcp/workstation | jq
```

If you also configured `CHAT_WITH_CLI_CLIENT_TOKEN`, `/devices` remains available for legacy/debug clients. Do not put OAuth passwords, Agent tokens, or bearer tokens directly into a Caddyfile or public configuration repository.

## 4. Workstation Agent

Create `~/.config/chat-with-cli/agent.env` with mode `0600`:

```text
CHAT_WITH_CLI_AGENT_TOKEN=<agent secret>
```

For Computer Use, the Agent must run inside the logged-in desktop user's session rather than as a root system service.

Example user unit: `~/.config/systemd/user/chat-with-cli-agent.service`

```ini
[Unit]
Description=chat-with-cli workstation agent
After=graphical-session.target network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=%h/.config/chat-with-cli/agent.env
ExecStart=/usr/local/bin/chat-with-cli agent --relay https://cli.example.com --device workstation --root %h/project --allow-exec --max-active-tasks 32
Restart=on-failure
RestartSec=2s
NoNewPrivileges=yes

[Install]
WantedBy=default.target
```

The Agent defaults to at most 32 concurrent PTY tasks; lower `--max-active-tasks` on small machines. For read-only screenshot/AT-SPI access, append `--allow-screen`. For keyboard, pointer, or semantic UI actions, append `--allow-computer-use` only when needed. Portal restore policy defaults to `--computer-persist=process`; use `none` for no restoration or explicitly choose `persistent` for restart-surviving consent.

The Agent writes privacy-preserving audit metadata under its `--state-dir` (default `~/.local/state/chat-with-cli/audit/events.jsonl`). It records method/time/duration/success only, never MCP arguments or results. Use the read-only `audit_recent` MCP tool for recent events; the file is size-bounded and rotated once.

```bash
systemctl --user daemon-reload
systemctl --user enable --now chat-with-cli-agent
```

## KDE / Wayland notes

Computer Use needs the graphical-session environment (`WAYLAND_DISPLAY`, session D-Bus, and related variables). A `systemd --user` service normally inherits these correctly when started from the graphical user session.

If the service was created before the graphical environment was imported, refresh it after login:

```bash
systemctl --user import-environment \
  DISPLAY WAYLAND_DISPLAY XDG_CURRENT_DESKTOP XDG_SESSION_TYPE DBUS_SESSION_BUS_ADDRESS
systemctl --user restart chat-with-cli-agent
```

On KDE/Wayland, `chat-with-cli` first tries KWin ScreenShot2 directly and safely falls back to Spectacle when KWin denies direct capture. Wayland input prefers the native XDG RemoteDesktop Portal D-Bus API; `wdotool` remains only a fallback. UI inspection uses AT-SPI2 when available.

For agent-driven GUI work, `computer_observe` is the preferred first call: it combines bounded AT-SPI observation with optional image capture, using `screenshot=auto` by default to avoid unnecessary image transfer. `computer_ui_invoke` should be preferred over a separate find/action pair when a unique semantic selector is available. For forms, `computer_ui_set_text` can write directly to AT-SPI EditableText controls without keyboard injection. Both support a bounded `timeout_ms` to wait for an asynchronously appearing selector.

The Agent can recover the user runtime directory, session D-Bus, Wayland display, and a UTF-8 locale when a user service starts with an incomplete graphical environment. Native Portal input still displays the desktop consent UI when required. In the default `process` persistence mode, one-time restore tokens stay in memory and rotate after restoration; `persistent` stores only the current rotating token beneath the Agent state directory with permission `0600`.

Avoid launching a Computer Use Agent through `sudo`: doing so commonly loses the user's Wayland and D-Bus session and weakens the privilege boundary at the same time.

## Multiple workstations

Each Agent chooses a URL-safe `--device` name. Its stable MCP resource is `/mcp/<device>`, for example `https://cli.example.com/mcp/workstation`. OAuth tokens are bound to that exact resource, so authorizing one device does not authorize another. The alpha Relay still shares one Agent credential across devices; per-device Agent credentials are planned before a stable release.
