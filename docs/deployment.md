# Deployment

A typical remote deployment has a tiny public Relay and one or more outbound-connected Agents.

## 1. Build

```bash
go build -trimpath -ldflags='-s -w' -o chat-with-cli ./cmd/chat-with-cli
sudo install -m 0755 chat-with-cli /usr/local/bin/chat-with-cli
```

Choose an instance mode before first start:

- **private** (default): one owner account, closed registration.
- **public**: open account registration; every device is owned by the account that first authorizes its Agent.

Both Agents and MCP clients use browser OAuth. Shared static bearer tokens are legacy-only and are rejected in public mode.

## 2. Relay environment

Private `/etc/chat-with-cli/relay.env`:

```text
CHAT_WITH_CLI_PUBLIC_URL=https://cli.example.com
CHAT_WITH_CLI_INSTANCE_MODE=private
CHAT_WITH_CLI_OWNER_PASSWORD_FILE=/var/lib/chat-with-cli/private-owner-password
```

Public instance:

```text
CHAT_WITH_CLI_PUBLIC_URL=https://cli.example.com
CHAT_WITH_CLI_INSTANCE_MODE=public
```

Set the environment file to mode `0600`. A private instance creates the owner (`owner` by default) on first boot. If no owner password is supplied, a strong random bootstrap password is written to `CHAT_WITH_CLI_OWNER_PASSWORD_FILE` with mode `0600`. After you save that account in your browser/password manager, the file may be deleted: future Relay starts use the persisted Argon2id password hash.

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

For a new private instance, inspect the bootstrap credential once:

```bash
sudo cat /var/lib/chat-with-cli/private-owner-password
```

## 3. TLS with Caddy

```caddyfile
cli.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8765
}
```

Useful checks:

```bash
curl -fsS https://cli.example.com/health
curl -fsS https://cli.example.com/.well-known/oauth-authorization-server | jq
curl -fsS https://cli.example.com/.well-known/oauth-protected-resource/mcp/workstation | jq
curl -fsS https://cli.example.com/.well-known/oauth-protected-resource/agent/workstation | jq
```

## 4. Workstation Agent

Do the first authorization interactively in the logged-in desktop session:

```bash
chat-with-cli login --relay https://cli.example.com --device workstation
```

Private mode: sign in as the owner account. Public mode: use **Create account** on the OAuth page if needed. The same browser login/password-manager entry is reused when ChatGPT later opens its MCP OAuth flow.

CLI OAuth state is stored by default in `~/.config/chat-with-cli/credentials.json` with mode `0600`. It contains OAuth client/access/refresh credentials, not the account password. Refresh tokens rotate automatically.

After the first login, manual start can omit the Relay URL when exactly one saved profile matches the device:

```bash
chat-with-cli agent --device workstation --root "$HOME/project" --allow-exec
```

Example user unit `~/.config/systemd/user/chat-with-cli-agent.service`:

```ini
[Unit]
Description=chat-with-cli workstation agent
After=graphical-session.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/chat-with-cli agent --relay https://cli.example.com --device workstation --root %h/project --allow-exec --max-active-tasks 32
Restart=on-failure
RestartSec=2s
NoNewPrivileges=yes

[Install]
WantedBy=default.target
```

Pre-authorize with `chat-with-cli login` before enabling the user unit; a background service should not be expected to complete a first-time browser login. The Agent refreshes saved OAuth credentials automatically before reconnecting.

The Agent defaults to at most 32 concurrent PTY tasks. For read-only screenshot/AT-SPI access, append `--allow-screen`; for keyboard, pointer, or semantic UI writes, append `--allow-computer-use`. Portal restore policy defaults to `--computer-persist=process`.

The Agent writes privacy-preserving audit metadata under its `--state-dir` (default `~/.local/state/chat-with-cli/audit/events.jsonl`). It records method/time/duration/success only, never MCP arguments or results.

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

Each Agent chooses a URL-safe `--device` name. Its Agent OAuth resource is `/agent/<device>` and its MCP resource is `/mcp/<device>`. In public mode the first successful Agent authorization claims that globally unique device name for the signed-in account; other accounts cannot authorize either resource for that device. Device transfer/rename administration is not implemented yet.
