# Deployment

A typical remote deployment has a tiny public Relay and one or more outbound-connected Agents.

## 1. Build

```bash
go build -trimpath -ldflags='-s -w' -o chat-with-cli ./cmd/chat-with-cli
sudo install -m 0755 chat-with-cli /usr/local/bin/chat-with-cli
```

Generate two independent tokens:

```bash
chat-with-cli token
chat-with-cli token
```

Keep them in root/user-readable environment files rather than command-line arguments where possible.

## 2. Relay environment

`/etc/chat-with-cli/relay.env`:

```text
CHAT_WITH_CLI_CLIENT_TOKEN=<client secret>
CHAT_WITH_CLI_AGENT_TOKEN=<agent secret>
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
ExecStart=/usr/local/bin/chat-with-cli relay --listen 127.0.0.1:8765
Restart=on-failure
RestartSec=2s
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
curl -fsS -H "Authorization: Bearer $CHAT_WITH_CLI_CLIENT_TOKEN" \
  https://cli.example.com/devices
```

Do not put bearer tokens directly into a Caddyfile or public configuration repository.

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
ExecStart=/usr/local/bin/chat-with-cli agent --relay https://cli.example.com --device workstation --root %h/project --allow-exec
Restart=on-failure
RestartSec=2s
NoNewPrivileges=yes

[Install]
WantedBy=default.target
```

For read-only screenshot/AT-SPI access, append `--allow-screen`. For keyboard, pointer, or semantic UI actions, append `--allow-computer-use` only when needed. Portal restore policy defaults to `--computer-persist=process`; use `none` for no restoration or explicitly choose `persistent` for restart-surviving consent.

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

Each Agent chooses a `--device` name. The MCP endpoint selects it using `?device=<name>`. The alpha Relay shares one Agent credential across devices; per-device credentials are planned before a stable release.
