# Deployment reference

Use [quick-start.md](quick-start.md) for the shortest path. This page collects
the production-shaped layout without enabling any service automatically.

## Relay layout

Use a dedicated unprivileged account, for example:

```text
/usr/local/bin/chat-with-cli
/etc/chat-with-cli/config.toml       0600
/var/lib/chat-with-cli/              0700
/var/lib/chat-with-cli/setup-token   0600, first run only
```

Generate the config and setup token locally:

```bash
sudo -u chat-with-cli chat-with-cli relay setup \
  --config /etc/chat-with-cli/config.toml \
  --state-dir /var/lib/chat-with-cli \
  --setup-token-file /var/lib/chat-with-cli/setup-token \
  --public-url https://cli.example.com \
  --instance-mode private
```

The account must be able to write the state/config paths. If a root-owned
installation is required, create and inspect the files as the service account
before starting the Relay. Do not pass account passwords in a unit's
`ExecStart`; use the setup token or a protected environment/secret mechanism.

A minimal Relay unit to review (not automatically installed or enabled):

```ini
[Unit]
Description=Chat with CLI Relay
After=network-online.target
Wants=network-online.target

[Service]
User=chat-with-cli
Group=chat-with-cli
ExecStart=/usr/local/bin/chat-with-cli relay --config /etc/chat-with-cli/config.toml
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
ReadWritePaths=/var/lib/chat-with-cli

[Install]
WantedBy=multi-user.target
```

Terminate public traffic at Caddy/Nginx or another trusted proxy. See
[reverse-proxy.md](reverse-proxy.md) and [cloudflare.md](cloudflare.md).

## Workstation Agent

```bash
chat-with-cli agent setup --relay https://cli.example.com \
  --device workstation --profile read-only --install-systemd
chat-with-cli login --relay https://cli.example.com \
  --device-id <id-from-agent-setup>
chat-with-cli doctor --relay https://cli.example.com \
  --device-id <id-from-agent-setup>
```

The generated user unit is intentionally inactive and disabled. Inspect its
absolute paths, capability flags, roots, state directory, and environment
before manually enabling it. A graphical Agent must run as the logged-in user;
do not use `sudo` to work around Wayland/D-Bus permissions.

## Operational checks

After any proxy or binary change, verify `/health`, OAuth metadata, protected
resource metadata, Agent WebSocket connectivity, and MCP `tools/list`. Keep
registration/DCR disabled when unnecessary, rotate/revoke credentials through
`/admin`, and preserve the state directory during binary rollbacks.

For backup, upgrades, private/public policy, and the security model, see the
linked guides in the repository root [README](../README.md).
