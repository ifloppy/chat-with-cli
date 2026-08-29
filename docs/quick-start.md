# Quick start

This guide starts a private Relay and a read-only workstation Agent. Use the
public-instance guide only when account registration is an intentional part of
the deployment.

## Build

```bash
go test ./...
go build -o chat-with-cli ./cmd/chat-with-cli
```

Run the local MCP server over stdio for a first smoke test:

```bash
./chat-with-cli local --root "$HOME/project"
```

The root grants filesystem reads only. Add `--allow-file-write` for file and
checkpoint writes, `--allow-exec` for PTY shell tasks, and the Computer Use
flags only when the desktop operation is required.

## Private Relay

On the Relay host, choose a state directory owned by the Relay account and
generate the configuration:

```bash
./chat-with-cli relay setup \
  --config /etc/chat-with-cli/config.toml \
  --state-dir /var/lib/chat-with-cli \
  --setup-token-file /var/lib/chat-with-cli/setup-token \
  --public-url https://cli.example.com \
  --instance-mode private
./chat-with-cli relay --config /etc/chat-with-cli/config.toml
```

Read the setup token locally from the path printed by the first command. Open
`https://cli.example.com/setup` and create the owner account. The token is
hashed in memory, consumed once, removed after successful setup, and never
printed in a URL or admin page. `/setup` returns 404 after initialization.

The Relay must be HTTPS in production. Put it behind a reverse proxy that
passes WebSockets; see [reverse-proxy.md](reverse-proxy.md).

## Workstation Agent

```bash
./chat-with-cli agent setup \
  --relay https://cli.example.com \
  --root "$HOME/project" \
  --device workstation \
  --profile read-only \
  --install-systemd
./chat-with-cli connect
# Review the generated config and unit before starting the Agent.
systemctl --user daemon-reload
systemctl --user enable --now chat-with-cli-agent.service
```

The generated config stores the Relay URL and immutable device ID, so `login`
can reuse them without manual transcription. Immutable IDs are canonicalized to
lowercase and are the resource identity; the device name is only a display
label and legacy route. Use the ID endpoint in MCP clients:

```text
https://cli.example.com/mcp/id/<immutable-id>
```

`agent setup --install-systemd` writes a hardened user unit but deliberately
does not enable or start it. Review the unit, complete browser OAuth, and use
`chat-with-cli doctor` before any manual activation.

## Next steps

- [Agent capabilities and config](agent.md)
- [ChatGPT and MCP compatibility](chatgpt.md)
- [Admin controls](admin.md)
- [Security checklist](security.md)
