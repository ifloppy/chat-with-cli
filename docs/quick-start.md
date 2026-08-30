# Quick start

This guide starts a private Relay and a read-only workstation Agent. Use the
public-instance guide only when account registration is an intentional part of
the deployment.

## Build

```bash
go test ./...
go build -o chat-with-cli ./cmd/chat-with-cli
```

For an installed workstation, `chat-with-cli ui` opens the interactive control
hub. Choose **Connect this workstation**: if local setup is missing, the same flow
creates it first, then opens OAuth when needed and connects. The separate
**Workstation settings** entry is for changing an existing configuration, while
**Account** shows OAuth status and Login / Logout. If no Relay is supplied, the client uses the community public Relay
`https://chat-with-cli.iruanp.com`; pass `--relay` to use a private Relay.

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

The generated config stores the Relay URL and immutable device ID. Normal
`connect` refreshes expired credentials and opens OAuth automatically when a
saved credential is rejected. Explicit `login` always performs a fresh browser
authorization; `logout` revokes that workstation token family and removes its
exact local credential. For SSH/headless machines, `connect` automatically
falls back to manual OAuth when no Linux graphical session is present;
`--manual-oauth` forces this mode. Open the one-time URL shown on the TTY in
any browser, authorize, then paste the browser's final localhost callback URL
back into the CLI. Immutable IDs are canonicalized to
lowercase and are the workstation identity; the device name is only a display
label and legacy route. Use the stable account endpoint in normal MCP clients:

```text
https://cli.example.com/mcp
```

The account grant can list and route only that user's devices. Use
`/mcp/id/<immutable-id>` only when deliberately pinning a client to one device.

`agent setup --install-systemd` writes a hardened user unit but deliberately
does not enable or start it. Review the unit, complete browser OAuth, and use
`chat-with-cli doctor` before any manual activation.

## Next steps

- [Agent capabilities and config](agent.md)
- [ChatGPT and MCP compatibility](chatgpt.md)
- [Admin controls](admin.md)
- [Security checklist](security.md)
