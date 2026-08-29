# chat-with-cli

Open-source remote development bridge for AI agents.

`chat-with-cli` is a Go single-binary MCP server, outbound workstation Agent,
and OAuth-enabled Relay. It provides bounded filesystem access, durable PTY
tasks, checkpoints, privacy-preserving audit metadata, and optional Linux
Computer Use controls.

> Status: early alpha (`v0.1.0-alpha.5`). Linux is the first supported host.
> Review [SECURITY.md](SECURITY.md) before exposing a Relay publicly.

After installation, run `chat-with-cli ui` (or simply `chat-with-cli` in an
interactive terminal) to open the terminal hub. It guides first-time setup,
uses `https://chat-with-cli.iruanp.com` as the default public Relay, and lets
you run connection diagnostics without memorising subcommands. Pass
`--relay https://your-relay.example` whenever you want to use another Relay.

## Five-minute quick start

Build and test locally:

```bash
git clone https://github.com/ifloppy/chat-with-cli.git
cd chat-with-cli
go test ./...
go build -o chat-with-cli ./cmd/chat-with-cli
```

Run a read-only local MCP server. Filesystem reads are limited to the root;
writes, shell execution, screenshots, and input remain disabled:

```bash
./chat-with-cli local --root "$HOME/project"
```

For a remote setup, create a Relay configuration on a TLS-terminating host:

```bash
./chat-with-cli relay setup \
  --config /etc/chat-with-cli/config.toml \
  --state-dir /var/lib/chat-with-cli \
  --public-url https://cli.example.com \
  --instance-mode private
./chat-with-cli relay --config /etc/chat-with-cli/config.toml
```

Read the one-time setup token from the local file path printed by `relay
setup`, open `https://cli.example.com/setup`, and create the owner account.
The setup page is disabled after the first administrator is created.

On the workstation, install the checksum-verified release, create a default
read-only Agent profile, and connect it. `connect` automatically opens browser
OAuth when needed. In a foreground terminal it then asks whether to use
interactive local approvals, allow all capabilities for this process only, or
stay with the configured profile:

```bash
curl -fsSL https://raw.githubusercontent.com/ifloppy/chat-with-cli/main/install.sh | sh
chat-with-cli agent setup \
  --relay https://cli.example.com \
  --root "$HOME/project" \
  --device workstation \
  --profile read-only \
  --install-systemd
chat-with-cli connect
# Review config/unit before starting anything.
systemctl --user daemon-reload
systemctl --user enable --now chat-with-cli-agent.service
```

Use `https://cli.example.com/mcp/id/<immutable-device-id>` as the remote MCP
endpoint. In ChatGPT or another MCP client, choose OAuth authentication and
refresh the tool list after authorization. For a developer workstation,
explicitly choose `--profile developer` or enable individual capabilities; see
[Agent configuration](docs/agent.md).

## Security defaults

| Capability | Default | Explicit opt-in |
| --- | --- | --- |
| Filesystem read | only inside `--root` | add a narrowly scoped root |
| Filesystem/checkpoint write | off | `--allow-file-write` |
| Arbitrary shell / PTY | off | `--allow-exec` |
| Exec filesystem boundary | none unless requested | `--exec-sandbox=landlock` on Linux |
| Screen read (screenshots) | off | `--allow-screen` |
| Accessibility read (AT-SPI) | off | `--allow-accessibility` |
| Keyboard, pointer, semantic UI writes | off | `--allow-computer-use` |

The default profile is read-only. `--root` is a filesystem-tool boundary, not
a sandbox for shell commands. Landlock restricts filesystem access only; it
does not remove the Agent user's network, process, or inherited-secret access.
Run the Agent as a dedicated unprivileged user and use `--exec-sandbox=landlock`
when shell work needs an additional kernel boundary.

Private Relay mode is the default. Public users manage their own devices,
browser sessions, password, and OAuth token families from `/account`; instance
operators manage registration/invites, DCR, MCP/Agent access, all users/devices,
and the emergency kill switch from `/admin`. Emergency disable operations contract authority immediately;
re-enabling devices/users or releasing the global kill switch requires recent
administrator re-authentication. OAuth uses PKCE S256, exact user/resource/scope
and device-owner binding, rotating refresh-token families, bounded sessions,
and one-way server-side token identifiers. Public traffic must use HTTPS behind
a carefully configured reverse proxy. A Relay that cannot durably persist
authorization state fails closed and reports HTTP 503 from `/health`.

**A public Relay is not an end-to-end privacy boundary.** Public mode isolates
ordinary users from each other, but the Relay operator controls the server
software and can modify it to observe or alter MCP requests and results. Do not
trust any public instance—including one operated by the software author—with
secrets or high-trust computer access. Self-host a private Relay when that
operator trust is unacceptable.

## Architecture

```text
MCP client / ChatGPT --HTTPS + OAuth--> Relay --outbound WebSocket--> Agent
                                             \
                                              `-- bounded Engine tools
```

The Relay cannot initiate a connection to the workstation. The Agent connects
outbound and reconnects automatically. A direct `local` stdio mode and a
loopback `serve` HTTP mode are available when no Relay is needed.

## Common commands

```text
chat-with-cli relay setup       create config and one-time setup token
chat-with-cli relay install     review or apply a checksum-verified binary install
chat-with-cli agent setup       create config and optional inactive user unit
chat-with-cli doctor            inspect local and Relay prerequisites
chat-with-cli status            show local config and user-unit state
chat-with-cli update            review or apply a verified atomic binary update
chat-with-cli rollback          review or restore the verified local previous binary
```

`agent setup --install-systemd` writes a hardened user unit but never enables
or starts it. Review the generated unit and activate it manually only when the
security audit and first browser login are complete.

## Documentation

- [Quick start](docs/quick-start.md)
- [Private Relay](docs/private-instance.md) · [Public Relay](docs/public-instance.md)
- [Agent configuration](docs/agent.md) · [Computer Use](docs/computer-use.md)
- [ChatGPT/MCP compatibility](docs/chatgpt.md)
- [Security](docs/security.md) · [Threat model](docs/threat-model.md)
- [Reverse proxy](docs/reverse-proxy.md) · [Cloudflare](docs/cloudflare.md)
- [User account](docs/account.md) · [Administration](docs/admin.md)
- [Install](docs/install.md) · [Upgrade](docs/upgrade.md) · [Backup/restore](docs/backup-restore.md)
- [Self-host with ChatGPT](docs/self-host-with-chatgpt.md)
- [Troubleshooting](docs/troubleshooting.md)

The MCP server currently advertises 31 tools. Read-only/destructive/open-world
annotations and human-readable titles are explicit. The raw Streamable HTTP
`initialize` and `tools/list` path is covered by a regression test; a client's
tool cache or policy may still hide tools after a server-side change.

## Computer Use

Computer Use is opt-in and Linux-first. Accessibility inspection uses AT-SPI2;
KWin ScreenShot2, Spectacle, `grim`, and GNOME Screenshot are supported where
available; Wayland input prefers the XDG RemoteDesktop Portal. The Agent does
not automatically use `/dev/uinput` or another consent-bypassing input path.
Portal persistence defaults to the Agent process lifetime. See
[Computer Use](docs/computer-use.md) and [Security](SECURITY.md).

## Known limitations

- The Relay state remains a single-process JSON store, locked and atomically replaced with fsync. Production startup now takes an exclusive process-lifetime lease, so a stale second Relay cannot run against the same state directory.
- Headless credential fallback stores raw OAuth access/refresh tokens in a
  0600 file. Account passwords are never stored there. Native Secret Service,
  KWallet, Keychain, and Credential Manager integrations remain future work.
- Landlock is Linux-only and filesystem-only. It is defense in depth, not a
  complete container or network sandbox.
- Legacy name routes remain for alpha compatibility. New deployments should
  use immutable `/agent/id/<id>` and `/mcp/id/<id>` routes.

## License

GPLv3. See [LICENSE](LICENSE). Version/build conventions are documented in
[docs/release.md](docs/release.md); local commits are encouraged while the
project remains unreleased.
