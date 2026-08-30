# Agent configuration

The default config path is `~/.config/chat-with-cli/config.toml` (or
`$XDG_CONFIG_HOME/chat-with-cli/config.toml`). Create it with:

```bash
chat-with-cli agent setup --relay https://cli.example.com --root "$HOME/project" --device workstation
```

CLI flags override config values. Secrets belong in environment variables or
the 0600 credential store, not TOML. The generated file contains no account
password.

## Profiles

| Profile | Enabled capabilities |
| --- | --- |
| `read-only` (`R`) | filesystem reads under roots |
| `read-write` (`W`) | read, filesystem/checkpoint write, PTY shell |
| `desktop-computer-use` (`D`) | screen/accessibility read and computer input/write |
| `all` (`A`) | read-write plus all desktop/computer-use capabilities |
| `custom` (`C`) | individual flags only |

Capabilities can also be selected separately:

```text
--root PATH                 repeat for allowed filesystem trees
--allow-file-write          filesystem and checkpoint writes
--allow-exec                arbitrary PTY shell commands
--exec-sandbox=landlock     Linux filesystem boundary for shell children
--allow-screen              screenshots
--allow-accessibility       AT-SPI semantic inspection
--allow-computer-use        keyboard, pointer, semantic UI writes
--kill-switch-file PATH     deny every Engine call while the file exists
--max-active-tasks N        bounded concurrent PTY tasks (maximum 256)
```

`agent setup` prints every configured filesystem root and warns when `/` or the
whole home directory is exposed. Prefer an explicit project/workspace root;
read-only still means every readable file under that root can be returned to an
authorized MCP client. A root is not a shell sandbox. With `--allow-exec`, a
shell without Landlock still has the Agent user's normal filesystem, network,
process, and environment access. Landlock is filesystem-only defense in depth.

## OAuth and device identity

`login` performs browser OAuth with PKCE S256. The local fallback store is
`~/.config/chat-with-cli/credentials.json`, mode 0600 under a 0700 directory.
It contains raw access/refresh tokens for unattended reconnects, but never the
Relay account password. Deleting it removes local credentials; the Relay admin
must revoke the server-side client or token family for immediate invalidation.
Refresh and atomic replacement are serialized across Agent processes with an
advisory lock. Remote Relay origins must use HTTPS/WSS (loopback HTTP is
allowed for local development), and active Agent WebSockets revalidate their
credential before every brokered RPC.

`agent setup` also creates a 0600 Ed25519 identity file and stores its path in
the config. The immutable device ID is derived from that public key rather than
chosen independently. For normal foreground use, run `chat-with-cli connect`; it performs browser OAuth automatically when credentials are missing or expired. `chat-with-cli login` remains available for explicit pre-authorization.
Before DCR, the CLI obtains a short-lived one-time registration challenge from
the Relay, signs it with the device private key, and submits that proof with
the DCR request. Device-bound Agent DCR accepts only loopback HTTP callbacks;
external HTTPS callbacks remain available to ordinary MCP clients, not Agents.
Every later WebSocket connection uses a separate one-time
Relay challenge bound to the Agent resource and current bearer fingerprint.
The Relay binds the verified public key to the device. A stolen Agent OAuth
bearer or captured old proof alone is insufficient to impersonate a PoP-bound
device.

Immutable IDs are normalized to one lowercase canonical form across OAuth,
Relay routes, Agent WebSockets, and the credential store. Protect both the
identity private key and credential file. `chat-with-cli status` and `doctor`
check identity-file permissions and ID/key consistency without printing key
material.

Legacy alpha Agents that have no Ed25519 identity are rejected by a current
Relay by default. For a controlled migration only, a Relay operator may enable
`relay.allow_legacy_unbound_agents = true` (or
`--allow-legacy-unbound-agents`). While enabled, the admin page shows a critical
warning because possession of an old Agent bearer is sufficient to impersonate
an unbound device. Create a new identity with `agent setup`, authorize and verify
the new immutable ID, permanently revoke the old route, then disable migration
mode. Do not reuse the retired ID.

When the authenticated Relay session is revoked or disconnected, the Agent
ends that remote session: in-flight calls are canceled, detached PTY tasks are
terminated, and the active Desktop Portal control session is closed. This is a
security-first default; do not rely on remote PTY tasks surviving disconnects.

## MCP tool audit output

Foreground `agent` and `connect` sessions print the complete 31-tool MCP
inventory when they start. Each entry includes its read-only/mutating and
open-world classification, plus the local capability summary. Every inbound
MCP call is then printed by tool name before authorization and execution. This
line is still emitted in `--approval-mode=allow-all`; the mode changes
authorization, not audit visibility. Arguments, file contents, commands,
screenshots, and results are intentionally omitted from this display.

## systemd user unit

`agent setup --install-systemd` writes a unit with `NoNewPrivileges`,
`PrivateTmp`, `ProtectSystem=strict`, `ProtectHome=read-only`, and related
hardening. It remains inactive and disabled. First complete OAuth, inspect the
unit and paths, then decide whether to enable it manually. Do not run the Agent
as root or with `sudo`; graphical session permissions usually belong to the
logged-in user.
