# Private Relay

Private mode is the default and is the recommended first deployment. It has a
single owner account, closed public registration, OAuth for MCP and Agent
resources, and optional legacy static bearer compatibility.

## First run

Prefer the local setup-token flow:

```bash
chat-with-cli relay setup \
  --config /etc/chat-with-cli/config.toml \
  --state-dir /var/lib/chat-with-cli \
  --public-url https://cli.example.com \
  --instance-mode private
chat-with-cli relay --config /etc/chat-with-cli/config.toml
```

Open `/setup` only from a controlled browser while holding the token from the
Relay host. Choose an owner username and a password of at least 12 characters.
After setup, sign in at `/admin` and delete any out-of-band copies of the
setup token.

For alpha compatibility, `--owner-password`, `--owner-password-file`, and the
deprecated `--oauth-password` can bootstrap the owner directly. Password files
must be local 0600 regular files; they are read once to create the Argon2id
hash and are not written into OAuth credentials.

## Static compatibility mode

Without `--public-url`, a Relay can run only in legacy private mode with both
`--client-token` and `--agent-token`. Do not expose this mode directly to the
Internet. It has no browser OAuth, per-user ownership, or dynamic resource
authorization: either shared credential should be treated as broad single-tenant
device authority. OAuth-enabled private and public instances reject shared
static tokens.

## Operations

- Keep `/var/lib/chat-with-cli` owned by the Relay user with mode 0700.
- The JSON state is lock-protected, atomically replaced, fsynced, and backward-compatible with alpha.4 state. Production Relay startup also takes an exclusive process-lifetime lease, so a concurrent writer for the same state directory is rejected.
- Configure `--trusted-proxy` only with the actual proxy address/CIDR. Proxy
  headers are ignored by default.
- Keep MCP and Agent enabled only while needed. `/admin` can disable either
  capability, disable users/devices, revoke tokens/clients, and activate the
  emergency kill switch.
- Use a dedicated unprivileged service account. The Relay does not need access
  to workstation files and never initiates the Agent WebSocket.

See [reverse-proxy.md](reverse-proxy.md), [backup-restore.md](backup-restore.md),
and [admin.md](admin.md).
