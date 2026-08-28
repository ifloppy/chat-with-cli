# Security operations

The canonical threat model is [threat-model.md](threat-model.md), with the
repository policy in [SECURITY.md](../SECURITY.md). This page is an operator
checklist.

Before exposure:

- Keep the Relay in private mode unless public multi-user access is required.
- Use HTTPS, a dedicated unprivileged Relay account, a 0700 state directory,
  and a proxy that preserves WebSockets.
- Complete `/setup` from a controlled browser using the local one-time token;
  then confirm `/setup` returns 404.
- Keep DCR and registration disabled when not needed. Disable shared static
  tokens in public mode.
- Use immutable device IDs, narrow filesystem roots, and read-only Agent
  profiles by default. Never describe `--root` as a shell sandbox.
- Keep Agent OAuth credentials and any setup/password files mode 0600. Never
  put bearer tokens or passwords in command arguments, URLs, logs, or tickets.

At runtime:

- Review `/admin` security controls, users, device ownership, sessions, OAuth
  clients, token metadata, and recent events.
- Require recent admin re-authentication and confirmation for revocation,
  deletion, credential rotation, and the emergency kill switch.
- Use the local panic file for immediate Engine denial. Use the Relay kill
  switch to deny OAuth-protected MCP and Agent access.
- Treat audit records as bounded operational metadata, not tamper-proof
  forensic evidence. They omit tool arguments, file contents, and command
  output by design.
- Run `doctor` after proxy, OAuth, desktop, or binary changes.

Known residual risks include same-user shell authority, inherited environment
secrets, filesystem TOCTOU races, JSON state's single-writer design, and the
raw local credential fallback. See the full policy for mitigations and scope.
