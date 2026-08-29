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
- Keep DCR and registration disabled when not needed. OAuth-enabled Relays reject
  shared static credentials. Legacy static mode is single-tenant and its shared
  credentials have broad authority over registered legacy devices.
- Use immutable device IDs, narrow filesystem roots, and read-only Agent
  profiles by default. Never describe `--root` as a shell sandbox.
- Keep Agent OAuth credentials and any setup/password files mode 0600. Never
  put bearer tokens or passwords in command arguments, URLs, logs, or tickets.

At runtime:

- Review `/admin` security controls, users, device ownership, sessions, OAuth
  clients, token metadata, and recent events.
- Make authority reduction easy and authority restoration deliberate. Disabling
  users/devices/MCP/Agent and engaging the Relay kill switch is immediate;
  re-enabling users/devices and releasing the kill switch requires recent
  administrator re-authentication. Destructive delete/revoke operations retain
  explicit confirmations.
- Use the local panic file for immediate Engine denial. Use the Relay kill
  switch to deny OAuth-protected MCP and Agent access. Revocation/disconnect
  also ends the Agent remote session, killing detached PTYs and closing Portal
  control so previously started work does not survive lost authorization.
- Treat audit records as bounded operational metadata, not tamper-proof
  forensic evidence. They omit tool arguments, file contents, and command
  output by design.
- Run `doctor` after proxy, OAuth, desktop, or binary changes.

Known residual risks include same-user shell authority, inherited environment secrets, filesystem TOCTOU races, the single-process JSON state model (protected by an exclusive Relay writer lease), and the raw local credential fallback. See the full policy for mitigations and scope.
