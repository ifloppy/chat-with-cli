# Threat model

## Assets

The primary assets are the workstation's files, shell authority, visible
desktop and input channel, Relay account credentials, OAuth access/refresh
tokens, browser sessions, device ownership, and audit metadata.

## Trust boundaries

1. A human authenticates in a browser to the Relay.
2. An MCP client receives a resource-bound OAuth token for exactly one MCP
   device route.
3. The workstation Agent receives a separate resource-bound token for exactly
   one Agent route and opens the outbound WebSocket.
4. The Relay brokers requests but has no workstation filesystem access and does
   not initiate inbound workstation connections.
5. The Engine applies independent local capability gates before filesystem,
   PTY, screen, accessibility, or input operations.

## Security properties

OAuth uses exact redirect matching, PKCE S256, one-use expiring authorization
codes, short-lived resource/scope-bound access tokens, rotating refresh-token
families with replay revocation, CSRF-protected browser forms, bounded pending
requests, Argon2id passwords with bounded hashing concurrency, and rate limits.
Server state is one-way-token metadata only, lock-protected, atomically
replaced, fsynced, and permissioned. Admin actions support explicit
revocation, logout, device ownership changes, capability kill switches, and a
bounded operational audit trail.

New Agent identities use Ed25519. `agent setup` generates a local private key
and derives the immutable 128-bit route ID from its public key. Initial Agent
DCR proves possession of that key before an unowned device can be claimed, and
every authenticated Agent WebSocket uses a fresh proof bound to the exact
resource, bearer fingerprint, timestamp, and nonce. Proof replay caches are
bounded per device so one tenant cannot exhaust another device's replay
capacity. Names remain labels and legacy compatibility routes.

## Residual risks and assumptions

- A same-user shell is not contained by `--root`. Without Landlock it has the
  user's normal filesystem, network, process, and environment authority.
- Landlock is Linux-only filesystem defense in depth; it is not a network,
  process, container, or secret-isolation boundary.
- Path-based root checks can encounter TOCTOU races against a malicious local
  same-user process. Use a dedicated OS account/container for hostile tenants.
- The JSON state design assumes one Relay writer. The lock prevents concurrent
  partial writes but does not merge independent process memories.
- The fallback credential file contains raw OAuth tokens. Protect it as a
  login secret; native OS credential stores are future work.
- Computer Use can expose secrets from other visible applications and can
  perform external side effects. Desktop consent and client confirmation are
  part of the safety boundary, not substitutes for capability minimization.
- Prompt injection in pages, terminals, documents, and chat windows can induce
  an authorized AI to misuse granted capabilities. Scope roots, disable unused
  capabilities, and require human confirmation for consequential actions.

## Out of scope

This project does not promise a hostile same-user sandbox, covert persistence,
automatic production deployment, or bypass of desktop compositor consent.
