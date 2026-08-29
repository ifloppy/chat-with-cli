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
6. On a public instance, the Relay operator is inside the trusted computing
   base. Cross-user authorization protects tenants from each other; it does not
   hide MCP traffic from an operator who controls or modifies the Relay.

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
DCR first requires a short-lived, one-time Relay challenge bound to the device
ID, public key, client name, and loopback HTTP redirect URI. Device-bound Agent
clients cannot redirect authorization codes to external HTTPS origins; generic
MCP clients retain HTTPS callback support. The private-key signature is
consumed after one successful registration. Every authenticated Agent
WebSocket then requires a separate one-time Relay challenge signed by the same
key and bound to the exact resource and bearer fingerprint. Both challenge MAC
keys are process-ephemeral, so proofs captured before a Relay restart cannot be
replayed afterward. Only successfully consumed challenges occupy bounded
per-device replay state, so one tenant cannot exhaust another device's replay
capacity. Names remain labels and legacy compatibility routes.

## Residual risks and assumptions

- A public Relay provides no operator-excluding end-to-end privacy. The operator
  controls server code and TLS termination and can observe or alter brokered
  traffic. Self-host a private Relay when this trust is unacceptable, including
  when the alternative public instance is operated by the project author.
- A same-user shell is not contained by `--root`. Without Landlock it has the
  user's normal filesystem, network, process, and environment authority.
- Landlock is Linux-only filesystem defense in depth; it is not a network,
  process, container, or secret-isolation boundary.
- Path-based root checks can encounter TOCTOU races against a malicious local
  same-user process. Use a dedicated OS account/container for hostile tenants.
- The JSON state remains intentionally single-process. Production startup enforces an exclusive process-lifetime lease, so a second Relay targeting the same state directory fails instead of running with a stale authorization snapshot.
- The fallback credential file contains raw OAuth tokens. Protect it as a
  login secret; native OS credential stores are future work.
- Computer Use can expose secrets from other visible applications and can
  perform external side effects. Desktop consent and client confirmation are
  part of the safety boundary, not substitutes for capability minimization.
- Prompt injection in pages, terminals, documents, and chat windows can induce
  an authorized AI to misuse granted capabilities. Scope roots, disable unused
  capabilities, and require human confirmation for consequential actions.

## Out of scope

This project does not promise a hostile same-user sandbox, protection from a
malicious public Relay operator, covert persistence, automatic production
deployment, or bypass of desktop compositor consent.
