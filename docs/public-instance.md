# Public Relay

Public mode is an explicit operational choice. It enables multi-user browser
OAuth, but it also creates an account-registration and abuse surface.

## Enable it deliberately

Generate setup configuration with `--instance-mode public`, start the Relay,
and finish `/setup` while holding the local one-time setup token:

```bash
chat-with-cli relay setup \
  --config /etc/chat-with-cli/config.toml \
  --state-dir /var/lib/chat-with-cli \
  --public-url https://cli.example.com \
  --instance-mode public
chat-with-cli relay --config /etc/chat-with-cli/config.toml
```

Registration is held closed while first-run setup is pending. The setup form
lets the owner explicitly enable registration. It can later be disabled from
`/admin` or with `--disable-registration` on the next process start.

## Identity and ownership

`agent setup` creates a local Ed25519 device identity (0600) and derives the
immutable 128-bit device ID from the SHA-256 hash of its public key. The display
name is only a label. New resources are `/agent/id/<id>` and `/mcp/id/<id>`;
legacy name routes remain compatibility-only.

A new immutable device can be claimed only by an Agent OAuth client that proves
possession of the matching private key during Dynamic Client Registration. The
Relay binds the verified public key to the device record. Before every later
Agent WebSocket, the Agent obtains a short-lived one-time Relay challenge and
signs it with Ed25519. The challenge is bound to the exact Agent resource and
current bearer-token fingerprint, can be consumed only once, and is invalid
after a Relay restart. A stolen Agent bearer, public key, or previously
captured handshake therefore cannot impersonate a bound workstation.

MCP authorization remains restricted to the same account and exact MCP
resource. MCP bearer tokens are not sender-constrained by the device key and
remain high-value credentials. Use `/admin` to rename labels, disable,
unlink/revoke, or permanently disable devices and revoke credentials.

## Abuse controls

The Relay bounds users, DCR clients, pending authorization requests, password
hash concurrency, login attempts, DCR/authorization/token/revoke rates,
WebSocket connections, and in-flight broker calls. These are guardrails, not a
replacement for upstream rate limiting or an invite system. Invite-only
registration is not implemented; keep registration disabled when it is not
needed.

Use a reverse proxy with HTTPS, WebSocket support, request-rate controls, and
no caching for OAuth or MCP responses. Review Cloudflare guidance in
[cloudflare.md](cloudflare.md) if the origin is proxied.
