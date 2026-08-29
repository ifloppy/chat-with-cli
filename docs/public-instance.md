# Public Relay

Public mode is an explicit operational choice. It enables multi-user browser
OAuth, but it also creates an account-registration and abuse surface.

> **Do not treat a public Relay as end-to-end trusted.** It isolates ordinary
> users from each other, not users from the instance operator. The operator can
> modify the open-source server, TLS endpoint, or broker to record or alter MCP
> traffic. This warning applies even to a public instance operated by the
> software author. Use a private self-hosted Relay for secrets or high-trust
> computer access.

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
lets the owner explicitly enable open registration. It can later be disabled
from `/admin` or with `--disable-registration` on the next process start.

For a safer public beta, leave open registration disabled and create single-use
24-hour invites from `/admin`. Invite plaintext is shown once and only its
one-way hash is persisted. A valid invite can create an account even while open
registration is closed. Account creation, invite consumption, the first device
claim/authorization, authorization code, and browser session are committed as
one authorization-state transaction; failure rolls them all back.

## Identity and ownership

`agent setup` creates a local Ed25519 device identity (0600) and derives the
immutable 128-bit device ID from the SHA-256 hash of its public key. The display
name is only a label. New resources are `/agent/id/<id>` and `/mcp/id/<id>`;
legacy name routes remain compatibility-only.

A new immutable device can be claimed only by an Agent OAuth client that proves
possession of the matching private key. Before DCR, the Relay issues a
short-lived one-time registration challenge bound to the canonical device ID,
public key, client name, and redirect URI; the Agent signs it and the Relay
consumes it after one successful registration. A Relay restart invalidates all
outstanding registration challenges. The Relay then binds the verified public
key to the device record. Before every later Agent WebSocket, the Agent obtains
a separate one-time Relay challenge bound to the exact Agent resource and
current bearer-token fingerprint and signs it with Ed25519. A stolen Agent
bearer, public key, captured DCR proof, or captured WebSocket handshake
therefore cannot impersonate a bound workstation.

Legacy unbound Agent connections are disabled by default, including on public
instances. The migration-only `relay.allow_legacy_unbound_agents` option should
never be left enabled on an Internet-facing Relay after old devices have been
moved to new Ed25519 identities. Permanently revoked identities are tombstoned
and cannot be reclaimed with the old private key.

MCP authorization remains restricted to the same account and exact MCP
resource. MCP bearer tokens are not sender-constrained by the device key and
remain high-value credentials. Users manage their own devices, browser sessions,
password, and OAuth token families from `/account`; revoking a user's token
family never revokes a shared OAuth client used by another tenant. Operators
retain full instance control from `/admin`.

## Abuse controls

The Relay bounds users, DCR clients, pending authorization requests, password
hash concurrency, login attempts, DCR/authorization/token/revoke rates,
WebSocket connections, and in-flight broker calls. These are guardrails, not a
replacement for upstream rate limiting, host quotas, or abuse monitoring.
Invite-only registration reduces the anonymous sign-up surface but is not a
CAPTCHA, identity-verification system, or billing/anti-fraud platform.

Use a reverse proxy with HTTPS, WebSocket support, request-rate controls, and
no caching for OAuth or MCP responses. Review Cloudflare guidance in
[cloudflare.md](cloudflare.md) if the origin is proxied.
