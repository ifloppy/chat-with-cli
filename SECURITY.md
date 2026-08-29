# Security Policy and Threat Model

`chat-with-cli` deliberately exposes capabilities that can become equivalent
to local-user control when enabled. Treat OAuth refresh tokens, browser
sessions, authorized MCP clients, Agent credentials, and legacy static tokens
as high-value credentials.

The short operator checklist is [docs/security.md](docs/security.md); the
detailed trust model is [docs/threat-model.md](docs/threat-model.md).

## Trust boundaries

1. **Browser/user -> Relay:** the browser authenticates and consents to an
   OAuth request. Private mode has one owner; public mode permits registration
   only when the owner enables it.
2. **MCP client -> Relay:** access is bound to one exact `/mcp/<route>` resource
   and `mcp` scope.
3. **Agent -> Relay:** the workstation Agent is a separate OAuth client bound
   to one exact `/agent/<route>` resource and `agent:connect` scope.
4. **Relay -> device:** the broker routes a request only to the authenticated
   resource's device connection. The Relay never dials the workstation.
5. **Agent -> Engine:** local capability gates protect filesystem, PTY,
   screenshot, accessibility, and input operations.
6. **Engine -> host:** OS user permissions, desktop Portal consent, and any
   optional Landlock policy remain part of the boundary.

The Relay does not need workstation filesystem access. The Agent initiates an
outbound WebSocket and reconnects; inbound firewall access to the workstation
is not required.

## Default-deny capabilities

- Filesystem reads require explicit `--root` trees.
- Filesystem and checkpoint writes require `--allow-file-write`.
- Arbitrary PTY shell commands require `--allow-exec`.
- `--exec-sandbox=landlock` adds a Linux filesystem-only boundary to shell
  children. On Linux the `developer` profile selects it by default; explicit
  `--exec-sandbox=none` opts back into unsandboxed shell authority.
- Screenshots require `--allow-screen`; AT-SPI accessibility reads require
  `--allow-accessibility`.
- Keyboard, pointer, semantic UI actions, and editable-text mutation require
  `--allow-computer-use`.
- Portal restore-token persistence is process-only by default; restart-safe
  storage requires explicit `--computer-persist=persistent`.
- A configured local panic file denies every Engine call while it exists.

`--root` is not a shell sandbox. A same-user shell without Landlock can read or
modify the user's other files, use the network, inspect processes, and inherit
environment secrets. Run the Agent as a dedicated unprivileged account and
scope roots narrowly. Do not run it as root.

## Authentication and authorization

The Relay implements protected-resource and authorization-server discovery,
Dynamic Client Registration, mandatory PKCE S256, one-use expiring
authorization codes, exact redirect matching, short-lived resource-bound
access tokens, rotating refresh-token families with replay revocation, and
OAuth revocation. MCP grants require `mcp`; Agent grants require
`agent:connect`; access is bound to the exact user, resource, scope, device
owner, and token family. OAuth-enabled Relays reject shared static client/Agent
tokens because a shared bearer cannot enforce per-user device ownership. Legacy
static mode is a separate single-tenant compatibility mode.

Relay passwords use Argon2id with random per-password salts. Password hashing
is concurrency-limited and unknown users use a dummy hash path to reduce
username timing differences. Login, DCR, authorization, token, revoke, setup,
and admin flows have bounded rates and body sizes. Pending authorization,
client, user, session, and broker resources have bounded counts/lifetimes.


Authorization-state persistence is fail-closed. If the Relay cannot durably
write OAuth/security state, the running process freezes MCP and Agent access
instead of continuing with potentially stale authorization. Repair storage and
restart from the last durable state. Revoking either an access or refresh token
revokes its complete refresh-token family.

Browser forms use CSRF tokens bound to cookies and pending requests. Admin and
setup pages use HttpOnly, SameSite cookies, Secure cookies on HTTPS, CSP,
frame-denial, nosniff, Referrer-Policy, Permissions-Policy, and no-store
responses. Destructive admin actions require explicit confirmation and recent
administrator authentication.

Server state contains password hashes, one-way SHA-256 token/session
identifiers, and associated metadata. Raw server-side OAuth bearer tokens and
browser-session cookies are never persisted or displayed in the admin UI.
The local fallback file `~/.config/chat-with-cli/credentials.json` necessarily
contains raw Agent OAuth access/refresh tokens for unattended reconnects. It is
0600 beneath a 0700 directory; protect it as a login credential. The account
password is never written there. Refresh and atomic replacement are serialized
across Agent processes with an advisory lock. Native Secret Service, KWallet,
Keychain, and Credential Manager backends remain future work.

## Device identity

New deployments use an Ed25519 device identity created by `agent setup`. The
immutable 128-bit route ID is derived from the public key; the human-readable
name remains only a label. Public instances require this cryptographic identity
for new device claims. During Agent DCR the client proves possession of the
matching private key. Before every later Agent WebSocket, the authenticated
Agent obtains a short-lived one-time challenge from the Relay and signs it with
the device key. The challenge is bound to the exact Agent resource and bearer
fingerprint, is consumed after one valid handshake, and is authenticated by a
per-process Relay key so every outstanding challenge becomes invalid after a
Relay restart. Consumed-challenge replay state is isolated per device. Knowing
the ID, public key, Agent bearer, or a previously captured handshake alone is
insufficient to impersonate a PoP-bound device.

Legacy already-owned alpha devices without a bound key are **denied by default**
because a bearer-only Agent token cannot resist device impersonation. The
`--allow-legacy-unbound-agents` / `relay.allow_legacy_unbound_agents` switch is
a migration-only escape hatch and produces a critical admin warning. Use it
only long enough to create a new Ed25519 identity/ID, verify that device online,
permanently revoke the old route, and disable migration mode again. Permanent
revocation writes a durable tombstone: the old immutable ID can never be
reclaimed even by someone holding its private key. MCP OAuth bearer tokens are
still bearer credentials and are not sender-constrained by the Agent device key.

The admin control plane can rename labels without changing routes, disable or
unlink devices, revoke device token families, and permanently disable Agent or
MCP access. Device capabilities are still enforced locally by the Agent; Relay
admin state cannot grant a capability the Agent did not enable. Authenticated
Agent WebSockets continuously revalidate their one-way bearer fingerprint,
including while idle and while an RPC is in flight. MCP caller authorization is
also revalidated before dispatch and during in-flight work. Token/client/device
revocation resets the affected remote Agent session; a lost Agent session kills
detached PTYs and closes Desktop Portal control before reconnecting. This keeps
previously-started background work from surviving loss of remote authority.

## Prompt injection and Computer Use

A web page, chat message, README, issue, terminal output, or visible desktop
application can contain instructions intended to manipulate an AI agent. An
authorized client may then use the capabilities the operator granted.

Use narrow roots, a dedicated browser/profile, explicit client confirmation for
external side effects, and `--computer-persist=none` for one-off work. Revoke
Computer Use when it is no longer needed. AT-SPI trees, text reads, and
screenshots can expose secrets visible in other applications. Tool annotations
are client hints, never an authorization system.

## Filesystem and sandbox limitations

Filesystem tools resolve symlinks before root checks, reject unsafe credential,
config, checkpoint, and state paths, and use atomic writes with restrictive
permissions. Path-based checks can still encounter TOCTOU races against a
malicious same-user process. Put hostile tenants in separate OS accounts,
containers, namespaces, or VMs.

Landlock is Linux-only and currently grants common runtime paths plus selected
workspace roots. It limits filesystem operations but does not restrict network,
signals, processes, inherited file descriptors, environment variables, or
kernel escape vulnerabilities. Treat it as defense in depth, not a complete
container.

## Audit and limits

The Agent audit log records bounded metadata only: UTC timestamp, event ID,
method, duration, and success/failure. It omits tool arguments, file contents,
terminal input, UI text, and command output. The current and one rotated JSONL
file are capped at roughly 8 MiB. Admin security events are bounded as well.
These records are operational evidence, not tamper-evident forensic storage;
export to a separate append-only system when stronger guarantees are required.

WebSocket frames, screenshots, file reads/searches, task output, active PTY
tasks, broker calls/connections, OAuth clients, pending authorizations, users,
sessions, and security events are bounded. These limits reduce accidental
exhaustion but do not replace host/container CPU, memory, process, and disk
quotas for public instances.

## Public deployment checklist

- Use HTTPS and a reverse proxy with WebSocket support; never trust forwarded
  client-IP headers unless the proxy CIDR is explicitly configured.
- Keep registration and DCR closed unless needed; apply upstream rate limits
  and quotas before public exposure.
- Inspect Cloudflare/WAF challenge services rather than logging credentials or
  broadly bypassing protection. See [docs/cloudflare.md](docs/cloudflare.md).
- Back up the Relay state separately from the local Agent credential file, and
  test restore with one Relay writer. See [docs/backup-restore.md](docs/backup-restore.md).
- Review `/admin` regularly and keep the local Agent service disabled until its
  generated unit and capability profile have been audited.

## Reporting

Please report suspected vulnerabilities privately through GitHub Security
Advisories once the public repository is available. Never include passwords,
tokens, private callbacks, filesystem contents, or desktop screenshots in a
public issue.
