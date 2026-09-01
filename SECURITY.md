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

### Public Relay operator trust

Public multi-user isolation protects one normal account from another normal
account. It does **not** protect a user from the Relay operator. The operator
controls the executable, persistent state, TLS endpoint, and request broker and
can run modified code that records or changes MCP requests/results. There is no
end-to-end cryptographic privacy guarantee between an MCP client and the Agent
that excludes the Relay.

Treat every public Relay operator as part of the trusted computing base. This
applies even to an instance operated by the project author. Users who cannot
accept that trust must self-host a private Relay on infrastructure they control.
Server-side audit defaults and "we do not log content" statements describe the
shipped code, not a property that remote users can verify against a modified
public deployment.

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


Authorization-state persistence is fail-closed across process restarts. The Relay keeps a 0600 `oauth-state.guard` file open for its lifetime, marks it `dirty` before each authorization-state transaction, fsyncs the JSON state, and marks the guard `clean` only after the durable write succeeds. A dirty guard freezes MCP and Agent access after restart. Repair storage, repeat the intended revoke/disable operation, and persist it successfully; recovery writes force the emergency kill switch on, so the subsequent restart remains blocked until an administrator reviews state and explicitly releases it. Do not delete the guard to bypass recovery. Revoking either an access or refresh token revokes its complete refresh-token family.

Browser forms use CSRF tokens bound to cookies and pending requests. `/account`
lets a user manage only that account's devices, sessions, password, and OAuth
token families; it never revokes a shared OAuth client belonging to other
users. Admin and setup pages use HttpOnly, SameSite cookies, Secure cookies on HTTPS, CSP,
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
for new device claims. Before Agent DCR, the client requests a short-lived
one-time registration challenge from the Relay. That challenge is bound to the
canonical device ID, Ed25519 public key, client name, and loopback HTTP
redirect URI; device-bound Agent DCR rejects external callbacks even though
generic MCP clients may use HTTPS callbacks. The Agent signs the challenge
with the matching private key and the Relay
consumes it after one successful registration. The registration challenge MAC
key is process-ephemeral, so captured proofs cannot be replayed across Relay
restarts. Before every later Agent WebSocket, the authenticated Agent obtains a
second short-lived one-time challenge bound to the exact Agent resource and
bearer fingerprint and signs it with the same device key. Consumed-challenge
replay state is isolated per device. Knowing the ID, public key, Agent bearer,
or any previously captured DCR/WebSocket proof alone is insufficient to
impersonate a PoP-bound device.

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

The durable Agent audit log records bounded metadata only: UTC timestamp, event
ID, method, duration, and success/failure. It omits tool arguments, file
contents, terminal input, UI text, and command output. The current and one
rotated JSONL file are capped at roughly 8 MiB. Separately, the local CLI
console audit stream shows a human-readable, redacted argument summary so an
operator can tell which path/query/task/command was requested. Payload-like
values (file contents, patch text, terminal/UI input, environment values) are
withheld, secret-like fields are redacted, and displayed scalar values are
bounded. Admin security events are bounded as well. These records are
operational evidence, not tamper-evident forensic storage; export to a separate
append-only system when stronger guarantees are required.

WebSocket frames, screenshots, file reads/searches, task output, active PTY
tasks, broker calls/connections, OAuth clients, pending authorizations, users,
sessions, and security events are bounded. These limits reduce accidental
exhaustion but do not replace host/container CPU, memory, process, and disk
quotas for public instances.

Optional Relay usage metering counts authenticated MCP request/response payload
bytes and brokered Agent WebSocket payload bytes per user. It is disabled by
default and is a traffic budget, not an authorization boundary: the Relay
operator can still observe or alter traffic. Keep AdMob reward verification
server-side; the browser and client must never be trusted to choose a user,
quota, or reward claim. Store `CHAT_WITH_CLI_ADMOB_VERIFIER_SECRET` out of band,
never in Relay state or web assets. Usage counters, activation-code hashes, and
redeemed reward IDs live in the mode-0600 `usage-state.json`, separate from the
fail-closed `oauth-state.json`. High-frequency byte accounting is checkpointed
in batches; a usage checkpoint failure is retried and never opens or freezes an
authorization boundary. Quota grants and redemptions synchronously persist and
roll back on failure.

## Public deployment checklist

- Use HTTPS and a reverse proxy with WebSocket support; never trust forwarded
  client-IP headers unless the proxy CIDR is explicitly configured.
- Prefer single-use, expiring invites while testing a public instance. Open
  self-registration is a larger abuse surface and should be deliberate.
- Keep DCR closed when it is not needed; apply upstream rate limits and host
  quotas before public exposure.
- State prominently that the public Relay operator is trusted and that users
  should self-host for secrets or high-trust computer access.
- Inspect Cloudflare/WAF challenge services rather than logging credentials or
  broadly bypassing protection. See [docs/cloudflare.md](docs/cloudflare.md).
- Back up the Relay state separately from the local Agent credential file, and
  test restore while the production process-lifetime state lease is active. See [docs/backup-restore.md](docs/backup-restore.md).
- Review `/admin` regularly and keep the local Agent service disabled until its
  generated unit and capability profile have been audited.

## Reporting

Please report suspected vulnerabilities privately through GitHub Security
Advisories once the public repository is available. Never include passwords,
tokens, private callbacks, filesystem contents, or desktop screenshots in a
public issue.
