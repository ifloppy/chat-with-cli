# Security Policy and Threat Model

`chat-with-cli` deliberately exposes capabilities that can become equivalent to local-user control when enabled. Treat an OAuth refresh token, browser session, authorized MCP client, or legacy static token as a high-value credential.

## Trust boundaries

1. **Browser/user -> Relay:** a Relay account authenticates the human authorization step. Private instances have one bootstrapped owner account; public instances allow open account registration.
2. **MCP client -> Relay:** OAuth access is bound to one exact `/mcp/<device>` resource and the `mcp` scope.
3. **Agent -> Relay:** the workstation is also an OAuth client. Its access is bound to one exact `/agent/<device>` resource and the `agent:connect` scope.
4. **Relay identity -> device:** a device name is claimed by one Relay user; MCP authorization is allowed only to that owner.
5. **Relay -> Engine tools:** requests are routed to one named connected device.
6. **Engine -> host:** filesystem, PTY, screen, and input capabilities are independently policy-gated.

The Relay is a transport broker. It should not need filesystem access to the workstation and cannot initiate an inbound network connection to it.

## Default-deny capabilities

- Files are limited to explicit `--root` trees.
- Arbitrary command execution requires `--allow-exec`.
- Screenshots, `computer_observe`, and read-only AT-SPI UI inspection require `--allow-screen` or `--allow-computer-use`. `computer_observe` may include a screenshot automatically when semantic UI is insufficient.
- Keyboard/pointer injection, semantic UI actions, and direct AT-SPI editable-text mutation require `--allow-computer-use`.
- XDG RemoteDesktop consent persistence defaults to process lifetime; restart-surviving restore-token storage requires explicit `--computer-persist=persistent`.

Do not grant capabilities merely because a client supports the corresponding MCP tool.

## Prompt injection and confused-deputy risk

Computer Use changes the risk model substantially. A web page, chat message, README, issue, terminal output, or other untrusted content visible to the model can contain instructions intended to manipulate an AI agent.

Capability flags are therefore necessary but not sufficient. Operators should also:

- scope filesystem roots to the work actually required;
- avoid running the Agent as root;
- use a dedicated browser/profile for autonomous GUI work where practical;
- require user confirmation for consequential actions at the MCP/client layer;
- keep secrets out of visible terminals and browser pages when screenshots are enabled;
- revoke Computer Use when a task no longer needs it;
- prefer `--computer-persist=none` for one-off sessions, and use `persistent` only on machines intended for unattended recovery.

Tool annotations mark read-only versus destructive/open-world actions, but annotations are hints, not an authorization system. `computer_ui_invoke` and `computer_ui_set_text` deliberately refuse ambiguous or incomplete selectors rather than choosing a control heuristically. Direct EditableText mutation avoids synthetic keystrokes but is still a consequential GUI write capability. AT-SPI inspection and `computer_ui_get_text` can reveal text and control names from other visible applications, so read-only UI access should still be treated as sensitive screen access.

## Filesystem boundary

Existing symlinks are resolved before root-boundary checks, and tests cover direct symlink escapes. As with most pathname-based sandboxing, hostile concurrent filesystem mutation can create TOCTOU edge cases. Do not treat `--root` as a kernel-grade sandbox against a malicious local process running as the same user.

For stronger isolation, run the Agent in a container/namespace or dedicated Unix account and mount only the required workspaces.

## Authentication and transport

The Relay implements RFC 9728 protected-resource discovery, authorization-server metadata, Dynamic Client Registration, mandatory PKCE S256, short-lived resource-bound access tokens, and rotating refresh tokens. Both the workstation Agent and MCP clients use this browser OAuth flow. Agent grants require `agent:connect`; MCP grants require `mcp`. Tokens are bound to the exact resource URL and Relay user.

Relay account passwords are hashed with Argon2id using a random per-password salt. The server persists only password hashes, SHA-256 access/refresh-token identifiers, SHA-256 browser-session identifiers, and associated metadata. It never persists raw OAuth bearer tokens or raw browser-session cookies. Browser sessions are HttpOnly, SameSite=Lax, Secure on HTTPS, and expire after 30 days.

The CLI is necessarily different: `~/.config/chat-with-cli/credentials.json` contains the raw OAuth access and refresh tokens needed for unattended reconnects. It is written atomically with mode `0600` beneath a `0700` directory. Treat that file as a login credential. The account password is not stored there; it can remain in the user's browser/password manager.

Private instances bootstrap an owner account on first start. If no owner password is supplied, the Relay generates one and writes the raw bootstrap password to the configured owner-password file with mode `0600`. Save it in an appropriate password manager and delete the bootstrap file if operationally convenient after the account is established. Public instances start with open registration and do not create a default owner.

Device names are globally unique within one Relay. The first successful Agent authorization claims an unowned device for that signed-in user. MCP authorization requires the same owner. This prevents cross-user access, but a public user can intentionally claim an unowned name before its intended owner does; this is an availability/name-squatting limitation, not a privilege escalation. Device transfer/rename and administrative account-management tooling are not yet implemented.

Legacy static MCP and Agent bearer tokens remain available only for private migration/debug deployments. They intentionally bypass the finer user/resource ownership model and should be removed after browser OAuth migration. Public instance mode rejects configured static client or Agent tokens.

Use TLS for every non-loopback deployment. The built-in HTTP server is intended to bind behind a reverse proxy; it is not a certificate-management stack. Do not place account passwords, OAuth tokens, browser-session cookies, legacy static tokens, or CLI credential files in repositories, issue reports, shell history, or reverse-proxy access logs. Refresh tokens rotate on use; revocation and Relay state deletion can invalidate issued credentials.

## Audit metadata

The Agent records one bounded JSONL audit event for every Engine tool call: event ID, UTC time, method name, duration, and success/failure. Request arguments and result contents are deliberately never recorded, so file contents, terminal input, UI text, and credentials are not duplicated into the audit trail. The current log and one rotated log are capped at roughly 8 MiB each and stored beneath the Agent state directory with restrictive permissions. `audit_recent` exposes only this metadata.

This is an operational audit trail, not tamper-evident forensic storage. An Agent granted `--allow-exec` intentionally provides arbitrary commands with the desktop user’s OS permissions, so that user (or an authorized shell task) may be able to modify the Agent state directory. Export audit events to a separate append-only system if stronger evidence guarantees are required.

## Resource limits

- Agent WebSocket messages are capped.
- Screenshots have a hard encoded-input size bound before MCP delivery.
- File reads/search results are bounded.
- Per-task persisted PTY logs are capped; output continues to be drained after truncation.
- Audit metadata is bounded to the current 8 MiB JSONL file plus one rotated file.
- Concurrent remote requests are bounded inside the Agent.
- Concurrent PTY tasks are capped (32 by default, configurable with `--max-active-tasks`).
- OAuth registration, authorization requests, codes, access tokens, refresh tokens, browser sessions, and registered users have bounded counts and/or lifetimes. Password hashing is concurrency-limited, and repeated bad account-login attempts lock that pending authorization request.

These controls reduce accidental exhaustion; they are not a substitute for OS-level CPU, memory, process, and disk quotas when serving mutually untrusted clients.

Public mode is intentionally an open-registration service. It does not currently provide email verification, CAPTCHA, account recovery, quotas per user, or an administrative UI. Internet-facing public operators should add appropriate reverse-proxy/WAF rate limits and OS/container CPU, memory, process, and disk quotas. Open registration plus globally unique device names also means account spam and device-name squatting are availability risks that must be handled operationally until first-class administration tools exist.

## Reporting

Please report suspected vulnerabilities privately through GitHub Security Advisories once the public repository is available. Avoid opening a public issue containing credentials, exploit details, or private machine information.
