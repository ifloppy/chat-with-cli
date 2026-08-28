# Security Policy and Threat Model

`chat-with-cli` deliberately exposes capabilities that can become equivalent to local-user control when enabled. Treat an Agent token or an authorized MCP client as a high-value credential.

## Trust boundaries

1. **MCP client -> Relay:** authenticated with the client credential and protected by HTTPS in production.
2. **Agent -> Relay:** a separate Agent credential over outbound WSS.
3. **Relay -> Engine tools:** requests are routed to one named connected device.
4. **Engine -> host:** filesystem, PTY, screen, and input capabilities are independently policy-gated.

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

The alpha Relay uses separate high-entropy bearer tokens for MCP clients and Agents. Token comparisons are constant-time. Never place tokens in repository files, command examples copied into issue reports, or reverse-proxy access logs.

Use TLS for every non-loopback deployment. The built-in HTTP server is intentionally suitable for binding behind a reverse proxy; it is not a certificate-management stack.

OAuth 2.1 / MCP authorization is planned. Until then, deployments that require per-user identity, delegated authorization, or fine-grained token revocation should place an appropriate identity-aware proxy in front of the Relay or wait for native OAuth support.

## Resource limits

- Agent WebSocket messages are capped.
- Screenshots have a hard encoded-input size bound before MCP delivery.
- File reads/search results are bounded.
- Per-task persisted PTY logs are capped; output continues to be drained after truncation.
- Concurrent remote requests are bounded inside the Agent.

These controls reduce accidental exhaustion; they are not a substitute for OS-level CPU, memory, process, and disk quotas when serving mutually untrusted clients.

## Reporting

Please report suspected vulnerabilities privately through GitHub Security Advisories once the public repository is available. Avoid opening a public issue containing credentials, exploit details, or private machine information.
