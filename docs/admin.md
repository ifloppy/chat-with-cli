# Administration

Open `/admin` on the Relay. The first owner is created through `/setup`; the
setup token is local-only, short-lived, single-use, and never shown to
anonymous users. All admin forms use a CSRF cookie plus hidden token. Cookies
are HttpOnly, SameSite, and Secure on HTTPS; pages set CSP, frame protection,
nosniff, Referrer-Policy, and no-store headers.

The dashboard shows version, uptime, mode, Relay/device status, users, OAuth
clients, browser sessions, token metadata, and bounded security events. It
never displays raw bearer tokens or browser-session cookies; token/session
actions use one-way handles.

Available controls include:

- enable/disable public registration and DCR;
- emergency disable/re-enable MCP or Agent access;
- disable, unlink/revoke, and rename devices; device IDs remain immutable and
  canonicalized;
- create, disable, delete, and rotate credentials for users; log out one or
  all browser sessions;
- revoke OAuth clients, individual access tokens, refresh-token families, and
  individual browser sessions;
- activate or release the Relay kill switch.

Authority-reducing controls are intentionally fast: disabling MCP/Agent,
disabling a user/device, or engaging the global kill switch does not require a
fresh password prompt. Authority-expanding recovery is stricter: re-enabling a
user/device or releasing the kill switch requires a password re-check through
`/admin/reauth`; destructive revocations/deletions retain explicit confirmation.
Repeated disable requests are idempotent and cannot accidentally toggle access
back on.

If authorization state cannot be durably persisted, the Relay freezes MCP and
Agent authorization fail-closed, shows a red dashboard warning, and `/health`
returns 503 until the storage problem is fixed and the Relay restarts cleanly.
The dashboard is a control plane, not a replacement for OS permissions: a
running Agent's local capability policy and desktop Portal consent still apply.
