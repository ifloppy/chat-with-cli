# Administration

Open `/admin` on the Relay. The first owner is created through `/setup`; the
setup token is local-only, short-lived, single-use, and never shown to
anonymous users. All admin forms use a CSRF cookie plus hidden token. Cookies
are HttpOnly, SameSite, and Secure on HTTPS; pages set CSP, frame protection,
nosniff, Referrer-Policy, and no-store headers.

The dashboard shows version, uptime, mode, Relay/device status, users, OAuth
clients, browser sessions, token metadata, active invite handles, and bounded
security events. In public mode it also states the operator trust boundary:
operators control the server and therefore cannot credibly promise that a
modified deployment is unable to inspect MCP traffic. It
never displays raw bearer tokens or browser-session cookies; token/session
actions use one-way handles.

Available controls include:

- review the current private/public instance mode and, when the mode was not
  fixed by startup configuration, switch it from the dashboard; a mode change
  closes open registration until it is explicitly enabled again;
- enable/disable open public registration and DCR, create single-use 24-hour
  invites, and revoke unused invites;
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

If authorization state cannot be durably persisted, the Relay marks `oauth-state.guard` dirty, freezes MCP and Agent authorization fail-closed across restarts, shows a red dashboard warning, and returns 503 from `/health`. Repair storage and repeat the intended revoke/disable action while the Relay remains frozen. A successful recovery save forces the global kill switch on and marks the guard clean; restart, verify users/devices/tokens, then use recent re-authentication to release the kill switch. Never delete the guard merely to make the Relay start healthy.
The dashboard is an operator control plane, not a cryptographic boundary from
the operator and not a replacement for OS permissions. A running Agent's local
capability policy and desktop Portal consent still apply. Normal users use
`/account` for tenant-scoped device/session/token-family management.
