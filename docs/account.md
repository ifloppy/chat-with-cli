# User account

`/account` is the tenant-scoped control plane for both public and private OAuth
instances. It is intentionally separate from the operator-only `/admin` page.

A signed-in user can see only devices owned by that account, the account's
browser sessions, and the account's OAuth token families. Users can rename or
disable their devices, permanently retire a device identity, revoke one of
their own OAuth grants, sign out other browser sessions, and change their
password. Enabling or permanently revoking a device requires the current
account password; password changes revoke all existing OAuth credentials and
browser sessions for that account.

OAuth client registrations can be shared by multiple users. `/account`
therefore revokes the current user's token family rather than deleting the
underlying client registration. This prevents one tenant from disconnecting
other tenants that use the same MCP client.

On public instances the page displays the operator trust warning. Tenant
isolation does not protect a user from the Relay operator, who controls the
server software and can modify it to observe or alter MCP traffic. Self-host a
private Relay when this trust is unacceptable.
