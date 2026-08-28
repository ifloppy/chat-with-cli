# Backup and restore

The Relay state file is normally:

```text
<state-dir>/oauth-state.json
```

It contains Argon2id password hashes, one-way token/session identifiers,
device/user/client metadata, settings, and bounded security events. It does
not contain raw OAuth bearer tokens or browser cookies. Treat it as sensitive
nonetheless.

Stop the Relay before taking a filesystem backup so the copy is a consistent
application snapshot. Preserve the state directory mode 0700, state file mode
0600, owner, and the `.lock` file's directory. Include the TOML config only if
its contents are appropriate for the backup; secrets should remain in the
environment or a separate secret store.

The workstation credential file is separate, normally
`~/.config/chat-with-cli/credentials.json`. It contains raw access/refresh
tokens and must be copied only as a 0600 secret. Do not combine it with a
Relay state backup or put it in source control.

Restore the entire state/config pair to the same paths and permissions, then
start one Relay process and run `doctor`. Restoring old server state does not
restore a deleted workstation credential. Conversely, deleting the local
credential does not revoke server-side tokens; use `/admin` or OAuth revocation
for that.

The alpha.4 JSON state is loaded without a destructive migration. Keep an
original read-only backup until the new binary has passed health, admin,
Agent, and MCP checks.
