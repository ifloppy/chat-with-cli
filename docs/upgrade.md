# Upgrade and rollback

The repository currently ships a single Go binary and a JSON state format that
loads alpha.4 state. Upgrade the Relay and Agent independently only after
checking compatibility and keeping the existing configuration and state.

## Review-first procedure

1. Download the release tarball and its published SHA256 checksum over HTTPS.
2. Inspect the archive and verify the checksum with `sha256sum` or an
   equivalent trusted tool before replacing a binary.
3. Run `go test ./...` when building from source and record `chat-with-cli
   version` for the old and new binaries.
4. Back up the Relay state/config and Agent credential/config files with their
   restrictive permissions. See [backup-restore.md](backup-restore.md).
5. Stop the one Relay process during replacement, install the new binary, and
   start it only after reviewing the command, unit, and paths. Do not run two
   writers against one state directory.
6. Run `doctor`, check `/health`, OAuth metadata, the Agent connection, and
   authenticated `tools/list`. Refresh tools in MCP clients after descriptor
   changes.

`chat-with-cli update` and `chat-with-cli rollback` are intentionally
review-first procedures in this alpha; they do not download, replace, enable,
or start a service.

For rollback, restore the previous checksum-verified binary while keeping the
state directory unchanged. If a newer binary has migrated state in a future
release, follow its documented migration/rollback note rather than copying an
old state file over newer data.
