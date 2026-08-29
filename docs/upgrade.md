# Upgrade and rollback

Upgrade the Relay and Agent independently only after checking compatibility and
keeping existing configuration/state backups. Do not run two Relay writers
against the same JSON state directory.

## Binary update

`chat-with-cli update` is review-only unless `--apply` is supplied:

```bash
chat-with-cli update --version latest
sudo chat-with-cli update --version latest --apply
```

The apply path resolves a concrete release tag, downloads the Linux binary and
that release's `SHA256SUMS`, verifies the asset, saves the current binary as
`<binary>.previous` with a local checksum sidecar, and atomically installs the
new binary. It never restarts services automatically.

For a deterministic deployment, use an explicit tag instead of `latest`.

After replacing a Relay binary:

1. Review the release notes and state-format migration notes.
2. Restart exactly one Relay process when you choose to activate the update.
3. Run `chat-with-cli doctor`.
4. Check `/health`, OAuth metadata, Agent connectivity, and authenticated
   `tools/list`.
5. Refresh tools in MCP clients after descriptor changes.

## Rollback

Preview and apply rollback separately:

```bash
chat-with-cli rollback
sudo chat-with-cli rollback --apply
```

The backup checksum is verified before restoration. The command changes only
the binary and never restarts a service. If a newer release migrated persistent
state, follow that release's rollback instructions rather than restoring an old
binary against incompatible state.
