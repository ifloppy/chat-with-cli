# Install and lifecycle

## One-command workstation install

For a normal unprivileged Linux workstation:

```bash
curl -fsSL https://raw.githubusercontent.com/ifloppy/chat-with-cli/main/install.sh | sh
```

The bootstrap script detects Linux amd64/arm64, resolves the newest GitHub
release (including prereleases), downloads the matching binary and
`SHA256SUMS`, verifies SHA-256, and atomically installs to
`~/.local/bin/chat-with-cli`. It does **not** use sudo, start an Agent, or
enable a service. Review `install.sh` first if you do not want to execute a
network-delivered script directly. Pin a release with
`CHAT_WITH_CLI_VERSION=vX.Y.Z` or choose another destination with
`CHAT_WITH_CLI_INSTALL_DIR=/path`.

The installer is deliberately review-first. Without `--apply`, it performs no
network request and changes no files.

## Install the Relay binary

Preview the exact destination and release asset:

```bash
chat-with-cli relay install --version latest
```

Apply the install only after review:

```bash
sudo chat-with-cli relay install --version latest --apply
```

`latest` resolves the newest non-draft GitHub release, including prereleases.
For reproducible deployment, provide an explicit tag such as
`--version v0.1.0-alpha.5`.

The installer downloads the Linux amd64/arm64 binary and `SHA256SUMS` from the
same concrete GitHub release, verifies the published SHA-256 entry, and then
atomically replaces the destination. It never executes downloaded shell code.

## Optional systemd unit

To also write the hardened Relay unit:

```bash
sudo chat-with-cli relay install --version latest --apply --write-systemd
```

The command only writes the unit. It does **not** run `daemon-reload`, enable,
or start the service. Existing units are not overwritten unless
`--force-systemd` is explicitly supplied. Run `chat-with-cli relay setup` to
create `/etc/chat-with-cli/config.toml` and the one-time setup token before
starting the unit.

## Update

Preview:

```bash
chat-with-cli update --version latest
```

Apply:

```bash
sudo chat-with-cli update --version latest --apply
```

Before replacement the current binary is copied to `<binary>.previous` and a
local `<binary>.previous.sha256` is written. No service is restarted.

## Rollback

Preview:

```bash
chat-with-cli rollback
```

Restore the local previous binary:

```bash
sudo chat-with-cli rollback --apply
```

Rollback verifies the local sidecar checksum before restoring the backup. A
modified or symlinked backup/destination is rejected. State/config files are
not rolled back automatically; follow release-specific migration notes before
rolling a binary back across a state-format migration.

Checksums protect release/download integrity but do not make a compromised
GitHub repository or account trustworthy. Protect the project release account
and review release provenance for high-value deployments.
