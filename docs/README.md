# Chat with CLI user guide

[简体中文 / Chinese](README.zh-CN.md)

`chat-with-cli` is a single Go binary that connects an MCP client to a Linux
workstation through an outbound Agent and a Relay. Start with the narrowest
capability profile and expand it only when the task needs it.

## Fastest workstation path

```bash
curl -fsSL https://raw.githubusercontent.com/ifloppy/chat-with-cli/main/install.sh | sh
chat-with-cli ui
```

The interactive terminal hub defaults to the community public Relay at
`https://chat-with-cli.iruanp.com`. Choose a private Relay in the first prompt
or pass `--relay https://your-relay.example` to any command. The installer
verifies the downloaded binary with `SHA256SUMS`, installs it under
`~/.local/bin`, and never starts a service automatically.

For a scripted setup:

```bash
chat-with-cli agent setup \
  --relay https://chat-with-cli.iruanp.com \
  --root "$HOME/project" \
  --profile read-only \
  --install-systemd
chat-with-cli connect
chat-with-cli doctor
```

Review the generated unit and enable it only after OAuth succeeds:

```bash
systemctl --user daemon-reload
systemctl --user enable --now chat-with-cli-agent.service
```

## Which guide should I read?

- [Quick start](quick-start.md) — build locally or connect a first Agent.
- [Install](install.md) — verified installation, paths, and review-first updates.
- [Agent configuration](agent.md) — roots, profiles, identities, and systemd.
- [ChatGPT/MCP compatibility](chatgpt.md) — endpoint and OAuth setup.
- [Private Relay](private-instance.md) — self-hosted single-owner operation.
- [Public Relay](public-instance.md) — multi-user policy and trust boundary.
- [Deployment](deployment.md) and [reverse proxy](reverse-proxy.md) — production hosting.
- [Account](account.md) and [administration](admin.md) — device/session controls.
- [Security](security.md) and [threat model](threat-model.md) — assumptions and limits.
- [Computer Use](computer-use.md) — opt-in desktop screenshots and input.
- [Troubleshooting](troubleshooting.md) — common connection failures.
- [Backup/restore](backup-restore.md) and [upgrade/rollback](upgrade.md) — maintenance.
- [Version workflow](release.md) — local candidate versions before publication.

## Capability profiles

| Profile | Intended use | Default authority |
| --- | --- | --- |
| `read-only` (`R`) | First connection and ordinary code reading | Filesystem reads only |
| `read-write` (`W`) | Deliberate local development | Filesystem writes and PTY execution; Linux uses Landlock by default |
| `desktop-computer-use` (`D`) | Explicit desktop automation | Screen/accessibility reads and computer input |
| `all` (`A`) | Full workstation capability set | Read-write plus desktop automation; Linux exec uses Landlock by default |
| `custom` (`C`) | Operators who want individual flags | The flags in the generated config |

The Relay cannot make a workstation grant a capability. Local profiles and the
foreground approval mode remain the final authority. Do not run an Agent as
root, and do not expose a broad filesystem root unless that scope is intended.

## Public Relay, usage, and advertising

The web UI currently exposes AdSense display advertising. Configure the AdSense
publisher/slot only on a Relay whose privacy notice and consent model are ready.
The older native AdMob companion/reward implementation remains in the codebase
for compatibility and future work, but it is parked: it is not exposed in the
admin/account/landing UI and the public monetization contract reports it as
disabled.

When `--usage-metering-enabled` is enabled, the Relay maintains a per-account
payload quota. Authenticated MCP HTTP request/response bytes and brokered Agent
WebSocket payload bytes are counted, and new requests are rejected with HTTP
`402` after the account is exhausted. The default is 100 MiB for each account;
use `--usage-default-quota-bytes` or the admin console to change the default.
The admin console can add quota directly or create a single-use activation code;
users redeem codes from `/account`. These grants are additive and survive a
restart. Counters and activation-code hashes are stored in the private
`usage-state.json`, separately from authorization data in `oauth-state.json`.
Traffic increments are checkpointed in batches and flushed on clean Relay
shutdown; quota grants and redemptions are persisted synchronously.

When both the AdSense publisher client ID and slot are configured, the public
landing page renders responsive placements. User-facing web pages also verify
that the AdSense loader itself is reachable. If browser tracking/ad blocking
prevents `adsbygoogle.js` from loading, the web UI shows a non-dismissible
recovery screen asking the visitor to allow ads for this site and reload.
Administrative, first-run setup, OAuth/security pages, and all MCP/Agent/API
traffic are deliberately exempt so an advertising failure cannot lock out the
operator or break protocol traffic. A normal AdSense `unfilled` result is not
considered ad blocking; empty placements collapse instead of blocking access.

Relevant Relay options are available on `relay` and `relay setup`:

```bash
chat-with-cli relay --help
chat-with-cli relay setup --help
```

The public, non-secret configuration is also available at
`/api/monetization/config` for a companion app. The endpoint intentionally
does not mint entitlements or expose the verifier secret.

## Language and appearance

Relay pages ship with a local Material 3-inspired design system. They follow
the browser's light/dark preference by default, and the control in the top
bar can select automatic, light, or dark mode. The same control selects
English or Simplified Chinese; `?lang=zh-CN` can be used for a shareable first
render preference. No external font or UI framework is required.

## Security reminder

A public Relay separates ordinary users from one another, not from the Relay
operator. The operator controls the server software and can observe or alter
brokered MCP traffic. Use a private, self-hosted Relay for secrets or
high-trust Computer Use. Read [SECURITY.md](../SECURITY.md) before opening a
Relay to the Internet.
