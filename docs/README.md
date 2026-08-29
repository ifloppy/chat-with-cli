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
| `read-only` | First connection and ordinary code reading | Filesystem reads only |
| `developer` | Deliberate local development | Filesystem writes and PTY execution; Linux uses Landlock by default |
| `computer-use` | Explicit desktop automation | Screen/accessibility reads and computer input |
| `custom` | Operators who want individual flags | The flags in the generated config |

The Relay cannot make a workstation grant a capability. Local profiles and the
foreground approval mode remain the final authority. Do not run an Agent as
root, and do not expose a broad filesystem root unless that scope is intended.

## Public Relay and rewarded access

The web UI has optional, disabled-by-default AdSense and AdMob integration
points. Configure the AdSense publisher/slot only on a Relay whose privacy
notice and consent model are ready. AdMob is a native companion-app concern;
the Relay may link to a reward flow, but it must accept usage unlocks only from
a server-side verifier using a short-lived signed entitlement. A browser
button or an unverified receipt must never grant MCP/Agent authority.

Relevant Relay options are available on `relay` and `relay setup`:

```bash
chat-with-cli relay --help
chat-with-cli relay setup --help
```

The public, non-secret configuration is also available at
`/api/monetization/config` for a companion app. The endpoint intentionally
does not mint entitlements.

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
