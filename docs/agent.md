# Agent configuration

The default config path is `~/.config/chat-with-cli/config.toml` (or
`$XDG_CONFIG_HOME/chat-with-cli/config.toml`). Create it with:

```bash
chat-with-cli agent setup --relay https://cli.example.com --device workstation
```

CLI flags override config values. Secrets belong in environment variables or
the 0600 credential store, not TOML. The generated file contains no account
password.

## Profiles

| Profile | Enabled capabilities |
| --- | --- |
| `read-only` | filesystem reads under roots |
| `developer` | read, filesystem/checkpoint write, PTY shell |
| `computer-use` | screen/accessibility read and computer input/write |
| `custom` | individual flags only |

Capabilities can also be selected separately:

```text
--root PATH                 repeat for allowed filesystem trees
--allow-file-write          filesystem and checkpoint writes
--allow-exec                arbitrary PTY shell commands
--exec-sandbox=landlock     Linux filesystem boundary for shell children
--allow-screen              screenshots
--allow-accessibility       AT-SPI semantic inspection
--allow-computer-use        keyboard, pointer, semantic UI writes
--kill-switch-file PATH     deny every Engine call while the file exists
--max-active-tasks N        bounded concurrent PTY tasks (maximum 256)
```

The default root is the current directory when no root is specified. Resolve
roots deliberately; a root is not a shell sandbox. With `--allow-exec`, a
shell without Landlock still has the Agent user's normal filesystem, network,
process, and environment access. Landlock is filesystem-only defense in depth.

## OAuth and device identity

`login` performs browser OAuth with PKCE S256. The local fallback store is
`~/.config/chat-with-cli/credentials.json`, mode 0600 under a 0700 directory.
It contains raw access/refresh tokens for unattended reconnects, but never the
Relay account password. Deleting it removes local credentials; the Relay admin
must revoke the server-side client or token family for immediate invalidation.

Use the immutable device ID for both `login` and `agent` after setup. Keep the
ID and credential file private even though the human-readable name is only a
label.

## systemd user unit

`agent setup --install-systemd` writes a unit with `NoNewPrivileges`,
`PrivateTmp`, `ProtectSystem=strict`, `ProtectHome=read-only`, and related
hardening. It remains inactive and disabled. First complete OAuth, inspect the
unit and paths, then decide whether to enable it manually. Do not run the Agent
as root or with `sudo`; graphical session permissions usually belong to the
logged-in user.
