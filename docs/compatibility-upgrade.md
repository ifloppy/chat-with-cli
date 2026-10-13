# Compatibility and safe upgrades

Current protocol remains backwards compatible with `v0.1.0-alpha.5`. The
Agent's `agent_hello` report has an optional feature list. The Relay treats a
missing `mcp_gateway_v1` as **unsupported** rather than guessing based on
the version string. Existing tools still work with either binary generation.

| Relay | Agent | Tool catalog (device-pinned) |
| --- | --- | --- |
| Old | Old | 34 native tools |
| Old | New | 34 native tools; Gateway not published |
| New | Old | 34 native tools; Gateway not published |
| New | New | 38 tools, including four Gateway tools |

The account `/mcp` resource adds `devices_list`. It advertises Gateway
tools only when at least one enabled online device is present and all enabled
online devices support the Gateway. A mixed account can use a device-pinned
resource for a new Agent if it needs the extra Gateway tools. `devices_list`
also reports `mcp_gateway` for capable devices. Since ChatGPT snapshots tool
descriptors, refresh its MCP actions after changing devices/Agent versions.

## Verify compatibility without touching production

```bash
go test ./...
go build -o /tmp/cwc-new ./cmd/chat-with-cli
python3 scripts/compat_matrix.py \
  ~/.local/bin/chat-with-cli /tmp/cwc-new
```

The matrix launches four combinations in isolated temporary directories and
ephemeral loopback ports using test-only credentials. It checks both legacy
`system_info` and new Gateway discovery. CI builds a fixed historical
`v0.1.0-alpha.5` reference and repeats this matrix.

## Upgrade a locally built CLI without losing rollback

```bash
go build -o /tmp/cwc-candidate ./cmd/chat-with-cli

# Preview only; checks that the candidate is a Chat With CLI Go executable.
go run ./cmd/chat-with-cli install-local \
  --candidate /tmp/cwc-candidate \
  --binary "$HOME/.local/bin/chat-with-cli"

# Explicitly apply, saving <binary>.previous + checksum in the same directory.
go run ./cmd/chat-with-cli install-local \
  --candidate /tmp/cwc-candidate \
  --binary "$HOME/.local/bin/chat-with-cli" --apply

# If needed, restore checksum-verified previous executable:
"$HOME/.local/bin/chat-with-cli" rollback \
  --binary "$HOME/.local/bin/chat-with-cli" --apply
```

**Neither install nor rollback restarts an Agent or Relay.** Plan process
restart separately and keep an independent SSH/local session open. The old
process continues running its existing image until terminated. This protects
the only working management connection from accidental replacement.

The installed Agent configuration, identity and credentials are not rewritten
by this workflow. Keep a secure backup when intentionally changing settings.
Do not use `sudo` for the workstation Agent; OAuth/Wayland permissions belong
to the login session. The built-in `update` (verified GitHub release) and
`rollback` commands remain available.

## TUI entry points

- `chat-with-cli ui`: inspect Dashboard, MCP and journal.
- `o`: open existing interactive setup in a temporarily suspended TUI.
- `c`: connect in foreground, temporarily suspending TUI until the Agent exits.
  Connection is not detached; quit the Agent to resume the TUI.
- `s`: start an already-installed systemd user service, with a confirmation.
- `q`: exit TUI without stopping any existing service or Agent.

The process detector is best-effort and intentionally reports **unverified**
foreground CLI processes, not guaranteed authenticated Agent connectivity.
A local control socket and detachable foreground lifecycle management are
future improvements; this stage does not claim to implement them.
