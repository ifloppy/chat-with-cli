# Troubleshooting

Start with:

```bash
chat-with-cli doctor --relay https://relay.example \
  --device-id <immutable-device-id>
```

The command checks local roots, optional desktop prerequisites, DNS/TLS,
health, OAuth metadata, DCR, protected-resource metadata, an existing Agent
credential/connection, and Cloudflare challenge headers. Add `--mcp-token`
only when you already have an MCP bearer token and want authenticated
`initialize`/`tools/list`; the value is never printed.

## OAuth failures

- Confirm the external `--public-url` is HTTPS and has no path, query, or
  fragment.
- Check that the proxy preserves `Host`, callback redirects, and WebSockets.
- Confirm the browser uses the same Relay origin as the resource URL.
- A 402/insufficient-balance response from an unrelated upstream model is not
  an OAuth protocol error; inspect the actual Relay response separately.
- A response with `cf-mitigated: challenge` is an HTML Cloudflare challenge.
  Inspect the Cloudflare Service field; do not weaken OAuth or log tokens.

## Agent/MCP failures

- Use the exact immutable `/agent/id/<id>` and `/mcp/id/<id>` paths.
- Confirm the Agent's local credential has not expired and that the Relay
  admin has not disabled the device, Agent, or token family.
- If MCP shows zero tools, compare the raw server `tools/list` result with the
  client cache and use its Refresh Tools action. The server regression test
  expects 31 descriptors.
- A disconnected Agent is expected to make MCP calls fail; the Relay never
  dials the workstation inbound.

## Desktop failures

If Computer Use is enabled, run doctor from the logged-in graphical session.
Check `WAYLAND_DISPLAY`/`DISPLAY`, session D-Bus, AT-SPI, Portal availability,
and a screenshot backend. Do not run the Agent through `sudo`; it commonly
loses the user's desktop bus and weakens the privilege boundary.

## State and service failures

Use `chat-with-cli status` for the generated user config/unit state. Check
permissions and symlink errors in config, credentials, and state directories.
Only one Relay process should use a state directory. Keep the current unit
inactive until its paths, capabilities, OAuth login, and generated hardening
have been reviewed.
