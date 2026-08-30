# ChatGPT and MCP compatibility

Use the stable account MCP resource URL:

```text
https://relay.example/mcp
```

After OAuth, the account endpoint exposes `devices_list` and requires its
returned `device` selector on each workstation tool call. This is deliberately
stateless, so concurrent chats cannot accidentally change a shared "current
device". The Relay revalidates current ownership and device state for every
call. Use `https://relay.example/mcp/id/<immutable-device-id>` only when you
intentionally want an OAuth grant pinned to one workstation.

Configure the client for OAuth. The Relay publishes protected-resource
metadata, authorization-server metadata, Dynamic Client Registration, PKCE
S256, and resource-bound `mcp` access tokens. Do not put an access token in the
endpoint URL.

## What the server advertises

A device-pinned endpoint exposes 31 workstation tools. The account `/mcp`
endpoint exposes 32: `devices_list` plus the same 31 workstation tools, with a
required `device` selector added to their input schemas. Every descriptor has a name, human-readable title,
description, input schema, and explicit read-only/destructive/open-world
annotations. Screenshot tools return MCP image content rather than base64 text
inside a normal text result.

The repository test covers a raw stateless HTTP `initialize` followed by
`tools/list`. This proves what the Relay-side server sends; it cannot control a
client's cache, account policy, plan, or safety filtering.

## If the client shows zero tools

1. Prefer the stable `/mcp` account endpoint and confirm the OAuth resource is
   exactly the same URL. `tools/list` does not require an Agent to be online.
2. Confirm `/health`, OAuth metadata, protected-resource metadata, and the MCP
   challenge are not HTML challenge pages.
3. Reconnect or use the client's **Refresh tools** action after a descriptor
   change. A cached tool list can outlive a successful OAuth login.
4. Run `chat-with-cli doctor --relay ... --device-id ...`. For a separately
   issued MCP bearer token, add `--mcp-token`; this performs authenticated
   `initialize` and `tools/list` checks without displaying the token.
5. If the server-side raw check returns 32 on `/mcp` (or 31 on a device-pinned
   endpoint) while the client still shows zero, refresh/re-add the client. Relay
   discovery diagnostics log only RPC method, path, and status by default; set
   `CHAT_WITH_CLI_MCP_DIAGNOSTICS=0` to disable them. Never log Authorization
   headers, OAuth form bodies, or full callback URLs.

The compatibility regression sequence is intentionally narrow: minimal
descriptor, schema, output schema, title/annotations, tool count, then client
refresh. This repository does not claim that a particular external ChatGPT
cache or plan policy is fixed by descriptor changes alone.
