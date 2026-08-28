# ChatGPT and MCP compatibility

Use the immutable MCP resource URL:

```text
https://relay.example/mcp/id/<immutable-device-id>
```

Configure the client for OAuth. The Relay publishes protected-resource
metadata, authorization-server metadata, Dynamic Client Registration, PKCE
S256, and resource-bound `mcp` access tokens. Do not put an access token in the
endpoint URL.

## What the server advertises

The current binary exposes 31 tools through both the SDK session and raw
Streamable HTTP. Every descriptor has a name, human-readable title,
description, input schema, and explicit read-only/destructive/open-world
annotations. Screenshot tools return MCP image content rather than base64 text
inside a normal text result.

The repository test covers a raw stateless HTTP `initialize` followed by
`tools/list`. This proves what the Relay-side server sends; it cannot control a
client's cache, account policy, plan, or safety filtering.

## If the client shows zero tools

1. Confirm the Agent is online and the device ID is the same in the Agent log,
   OAuth resource, and MCP endpoint.
2. Confirm `/health`, OAuth metadata, protected-resource metadata, and the MCP
   challenge are not HTML challenge pages.
3. Reconnect or use the client's **Refresh tools** action after a descriptor
   change. A cached tool list can outlive a successful OAuth login.
4. Run `chat-with-cli doctor --relay ... --device-id ...`. For a separately
   issued MCP bearer token, add `--mcp-token`; this performs authenticated
   `initialize` and `tools/list` checks without displaying the token.
5. If the server-side raw check returns 31 while the client still shows zero,
   capture only status codes and protocol versions. Do not log Authorization
   headers, OAuth form bodies, or full callback URLs.

The compatibility regression sequence is intentionally narrow: minimal
descriptor, schema, output schema, title/annotations, tool count, then client
refresh. This repository does not claim that a particular external ChatGPT
cache or plan policy is fixed by descriptor changes alone.
