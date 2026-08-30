# Reverse proxy

The Relay should listen on loopback or a private interface and receive public
HTTPS traffic through a trusted reverse proxy. Set `--public-url` to the
external HTTPS origin, not the loopback address. Configure `--trusted-proxy`
with only the proxy's source address/CIDR if abuse limits should use the
forwarded client IP; forwarded headers are otherwise ignored.

The proxy must:

- pass `GET /`, `/setup`, `/admin`, `/.well-known/*`, `/oauth/*`, and
  `/mcp/...` without rewriting the origin or path;
- support the WebSocket upgrade on `/agent/...` and keep idle connections open;
- avoid caching OAuth, admin, and MCP responses;
- preserve `Host` and TLS termination semantics, and send a real client IP
  only when the proxy is listed in `--trusted-proxy`;
- apply rate limits without challenging API traffic with an HTML page.

Example Caddy shape:

```caddyfile
cli.example.com {
    reverse_proxy 127.0.0.1:8765
}
```

Example Nginx shape:

```nginx
location / {
    proxy_pass http://127.0.0.1:8765;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 1h;
}
```

Do not copy these snippets without restricting the host, firewall, service
account, and proxy trust boundary. Run `chat-with-cli doctor --relay
https://cli.example.com --device-id ...` after deployment.

## CDN caching

UI asset URLs are content-addressed by the Relay, so a CSS/JavaScript change automatically produces a new URL even when a CDN overrides browser cache TTLs. Preserve the Relay's `ETag` and `Cache-Control` headers when possible; do not cache OAuth HTML responses, which are sent with `Cache-Control: no-store`.
