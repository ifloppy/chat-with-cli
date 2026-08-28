# Cloudflare

Cloudflare can proxy the Relay, but OAuth and MCP are automated API traffic,
not ordinary browser page loads. Keep the origin `--public-url` equal to the
public HTTPS URL and ensure WebSocket proxying is enabled for `/agent/...`.
Disable caching for `/oauth/*`, `/.well-known/*`, `/mcp/*`, `/agent/*`, and
admin/setup responses.

## Managed challenges

The Relay's `doctor` recognizes a response with
`cf-mitigated: challenge`. Cloudflare documents that Challenge Page responses
also use `text/html`, even when the requested endpoint is an API. An HTML
challenge on `/oauth/register`, `/oauth/token`, or `/mcp/...` is therefore a
proxy/security-product failure, not an OAuth JSON error.

Bot Fight Mode is evaluated outside the Ruleset Engine. Custom WAF Allow,
Skip, or Page Rules cannot bypass it. This is why a normal allow/skip rule may
not fix the observed challenge. Cloudflare's current options are to disable
Bot Fight Mode, use a product with scoped exceptions such as Super Bot Fight
Mode, or use an appropriate protected origin path/IP design. Super Bot Fight
Mode can use scoped Skip rules, but those rules must not broadly exempt a
public OAuth or MCP endpoint.

Browser Integrity Check, Security Level, IP Access Rules, rate limiting, and
WAF Managed Rules are separate controls. Inspect Security Events and identify
the **Service** that challenged the request before changing policy. For
reference, see Cloudflare's [challenge detection](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/),
[Bot Fight Mode](https://developers.cloudflare.com/bots/get-started/bot-fight-mode/),
and [Skip action](https://developers.cloudflare.com/waf/custom-rules/skip/)
documentation.

Do not solve this by logging bearer tokens or disabling all WAF protections.
Prefer a narrow exception for a known monitoring source, or a product/config
that supports legitimate automated clients, then rerun `doctor` and the raw
MCP compatibility check.
