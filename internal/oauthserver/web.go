package oauthserver

import (
	"context"
	"crypto/subtle"
	"html/template"
	"net/http"
	"os"
	"strings"
	"time"
)

const setupCSRFCookie = "cwc_setup_csrf"

type uiCSPNonceContextKey struct{}

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := randomToken(24)
		r = r.WithContext(context.WithValue(r.Context(), uiCSPNonceContextKey{}, nonce))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		// The UI assets are local and only the optional, explicitly configured
		// AdSense loader is allowed to come from Google. Keeping scripts out of
		// the HTML lets the Relay retain a strict CSP without sacrificing the
		// theme, language, copy, and progressive-enhancement interactions. The
		// narrowly scoped style-src-attr exception is required by Material Web's
		// menu positioning; script-src remains free of unsafe-inline.
		w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; style-src 'self' 'nonce-"+nonce+"'; style-src-attr 'unsafe-inline'; script-src 'self' https://pagead2.googlesyndication.com; connect-src 'self' https://pagead2.googlesyndication.com https://googleads.g.doubleclick.net; frame-src https://googleads.g.doubleclick.net; img-src 'self' data: https://pagead2.googlesyndication.com https://googleads.g.doubleclick.net; font-src 'self'")
		next.ServeHTTP(w, r)
	})
}

type landingPageData struct {
	Version             string
	Mode                string
	Admin               bool
	GitHubURL           string
	PublicURL           string
	SetupAvailable      bool
	Degraded            bool
	Locale              string
	AdSenseClientID     string
	AdSenseSlot         string
	AdMobAppID          string
	AdMobRewardUnitID   string
	UsageUnlockEnabled  bool
	UsageUnlockEndpoint string
}

var landingTemplate = template.Must(template.New("landing").Parse(`<!doctype html>
<html lang="en" data-locale="{{.Locale}}" data-admin="{{.Admin}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="A secure, open-source bridge between AI tools and your workstation."><title data-i18n="Chat with CLI · Connect with confidence">Chat with CLI · Connect with confidence</title><link rel="stylesheet" href="/assets/app.css?v=4"><script src="/assets/app.js?v=4" defer></script></head>
<body><div class="page">
<header class="topbar"><a class="brand" href="/"><span class="brand-mark" aria-hidden="true">⌁</span><span class="brand-name">Chat with CLI</span></a><nav class="nav" aria-label="Primary navigation" data-i18n-aria-label="Primary navigation"><a href="/docs" data-i18n="Docs">Docs</a><a href="/connect" data-i18n="Connect">Connect</a><div class="ui-controls" data-ui-controls></div></nav></header>
<main>
<section class="hero"><div class="hero-grid"><div><span class="eyebrow" data-i18n="{{.Mode}} relay">{{.Mode}} relay</span><h1><span data-i18n="Install once. Connect everywhere.">Install once. Connect everywhere.</span></h1><p class="lead" data-i18n="A calm, secure bridge between your AI tools and the workstation where work gets done.">A calm, secure bridge between your AI tools and the workstation where work gets done.</p>
<div class="actions">{{if .SetupAvailable}}<a class="button primary" href="/setup" data-i18n="Finish first-run setup">Finish first-run setup</a>{{else}}{{if eq .Mode "public"}}<a class="button primary" href="/account" data-i18n="Manage my account">Manage my account</a><a class="button tonal" href="/connect" data-i18n="Connect my computer">Connect my computer</a>{{else}}<a class="button primary" href="/account" data-i18n="My account">My account</a><a class="button tonal" href="/connect" data-i18n="Connect a workstation">Connect a workstation</a>{{end}}{{end}}<a class="button text" href="/docs" data-i18n="Documentation">Documentation</a><a class="button text" href="{{.GitHubURL}}" rel="noreferrer" data-i18n="GitHub">GitHub</a></div>
{{if eq .Mode "public"}}<div class="trust-card"><strong data-i18n="Do not trust a public Relay with sensitive access">Do not trust a public Relay with sensitive access</strong><span data-i18n="A public Relay isolates normal users from each other, but the operator controls the server code and can observe or alter MCP traffic. This includes instances run by the software author. Self-host a private Relay when confidentiality or high-trust computer access matters.">A public Relay isolates normal users from each other, but the operator controls the server code and can observe or alter MCP traffic. This includes instances run by the software author. Self-host a private Relay when confidentiality or high-trust computer access matters.</span></div>{{end}}
</div><div class="hero-visual" aria-label="MCP client connected through an outbound Relay to an Agent" data-i18n-aria-label="MCP client connected through an outbound Relay to an Agent"><div class="network"><span class="link left"></span><span class="link right"></span><span class="link bottom"></span><div class="node client" aria-hidden="true">✦<span>MCP</span></div><div class="node relay" aria-hidden="true">⌁<span>Relay</span></div><div class="node agent" aria-hidden="true">▣<span>Agent</span></div><div class="node mcp" aria-hidden="true">↗<span>Tools</span></div></div><span class="visual-caption" data-i18n="outbound · scoped · observable">outbound · scoped · observable</span></div></div></section>
<section class="section"><div class="section-heading"><div><span class="eyebrow" data-i18n="Features">Features</span><h2 data-i18n="Everything you need to work with confidence.">Everything you need to work with confidence.</h2></div><p data-i18n="A small surface area, thoughtful defaults, and clear control over every capability.">A small surface area, thoughtful defaults, and clear control over every capability.</p></div><div class="feature-grid"><article class="feature-card"><div class="feature-icon" aria-hidden="true">⌘</div><h3 data-i18n="MCP-native workflow">MCP-native workflow</h3><p data-i18n="Connect ChatGPT and other MCP clients to bounded filesystem, task, and optional Computer Use tools.">Connect ChatGPT and other MCP clients to bounded filesystem, task, and optional Computer Use tools.</p></article><article class="feature-card"><div class="feature-icon" aria-hidden="true">⇢</div><h3 data-i18n="Outbound by default">Outbound by default</h3><p data-i18n="The workstation Agent connects outward and reconnects automatically. The Relay never initiates a workstation connection.">The workstation Agent connects outward and reconnects automatically. The Relay never initiates a workstation connection.</p></article><article class="feature-card"><div class="feature-icon" aria-hidden="true">✓</div><h3 data-i18n="Guardrails you can see">Guardrails you can see</h3><p data-i18n="Read-only profiles, device-bound OAuth, local approvals, audit metadata, and an emergency kill switch keep authority legible.">Read-only profiles, device-bound OAuth, local approvals, audit metadata, and an emergency kill switch keep authority legible.</p></article></div></section>
<section class="section"><div class="stats"><div class="stat"><strong>31</strong><span data-i18n="MCP tools, clearly annotated">MCP tools, clearly annotated</span></div><div class="stat"><strong>0</strong><span data-i18n="capabilities enabled by surprise">capabilities enabled by surprise</span></div><div class="stat"><strong>1</strong><span data-i18n="small binary to install">small binary to install</span></div></div></section>
<section class="section"><div class="section-heading"><div><span class="eyebrow" data-i18n="Relay">Relay</span><h2 data-i18n="A connection you can understand.">A connection you can understand.</h2></div><p data-i18n="See the instance mode, software version, and authorization health before you connect anything.">See the instance mode, software version, and authorization health before you connect anything.</p></div><div class="grid"><div class="card"><h3 data-i18n="Relay">Relay</h3><div class="meta"><span data-i18n="Version">Version</span><b>{{.Version}}</b><span data-i18n="Instance">Instance</span><b data-i18n="{{.Mode}}">{{.Mode}}</b><span data-i18n="Status">Status</span>{{if .Degraded}}<b class="status bad" data-i18n="authorization frozen">authorization frozen</b>{{else}}<b class="status ok" data-i18n="ready">ready</b>{{end}}</div></div><div class="card"><h3>{{if .SetupAvailable}}<span data-i18n="Setup required">Setup required</span>{{else}}<span data-i18n="Relay configured">Relay configured</span>{{end}}</h3>{{if .SetupAvailable}}<p data-i18n="The Relay has not created its owner account yet. Use the one-time token stored locally on the Relay host.">The Relay has not created its owner account yet. Use the one-time token stored locally on the Relay host.</p>{{else}}<p data-i18n="Owner setup is complete. Devices and credentials are visible only after administrator sign-in.">Owner setup is complete. Devices and credentials are visible only after administrator sign-in.</p>{{end}}</div><div class="card"><h3 data-i18n="Private by design">Private by design</h3><p data-i18n="OAuth credentials are bound to one user, exact device resource, and scope. New public devices use cryptographic immutable IDs.">OAuth credentials are bound to one user, exact device resource, and scope. New public devices use cryptographic immutable IDs.</p></div></div></section>
{{if .AdSenseClientID}}{{if .AdSenseSlot}}<section class="ad-slot ad-slot-top" data-ad-placement="top" data-adsense-client="{{.AdSenseClientID}}" aria-label="Advertisement" data-i18n-aria-label="Advertisement"><div class="ad-label" data-i18n="Advertisement">Advertisement</div><ins class="adsbygoogle adsense-unit" data-ad-client="{{.AdSenseClientID}}" data-ad-slot="{{.AdSenseSlot}}" data-ad-format="auto" data-full-width-responsive="true"></ins></section>{{end}}{{end}}
{{if .AdSenseClientID}}{{if .AdSenseSlot}}<section class="ad-slot ad-slot-inline" data-ad-placement="inline" data-adsense-client="{{.AdSenseClientID}}" aria-label="Advertisement" data-i18n-aria-label="Advertisement"><div class="ad-label" data-i18n="Advertisement">Advertisement</div><ins class="adsbygoogle adsense-unit" data-ad-client="{{.AdSenseClientID}}" data-ad-slot="{{.AdSenseSlot}}" data-ad-format="auto" data-full-width-responsive="true"></ins></section>{{end}}{{end}}
{{if .UsageUnlockEnabled}}<section class="support-card" data-admob-app-id="{{.AdMobAppID}}" data-admob-reward-unit-id="{{.AdMobRewardUnitID}}"><div><h3 data-i18n="Keep the public Relay available">Keep the public Relay available</h3><p data-i18n="A companion app can verify a rewarded AdMob view and issue a short-lived, signed usage entitlement.">A companion app can verify a rewarded AdMob view and issue a short-lived, signed usage entitlement.</p></div><a class="button primary" href="{{.UsageUnlockEndpoint}}" rel="noreferrer" data-i18n="Open reward app">Open reward app</a></section>{{end}}
{{if .AdSenseClientID}}{{if .AdSenseSlot}}<section class="ad-slot ad-slot-bottom" data-ad-placement="bottom" data-adsense-client="{{.AdSenseClientID}}" aria-label="Advertisement" data-i18n-aria-label="Advertisement"><div class="ad-label" data-i18n="Advertisement">Advertisement</div><ins class="adsbygoogle adsense-unit" data-ad-client="{{.AdSenseClientID}}" data-ad-slot="{{.AdSenseSlot}}" data-ad-format="auto" data-full-width-responsive="true"></ins></section>{{end}}{{end}}
{{if not .SetupAvailable}}<section class="section"><div class="section-heading"><div><span class="eyebrow" data-i18n="Get started">Get started</span><h2 data-i18n="Add a workstation in a few calm steps.">Add a workstation in a few calm steps.</h2></div></div><div class="steps"><div class="step"><b data-i18n="1. Create a safe local Agent config">1. Create a safe local Agent config</b><span class="muted" data-i18n="Read-only is the default profile.">Read-only is the default profile.</span><div class="copy-row"><code class="command" id="setup-command">chat-with-cli agent setup --relay {{.PublicURL}} --root /path/to/workspace --profile read-only --install-systemd</code><button class="copy-button" type="button" data-copy-target="setup-command" data-i18n="Copy">Copy</button></div></div><div class="step"><b data-i18n="2. Connect interactively">2. Connect interactively</b><span class="muted"><span data-i18n="Run">Run</span> <code>chat-with-cli connect</code>. <span data-i18n="Browser OAuth opens automatically when needed, then the local terminal asks how to approve temporary capabilities for this session.">Browser OAuth opens automatically when needed, then the local terminal asks how to approve temporary capabilities for this session.</span></span></div><div class="step"><b data-i18n="3. Connect your MCP client">3. Connect your MCP client</b><div class="copy-row"><code class="command" id="mcp-endpoint">{{.PublicURL}}/mcp</code><button class="copy-button" type="button" data-copy-target="mcp-endpoint" data-i18n="Copy">Copy</button></div></div></div></section>{{end}}
</main><footer class="footer"><span><span data-i18n="Health endpoint">Health endpoint</span>: <code>/health</code>. <span data-i18n="No device inventory or host information is exposed on this public page.">No device inventory or host information is exposed on this public page.</span></span><span><a href="/docs" data-i18n="Documentation">Documentation</a> · <a href="{{.GitHubURL}}" rel="noreferrer" data-i18n="Open source">Open source</a></span></footer>
</div></body></html>`))

// All public pages use the shared local asset bundle. Keeping the templates
// together makes the single-binary deployment easy to audit and version.
var docsTemplateV2 = template.Must(template.New("docs-v2").Parse(`<!doctype html>
<html lang="en" data-locale="{{.Locale}}" data-admin="{{.Admin}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="description" content="Chat with CLI guides and operational documentation."><title data-i18n="Documentation · Chat with CLI">Documentation · Chat with CLI</title><link rel="stylesheet" href="/assets/app.css?v=4"><script src="/assets/app.js?v=4" defer></script></head>
<body><div class="page narrow"><header class="topbar"><a class="brand" href="/"><span class="brand-mark" aria-hidden="true">⌁</span><span class="brand-name">Chat with CLI</span></a><nav class="nav"><a href="/" data-i18n="Home">Home</a><a href="/connect" data-i18n="Connect">Connect</a><div class="ui-controls" data-ui-controls></div></nav></header><main><div class="page-header"><span class="eyebrow" data-i18n="Documentation">Documentation</span><h1 data-i18n="Chat with CLI documentation">Chat with CLI documentation</h1><p data-i18n="Start here when you are deploying a Relay, pairing a workstation, or connecting an MCP client.">Start here when you are deploying a Relay, pairing a workstation, or connecting an MCP client.</p></div><div class="card"><p class="muted" data-i18n="The binary ships with this navigation page. The complete, versioned operator documentation is maintained in the open-source project.">The binary ships with this navigation page. The complete, versioned operator documentation is maintained in the open-source project.</p><p><a href="{{.Base}}/blob/main/docs/README.zh-CN.md" data-i18n="中文">中文</a> · <a href="{{.Base}}/blob/main/docs/README.md" data-i18n="English guide">English guide</a></p></div><div class="grid"><div class="card"><h3 data-i18n="Start and connect">Start and connect</h3><p><a href="{{.Base}}/blob/main/docs/quick-start.md" data-i18n="Quick start">Quick start</a></p><p><a href="{{.Base}}/blob/main/docs/install.md" data-i18n="Install">Install</a> · <a href="{{.Base}}/blob/main/docs/agent.md" data-i18n="Agent configuration">Agent configuration</a></p><p><a href="{{.Base}}/blob/main/docs/chatgpt.md" data-i18n="ChatGPT / MCP">ChatGPT / MCP</a> · <a href="{{.Base}}/blob/main/docs/self-host-with-chatgpt.md" data-i18n="Self-host with ChatGPT">Self-host with ChatGPT</a></p></div><div class="card"><h3 data-i18n="Operate a Relay">Operate a Relay</h3><p><a href="{{.Base}}/blob/main/docs/private-instance.md" data-i18n="Private Relay">Private Relay</a> · <a href="{{.Base}}/blob/main/docs/public-instance.md" data-i18n="Public Relay">Public Relay</a></p><p><a href="{{.Base}}/blob/main/docs/deployment.md" data-i18n="Deployment">Deployment</a> · <a href="{{.Base}}/blob/main/docs/reverse-proxy.md" data-i18n="Reverse proxy">Reverse proxy</a></p><p><a href="{{.Base}}/blob/main/docs/admin.md" data-i18n="Administration">Administration</a> · <a href="{{.Base}}/blob/main/docs/backup-restore.md" data-i18n="Backup and restore">Backup and restore</a></p></div><div class="card"><h3 data-i18n="Safety and maintenance">Safety and maintenance</h3><p><a href="{{.Base}}/blob/main/docs/security.md" data-i18n="Security">Security</a> · <a href="{{.Base}}/blob/main/docs/threat-model.md" data-i18n="Threat model">Threat model</a></p><p><a href="{{.Base}}/blob/main/docs/computer-use.md" data-i18n="Computer Use">Computer Use</a> · <a href="{{.Base}}/blob/main/docs/cloudflare.md" data-i18n="Cloudflare">Cloudflare</a></p><p><a href="{{.Base}}/blob/main/docs/upgrade.md" data-i18n="Upgrade and rollback">Upgrade and rollback</a> · <a href="{{.Base}}/blob/main/docs/troubleshooting.md" data-i18n="Troubleshooting">Troubleshooting</a></p></div></div><div class="support-card"><div><h3 data-i18n="Need a quick path?">Need a quick path?</h3><p><span data-i18n="Use the interactive terminal hub after installation:">Use the interactive terminal hub after installation:</span> <code>chat-with-cli ui</code>.</p></div><a class="button primary" href="/connect" data-i18n="Connect a workstation">Connect a workstation</a></div></main><footer class="footer"><span data-i18n="Docs are maintained alongside each version of the source.">Docs are maintained alongside each version of the source.</span><span><a href="/" data-i18n="Back to home">Back to home</a> · <a href="{{.Base}}" rel="noreferrer" data-i18n="Open source">Open source</a></span></footer></div></body></html>`))

var connectTemplateV2 = template.Must(template.New("connect-v2").Parse(`<!doctype html>
<html lang="en" data-locale="{{.Locale}}" data-admin="{{.Admin}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title data-i18n="Connect a computer · Chat with CLI">Connect a computer · Chat with CLI</title><link rel="stylesheet" href="/assets/app.css?v=4"><script src="/assets/app.js?v=4" defer></script></head>
<body><div class="page narrow"><header class="topbar"><a class="brand" href="/"><span class="brand-mark" aria-hidden="true">⌁</span><span class="brand-name">Chat with CLI</span></a><nav class="nav"><a href="/" data-i18n="Home">Home</a><a href="/docs" data-i18n="Docs">Docs</a><div class="ui-controls" data-ui-controls></div></nav></header><main><div class="page-header"><span class="eyebrow" data-i18n="Connect">Connect</span><h1 data-i18n="Connect a computer">Connect a computer</h1><p data-i18n="Pair a workstation with a small, explicit, read-only first step.">Pair a workstation with a small, explicit, read-only first step.</p></div>{{if .Public}}<div class="warning"><b data-i18n="Public Relay warning">Public Relay warning</b><span data-i18n="This Relay operator controls the server software and can observe or alter brokered MCP traffic. Do not connect sensitive workspaces or secrets to any public instance, including one operated by the project author. For high-trust use, connect only long enough to bootstrap your own private Relay.">This Relay operator controls the server software and can observe or alter brokered MCP traffic. Do not connect sensitive workspaces or secrets to any public instance, including one operated by the project author. For high-trust use, connect only long enough to bootstrap your own private Relay.</span></div>{{end}}<div class="steps"><div class="step"><b data-i18n="1 · Install the verified binary">1 · Install the verified binary</b><div class="copy-row"><code class="command" id="install-command">curl -fsSL {{.PublicURL}}/install.sh | sh</code><button class="copy-button" type="button" data-copy-target="install-command" data-i18n="Copy">Copy</button></div><span class="muted"><span data-i18n="The installer verifies the release binary against SHA256SUMS and installs to">The installer verifies the release binary against SHA256SUMS and installs to</span> <code>~/.local/bin</code>. <span data-i18n="It does not start the Agent or use sudo. Review the script first if you prefer not to pipe network content to a shell.">It does not start the Agent or use sudo. Review the script first if you prefer not to pipe network content to a shell.</span></span><div class="actions"><a class="button tonal" href="{{.GitHub}}/releases" rel="noreferrer" data-i18n="Open releases">Open releases</a><a class="button text" href="/docs" data-i18n="Install documentation">Install documentation</a></div></div><div class="step"><b data-i18n="2 · Create a safe Agent profile">2 · Create a safe Agent profile</b><div class="copy-row"><code class="command" id="agent-setup-command">chat-with-cli agent setup --relay {{.PublicURL}} --root "$HOME/project" --profile read-only --install-systemd</code><button class="copy-button" type="button" data-copy-target="agent-setup-command" data-i18n="Copy">Copy</button></div><span class="muted" data-i18n="Replace the root with the smallest workspace you want ChatGPT to read. The generated systemd unit is not started automatically.">Replace the root with the smallest workspace you want ChatGPT to read. The generated systemd unit is not started automatically.</span></div><div class="step"><b data-i18n="3 · Connect and authorize this device">3 · Connect and authorize this device</b><code class="command">chat-with-cli connect</code><span class="muted"><span data-i18n="OAuth opens automatically if needed.">OAuth opens automatically if needed.</span> <span data-i18n="On an invite-only public instance, the OAuth page asks for the single-use invite during account creation. The Agent's immutable device ID is derived from its local Ed25519 key.">On an invite-only public instance, the OAuth page asks for the single-use invite during account creation. The Agent's immutable device ID is derived from its local Ed25519 key.</span></span></div><div class="step"><b data-i18n="4 · Review and start the Agent">4 · Review and start the Agent</b><code class="command">chat-with-cli doctor
systemctl --user daemon-reload
systemctl --user enable --now chat-with-cli-agent.service</code><span class="muted" data-i18n="Do not run the Agent as root. Review the roots and capabilities before enabling the unit.">Do not run the Agent as root. Review the roots and capabilities before enabling the unit.</span></div><div class="step"><b data-i18n="5 · Add it to ChatGPT">5 · Add it to ChatGPT</b><span class="muted" data-i18n="Use the stable account MCP endpoint; OAuth limits device discovery and routing to the signed-in account.">Use the stable account MCP endpoint; OAuth limits device discovery and routing to the signed-in account.</span><code class="command">{{.PublicURL}}/mcp</code></div><div class="step"><b data-i18n="6 · Prefer self-hosting after bootstrap">6 · Prefer self-hosting after bootstrap</b><span class="muted" data-i18n="Once ChatGPT can work through this computer, it can help deploy a verified private Relay on your VPS. Keep the new Relay's owner password and setup token out of the public Relay path.">Once ChatGPT can work through this computer, it can help deploy a verified private Relay on your VPS. Keep the new Relay's owner password and setup token out of the public Relay path.</span><div class="actions"><a class="button tonal" href="{{.GitHub}}/blob/main/docs/self-host-with-chatgpt.md" rel="noreferrer" data-i18n="Self-hosting guide">Self-hosting guide</a></div></div></div></main><footer class="footer"><span><a href="/" data-i18n="Back to home">Back to home</a> · <a href="/account" data-i18n="My account">My account</a></span><span><a href="/docs" data-i18n="Documentation">Documentation</a></span></footer></div></body></html>`))

var setupTemplateV2 = template.Must(template.New("setup-v2").Parse(`<!doctype html>
<html lang="en" data-locale="{{.Locale}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title data-i18n="Set up Chat with CLI">Set up Chat with CLI</title><link rel="stylesheet" href="/assets/app.css?v=4"><script src="/assets/app.js?v=4" defer></script></head>
<body><div class="page compact"><header class="topbar"><a class="brand" href="/"><span class="brand-mark" aria-hidden="true">⌁</span><span class="brand-name">Chat with CLI</span></a><div class="ui-controls" data-ui-controls></div></header><main><div class="page-header"><span class="eyebrow" data-i18n="First run">First run</span><h1 data-i18n="First-run setup">First-run setup</h1><p data-i18n="Create the first administrator and choose how this Relay accepts users. This page permanently disappears after successful setup.">Create the first administrator and choose how this Relay accepts users. This page permanently disappears after successful setup.</p></div><div class="steps"><div class="step"><b data-i18n="1 · Local token">1 · Local token</b><span class="muted" data-i18n="Read the protected setup-token file on the Relay host.">Read the protected setup-token file on the Relay host.</span></div><div class="step"><b data-i18n="2 · Owner account">2 · Owner account</b><span class="muted" data-i18n="Create a strong administrator password.">Create a strong administrator password.</span></div><div class="step"><b data-i18n="3 · Add devices">3 · Add devices</b><span class="muted" data-i18n="Sign in, then pair workstations with immutable IDs.">Sign in, then pair workstations with immutable IDs.</span></div></div><div class="warning"><b data-i18n="Keep the setup token local.">Keep the setup token local.</b> <span data-i18n="Do not paste it into chat, logs, tickets, or command arguments. It is single-use and removed after successful initialization.">Do not paste it into chat, logs, tickets, or command arguments. It is single-use and removed after successful initialization.</span></div><form class="surface" method="post" action="/setup"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><label><span data-i18n="One-time setup token">One-time setup token</span><input name="setup_token" autocomplete="one-time-code" required></label><label><span data-i18n="Owner username">Owner username</span><input name="username" autocomplete="username" value="owner" minlength="3" maxlength="64" required></label><label><span data-i18n="Owner password">Owner password</span><input type="password" name="password" autocomplete="new-password" minlength="12" maxlength="1024" required><small data-i18n="Minimum 12 characters. The Relay stores an Argon2id hash, not this password.">Minimum 12 characters. The Relay stores an Argon2id hash, not this password.</small></label><label><span data-i18n="Instance mode">Instance mode</span><select name="mode"><option value="private" data-i18n="Private — recommended">Private — recommended</option><option value="public" data-i18n="Public — multi-user">Public — multi-user</option></select></label><label class="check"><input type="checkbox" name="registration" value="open"><span data-i18n="Enable public self-registration immediately. Leave this off unless you intentionally operate a public multi-user Relay.">Enable public self-registration immediately. Leave this off unless you intentionally operate a public multi-user Relay.</span></label><button class="primary" type="submit" data-i18n="Create owner and finish setup">Create owner and finish setup</button></form><p class="muted"><span data-i18n="After setup, sign in to">After setup, sign in to</span> <code>/admin</code><span data-i18n="to review security controls before connecting a workstation."> to review security controls before connecting a workstation.</span></p></main><footer class="footer"><a href="/" data-i18n="Back to home">Back to home</a><a href="/docs" data-i18n="Documentation">Documentation</a></footer></div></body></html>`))

func (s *Server) setupAvailable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.setupTokenHash != "" && len(s.users) == 0
}

func (s *Server) handleLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	version, mode, github := s.cfg.Version, s.cfg.Mode, s.cfg.GitHubURL
	degraded := s.persistenceFault
	s.mu.Unlock()
	if version == "" {
		version = "development"
	}
	if github == "" {
		github = "https://github.com/ifloppy/chat-with-cli"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	s.mu.Lock()
	adsenseClientID, adsenseSlot := strings.TrimSpace(s.cfg.AdSenseClientID), strings.TrimSpace(s.cfg.AdSenseSlot)
	admobAppID, admobRewardUnitID := strings.TrimSpace(s.cfg.AdMobAppID), strings.TrimSpace(s.cfg.AdMobRewardUnitID)
	usageUnlockEnabled, usageUnlockEndpoint, usageMeteringEnabled := s.rewardedUsageReadyLocked(), strings.TrimSpace(s.cfg.UsageUnlockEndpoint), s.usageMeteringEnabled
	s.mu.Unlock()
	current, loggedIn := s.sessionUser(r)
	_ = executeTemplateWithUINonce(w, r, landingTemplate, landingPageData{Version: version, Mode: mode, Admin: loggedIn && current.Admin, GitHubURL: github, PublicURL: strings.TrimRight(s.base.String(), "/"), SetupAvailable: s.setupAvailable(), Degraded: degraded, Locale: uiLocale(r), AdSenseClientID: adsenseClientID, AdSenseSlot: adsenseSlot, AdMobAppID: admobAppID, AdMobRewardUnitID: admobRewardUnitID, UsageUnlockEnabled: usageMeteringEnabled && usageUnlockEnabled && usageUnlockEndpoint != "", UsageUnlockEndpoint: usageUnlockEndpoint})
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	public := s.cfg.Mode == ModePublic
	github := s.cfg.GitHubURL
	s.mu.Unlock()
	if github == "" {
		github = "https://github.com/ifloppy/chat-with-cli"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	current, loggedIn := s.sessionUser(r)
	_ = executeTemplateWithUINonce(w, r, connectTemplateV2, map[string]any{"Public": public, "Admin": loggedIn && current.Admin, "PublicURL": strings.TrimRight(s.base.String(), "/"), "GitHub": strings.TrimRight(github, "/"), "Locale": uiLocale(r)})
}

func (s *Server) handleDocs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	github := s.cfg.GitHubURL
	s.mu.Unlock()
	if github == "" {
		github = "https://github.com/ifloppy/chat-with-cli"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	current, loggedIn := s.sessionUser(r)
	_ = executeTemplateWithUINonce(w, r, docsTemplateV2, map[string]any{"Base": strings.TrimRight(github, "/"), "Admin": loggedIn && current.Admin, "Locale": uiLocale(r)})
}

func (s *Server) setSetupCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: setupCSRFCookie, Value: token, Path: "/setup", MaxAge: int(pendingLifetime.Seconds()), HttpOnly: true, Secure: s.base.Scheme == "https", SameSite: http.SameSiteStrictMode})
}

func doubleSubmitMatches(r *http.Request, cookieName string) bool {
	cookie, err := r.Cookie(cookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	value := r.FormValue("csrf_token")
	return value != "" && len(cookie.Value) == len(value) && subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(value)) == 1
}

func (s *Server) handleSetupGET(w http.ResponseWriter, r *http.Request) {
	if !s.setupAvailable() {
		http.NotFound(w, r)
		return
	}
	token := randomToken(24)
	s.setSetupCSRFCookie(w, token)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = executeTemplateWithUINonce(w, r, setupTemplateV2, map[string]string{"CSRFToken": token, "Locale": uiLocale(r)})
}

func (s *Server) handleSetupPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allowRate(r, "setup", 10, time.Minute) {
		rateLimited(w, 60)
		return
	}
	if !s.setupAvailable() {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil || !doubleSubmitMatches(r, setupCSRFCookie) {
		http.Error(w, "invalid setup form", http.StatusForbidden)
		return
	}
	provided := r.Form.Get("setup_token")
	mode, err := normalizeMode(r.Form.Get("mode"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.cfg.ModeConfigured && mode != s.cfg.Mode {
		http.Error(w, "instance mode is fixed by the Relay configuration; update the configured instance mode before setup", http.StatusBadRequest)
		return
	}
	if len(provided) < 16 || len(provided) > 256 {
		http.Error(w, "invalid setup token", http.StatusForbidden)
		return
	}
	if err := validatePassword(r.Form.Get("password")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	registrationOpen := r.Form.Get("registration") == "open"
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.users) != 0 || s.setupTokenHash == "" || subtle.ConstantTimeCompare([]byte(s.setupTokenHash), []byte(tokenKey(provided))) != 1 {
		http.Error(w, "invalid or expired setup token", http.StatusForbidden)
		return
	}
	snapshot := s.snapshotMutableStateLocked()
	user, err := s.createUserLocked(r.Form.Get("username"), r.Form.Get("password"), true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.cfg.Mode = mode
	s.registrationEnabled = mode == ModePublic && registrationOpen
	s.setupTokenHash = ""
	s.recordSecurityLocked(SecurityEvent{Event: "setup_completed", User: user.Username, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
	if err := s.saveOrRollbackLocked(snapshot); err != nil {
		http.Error(w, "failed to persist setup", http.StatusInternalServerError)
		return
	}
	if s.setupTokenPath != "" {
		if info, err := os.Lstat(s.setupTokenPath); err == nil && info.Mode().IsRegular() {
			_ = os.Remove(s.setupTokenPath)
		}
	}
	// The owner is intentionally not issued a bearer credential in the setup
	// response. The browser signs in through the normal admin session flow.
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) recordSecurityLocked(event SecurityEvent) {
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	if len(event.User) > 128 {
		event.User = event.User[:128]
	}
	if len(event.Device) > 128 {
		event.Device = event.Device[:128]
	}
	if len(s.securityEvents) >= 200 {
		copy(s.securityEvents, s.securityEvents[len(s.securityEvents)-199:])
		s.securityEvents = s.securityEvents[:199]
	}
	s.securityEvents = append(s.securityEvents, event)
}
