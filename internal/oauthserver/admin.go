package oauthserver

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ifloppy/chat-with-cli/internal/protocol"
)

const adminCSRFCookie = "cwc_admin_csrf"

func (s *Server) SetDeviceStatusProvider(provider func() map[string]DeviceStatus) {
	s.mu.Lock()
	s.statusProvider = provider
	s.mu.Unlock()
}

type adminDeviceView struct {
	Route        string
	ID           string
	Name         string
	Owner        string
	Disabled     bool
	Online       bool
	ConnectedAt  time.Time
	LastSeen     time.Time
	InFlight     int
	Capabilities protocol.AgentCapabilities
	ProofBound   bool
}

type adminUserView struct {
	ID          string
	Username    string
	Admin       bool
	Disabled    bool
	CreatedAt   time.Time
	LastLoginAt time.Time
	Devices     int
}

type adminTokenView struct {
	Handle   string
	Label    string
	Kind     string
	ClientID string
	Username string
	Resource string
	Expires  time.Time
}

type adminSessionView struct {
	Handle   string
	Label    string
	Username string
	Created  time.Time
	LastSeen time.Time
	Expires  time.Time
}

type adminInviteView struct {
	Handle        string
	Label         string
	Expires       time.Time
	UsesRemaining int
	CreatedBy     string
}

type adminUsageView struct {
	ID        string
	Username  string
	Quota     int64
	Used      int64
	Remaining int64
}

type adminActivationCodeView struct {
	Label         string
	Quota         int64
	Expires       time.Time
	UsesRemaining int
	CreatedBy     string
}

type adminPageData struct {
	Version                string
	Mode                   string
	ModeConfigured         bool
	RegistrationDisabled   bool
	PublicURL              string
	PersistenceFault       bool
	RegistrationEnabled    bool
	DCREnabled             bool
	MCPEnabled             bool
	AgentEnabled           bool
	KillSwitch             bool
	LegacyUnboundAgents    bool
	Uptime                 string
	OnlineAgents           int
	RegisteredDevices      int
	RetiredDevices         int
	Users                  int
	OAuthClients           int
	Sessions               int
	Devices                []adminDeviceView
	UserList               []adminUserView
	Clients                []Client
	Tokens                 []adminTokenView
	SessionList            []adminSessionView
	Invites                []adminInviteView
	UsageMeteringEnabled   bool
	UsageDefaultQuotaBytes int64
	AdSenseClientID        string
	AdSenseSlot            string
	UsageUsers             []adminUsageView
	ActivationCodes        []adminActivationCodeView
	Events                 []SecurityEvent
	CSRFToken              string
	Username               string
}

var adminLoginTemplate = template.Must(template.New("admin-login").Parse(`<!doctype html>
<html lang="en" data-admin="false"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin sign in · Chat with CLI</title></head>
<body><div class="page compact"><header class="topbar"><a class="brand" href="/"><span class="brand-mark" aria-hidden="true">⌁</span><span class="brand-name">Chat with CLI</span></a><nav class="nav"><a href="/" data-i18n="Home">Home</a><div class="ui-controls" data-ui-controls></div></nav></header>
<main><div class="page-header"><span class="eyebrow" data-i18n="Administration">Administration</span><h1 data-i18n="Chat with CLI admin">Chat with CLI admin</h1><p data-i18n="Sign in to manage devices, users, sessions, and emergency capability switches.">Sign in to manage devices, users, sessions, and emergency capability switches.</p></div>
<section class="auth-card"><form class="auth-form" method="post" action="/admin/login"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><label><span data-i18n="Username">Username</span><input name="username" autocomplete="username" required></label><label><span data-i18n="Password">Password</span><input type="password" name="password" autocomplete="current-password" required></label><button class="primary" type="submit" data-i18n="Sign in">Sign in</button></form></section>
<p class="auth-footer"><a href="/" data-i18n="Back to home">Back to home</a></p></main></div></body></html>`))

var adminReauthTemplate = template.Must(template.New("admin-reauth").Parse(`<!doctype html>
<html lang="en" data-admin="false"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Re-authenticate · Chat with CLI</title></head>
<body><div class="page compact"><header class="topbar"><a class="brand" href="/"><span class="brand-mark" aria-hidden="true">⌁</span><span class="brand-name">Chat with CLI</span></a><nav class="nav"><a href="/admin" data-i18n="Return to admin">Admin</a><div class="ui-controls" data-ui-controls></div></nav></header>
<main><div class="page-header"><span class="eyebrow" data-i18n="Security">Security</span><h1 data-i18n="Confirm it’s you">Confirm it’s you</h1><p data-i18n="High-risk administration actions require a password check within the last 15 minutes. This refreshes only the current browser session.">High-risk administration actions require a password check within the last 15 minutes. This refreshes only the current browser session.</p></div>
<section class="auth-card"><form class="auth-form" method="post" action="/admin/reauth"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><label><span data-i18n="Password for">Password for</span> {{.Username}}<input type="password" name="password" autocomplete="current-password" required autofocus></label><button class="primary" type="submit" data-i18n="Re-authenticate">Re-authenticate</button></form></section>
<p class="auth-footer"><a href="/admin" data-i18n="Cancel and return to admin">Cancel and return to admin</a></p></main></div></body></html>`))

var adminTemplate = template.Must(template.New("admin").Funcs(template.FuncMap{"join": strings.Join, "formatBytes": formatUsageBytes}).Parse(`<!doctype html>
<html lang="en" data-admin="true"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin · Chat with CLI</title></head>
<body><div class="page admin-page"><header class="topbar"><a class="brand" href="/"><span class="brand-mark" aria-hidden="true">⌁</span><span class="brand-name">Chat with CLI</span></a><nav class="nav"><a href="/" data-i18n="Home">Home</a><a href="/account" data-i18n="My account">My account</a><a href="/docs" data-i18n="Docs">Docs</a><a class="button outlined" href="/admin/reauth" data-i18n="Re-authenticate">Re-authenticate</a><form class="inline" method="post" action="/admin/logout"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><button class="text" type="submit" data-i18n="Sign out">Sign out</button></form><div class="ui-controls" data-ui-controls></div></nav></header>
<main><div class="page-header"><span class="eyebrow" data-i18n="Administration">Administration</span><h1 data-i18n="Operator admin">Operator admin</h1><p data-i18n="Review the Relay state and change high-impact controls from one auditable surface.">Review the Relay state and change high-impact controls from one auditable surface.</p></div>
<div class="admin-summary"><p><span data-i18n="Signed in as">Signed in as</span> <strong>{{.Username}}</strong> · <span data-i18n="Version">version</span> <strong>{{.Version}}</strong> · <strong data-i18n="{{.Mode}}">{{.Mode}}</strong> <span data-i18n="instance">instance</span> · <span data-i18n="Uptime">uptime</span> <strong>{{.Uptime}}</strong>.</p></div>
{{if .PersistenceFault}}<div class="banner critical"><b data-i18n="Authorization is frozen">Authorization is frozen</b><span data-i18n="The Relay detected an incomplete authorization-state transaction. MCP and Agent access remain fail-closed across restarts. Repair storage, repeat the intended revoke/disable action, and persist it successfully; recovery writes force the emergency kill switch on. Restart, verify the security state, then explicitly release the kill switch. Do not delete">The Relay detected an incomplete authorization-state transaction. MCP and Agent access remain fail-closed across restarts. Repair storage, repeat the intended revoke/disable action, and persist it successfully; recovery writes force the emergency kill switch on. Restart, verify the security state, then explicitly release the kill switch. Do not delete</span> <code>oauth-state.guard</code> <span data-i18n="to bypass recovery.">to bypass recovery.</span></div>{{end}}
{{if .KillSwitch}}<div class="banner critical"><b data-i18n="Emergency kill switch is active">Emergency kill switch is active</b><span data-i18n="MCP and Agent authorization is globally blocked. Releasing it requires recent administrator authentication.">MCP and Agent authorization is globally blocked. Releasing it requires recent administrator authentication.</span></div>{{end}}
{{if .LegacyUnboundAgents}}<div class="banner critical"><b data-i18n="Legacy bearer-only Agent migration mode is ENABLED">Legacy bearer-only Agent migration mode is ENABLED</b><span data-i18n="Unbound alpha Agents can connect using only an Agent bearer token. This weakens device impersonation resistance and must be used only long enough to migrate old devices to new Ed25519 identities, then disabled in the Relay configuration.">Unbound alpha Agents can connect using only an Agent bearer token. This weakens device impersonation resistance and must be used only long enough to migrate old devices to new Ed25519 identities, then disabled in the Relay configuration.</span></div>{{end}}
<div class="stats-grid" aria-label="Relay overview"><div class="stat-card"><span class="stat-value">{{.OnlineAgents}}</span><span class="stat-label" data-i18n="online agents">online agents</span></div><div class="stat-card"><span class="stat-value">{{.RegisteredDevices}}</span><span class="stat-label" data-i18n="registered devices">registered devices</span></div><div class="stat-card"><span class="stat-value">{{.RetiredDevices}}</span><span class="stat-label" data-i18n="retired identities">retired identities</span></div><div class="stat-card"><span class="stat-value">{{.Users}}</span><span class="stat-label" data-i18n="users">users</span></div><div class="stat-card"><span class="stat-value">{{.OAuthClients}}</span><span class="stat-label" data-i18n="OAuth clients">OAuth clients</span></div><div class="stat-card"><span class="stat-value">{{.Sessions}}</span><span class="stat-label" data-i18n="sessions">sessions</span></div></div>

<section class="surface" id="security-controls"><div class="section-heading"><div><span class="eyebrow" data-i18n="Security">Security</span><h2 data-i18n="Security controls">Security controls</h2></div><p data-i18n="Keep registration and runtime capabilities closed unless this Relay is intentionally operating them.">Keep registration and runtime capabilities closed unless this Relay is intentionally operating them.</p></div><div class="control-grid">
<div class="control-card"><div class="control-card-header"><div><h3 data-i18n="Instance mode">Instance mode</h3><p><span data-i18n="Current mode">Current mode</span>: <strong data-i18n="{{.Mode}}">{{.Mode}}</strong></p></div>{{if eq .Mode "public"}}<span class="status warn" data-i18n="Public">Public</span>{{else}}<span class="status ok" data-i18n="Private">Private</span>{{end}}</div>{{if .ModeConfigured}}<div class="field-help" data-i18n="This mode is fixed by the Relay configuration. Change the configured instance mode and restart to alter it.">This mode is fixed by the Relay configuration. Change the configured instance mode and restart to alter it.</div>{{else}}<form class="setting-form" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="action" value="set-mode"><label class="field-label" for="instance-mode-select" data-i18n="Set mode">Set mode</label><select id="instance-mode-select" name="value"><option value="private"{{if eq .Mode "private"}} selected{{end}} data-i18n="Private">Private</option><option value="public"{{if eq .Mode "public"}} selected{{end}} data-i18n="Public">Public</option></select><button class="tonal" type="submit" data-i18n="Apply mode">Apply mode</button></form>{{end}}</div>
<div class="control-card"><div class="control-card-header"><div><h3 data-i18n="Open registration">Open registration</h3><p data-i18n="Allow new users to create accounts without an invite.">Allow new users to create accounts without an invite.</p></div>{{if and .RegistrationEnabled (eq .Mode "public")}}<span class="status ok" data-i18n="Open">Open</span>{{else}}<span class="status" data-i18n="Closed">Closed</span>{{end}}</div>{{if eq .Mode "public"}}{{if .RegistrationDisabled}}<div class="field-help" data-i18n="Registration is fixed closed by the Relay configuration. Remove the configuration override and restart to change it.">Registration is fixed closed by the Relay configuration. Remove the configuration override and restart to change it.</div><button type="button" disabled data-i18n="Fixed by configuration">Fixed by configuration</button>{{else}}<form class="setting-form" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="action" value="set-registration"><input type="hidden" name="value" value="{{if .RegistrationEnabled}}off{{else}}on{{end}}"><button class="tonal" type="submit">{{if .RegistrationEnabled}}<span data-i18n="Close registration">Close registration</span>{{else}}<span data-i18n="Open registration">Open registration</span>{{end}}</button></form>{{end}}{{else}}<div class="field-help" data-i18n="Open registration is available only in public mode.">Open registration is available only in public mode.</div><button type="button" disabled data-i18n="Available in public mode">Available in public mode</button>{{end}}</div>
<div class="control-card"><div class="control-card-header"><div><h3 data-i18n="DCR">DCR</h3><p data-i18n="Dynamic client registration for Agents.">Dynamic client registration for Agents.</p></div>{{if .DCREnabled}}<span class="status ok" data-i18n="Enabled">Enabled</span>{{else}}<span class="status" data-i18n="Disabled">Disabled</span>{{end}}</div><form class="setting-form" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="action" value="set-dcr"><input type="hidden" name="value" value="{{if .DCREnabled}}off{{else}}on{{end}}"><button class="tonal" type="submit">{{if .DCREnabled}}<span data-i18n="Disable DCR">Disable DCR</span>{{else}}<span data-i18n="Enable DCR">Enable DCR</span>{{end}}</button></form></div>
<div class="control-card"><div class="control-card-header"><div><h3 data-i18n="MCP access">MCP access</h3><p data-i18n="Allow clients to invoke the workstation MCP surface.">Allow clients to invoke the workstation MCP surface.</p></div>{{if .MCPEnabled}}<span class="status ok" data-i18n="Enabled">Enabled</span>{{else}}<span class="status" data-i18n="Disabled">Disabled</span>{{end}}</div><form class="setting-form" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="action" value="set-mcp"><input type="hidden" name="value" value="{{if .MCPEnabled}}off{{else}}on{{end}}"><button class="tonal" type="submit">{{if .MCPEnabled}}<span data-i18n="Disable MCP">Disable MCP</span>{{else}}<span data-i18n="Enable MCP">Enable MCP</span>{{end}}</button></form></div>
<div class="control-card"><div class="control-card-header"><div><h3 data-i18n="Agent access">Agent access</h3><p data-i18n="Allow workstations to maintain outbound sessions.">Allow workstations to maintain outbound sessions.</p></div>{{if .AgentEnabled}}<span class="status ok" data-i18n="Enabled">Enabled</span>{{else}}<span class="status" data-i18n="Disabled">Disabled</span>{{end}}</div><form class="setting-form" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="action" value="set-agent"><input type="hidden" name="value" value="{{if .AgentEnabled}}off{{else}}on{{end}}"><button class="tonal" type="submit">{{if .AgentEnabled}}<span data-i18n="Disable Agent">Disable Agent</span>{{else}}<span data-i18n="Enable Agent">Enable Agent</span>{{end}}</button></form></div>
<div class="control-card"><div class="control-card-header"><div><h3 data-i18n="Emergency stop">Emergency stop</h3><p data-i18n="Block all MCP and Agent authorization immediately.">Block all MCP and Agent authorization immediately.</p></div>{{if .KillSwitch}}<span class="status bad" data-i18n="ACTIVE">ACTIVE</span>{{else}}<span class="status ok" data-i18n="Off">Off</span>{{end}}</div><form class="setting-form" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="action" value="set-kill-switch"><input type="hidden" name="value" value="{{if .KillSwitch}}off{{else}}on{{end}}">{{if .KillSwitch}}<input name="confirm" data-i18n-placeholder="type RELEASE" placeholder="type RELEASE" required>{{end}}<button class="danger" type="submit">{{if .KillSwitch}}<span data-i18n="Release kill switch">Release kill switch</span>{{else}}<span data-i18n="Emergency disable now">Emergency disable now</span>{{end}}</button></form></div>
</div></section>

<section class="surface" id="usage-controls"><div class="section-heading"><div><span class="eyebrow" data-i18n="Support">Support</span><h2 data-i18n="Relay usage and support">Relay usage and support</h2></div><p data-i18n="This optional system accounts request and response payload bytes through the Relay. It is disabled by default and never grants authority by itself.">This optional system accounts request and response payload bytes through the Relay. It is disabled by default and never grants authority by itself.</p></div><div class="control-grid"><div class="control-card"><div class="control-card-header"><div><h3 data-i18n="Traffic quota">Traffic quota</h3><p><span data-i18n="Default for new accounts">Default for new accounts</span>: <strong>{{formatBytes .UsageDefaultQuotaBytes}}</strong></p></div>{{if .UsageMeteringEnabled}}<span class="status ok" data-i18n="Enabled">Enabled</span>{{else}}<span class="status" data-i18n="Disabled by default">Disabled by default</span>{{end}}</div><div class="field-help" data-i18n="Only authenticated, user-owned MCP and Agent traffic is counted. Existing accounts keep their granted quota when this default changes.">Only authenticated, user-owned MCP and Agent traffic is counted. Existing accounts keep their granted quota when this default changes.</div><form class="setting-form" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="action" value="set-usage"><input type="hidden" name="value" value="{{if .UsageMeteringEnabled}}off{{else}}on{{end}}"><button class="tonal" type="submit">{{if .UsageMeteringEnabled}}<span data-i18n="Disable traffic quotas">Disable traffic quotas</span>{{else}}<span data-i18n="Enable traffic quotas">Enable traffic quotas</span>{{end}}</button></form><form class="setting-form" method="post" action="/admin/monetization"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="action" value="set-monetization"><input name="default_quota_bytes" type="number" min="1" max="1125899906842624" value="{{.UsageDefaultQuotaBytes}}" data-i18n-placeholder="default quota in bytes" placeholder="default quota in bytes" required><input type="text" name="adsense_client_id" value="{{.AdSenseClientID}}" data-i18n-placeholder="AdSense client ID" placeholder="AdSense client ID"><input type="text" name="adsense_slot" value="{{.AdSenseSlot}}" data-i18n-placeholder="AdSense slot ID" placeholder="AdSense slot ID"><button class="tonal" type="submit" data-i18n="Save AdSense settings">Save AdSense settings</button></form></div></div></section>

<section class="surface table-card"><div class="section-heading table-intro"><div><span class="eyebrow" data-i18n="Activation codes">Activation codes</span><h2 data-i18n="Support codes">Support codes</h2></div><p data-i18n="Create a single-use code that adds traffic quota to one account. The plaintext is shown once and only its hash is persisted.">Create a single-use code that adds traffic quota to one account. The plaintext is shown once and only its hash is persisted.</p></div><div class="table-wrap"><form class="setting-form" method="post" action="/admin/activation-code"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="action" value="create-activation-code"><input name="value" type="number" min="1" max="1125899906842624" data-i18n-placeholder="quota in bytes" placeholder="quota in bytes" required><button class="tonal" type="submit" data-i18n="Create activation code">Create activation code</button></form><table><thead><tr><th data-i18n="Code hash">Code hash</th><th data-i18n="Quota">Quota</th><th data-i18n="Expires">Expires</th><th data-i18n="Uses">Uses</th><th data-i18n="Created by">Created by</th></tr></thead><tbody>{{range .ActivationCodes}}<tr><td><code>{{.Label}}</code></td><td>{{formatBytes .Quota}}</td><td>{{.Expires}}</td><td>{{.UsesRemaining}}</td><td>{{.CreatedBy}}</td></tr>{{else}}<tr><td colspan="5" class="muted" data-i18n="No active activation codes.">No active activation codes.</td></tr>{{end}}</tbody></table></div></section>

<section class="surface table-card"><div class="section-heading table-intro"><div><span class="eyebrow" data-i18n="Account quotas">Account quotas</span><h2 data-i18n="Grant quota to users">Grant quota to users</h2></div><p data-i18n="Add quota manually for a user. Grants are additive and are recorded as administrator security events.">Add quota manually for a user. Grants are additive and are recorded as administrator security events.</p></div><div class="table-wrap"><table><thead><tr><th data-i18n="User">User</th><th data-i18n="Granted">Granted</th><th data-i18n="Used">Used</th><th data-i18n="Remaining">Remaining</th><th data-i18n="Action">Action</th></tr></thead><tbody>{{range .UsageUsers}}<tr><td>{{.Username}}</td><td>{{formatBytes .Quota}}</td><td>{{formatBytes .Used}}</td><td>{{formatBytes .Remaining}}</td><td><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="grant-quota"><input type="hidden" name="target" value="{{.ID}}"><input name="value" type="number" min="1" max="1125899906842624" data-i18n-placeholder="quota to add in bytes" placeholder="quota to add in bytes" required><button class="tonal" type="submit" data-i18n="Add quota">Add quota</button></form></td></tr>{{else}}<tr><td colspan="5" class="muted" data-i18n="No user quotas yet.">No user quotas yet.</td></tr>{{end}}</tbody></table></div></section>

{{if eq .Mode "public"}}<section class="surface table-card"><div class="section-heading table-intro"><div><span class="eyebrow" data-i18n="Invites">Invites</span><h2 data-i18n="Invite-only access">Invite-only access</h2></div><p data-i18n="Single-use invites allow registration while open self-registration is disabled. Invite plaintext is shown once; only a one-way hash is persisted.">Single-use invites allow registration while open self-registration is disabled. Invite plaintext is shown once; only a one-way hash is persisted.</p></div><div class="table-wrap"><form class="inline" method="post" action="/admin/invite"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><button class="tonal" type="submit" data-i18n="Create 24-hour invite">Create 24-hour invite</button></form><table><thead><tr><th data-i18n="Handle">Handle</th><th data-i18n="Expires">Expires</th><th data-i18n="Uses">Uses</th><th data-i18n="Created by">Created by</th><th data-i18n="Action">Action</th></tr></thead><tbody>{{range .Invites}}<tr><td><code>{{.Label}}</code></td><td>{{.Expires}}</td><td>{{.UsesRemaining}}</td><td>{{.CreatedBy}}</td><td><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="revoke-invite"><input type="hidden" name="target" value="{{.Handle}}"><button type="submit" data-i18n="Revoke">Revoke</button></form></td></tr>{{else}}<tr><td colspan="5" class="muted" data-i18n="No active invites.">No active invites.</td></tr>{{end}}</tbody></table></div></section>{{end}}


<section class="surface table-card"><div class="section-heading table-intro"><div><span class="eyebrow" data-i18n="Devices">Devices</span><h2 data-i18n="Registered devices">Registered devices</h2></div><p data-i18n="Disable is reversible. Revoke permanently retires the device identity so the same private key can never claim this ID again; reconnecting requires a newly generated device identity.">Disable is reversible. Revoke permanently retires the device identity so the same private key can never claim this ID again; reconnecting requires a newly generated device identity.</p></div><div class="table-wrap"><table><thead><tr><th data-i18n="Display name">Display name</th><th data-i18n="Immutable ID / route">Immutable ID / route</th><th data-i18n="Owner">Owner</th><th data-i18n="Connection">Connection</th><th data-i18n="Capabilities">Capabilities</th><th data-i18n="Actions">Actions</th></tr></thead><tbody>{{range .Devices}}<tr><td><b>{{.Name}}</b></td><td><code>{{.ID}}</code><br><small>{{.Route}}</small><br>{{if .ProofBound}}<span class="status ok" data-i18n="PoP bound">PoP bound</span>{{else}}<span class="status bad" data-i18n="legacy unbound">legacy unbound</span>{{end}}</td><td>{{.Owner}}</td><td>{{if .Online}}<span class="status ok" data-i18n="online">online</span>{{else}}<span class="muted" data-i18n="offline">offline</span>{{end}}{{if .Disabled}}<br><span class="status bad" data-i18n="disabled">disabled</span>{{end}}{{if not .LastSeen.IsZero}}<br><small><span data-i18n="last seen">last seen</span> {{.LastSeen}}</small>{{end}}{{if .InFlight}}<br><small><span data-i18n="in flight">in flight</span> {{.InFlight}}</small>{{end}}</td><td>{{if .Online}}<small>{{if .Capabilities.FilesystemRead}}<span data-i18n="filesystem read">filesystem read</span><br>{{end}}{{if .Capabilities.FilesystemWrite}}<span data-i18n="filesystem write">filesystem write</span><br>{{end}}{{if .Capabilities.Exec}}<span data-i18n="exec">exec</span>{{if .Capabilities.ExecSandbox}} ({{.Capabilities.ExecSandbox}}){{end}}<br>{{end}}{{if .Capabilities.ScreenRead}}<span data-i18n="screen read">screen read</span><br>{{end}}{{if .Capabilities.AccessibilityRead}}<span data-i18n="accessibility read">accessibility read</span><br>{{end}}{{if .Capabilities.ComputerInput}}<span data-i18n="computer input">computer input</span>{{end}}</small>{{else}}<span class="muted" data-i18n="not reported">not reported</span>{{end}}</td><td class="table-actions"><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="rename-device"><input type="hidden" name="target" value="{{.Route}}"><input name="value" data-i18n-placeholder="new display name" placeholder="new display name" required><button type="submit" data-i18n="Rename">Rename</button></form><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="disable-device"><input type="hidden" name="target" value="{{.Route}}"><input type="hidden" name="value" value="{{if .Disabled}}off{{else}}on{{end}}"><button type="submit">{{if .Disabled}}<span data-i18n="Enable">Enable</span>{{else}}<span data-i18n="Disable">Disable</span>{{end}}</button></form><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="revoke-device"><input type="hidden" name="target" value="{{.Route}}"><input name="confirm" data-i18n-placeholder="REVOKE" placeholder="REVOKE" required><button class="danger" type="submit" data-i18n="Revoke permanently">Revoke permanently</button></form></td></tr>{{else}}<tr><td colspan="6" class="muted" data-i18n="No devices have been claimed.">No devices have been claimed.</td></tr>{{end}}</tbody></table></div></section>

<section class="surface table-card"><div class="section-heading table-intro"><div><span class="eyebrow" data-i18n="Users">Users</span><h2 data-i18n="User accounts">User accounts</h2></div><p data-i18n="Create and manage tenant accounts. Password rotation revokes existing credentials for that user.">Create and manage tenant accounts. Password rotation revokes existing credentials for that user.</p></div><div class="table-wrap"><form class="setting-form" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="action" value="create-user"><input name="target" autocomplete="username" data-i18n-placeholder="new username" placeholder="new username" minlength="3" maxlength="64" required><input name="value" type="password" autocomplete="new-password" data-i18n-placeholder="temporary password" placeholder="temporary password" minlength="12" required><button class="tonal" type="submit" data-i18n="Create user">Create user</button></form><table><thead><tr><th data-i18n="Username">Username</th><th data-i18n="Role / state">Role / state</th><th data-i18n="Created / last login">Created / last login</th><th data-i18n="Actions">Actions</th></tr></thead><tbody>{{range .UserList}}<tr><td><b>{{.Username}}</b></td><td>{{if .Admin}}<span class="status" data-i18n="admin">admin</span>{{end}}{{if .Disabled}}<span class="status bad" data-i18n="disabled">disabled</span>{{else}}<span class="status ok" data-i18n="active">active</span>{{end}}<br>{{.Devices}} <span data-i18n="device(s)">device(s)</span></td><td>{{.CreatedAt}}<br>{{if not .LastLoginAt.IsZero}}{{.LastLoginAt}}{{else}}<span class="muted" data-i18n="never">never</span>{{end}}</td><td class="table-actions"><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="disable-user"><input type="hidden" name="target" value="{{.ID}}"><input type="hidden" name="value" value="{{if .Disabled}}off{{else}}on{{end}}"><button type="submit">{{if .Disabled}}<span data-i18n="Enable">Enable</span>{{else}}<span data-i18n="Disable">Disable</span>{{end}}</button></form><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="logout-user"><input type="hidden" name="target" value="{{.ID}}"><button type="submit" data-i18n="Logout all">Logout all</button></form><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="rotate-password"><input type="hidden" name="target" value="{{.ID}}"><input name="value" type="password" data-i18n-placeholder="new password" placeholder="new password" minlength="12" required><button type="submit" data-i18n="Rotate password">Rotate password</button></form><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="delete-user"><input type="hidden" name="target" value="{{.ID}}"><input name="confirm" data-i18n-placeholder="DELETE" placeholder="DELETE" required><button class="danger" type="submit" data-i18n="Delete">Delete</button></form></td></tr>{{end}}</tbody></table></div></section>

<details class="surface disclosure"><summary><span data-i18n="Browser sessions">Browser sessions</span> · {{.Sessions}}</summary><p class="muted" data-i18n="Session handles are one-way identifiers; browser cookie values are never displayed.">Session handles are one-way identifiers; browser cookie values are never displayed.</p><div class="table-wrap"><table><thead><tr><th data-i18n="Handle">Handle</th><th data-i18n="User">User</th><th data-i18n="Created">Created</th><th data-i18n="Last seen">Last seen</th><th data-i18n="Expires">Expires</th><th data-i18n="Action">Action</th></tr></thead><tbody>{{range .SessionList}}<tr><td><code>{{.Label}}</code></td><td>{{.Username}}</td><td>{{.Created}}</td><td>{{.LastSeen}}</td><td>{{.Expires}}</td><td><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="logout-session"><input type="hidden" name="target" value="{{.Handle}}"><button type="submit" data-i18n="Log out">Log out</button></form></td></tr>{{else}}<tr><td colspan="6" class="muted" data-i18n="No active browser sessions.">No active browser sessions.</td></tr>{{end}}</tbody></table></div></details>
<details class="surface disclosure"><summary><span data-i18n="OAuth clients and token metadata">OAuth clients and token metadata</span> · {{.OAuthClients}} <span data-i18n="clients">clients</span> / {{len .Tokens}} <span data-i18n="token records">token records</span></summary><div class="table-wrap"><table><thead><tr><th data-i18n="Client">Client</th><th data-i18n="Name / redirects">Name / redirects</th><th data-i18n="Actions">Actions</th></tr></thead><tbody>{{range .Clients}}<tr><td><code>{{.ID}}</code><br><small>{{.IssuedAt}}</small></td><td>{{.Name}}<br><small>{{join .RedirectURIs ", "}}</small></td><td><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="revoke-client"><input type="hidden" name="target" value="{{.ID}}"><input name="confirm" data-i18n-placeholder="REVOKE" placeholder="REVOKE" required><button class="danger" type="submit" data-i18n="Revoke client">Revoke client</button></form></td></tr>{{else}}<tr><td colspan="3" class="muted" data-i18n="No approved clients.">No approved clients.</td></tr>{{end}}</tbody></table><p><b>{{len .Tokens}}</b> <span data-i18n="active token records (metadata only; bearer values are never displayed).">active token records (metadata only; bearer values are never displayed).</span></p><table><thead><tr><th data-i18n="Handle">Handle</th><th data-i18n="Kind">Kind</th><th data-i18n="User">User</th><th data-i18n="Resource">Resource</th><th data-i18n="Expires">Expires</th><th data-i18n="Action">Action</th></tr></thead><tbody>{{range .Tokens}}<tr><td><code>{{.Label}}</code></td><td>{{.Kind}}</td><td>{{.Username}}</td><td><code>{{.Resource}}</code></td><td>{{.Expires}}</td><td><form class="inline" method="post" action="/admin/action"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="action" value="revoke-token"><input type="hidden" name="target" value="{{.Handle}}"><input name="confirm" data-i18n-placeholder="REVOKE" placeholder="REVOKE" required><button class="danger" type="submit" data-i18n="Revoke">Revoke</button></form></td></tr>{{else}}<tr><td colspan="6" class="muted" data-i18n="No active tokens.">No active tokens.</td></tr>{{end}}</tbody></table></div></details>
<details class="surface disclosure"><summary><span data-i18n="Recent security events">Recent security events</span> · {{len .Events}}</summary><div class="table-wrap"><table><thead><tr><th data-i18n="Time">Time</th><th data-i18n="Event">Event</th><th data-i18n="User / device">User / device</th><th data-i18n="Result">Result</th></tr></thead><tbody>{{range .Events}}<tr><td>{{.Time}}</td><td>{{.Event}}</td><td>{{.User}}{{if .Device}} / {{.Device}}{{end}}</td><td>{{if .Success}}<span class="status ok" data-i18n="success">success</span>{{else}}<span class="status bad" data-i18n="failure">failure</span>{{end}}</td></tr>{{else}}<tr><td colspan="4" class="muted" data-i18n="No events recorded.">No events recorded.</td></tr>{{end}}</tbody></table></div></details>
</main><footer class="footer"><a href="/" data-i18n="Back to home">Back to home</a><span><span data-i18n="Admin changes are recorded as security events.">Admin changes are recorded as security events.</span></span></footer></div></body></html>`))

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := s.sessionUser(r)
	if !ok || !user.Admin {
		token := randomToken(24)
		http.SetCookie(w, &http.Cookie{Name: adminCSRFCookie, Value: token, Path: "/admin", MaxAge: int(sessionLifetime.Seconds()), HttpOnly: true, Secure: s.base.Scheme == "https", SameSite: http.SameSiteStrictMode})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = executeUITemplate(w, r, adminLoginTemplate, map[string]string{"CSRFToken": token})
		return
	}
	s.renderAdmin(w, r, user)
}

func (s *Server) handleAdminReauthGET(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessionUser(r)
	if !ok || !user.Admin {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	csrf := randomToken(24)
	http.SetCookie(w, &http.Cookie{Name: adminCSRFCookie, Value: csrf, Path: "/admin", MaxAge: int(sessionLifetime.Seconds()), HttpOnly: true, Secure: s.base.Scheme == "https", SameSite: http.SameSiteStrictMode})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = executeUITemplate(w, r, adminReauthTemplate, map[string]string{"CSRFToken": csrf, "Username": user.Username})
}

func (s *Server) handleAdminReauthPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allowRate(r, "admin-reauth", 10, time.Minute) {
		rateLimited(w, 60)
		return
	}
	current, ok := s.sessionUser(r)
	if !ok || !current.Admin {
		http.Error(w, "administrator authentication required", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil || !doubleSubmitMatches(r, adminCSRFCookie) {
		http.Error(w, "invalid admin form", http.StatusForbidden)
		return
	}
	verified, authenticated, busy := s.authenticate(current.Username, r.Form.Get("password"))
	if busy {
		http.Error(w, "login capacity is busy; retry shortly", http.StatusTooManyRequests)
		return
	}
	if !authenticated || verified.ID != current.ID || !verified.Admin {
		s.recordSecurity(SecurityEvent{Event: "admin_reauth", User: current.Username, RemoteIP: requestIP(r, s.trustedProxies), Success: false})
		http.Error(w, "invalid administrator password", http.StatusUnauthorized)
		return
	}
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		http.Error(w, "administrator session expired", http.StatusUnauthorized)
		return
	}
	newSession := randomToken(32)
	s.mu.Lock()
	recovering := s.persistenceFault
	snapshot := s.snapshotMutableStateLocked()
	handle := tokenKey(cookie.Value)
	record, exists := s.sessions[handle]
	if !exists || record.UserID != current.ID || !s.liveAdminLocked(current) || verified.PasswordHash != current.PasswordHash {
		s.mu.Unlock()
		http.Error(w, "administrator session expired", http.StatusUnauthorized)
		return
	}
	now := time.Now().Unix()
	delete(s.sessions, handle)
	delete(s.ephemeralSessions, handle)
	record.LastSeenAt = now
	record.LastReauthAt = now
	newHandle := tokenKey(newSession)
	s.sessions[newHandle] = record
	s.recordSecurityLocked(SecurityEvent{Event: "admin_reauth", User: current.Username, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
	if recovering {
		// Fresh authentication is kept process-local during recovery. It may
		// authorize a subsequent authority-reducing recovery action, but must
		// not consume the dirty authorization-state guard by itself.
		s.ephemeralSessions[newHandle] = struct{}{}
		err = nil
	} else {
		err = s.saveOrRollbackLocked(snapshot)
	}
	s.mu.Unlock()
	if err != nil {
		http.Error(w, "failed to persist re-authentication", http.StatusServiceUnavailable)
		return
	}
	s.setSessionCookie(w, newSession)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if !s.allowRate(r, "admin-login", 15, time.Minute) {
		rateLimited(w, 60)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil || !doubleSubmitMatches(r, adminCSRFCookie) {
		http.Error(w, "invalid admin form", http.StatusForbidden)
		return
	}
	user, authenticated, busy := s.authenticate(r.Form.Get("username"), r.Form.Get("password"))
	if busy {
		http.Error(w, "login capacity is busy; retry shortly", http.StatusTooManyRequests)
		return
	}
	if !authenticated || !user.Admin {
		// Do not record the submitted username: a malformed client can put a
		// password or another secret in that field, and security events are
		// deliberately durable operator-visible metadata.
		s.recordSecurity(SecurityEvent{Event: "admin_login", RemoteIP: requestIP(r, s.trustedProxies), Success: false})
		http.Error(w, "invalid administrator credentials", http.StatusUnauthorized)
		return
	}
	session, err := s.createSession(user)
	if err != nil {
		http.Error(w, "failed to persist login session", http.StatusInternalServerError)
		return
	}
	s.recordSecurity(SecurityEvent{Event: "admin_login", User: user.Username, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
	s.setSessionCookie(w, session)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !doubleSubmitMatches(r, adminCSRFCookie) {
		http.Error(w, "invalid admin form", http.StatusForbidden)
		return
	}
	s.clearSession(w, r)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) renderAdmin(w http.ResponseWriter, r *http.Request, current User) {
	data := s.adminData(current)
	csrf := randomToken(24)
	http.SetCookie(w, &http.Cookie{Name: adminCSRFCookie, Value: csrf, Path: "/admin", MaxAge: int(sessionLifetime.Seconds()), HttpOnly: true, Secure: s.base.Scheme == "https", SameSite: http.SameSiteStrictMode})
	data.CSRFToken = csrf
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = executeUITemplate(w, r, adminTemplate, data)
}

func (s *Server) adminData(current User) adminPageData {
	s.mu.Lock()
	s.cleanupLocked(time.Now())
	uptime := time.Since(s.startedAt)
	if uptime < 0 {
		uptime = 0
	}
	data := adminPageData{Version: s.cfg.Version, Mode: s.cfg.Mode, ModeConfigured: s.cfg.ModeConfigured, RegistrationDisabled: s.cfg.RegistrationDisabled, PublicURL: strings.TrimRight(s.base.String(), "/"), PersistenceFault: s.persistenceFault, Uptime: uptime.Round(time.Second).String(), RegistrationEnabled: s.registrationEnabled, DCREnabled: s.dcrEnabled, MCPEnabled: s.mcpEnabled, AgentEnabled: s.agentEnabled, KillSwitch: s.killSwitch, LegacyUnboundAgents: s.cfg.AllowLegacyUnboundAgents, RetiredDevices: len(s.retiredDevices), Users: len(s.users), OAuthClients: len(s.clients), Sessions: len(s.sessions), Username: current.Username, Events: append([]SecurityEvent(nil), s.securityEvents...), UsageMeteringEnabled: s.usageMeteringEnabled, UsageDefaultQuotaBytes: s.usageDefaultQuotaBytes, AdSenseClientID: s.cfg.AdSenseClientID, AdSenseSlot: s.cfg.AdSenseSlot}
	provider := s.statusProvider
	devices := make(map[string]string, len(s.devices))
	for name, userID := range s.devices {
		devices[name] = userID
	}
	for name, userID := range devices {
		user := s.users[userID]
		record := s.ensureDeviceRecordLocked(name, userID)
		data.Devices = append(data.Devices, adminDeviceView{Route: name, ID: record.ID, Name: record.DisplayName, Owner: user.Username, Disabled: s.disabledDevices[name] || record.Disabled, ProofBound: record.DevicePublicKey != ""})
	}
	for _, user := range s.users {
		count := 0
		for _, owner := range s.devices {
			if owner == user.ID {
				count++
			}
		}
		view := adminUserView{ID: user.ID, Username: user.Username, Admin: user.Admin, Disabled: user.Disabled, Devices: count}
		if user.CreatedAt > 0 {
			view.CreatedAt = time.Unix(user.CreatedAt, 0)
		}
		if user.LastLoginAt > 0 {
			view.LastLoginAt = time.Unix(user.LastLoginAt, 0)
		}
		data.UserList = append(data.UserList, view)
		usage := s.ensureUsageRecordLocked(user.ID)
		data.UsageUsers = append(data.UsageUsers, adminUsageView{ID: user.ID, Username: user.Username, Quota: usage.QuotaBytes, Used: usage.UsedBytes, Remaining: usageRemaining(usage)})
	}
	for _, client := range s.clients {
		if client.Approved {
			data.Clients = append(data.Clients, client)
		}
	}
	for handle, record := range s.access {
		user := s.users[record.UserID]
		data.Tokens = append(data.Tokens, adminTokenView{Handle: handle, Label: shortHandle(handle), Kind: "access", ClientID: record.ClientID, Username: user.Username, Resource: record.Resource, Expires: time.Unix(record.Expires, 0)})
	}
	for handle, record := range s.refresh {
		user := s.users[record.UserID]
		data.Tokens = append(data.Tokens, adminTokenView{Handle: handle, Label: shortHandle(handle), Kind: "refresh", ClientID: record.ClientID, Username: user.Username, Resource: record.Resource, Expires: time.Unix(record.Expires, 0)})
	}
	for handle, record := range s.sessions {
		user := s.users[record.UserID]
		data.SessionList = append(data.SessionList, adminSessionView{Handle: handle, Label: shortHandle(handle), Username: user.Username, Created: time.Unix(record.CreatedAt, 0), LastSeen: time.Unix(record.LastSeenAt, 0), Expires: time.Unix(record.Expires, 0)})
	}
	for handle, record := range s.invites {
		if record.Expires > time.Now().Unix() && record.UsesRemaining > 0 {
			data.Invites = append(data.Invites, adminInviteView{Handle: handle, Label: shortHandle(handle), Expires: time.Unix(record.Expires, 0), UsesRemaining: record.UsesRemaining, CreatedBy: record.CreatedBy})
		}
	}
	for handle, record := range s.activationCodes {
		if record.Expires > time.Now().Unix() && record.UsesRemaining > 0 {
			data.ActivationCodes = append(data.ActivationCodes, adminActivationCodeView{Label: shortHandle(handle), Quota: record.QuotaBytes, Expires: time.Unix(record.Expires, 0), UsesRemaining: record.UsesRemaining, CreatedBy: record.CreatedBy})
		}
	}
	data.RegisteredDevices = len(data.Devices)
	s.mu.Unlock()
	if provider != nil {
		statuses := provider()
		for i := range data.Devices {
			if status, ok := statuses[data.Devices[i].Route]; ok {
				data.Devices[i].Online, data.Devices[i].ConnectedAt, data.Devices[i].LastSeen, data.Devices[i].InFlight, data.Devices[i].Capabilities = status.Online, status.ConnectedAt, status.LastSeen, status.InFlight, status.Capabilities
				if status.Online {
					data.OnlineAgents++
				}
			}
		}
	}
	sort.Slice(data.Devices, func(i, j int) bool { return data.Devices[i].Name < data.Devices[j].Name })
	sort.Slice(data.UserList, func(i, j int) bool { return data.UserList[i].Username < data.UserList[j].Username })
	sort.Slice(data.Clients, func(i, j int) bool { return data.Clients[i].IssuedAt > data.Clients[j].IssuedAt })
	sort.Slice(data.Tokens, func(i, j int) bool { return data.Tokens[i].Expires.Before(data.Tokens[j].Expires) })
	sort.Slice(data.SessionList, func(i, j int) bool { return data.SessionList[i].LastSeen.After(data.SessionList[j].LastSeen) })
	sort.Slice(data.UsageUsers, func(i, j int) bool { return data.UsageUsers[i].Username < data.UsageUsers[j].Username })
	sort.Slice(data.ActivationCodes, func(i, j int) bool { return data.ActivationCodes[i].Expires.Before(data.ActivationCodes[j].Expires) })
	if len(data.Events) > 50 {
		data.Events = data.Events[len(data.Events)-50:]
	}
	return data
}

func shortHandle(handle string) string {
	if len(handle) <= 16 {
		return handle
	}
	return handle[:16] + "…"
}

func (s *Server) handleAdminAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := s.sessionUser(r)
	if !ok || !user.Admin {
		http.Error(w, "administrator authentication required", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil || !doubleSubmitMatches(r, adminCSRFCookie) {
		http.Error(w, "invalid admin form", http.StatusForbidden)
		return
	}
	action := strings.TrimSpace(r.Form.Get("action"))
	if requiresFreshAdminAuth(action, r.Form.Get("value")) && !adminSessionFresh(s, r) {
		http.Redirect(w, r, "/admin/reauth", http.StatusSeeOther)
		return
	}
	if isConfirmRequired(action, r.Form.Get("value")) && !validConfirmation(action, r.Form.Get("value"), r.Form.Get("confirm")) {
		http.Error(w, "confirmation text is required", http.StatusBadRequest)
		return
	}
	if err := s.applyAdminAction(action, r.Form.Get("target"), r.Form.Get("value"), user, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func requiresFreshAdminAuth(action, value string) bool {
	switch action {
	case "revoke-device", "delete-user", "revoke-client", "revoke-token", "rotate-password", "rename-device", "create-user", "grant-quota":
		return true
	case "disable-device", "disable-user":
		disabled, valid := parseToggle(value)
		return valid && !disabled
	case "set-registration", "set-dcr", "set-mcp", "set-agent", "set-usage", "set-reward":
		enabled, valid := parseToggle(value)
		return valid && enabled
	case "set-mode":
		_, err := normalizeMode(value)
		return err == nil
	case "set-kill-switch":
		// Emergency disable must remain available to any authenticated admin;
		// releasing the global kill switch expands authority and requires a
		// recently authenticated session.
		enabled, valid := parseToggle(value)
		return valid && !enabled
	default:
		return false
	}
}

func isConfirmRequired(action, value string) bool {
	switch action {
	case "revoke-device", "delete-user", "revoke-client", "revoke-token":
		return true
	case "set-kill-switch":
		enabled, valid := parseToggle(value)
		return valid && !enabled
	default:
		return false
	}
}

func validConfirmation(action, value, confirmation string) bool {
	want := "REVOKE"
	if action == "set-kill-switch" {
		enabled, valid := parseToggle(value)
		if !valid || enabled {
			return false
		}
		want = "RELEASE"
	}
	if action == "delete-user" {
		want = "DELETE"
	}
	return len(confirmation) == len(want) && subtle.ConstantTimeCompare([]byte(confirmation), []byte(want)) == 1
}

func adminSessionFresh(s *Server, r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		return false
	}
	s.mu.Lock()
	record := s.sessions[tokenKey(cookie.Value)]
	user, userExists := s.users[record.UserID]
	s.mu.Unlock()
	if !userExists || user.ID != record.UserID || user.Disabled || !user.Admin || record.Expires <= time.Now().Unix() || record.LastReauthAt <= 0 {
		return false
	}
	age := time.Since(time.Unix(record.LastReauthAt, 0))
	return age >= 0 && age <= 15*time.Minute
}

func parseToggle(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "on", "true", "1":
		return true, true
	case "off", "false", "0":
		return false, true
	default:
		return false, false
	}
}

func persistenceRecoveryActionAllowed(action, value string) bool {
	switch action {
	case "rotate-password", "revoke-device", "delete-user", "logout-user", "logout-all", "logout-session", "revoke-client", "revoke-token", "revoke-invite":
		return true
	case "disable-device", "disable-user":
		disabled, valid := parseToggle(value)
		return valid && disabled
	case "set-registration", "set-dcr", "set-mcp", "set-agent", "set-usage", "set-reward":
		enabled, valid := parseToggle(value)
		return valid && !enabled
	case "set-mode":
		mode, err := normalizeMode(value)
		return err == nil && mode == ModePrivate
	case "set-kill-switch":
		enabled, valid := parseToggle(value)
		return valid && enabled
	default:
		return false
	}
}

func (s *Server) applyAdminAction(action, target, value string, current User, r *http.Request) error {
	if action == "grant-quota" {
		quota, err := parseUsageQuota(value)
		if err != nil {
			return err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.liveAdminLocked(current) {
			return errInvalidAdminAction
		}
		if s.persistenceFault {
			return errPersistenceRecoveryOnly
		}
		snapshot := s.snapshotUsageStateLocked()
		if err := s.grantQuotaLocked(target, quota); err != nil {
			return err
		}
		if err := s.saveUsageOrRollbackLocked(snapshot); err != nil {
			return err
		}
		s.recordSecurityLocked(SecurityEvent{Event: action, User: current.Username, Device: target, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
		return nil
	}
	if action == "create-user" {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.liveAdminLocked(current) {
			if s.persistenceFault {
				return errPersistenceRecoveryOnly
			}
			return errInvalidAdminAction
		}
		if s.persistenceFault {
			return errPersistenceRecoveryOnly
		}
		snapshot := s.snapshotMutableStateLocked()
		user, err := s.createUserLocked(target, value)
		if err != nil {
			return err
		}
		s.recordSecurityLocked(SecurityEvent{Event: action, User: user.Username, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
		return s.saveOrRollbackLocked(snapshot)
	}
	if action == "rotate-password" {
		if err := validatePassword(value); err != nil {
			return err
		}
		hash, err := hashPassword(value)
		if err != nil {
			return err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.liveAdminLocked(current) {
			if s.persistenceFault {
				return errPersistenceRecoveryOnly
			}
			return errInvalidAdminAction
		}
		recovering := s.persistenceFault
		if recovering && !persistenceRecoveryActionAllowed(action, value) {
			return errPersistenceRecoveryOnly
		}
		snapshot := s.snapshotMutableStateLocked()
		user, exists := s.users[target]
		if !exists || user.Disabled {
			return errUnknownUser
		}
		user.PasswordHash = hash
		s.users[target] = user
		// Password rotation is a credential-compromise recovery action, not just
		// a browser logout. Revoke every token family so already-connected Agents
		// fail their next per-RPC revalidation as well.
		s.resetOwnedAgentSessionsLocked(target)
		s.revokeUserCredentialsLocked(target)
		s.recordSecurityLocked(SecurityEvent{Event: action, User: user.Username, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
		if recovering {
			return s.saveRecoveryOrRollbackLocked(snapshot)
		}
		return s.saveOrRollbackLocked(snapshot)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.liveAdminLocked(current) {
		if s.persistenceFault {
			return errPersistenceRecoveryOnly
		}
		return errInvalidAdminAction
	}
	recovering := s.persistenceFault
	if recovering && !persistenceRecoveryActionAllowed(action, value) {
		return errPersistenceRecoveryOnly
	}
	snapshot := s.snapshotMutableStateLocked()
	changed := true
	switch action {
	case "set-mode":
		if s.cfg.ModeConfigured {
			return errInvalidAdminAction
		}
		mode, err := normalizeMode(value)
		if err != nil || mode == s.cfg.Mode {
			return errInvalidAdminAction
		}
		s.cfg.Mode = mode
		// A mode transition is a trust-boundary change. Keep registration closed
		// until the operator explicitly enables it in a separate action.
		s.registrationEnabled = false
	case "set-registration":
		state, valid := parseToggle(value)
		if !valid || s.cfg.Mode != ModePublic || s.cfg.RegistrationDisabled {
			return errInvalidAdminAction
		}
		s.registrationEnabled = state
	case "set-dcr":
		state, valid := parseToggle(value)
		if !valid {
			return errInvalidAdminAction
		}
		s.dcrEnabled = state
	case "set-mcp":
		state, valid := parseToggle(value)
		if !valid {
			return errInvalidAdminAction
		}
		s.mcpEnabled = state
		if !state {
			s.resetAllAgentSessionsLocked()
		}
	case "set-agent":
		state, valid := parseToggle(value)
		if !valid {
			return errInvalidAdminAction
		}
		s.agentEnabled = state
		if !state {
			s.resetAllAgentSessionsLocked()
		}
	case "set-usage":
		state, valid := parseToggle(value)
		if !valid {
			return errInvalidAdminAction
		}
		s.usageMeteringEnabled = state
		s.usageConfigured = true
		if state {
			for userID := range s.users {
				s.ensureUsageRecordLocked(userID)
			}
		}
	case "set-reward":
		state, valid := parseToggle(value)
		if !valid {
			return errInvalidAdminAction
		}
		if state && (!s.usageMeteringEnabled || strings.TrimSpace(s.cfg.AdMobAppID) == "" || strings.TrimSpace(s.cfg.AdMobRewardUnitID) == "" || strings.TrimSpace(s.cfg.UsageUnlockEndpoint) == "" || strings.TrimSpace(s.cfg.AdMobVerifierSecret) == "") {
			return errors.New("enable traffic quotas and configure AdMob IDs, the reward endpoint, and CHAT_WITH_CLI_ADMOB_VERIFIER_SECRET before enabling rewarded usage")
		}
		s.cfg.UsageUnlockEnabled = state
		s.monetizationConfigured = true
	case "set-kill-switch":
		state, valid := parseToggle(value)
		if !valid {
			return errInvalidAdminAction
		}
		s.killSwitch = state
		if state {
			s.resetAllAgentSessionsLocked()
		}
	case "disable-device":
		if _, exists := s.devices[target]; !exists {
			return errUnknownDevice
		}
		state, valid := parseToggle(value)
		if !valid {
			return errInvalidAdminAction
		}
		s.disabledDevices[target] = state
		record := s.ensureDeviceRecordLocked(target, s.devices[target])
		record.Disabled = state
		s.deviceRecords[target] = record
		if state {
			s.agentSessionResetterSafe(target)
			s.revokeDeviceTokensLocked(target)
		}
	case "revoke-device":
		if _, exists := s.devices[target]; !exists {
			return errUnknownDevice
		}
		s.agentSessionResetterSafe(target)
		// Revocation retires the cryptographic route permanently. If the
		// device private key was compromised, deleting the record would let
		// the holder immediately reclaim the same immutable identity.
		s.retiredDevices[target] = true
		delete(s.devices, target)
		delete(s.disabledDevices, target)
		delete(s.deviceRecords, target)
		s.revokeDeviceTokensLocked(target)
		s.revokeDeviceClientsLocked(target)
	case "rename-device":
		if !validateDeviceRoute(target) || !validateDeviceDisplayName(value) {
			return errInvalidAdminAction
		}
		owner, exists := s.devices[target]
		if !exists {
			return errUnknownDevice
		}
		record := s.ensureDeviceRecordLocked(target, owner)
		record.DisplayName = strings.TrimSpace(value)
		s.deviceRecords[target] = record
	case "disable-user":
		user, exists := s.users[target]
		if !exists || user.ID == current.ID {
			return errUnknownUser
		}
		state, valid := parseToggle(value)
		if !valid {
			return errInvalidAdminAction
		}
		user.Disabled = state
		s.users[target] = user
		if user.Disabled {
			s.resetOwnedAgentSessionsLocked(target)
			s.revokeUserCredentialsLocked(target)
		}
	case "delete-user":
		if target == current.ID {
			return errCannotDeleteSelf
		}
		if _, exists := s.users[target]; !exists {
			return errUnknownUser
		}
		delete(s.users, target)
		for normalized, id := range s.usernames {
			if id == target {
				delete(s.usernames, normalized)
			}
		}
		ownedDevices := make(map[string]struct{})
		for device, owner := range s.devices {
			if owner == target {
				ownedDevices[device] = struct{}{}
			}
		}
		for device, record := range s.deviceRecords {
			if record.OwnerID == target {
				ownedDevices[device] = struct{}{}
			}
		}
		for device := range ownedDevices {
			// Deleting an account must not make its old device identities
			// claimable by whoever still holds a device private key. Include
			// orphaned device records left by an older or interrupted mutation.
			s.agentSessionResetterSafe(device)
			s.retiredDevices[device] = true
			s.revokeDeviceTokensLocked(device)
			s.revokeDeviceClientsLocked(device)
			delete(s.devices, device)
			delete(s.disabledDevices, device)
			delete(s.deviceRecords, device)
		}
		s.revokeUserCredentialsLocked(target)
		delete(s.usage, target)
		delete(s.usageGates, target)
		s.usageDirty = true
	case "logout-user":
		if _, exists := s.users[target]; !exists {
			return errUnknownUser
		}
		s.deleteUserSessionsLocked(target)
	case "logout-all":
		if _, exists := s.users[target]; !exists {
			return errUnknownUser
		}
		s.deleteUserSessionsLocked(target)
	case "logout-session":
		if !validOpaqueHandle(target) {
			return errUnknownSession
		}
		if _, exists := s.sessions[target]; !exists {
			return errUnknownSession
		}
		delete(s.sessions, target)
	case "revoke-client":
		if _, exists := s.clients[target]; !exists {
			return errUnknownClient
		}
		s.revokeClientLocked(target)
	case "revoke-token":
		if !validOpaqueHandle(target) {
			return errUnknownToken
		}
		if record, exists := s.refresh[target]; exists {
			s.resetAgentSessionForResourceLocked(record.Resource)
			s.revokeFamilyLocked(record.Family)
			break
		}
		if record, exists := s.refreshUsed[target]; exists {
			s.resetAgentSessionForResourceLocked(record.Resource)
			s.revokeFamilyLocked(record.Family)
			break
		}
		if record, exists := s.access[target]; exists {
			s.resetAgentSessionForResourceLocked(record.Resource)
			s.revokeFamilyLocked(record.Family)
			break
		}
		return errUnknownToken
	case "revoke-invite":
		if !validOpaqueHandle(target) {
			return errInvalidAdminAction
		}
		if _, exists := s.invites[target]; !exists {
			return errInvalidAdminAction
		}
		delete(s.invites, target)
	default:
		changed = false
	}
	if !changed {
		return errInvalidAdminAction
	}
	eventTarget := target
	if action == "revoke-token" || action == "logout-session" {
		eventTarget = shortHandle(target)
	}
	s.recordSecurityLocked(SecurityEvent{Event: action, User: current.Username, Device: eventTarget, RemoteIP: requestIP(r, s.trustedProxies), Success: true})
	if recovering {
		return s.saveRecoveryOrRollbackLocked(snapshot)
	}
	return s.saveOrRollbackLocked(snapshot)
}

func validOpaqueHandle(handle string) bool {
	if len(handle) != 64 {
		return false
	}
	_, err := hex.DecodeString(handle)
	return err == nil
}

func (s *Server) recordSecurity(event SecurityEvent) {
	s.mu.Lock()
	s.recordSecurityLocked(event)
	_ = s.saveLocked()
	s.mu.Unlock()
}

func validateDeviceDisplayName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 256 || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validateDeviceName(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func validateDeviceRoute(route string) bool {
	if strings.HasPrefix(route, "id/") {
		return protocol.ValidDeviceID(strings.TrimPrefix(route, "id/"))
	}
	return validateDeviceName(route)
}

func (s *Server) deleteUserSessionsLocked(userID string) {
	for key, record := range s.sessions {
		if record.UserID == userID {
			delete(s.sessions, key)
			delete(s.ephemeralSessions, key)
		}
	}
}

func (s *Server) liveAdminLocked(current User) bool {
	live, exists := s.users[current.ID]
	return exists && live.ID == current.ID && live.Admin && !live.Disabled && current.PasswordHash != "" && live.PasswordHash == current.PasswordHash
}

func (s *Server) revokeClientLocked(clientID string) {
	for _, record := range s.access {
		if record.ClientID == clientID {
			s.resetAgentSessionForResourceLocked(record.Resource)
		}
	}
	for _, record := range s.refresh {
		if record.ClientID == clientID {
			s.resetAgentSessionForResourceLocked(record.Resource)
		}
	}
	delete(s.clients, clientID)
	for key, record := range s.access {
		if record.ClientID == clientID {
			delete(s.access, key)
		}
	}
	for key, record := range s.refresh {
		if record.ClientID == clientID {
			delete(s.refresh, key)
		}
	}
	for key, record := range s.refreshUsed {
		if record.ClientID == clientID {
			delete(s.refreshUsed, key)
		}
	}
	for key, pending := range s.pending {
		if pending.ClientID == clientID {
			delete(s.pending, key)
		}
	}
	for key, code := range s.codes {
		if code.ClientID == clientID {
			delete(s.codes, key)
		}
	}
}

func (s *Server) revokeDeviceClientsLocked(device string) {
	if !strings.HasPrefix(device, "id/") {
		return
	}
	deviceID := strings.TrimPrefix(device, "id/")
	for clientID, client := range s.clients {
		if client.DeviceKeyVerified && client.DeviceID == deviceID {
			s.revokeClientLocked(clientID)
		}
	}
}

func (s *Server) revokeUserCredentialsLocked(userID string) {
	s.deleteUserSessionsLocked(userID)
	for key, code := range s.codes {
		if code.UserID == userID {
			delete(s.codes, key)
		}
	}
	for key, pending := range s.pending {
		if pending.UserID == userID {
			delete(s.pending, key)
		}
	}
	for key, record := range s.access {
		if record.UserID == userID {
			delete(s.access, key)
		}
	}
	for key, record := range s.refresh {
		if record.UserID == userID {
			delete(s.refresh, key)
		}
	}
	for key, record := range s.refreshUsed {
		if record.UserID == userID {
			delete(s.refreshUsed, key)
		}
	}
}

func (s *Server) revokeDeviceTokensLocked(device string) {
	for key, pending := range s.pending {
		if s.resourceUsesDevice(pending.Resource, device) {
			delete(s.pending, key)
		}
	}
	for key, code := range s.codes {
		if s.resourceUsesDevice(code.Resource, device) {
			delete(s.codes, key)
		}
	}
	for key, record := range s.access {
		if s.resourceUsesDevice(record.Resource, device) {
			delete(s.access, key)
		}
	}
	for key, record := range s.refresh {
		if s.resourceUsesDevice(record.Resource, device) {
			delete(s.refresh, key)
		}
	}
	for key, record := range s.refreshUsed {
		if s.resourceUsesDevice(record.Resource, device) {
			delete(s.refreshUsed, key)
		}
	}
}

func (s *Server) resourceUsesDevice(resource, device string) bool {
	_, resourceDevice, _, ok := s.resourceParts(resource)
	return ok && resourceDevice == device
}

func (s *Server) renameDeviceTokensLocked(old, new string) {
	for key, record := range s.access {
		record.Resource = strings.Replace(record.Resource, s.absolute("/mcp/"+old), s.absolute("/mcp/"+new), 1)
		record.Resource = strings.Replace(record.Resource, s.absolute("/agent/"+old), s.absolute("/agent/"+new), 1)
		s.access[key] = record
	}
	for key, record := range s.refresh {
		record.Resource = strings.Replace(record.Resource, s.absolute("/mcp/"+old), s.absolute("/mcp/"+new), 1)
		record.Resource = strings.Replace(record.Resource, s.absolute("/agent/"+old), s.absolute("/agent/"+new), 1)
		s.refresh[key] = record
	}
	for key, record := range s.refreshUsed {
		record.Resource = strings.Replace(record.Resource, s.absolute("/mcp/"+old), s.absolute("/mcp/"+new), 1)
		record.Resource = strings.Replace(record.Resource, s.absolute("/agent/"+old), s.absolute("/agent/"+new), 1)
		s.refreshUsed[key] = record
	}
}

var (
	errInvalidAdminAction      = &adminError{"invalid administrator action"}
	errUnknownUser             = &adminError{"unknown user"}
	errUnknownDevice           = &adminError{"unknown device"}
	errUnknownClient           = &adminError{"unknown OAuth client"}
	errUnknownToken            = &adminError{"unknown token record"}
	errUnknownSession          = &adminError{"unknown browser session"}
	errDeviceNameTaken         = &adminError{"device name is already in use"}
	errCannotDeleteSelf        = &adminError{"cannot delete the current administrator"}
	errPersistenceRecoveryOnly = &adminError{"authorization recovery mode only permits authority-reducing actions; complete recovery and restart before expanding access"}
)

type adminError struct{ message string }

func (e *adminError) Error() string { return e.message }
