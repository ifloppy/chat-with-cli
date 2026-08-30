package oauthserver

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

// materialWebJS is the audited, tree-shaken Material Web runtime generated
// from web/src/material-web.js. It is embedded so the Relay remains a single
// binary and never reaches a CDN for UI code.
//
//go:embed assets/material-web.js
var materialWebJS []byte

// appCSS is intentionally shipped with the binary. The Relay remains a
// single-file deployment while the web UI gets a consistent Material 3
// inspired design system instead of a collection of page-local styles.
const appCSS = `
:root {
  color-scheme: light;
  --md-primary: #6750a4;
  --md-on-primary: #ffffff;
  --md-primary-container: #eaddff;
  --md-on-primary-container: #21005d;
  --md-secondary: #625b71;
  --md-secondary-container: #e8def8;
  --md-tertiary-container: #ffd8e4;
  --md-on-tertiary-container: #31111d;
  --md-surface: #fffbfe;
  --md-surface-container-low: #f7f2fa;
  --md-surface-container: #f3edf7;
  --md-surface-container-high: #ece6f0;
  --md-on-surface: #1d1b20;
  --md-on-surface-variant: #49454f;
  --md-outline: #79747e;
  --md-outline-variant: #cac4d0;
  --md-success: #146c2e;
  --md-success-container: #b7f397;
  --md-warning: #8a4b00;
  --md-warning-container: #ffddb2;
  --md-danger: #ba1a1a;
  --md-danger-container: #ffdad6;
  --md-shadow: 0 10px 28px rgba(46, 33, 71, .10);
  --md-radius-sm: 8px;
  --md-radius-md: 16px;
  --md-radius-lg: 28px;
  /* Material Web consumes the canonical M3 system-token names. */
  --md-sys-color-primary: var(--md-primary);
  --md-sys-color-on-primary: var(--md-on-primary);
  --md-sys-color-primary-container: var(--md-primary-container);
  --md-sys-color-on-primary-container: var(--md-on-primary-container);
  --md-sys-color-secondary: var(--md-secondary);
  --md-sys-color-secondary-container: var(--md-secondary-container);
  --md-sys-color-surface: var(--md-surface);
  --md-sys-color-surface-container: var(--md-surface-container);
  --md-sys-color-surface-container-high: var(--md-surface-container-high);
  --md-sys-color-on-surface: var(--md-on-surface);
  --md-sys-color-on-surface-variant: var(--md-on-surface-variant);
  --md-sys-color-outline: var(--md-outline);
  --md-sys-color-outline-variant: var(--md-outline-variant);
  --md-sys-color-error: var(--md-danger);
  --md-sys-color-on-error: #ffffff;
  --md-sys-color-error-container: var(--md-danger-container);
  --md-sys-color-on-error-container: var(--md-danger);
  --md-sys-color-shadow: #000000;
  --md-ref-typeface-plain: Inter, ui-sans-serif, system-ui, sans-serif;
}

@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --md-primary: #d0bcff;
    --md-on-primary: #381e72;
    --md-primary-container: #4f378b;
    --md-on-primary-container: #eaddff;
    --md-secondary: #ccc2dc;
    --md-secondary-container: #4a4458;
    --md-tertiary-container: #633b48;
    --md-on-tertiary-container: #ffd8e4;
    --md-surface: #141218;
    --md-surface-container-low: #1d1b20;
    --md-surface-container: #211f26;
    --md-surface-container-high: #2b2930;
    --md-on-surface: #e6e1e9;
    --md-on-surface-variant: #cac4d0;
    --md-outline: #938f99;
    --md-outline-variant: #49454f;
    --md-success: #8bd875;
    --md-success-container: #0d3b18;
    --md-warning: #ffb95f;
    --md-warning-container: #603900;
    --md-danger: #ffb4ab;
    --md-danger-container: #690005;
    --md-shadow: 0 12px 32px rgba(0, 0, 0, .32);
  }
}

:root[data-theme="dark"] {
  color-scheme: dark;
  --md-primary: #d0bcff;
  --md-on-primary: #381e72;
  --md-primary-container: #4f378b;
  --md-on-primary-container: #eaddff;
  --md-secondary: #ccc2dc;
  --md-secondary-container: #4a4458;
  --md-tertiary-container: #633b48;
  --md-on-tertiary-container: #ffd8e4;
  --md-surface: #141218;
  --md-surface-container-low: #1d1b20;
  --md-surface-container: #211f26;
  --md-surface-container-high: #2b2930;
  --md-on-surface: #e6e1e9;
  --md-on-surface-variant: #cac4d0;
  --md-outline: #938f99;
  --md-outline-variant: #49454f;
  --md-success: #8bd875;
  --md-success-container: #0d3b18;
  --md-warning: #ffb95f;
  --md-warning-container: #603900;
  --md-danger: #ffb4ab;
  --md-danger-container: #690005;
  --md-shadow: 0 12px 32px rgba(0, 0, 0, .32);
}

:root[data-theme="light"] { color-scheme: light; }

* { box-sizing: border-box; }
html { min-width: 320px; scroll-behavior: smooth; }
body {
  min-height: 100vh;
  margin: 0;
  padding: 0 20px 72px;
  background:
    radial-gradient(circle at 6% -4%, color-mix(in srgb, var(--md-primary-container) 52%, transparent), transparent 34rem),
    radial-gradient(circle at 96% 10%, color-mix(in srgb, var(--md-tertiary-container) 38%, transparent), transparent 30rem),
    var(--md-surface);
  color: var(--md-on-surface);
  font: 16px/1.55 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  text-rendering: optimizeLegibility;
}
a { color: var(--md-primary); text-underline-offset: 3px; }
a:hover { color: var(--md-on-primary-container); }
button, input, select { font: inherit; }
button, a, input, select, summary { -webkit-tap-highlight-color: transparent; }
:focus-visible { outline: 3px solid color-mix(in srgb, var(--md-primary) 72%, transparent); outline-offset: 3px; }

.page { width: min(1180px, 100%); margin: 0 auto; }
.page.narrow { width: min(820px, 100%); }
.page.compact { width: min(540px, 100%); }
.topbar {
  display: flex; align-items: center; justify-content: space-between; gap: 18px;
  min-height: 76px; padding: 16px 0 12px;
}
.brand { display: inline-flex; align-items: center; gap: 11px; color: var(--md-on-surface); text-decoration: none; font-weight: 800; letter-spacing: -.02em; }
.brand:hover { color: var(--md-on-surface); }
.brand-mark {
  display: grid; place-items: center; width: 38px; height: 38px; border-radius: 12px;
  background: linear-gradient(145deg, var(--md-primary), #9a82db); color: var(--md-on-primary);
  box-shadow: 0 5px 14px color-mix(in srgb, var(--md-primary) 30%, transparent); font-weight: 900;
}
.brand-name { font-size: 18px; }
.nav { display: flex; align-items: center; justify-content: flex-end; gap: 8px; flex-wrap: wrap; }
.nav a { padding: 9px 11px; border-radius: 999px; color: var(--md-on-surface-variant); text-decoration: none; font-size: 14px; font-weight: 650; }
.nav a:hover { background: var(--md-surface-container-high); color: var(--md-on-surface); }
.ui-controls { display: flex; align-items: center; gap: 6px; }
.ui-controls-floating { position: fixed; z-index: 10; top: 16px; right: 20px; display: flex; align-items: center; gap: 6px; padding: 6px; border: 1px solid var(--md-outline-variant); border-radius: 999px; background: color-mix(in srgb, var(--md-surface) 88%, transparent); box-shadow: var(--md-shadow); }
.ui-controls select, .icon-button {
  min-height: 38px; border: 1px solid var(--md-outline-variant); border-radius: 999px;
  background: color-mix(in srgb, var(--md-surface) 72%, transparent); color: var(--md-on-surface-variant);
}
.ui-controls select { padding: 6px 27px 6px 11px; }
.icon-button { display: inline-flex; align-items: center; gap: 6px; padding: 7px 12px; cursor: pointer; }
.icon-button:hover { background: var(--md-surface-container-high); color: var(--md-on-surface); }
.icon-button, md-icon-button { display: inline-flex; align-items: center; justify-content: center; width: 40px; min-width: 40px; height: 40px; min-height: 40px; padding: 0; line-height: 0; }
.icon-button .theme-icon, md-icon-button .theme-icon, .language-button svg { display: grid; place-items: center; width: 20px; height: 20px; }
.theme-icon svg, .language-button svg { display: block; width: 20px; height: 20px; fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }

.hero { padding: 46px 0 42px; }
.hero-grid { display: grid; grid-template-columns: minmax(0, 1.12fr) minmax(300px, .88fr); gap: 48px; align-items: center; }
.eyebrow, .badge {
  display: inline-flex; align-items: center; gap: 7px; width: fit-content; padding: 7px 12px;
  border-radius: 999px; background: var(--md-primary-container); color: var(--md-on-primary-container);
  font-size: 12px; font-weight: 800; letter-spacing: .04em; text-transform: uppercase;
}
.eyebrow::before { content: ""; width: 7px; height: 7px; border-radius: 50%; background: var(--md-primary); box-shadow: 0 0 0 4px color-mix(in srgb, var(--md-primary) 18%, transparent); }
h1, h2, h3 { line-height: 1.14; letter-spacing: -.035em; }
h1 { margin: 18px 0 16px; font-size: clamp(40px, 6vw, 76px); }
h2 { margin: 0 0 10px; font-size: clamp(23px, 3vw, 32px); }
h3 { margin: 0 0 7px; font-size: 19px; }
.hero h1 { max-width: 760px; }
.gradient-text { background: linear-gradient(110deg, var(--md-primary), #a56bca 48%, #c04e77); -webkit-background-clip: text; background-clip: text; color: transparent; }
.lead { max-width: 680px; margin: 0; color: var(--md-on-surface-variant); font-size: clamp(17px, 2vw, 21px); }
.muted { color: var(--md-on-surface-variant); }
.actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin: 26px 0; }
.button, button {
  display: inline-flex; align-items: center; justify-content: center; gap: 8px; min-height: 44px;
  border: 1px solid var(--md-outline); border-radius: 999px; padding: 9px 18px;
  background: transparent; color: var(--md-on-surface); cursor: pointer; text-decoration: none; font-weight: 750;
  transition: transform .16s ease, box-shadow .16s ease, background .16s ease;
}
.button:hover, button:hover { transform: translateY(-1px); box-shadow: 0 5px 14px color-mix(in srgb, var(--md-on-surface) 13%, transparent); }
.button.primary, button.primary { border-color: var(--md-primary); background: var(--md-primary); color: var(--md-on-primary); }
.button.tonal { border-color: transparent; background: var(--md-secondary-container); color: var(--md-on-surface); }
.button.text { border-color: transparent; color: var(--md-primary); }
.button.danger, button.danger, .danger { border-color: var(--md-danger); background: var(--md-danger); color: #fff; }
button:disabled { cursor: wait; opacity: .65; transform: none; }

.hero-visual { position: relative; min-height: 330px; overflow: hidden; border-radius: var(--md-radius-lg); background: linear-gradient(145deg, var(--md-primary-container), var(--md-tertiary-container)); box-shadow: var(--md-shadow); }
.hero-visual::before, .hero-visual::after { content: ""; position: absolute; border-radius: 50%; filter: blur(2px); }
.hero-visual::before { width: 260px; height: 260px; left: -70px; bottom: -110px; background: color-mix(in srgb, var(--md-primary) 32%, transparent); }
.hero-visual::after { width: 220px; height: 220px; right: -60px; top: -90px; background: color-mix(in srgb, #f3a6c0 44%, transparent); }
.network { position: absolute; inset: 35px; display: grid; place-items: center; }
.network::before { content: ""; position: absolute; width: 190px; height: 190px; border: 1px dashed color-mix(in srgb, var(--md-primary) 60%, transparent); border-radius: 50%; }
.node { position: absolute; display: grid; place-items: center; width: 78px; height: 78px; border: 1px solid color-mix(in srgb, var(--md-on-primary-container) 18%, transparent); border-radius: 24px; background: color-mix(in srgb, var(--md-surface) 82%, transparent); box-shadow: 0 8px 25px color-mix(in srgb, var(--md-primary) 20%, transparent); color: var(--md-on-primary-container); font-size: 28px; }
.node span { display: block; margin-top: 3px; font-size: 10px; font-weight: 800; letter-spacing: .04em; text-transform: uppercase; }
.node.relay { z-index: 1; width: 100px; height: 100px; border-radius: 32px; background: var(--md-primary); color: var(--md-on-primary); font-size: 35px; }
.node.client { left: 4%; top: 40%; }
.node.agent { right: 4%; top: 40%; }
.node.mcp { left: 39%; bottom: 0; }
.link { position: absolute; height: 2px; width: 31%; background: linear-gradient(90deg, transparent, var(--md-primary), transparent); transform-origin: left center; opacity: .72; }
.link.left { left: 19%; top: 50%; transform: rotate(5deg); }
.link.right { right: 18%; top: 50%; transform: rotate(175deg); }
.link.bottom { left: 48%; top: 64%; width: 23%; transform: rotate(90deg); }
.visual-caption { position: absolute; right: 20px; bottom: 17px; color: var(--md-on-primary-container); font-size: 12px; font-weight: 750; opacity: .78; }

.section { padding: 34px 0; }
.section-heading { display: flex; justify-content: space-between; gap: 20px; align-items: end; margin-bottom: 18px; }
.section-heading p { max-width: 620px; margin: 0; color: var(--md-on-surface-variant); }
.feature-grid, .grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; }
.feature-card, .card, section, details, form.surface, .meta, .identity, .step {
  border: 1px solid var(--md-outline-variant); border-radius: var(--md-radius-md); background: color-mix(in srgb, var(--md-surface-container-low) 86%, transparent);
}
.feature-card, .card { padding: 22px; }
.feature-card { min-height: 190px; }
.feature-card p, .card p { margin: 0; color: var(--md-on-surface-variant); }
.feature-icon { display: grid; place-items: center; width: 42px; height: 42px; margin-bottom: 20px; border-radius: 14px; background: var(--md-secondary-container); color: var(--md-primary); font-size: 21px; }
.trust-card, .warning, .banner { border: 1px solid color-mix(in srgb, var(--md-warning) 44%, var(--md-outline-variant)); border-radius: var(--md-radius-md); padding: 17px 20px; background: color-mix(in srgb, var(--md-warning-container) 48%, var(--md-surface)); }
.trust-card strong, .warning b, .banner b { display: block; margin-bottom: 4px; color: var(--md-warning); }
.critical { border-color: color-mix(in srgb, var(--md-danger) 60%, var(--md-outline-variant)); background: color-mix(in srgb, var(--md-danger-container) 58%, var(--md-surface)); }
.critical b, .bad { color: var(--md-danger); }
.ok { color: var(--md-success); }
.status, .pill { display: inline-flex; align-items: center; gap: 6px; padding: 5px 10px; border-radius: 999px; background: var(--md-surface-container-high); color: var(--md-on-surface-variant); font-size: 12px; font-weight: 750; }
.status.ok::before, .status.bad::before { content: ""; width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
.stats, .meta { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
.stat { padding: 18px; border-radius: var(--md-radius-md); background: var(--md-surface-container); }
.stat strong { display: block; font-size: 28px; color: var(--md-primary); }
.stat span { color: var(--md-on-surface-variant); font-size: 13px; }
.ad-slot { min-height: 90px; margin: 24px 0; border: 1px dashed var(--md-outline); border-radius: var(--md-radius-md); background: var(--md-surface-container-low); text-align: center; }
.adsense-unit { display: block; min-height: 90px; }
.ad-slot .ad-label { padding: 14px; color: var(--md-on-surface-variant); font-size: 12px; }
.support-card { display: grid; grid-template-columns: 1fr auto; gap: 18px; align-items: center; padding: 22px; border-radius: var(--md-radius-md); background: linear-gradient(120deg, var(--md-primary-container), var(--md-secondary-container)); }
.support-card p { margin: 0; color: var(--md-on-primary-container); }

.page-header { padding: 24px 0 18px; }
.page-header h1 { margin: 10px 0 6px; font-size: clamp(32px, 5vw, 52px); }
.page-header p { margin: 0; color: var(--md-on-surface-variant); }
.toolbar { display: flex; justify-content: space-between; align-items: center; gap: 16px; flex-wrap: wrap; }
.toolbar .nav { display: flex; }
.card, section, details, form.surface, .meta { margin: 14px 0; padding: 20px; }
.steps { display: grid; gap: 12px; }
.step { position: relative; padding: 17px 18px 17px 21px; }
.step::before { content: ""; position: absolute; top: 21px; bottom: 21px; left: 0; width: 3px; border-radius: 4px; background: var(--md-primary); }
.step b { display: block; margin-bottom: 5px; }
code { color: var(--md-on-surface); font: 13px/1.5 ui-monospace, SFMono-Regular, Consolas, monospace; overflow-wrap: anywhere; }
code.command, .command { display: block; margin-top: 9px; padding: 12px 14px; border: 1px solid var(--md-outline-variant); border-radius: var(--md-radius-sm); background: var(--md-surface-container-high); white-space: pre-wrap; }
.copy-row { display: flex; align-items: stretch; gap: 8px; }
.copy-row code { flex: 1; }
.copy-button { flex: 0 0 auto; min-height: auto; padding: 7px 12px; }

form { margin: 0; }
label { display: block; margin: 14px 0 6px; color: var(--md-on-surface); font-weight: 700; }
label.check { display: flex; align-items: flex-start; gap: 10px; font-weight: 500; }
label.check input { width: auto; margin-top: 5px; }
input, select, textarea {
  width: 100%; min-height: 44px; border: 1px solid var(--md-outline); border-radius: 10px; padding: 9px 12px;
  background: var(--md-surface); color: var(--md-on-surface);
}
input:focus, select:focus, textarea:focus { border-color: var(--md-primary); box-shadow: 0 0 0 3px color-mix(in srgb, var(--md-primary) 20%, transparent); outline: none; }
form button { margin-top: 16px; }
form.inline { display: inline-flex; align-items: center; gap: 7px; flex-wrap: wrap; margin: 3px 4px 3px 0; }
form.inline input, form.inline select { width: auto; min-width: 130px; }
form.inline button { min-height: 37px; padding: 7px 13px; }
small { color: var(--md-on-surface-variant); }
.actions + .muted { margin-top: 18px; }
table { width: 100%; border-collapse: separate; border-spacing: 0; overflow: auto; display: block; }
th, td { min-width: 110px; padding: 13px 11px; border-bottom: 1px solid var(--md-outline-variant); text-align: left; vertical-align: top; }
th { color: var(--md-on-surface-variant); font-size: 12px; letter-spacing: .04em; text-transform: uppercase; }
tr:last-child td { border-bottom: 0; }
details > summary { cursor: pointer; list-style: none; font-size: 18px; font-weight: 750; }
details > summary::-webkit-details-marker { display: none; }
details > summary::after { content: "+"; float: right; color: var(--md-primary); font-size: 22px; }
details[open] > summary::after { content: "−"; }
.meta { grid-template-columns: minmax(7rem, .35fr) 1fr; }
.meta span { color: var(--md-on-surface-variant); }
.footer { display: flex; justify-content: space-between; gap: 16px; flex-wrap: wrap; padding-top: 30px; color: var(--md-on-surface-variant); font-size: 13px; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }
.copy-fallback { position: fixed; width: 1px; height: 1px; opacity: 0; pointer-events: none; }
.hidden { display: none !important; }

@media (max-width: 840px) {
  .hero-grid { grid-template-columns: 1fr; gap: 28px; }
  .hero-visual { min-height: 270px; }
  .feature-grid, .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 620px) {
  body { padding: 0 14px 48px; }
  .topbar { align-items: flex-start; flex-direction: column; }
  .topbar .nav { width: 100%; justify-content: flex-start; }
  .hero { padding-top: 25px; }
  h1 { font-size: 42px; }
  .feature-grid, .grid, .stats, .support-card, .usage-meter { grid-template-columns: 1fr; }
  .stats { gap: 8px; }
  .card, section, details, form.surface, .meta { padding: 16px; }
  .copy-row { display: block; }
  .copy-button { margin-top: 8px; }
  .nav a { padding-left: 8px; padding-right: 8px; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { scroll-behavior: auto !important; transition-duration: .01ms !important; animation-duration: .01ms !important; }
}

/* OAuth is intentionally native HTML + CSS only. Do not attach app.js or
   Material form-associated elements to this surface. */
.oauth-page {
  min-height: 100vh;
  padding: 0 20px 44px;
  background:
    radial-gradient(circle at 50% -18%, color-mix(in srgb, var(--md-primary-container) 64%, transparent), transparent 36rem),
    var(--md-surface);
}
.oauth-shell { width: min(760px, 100%); margin: 0 auto; }
.oauth-brand { display: flex; align-items: center; justify-content: space-between; gap: 16px; min-height: 82px; }
.oauth-card {
  overflow: hidden;
  border: 1px solid var(--md-outline-variant);
  border-radius: 24px;
  padding: clamp(24px, 5vw, 42px);
  background: var(--md-surface-container-low);
  box-shadow: 0 18px 54px color-mix(in srgb, var(--md-on-surface) 10%, transparent);
}
.oauth-heading { margin-bottom: 24px; }
.oauth-heading h1 { margin: 12px 0 8px; font-size: clamp(30px, 6vw, 44px); }
.oauth-heading p { max-width: 610px; margin: 0; color: var(--md-on-surface-variant); }
.oauth-client { display: grid; grid-template-columns: minmax(0, .85fr) minmax(0, 1.15fr); gap: 14px; margin: 0 0 14px; }
.oauth-client > div, .oauth-meta > div, .oauth-signed-in {
  min-width: 0;
  border: 1px solid var(--md-outline-variant);
  border-radius: 14px;
  padding: 14px 16px;
  background: var(--md-surface);
}
.oauth-client strong { display: block; margin-top: 4px; font-size: 17px; }
.oauth-client code, .oauth-meta code { display: block; margin-top: 4px; overflow-wrap: anywhere; }
.oauth-meta { display: grid; gap: 9px; margin: 0 0 18px; }
.oauth-meta > div { display: grid; grid-template-columns: 92px minmax(0, 1fr); align-items: start; gap: 14px; padding-block: 12px; }
.oauth-meta dt { color: var(--md-on-surface-variant); font-size: 13px; font-weight: 750; }
.oauth-meta dd { min-width: 0; margin: 0; }
.oauth-notice { display: grid; gap: 5px; margin: 12px 0; border-radius: 14px; padding: 14px 16px; }
.oauth-notice b { margin: 0; }
.oauth-notice span { color: var(--md-on-surface-variant); }
.oauth-notice.verified { border: 1px solid color-mix(in srgb, var(--md-success) 42%, var(--md-outline-variant)); background: color-mix(in srgb, var(--md-success-container) 44%, var(--md-surface)); }
.oauth-form { margin-top: 22px; border-top: 1px solid var(--md-outline-variant); padding-top: 22px; }
.oauth-form h2 { margin-bottom: 14px; }
.oauth-form label { margin-top: 12px; }
.oauth-submit { width: 100%; margin-top: 20px; }
.oauth-signed-in { margin-bottom: 14px; }
.oauth-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.oauth-actions button { margin-top: 0; }
.oauth-register { margin-top: 16px; border: 1px solid var(--md-outline-variant); border-radius: 14px; background: var(--md-surface); }
.oauth-register > summary { padding: 16px 18px; font-size: 16px; }
.oauth-register > .oauth-form { margin: 0; padding: 0 18px 18px; border-top: 0; }
.oauth-footer { display: flex; justify-content: space-between; gap: 16px; padding: 18px 4px 0; color: var(--md-on-surface-variant); font-size: 13px; }
@media (max-width: 620px) {
  .oauth-page { padding: 0 14px 32px; }
  .oauth-brand { min-height: 70px; }
  .oauth-brand .pill { display: none; }
  .oauth-card { border-radius: 18px; padding: 22px 18px; }
  .oauth-client { grid-template-columns: 1fr; }
  .oauth-meta > div { grid-template-columns: 1fr; gap: 2px; }
  .oauth-actions { align-items: stretch; flex-direction: column; }
  .oauth-actions button { width: 100%; }
  .oauth-footer { flex-direction: column; gap: 6px; }
}

/* Material 3 component layer. Keep these tokens and state layers local so the
   single-binary Relay does not depend on a CDN or an opaque runtime bundle. */
body {
  padding: 0;
  background: var(--md-surface);
}
.page {
  width: min(1200px, 100%);
  padding: 0 32px 72px;
}
.page.narrow { width: min(860px, 100%); }
.page.compact { width: min(560px, 100%); }
.topbar {
  min-height: 80px;
  padding: 16px 0;
  border-bottom: 1px solid var(--md-outline-variant);
}
.brand-mark { border-radius: 12px; box-shadow: none; }
.nav { gap: 4px; }
.nav a {
  position: relative;
  min-height: 40px;
  display: inline-flex;
  align-items: center;
  padding: 8px 14px;
  border-radius: 20px;
  overflow: hidden;
}
.nav a::after, .button::after, button::after, .icon-button::after {
  content: "";
  position: absolute;
  inset: 0;
  background: currentColor;
  opacity: 0;
  pointer-events: none;
  transition: opacity .16s ease;
}
.nav a:hover::after, .button:hover::after, button:hover::after, .icon-button:hover::after,
.nav a:focus-visible::after, .button:focus-visible::after, button:focus-visible::after, .icon-button:focus-visible::after { opacity: .08; }
.nav a:active, .button:active, button:active, .icon-button:active { transform: scale(.97); }
.ui-controls { gap: 8px; margin-left: 8px; padding-left: 12px; border-left: 1px solid var(--md-outline-variant); }
.ui-controls-floating {
  top: 16px;
  right: 24px;
  border-radius: 16px;
  padding: 4px;
}
.ui-controls select, .icon-button {
  min-height: 40px;
  border-radius: 12px;
  background: var(--md-surface);
}
.ui-controls select { padding: 7px 30px 7px 12px; }
.icon-button { position: relative; overflow: hidden; padding: 0; }
.language-button { gap: 0; }
.hero {
  margin-top: 12px;
  border: 1px solid var(--md-outline-variant);
  border-radius: 24px;
  background: var(--md-surface-container-low);
  padding: 48px;
}
.hero-visual { border-radius: 24px; box-shadow: var(--md-shadow); }
.eyebrow, .badge { border-radius: 8px; }
.feature-card, .card, .control-card, .stat-card, .auth-card, .surface, .table-card, .onboarding {
  border: 1px solid var(--md-outline-variant);
  border-radius: 16px;
  background: var(--md-surface-container-low);
  box-shadow: none;
}
.feature-card, .card { padding: 24px; }
.section { border: 0; background: transparent; margin: 0; padding: 40px 0; }
.section-heading { margin-bottom: 24px; }
.stat-card {
  display: flex;
  min-height: 126px;
  flex-direction: column;
  justify-content: space-between;
  gap: 10px;
  padding: 20px;
}
.stat-value { display: block; color: var(--md-on-surface); font-size: 32px; font-weight: 760; letter-spacing: -.04em; line-height: 1; }
.stat-label { display: block; color: var(--md-on-surface-variant); font-size: 14px; line-height: 1.35; }
.stats-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
.button, button {
  position: relative;
  min-height: 40px;
  overflow: hidden;
  border-radius: 20px;
  border-color: transparent;
  padding: 9px 20px;
  box-shadow: none;
  transition: background .16s ease, box-shadow .16s ease, transform .12s ease;
}
.button:hover, button:hover { box-shadow: none; transform: translateY(-1px); }
.button.primary, button.primary { box-shadow: 0 1px 2px color-mix(in srgb, var(--md-on-surface) 18%, transparent); }
.button.tonal { border-color: transparent; background: var(--md-secondary-container); color: var(--md-on-surface); }
.button.outlined, button.outlined { border-color: var(--md-outline); background: transparent; color: var(--md-primary); }
.button.text { min-height: 40px; padding-inline: 12px; }
.button.danger, button.danger, .danger { border-color: transparent; }
button:disabled { cursor: not-allowed; opacity: .55; box-shadow: none; }
.ripple {
  position: absolute;
  z-index: 1;
  width: 20px;
  height: 20px;
  border-radius: 50%;
  background: currentColor;
  opacity: .24;
  pointer-events: none;
  transform: scale(0);
  animation: md-ripple .52s ease-out;
}
@keyframes md-ripple { to { opacity: 0; transform: scale(7); } }
.surface { margin: 20px 0; padding: 24px; }
.admin-page .page-header { padding: 32px 0 24px; }
.admin-page .page-header h1 { font-size: clamp(32px, 5vw, 52px); }
.admin-summary { display: flex; align-items: end; justify-content: space-between; gap: 20px; flex-wrap: wrap; margin: 0 0 24px; }
.admin-summary p { margin: 0; color: var(--md-on-surface-variant); }
.admin-summary strong { color: var(--md-on-surface); }
.section-heading .eyebrow { margin-bottom: 10px; }
.control-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
.control-card { display: flex; flex-direction: column; gap: 14px; min-height: 178px; padding: 20px; }
.control-card h3 { margin: 0; }
.control-card p { margin: 0; color: var(--md-on-surface-variant); font-size: 14px; }
.control-card-header { display: flex; justify-content: space-between; align-items: start; gap: 12px; }
.setting-form { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-top: auto; }
.setting-form select { width: auto; min-width: 140px; }
.setting-form button { margin-top: 0; }
.field-label { display: block; margin: 0; color: var(--md-on-surface-variant); font-size: 12px; font-weight: 700; letter-spacing: .03em; text-transform: uppercase; }
.field-help { color: var(--md-on-surface-variant); font-size: 13px; }
.status, .pill { min-height: 28px; border: 1px solid var(--md-outline-variant); border-radius: 8px; padding: 4px 9px; }
.status.ok { border-color: color-mix(in srgb, var(--md-success) 35%, var(--md-outline-variant)); background: color-mix(in srgb, var(--md-success-container) 42%, var(--md-surface)); }
.status.bad { border-color: color-mix(in srgb, var(--md-danger) 35%, var(--md-outline-variant)); background: color-mix(in srgb, var(--md-danger-container) 42%, var(--md-surface)); }
.status.warn { border-color: color-mix(in srgb, var(--md-warning) 35%, var(--md-outline-variant)); background: color-mix(in srgb, var(--md-warning-container) 42%, var(--md-surface)); }
.table-card { padding: 0; overflow: hidden; }
.table-card > .table-intro, .table-card > form:first-child { margin: 0; padding: 20px 24px; }
.table-wrap { overflow-x: auto; padding: 0 24px 20px; }
.table-wrap table { min-width: 720px; }
table { display: table; overflow: visible; }
th, td { padding: 16px 12px; }
th { background: var(--md-surface-container); }
.table-actions { min-width: 250px; }
.disclosure { padding: 0; overflow: hidden; }
.disclosure > summary { padding: 20px 24px; }
.disclosure > table, .disclosure > p, .disclosure > .table-wrap { margin-inline: 24px; }
.disclosure > table { width: calc(100% - 48px); }
.auth-card { margin: 28px 0; padding: 28px; }
.auth-card .eyebrow { margin-bottom: 8px; }
.auth-card h1 { margin: 8px 0 10px; font-size: clamp(32px, 6vw, 46px); }
.auth-card > p { color: var(--md-on-surface-variant); }
.auth-form { display: grid; gap: 4px; margin-top: 24px; }
.auth-form label { margin: 8px 0 0; }
.auth-form button { justify-self: start; margin-top: 16px; }
.auth-footer { display: flex; gap: 16px; flex-wrap: wrap; margin-top: 20px; }
.topbar .button { min-height: 36px; padding: 7px 14px; }
.onboarding { padding: 24px; }
.onboarding > p { margin-top: 0; color: var(--md-on-surface-variant); }
.banner { margin: 18px 0; }
.admin-page > main > .banner.warning, .admin-page > main > .onboarding { display: none; }
.page-header-row { display: flex; align-items: end; justify-content: space-between; gap: 24px; }
.page-header-copy { min-width: 0; }
.page-header-actions { display: flex; flex: 0 0 auto; gap: 8px; flex-wrap: wrap; }
.account-avatar, .admin-avatar {
  position: relative; display: inline-flex !important; align-items: center; justify-content: center;
  width: 40px; height: 40px; min-height: 40px; padding: 0 !important; border-radius: 50% !important;
  overflow: hidden; text-decoration: none; transition: background .16s ease, box-shadow .16s ease, transform .12s ease;
}
.account-avatar { background: var(--md-primary-container); color: var(--md-on-primary-container) !important; }
.admin-avatar { background: var(--md-surface-container); border: 1px solid var(--md-outline-variant); color: var(--md-primary) !important; }
.account-avatar:hover, .admin-avatar:hover { box-shadow: 0 2px 8px color-mix(in srgb, var(--md-on-surface) 16%, transparent); }
.account-avatar svg, .admin-avatar svg { width: 20px; height: 20px; fill: none; stroke: currentColor; stroke-linecap: round; stroke-linejoin: round; stroke-width: 1.8; }
.language-picker { position: relative; }
.language-button { width: 40px; height: 40px; padding: 0 !important; }
.language-button svg { width: 19px; height: 19px; fill: none; stroke: currentColor; stroke-linecap: round; stroke-linejoin: round; stroke-width: 1.8; }
.language-menu {
  position: absolute; z-index: 30; top: calc(100% + 8px); right: 0; min-width: 152px; padding: 8px;
  border: 1px solid var(--md-outline-variant); border-radius: 16px; background: var(--md-surface-container-low);
  box-shadow: var(--md-shadow);
}
.language-menu[hidden] { display: none; }
.language-menu button, .language-menu md-text-button { display: flex; width: 100%; min-height: 38px; justify-content: flex-start; margin: 0; padding: 7px 12px; border-radius: 10px; }
.language-menu [aria-checked="true"] { background: var(--md-secondary-container); color: var(--md-on-surface); }
dialog.action-dialog {
  width: min(520px, calc(100vw - 32px)); max-width: calc(100vw - 32px); margin: auto; padding: 0;
  border: 1px solid var(--md-outline-variant); border-radius: 28px; color: var(--md-on-surface);
  background: var(--md-surface-container-low); box-shadow: 0 24px 64px rgba(46, 33, 71, .24);
}
dialog.action-dialog::backdrop { background: rgba(20, 18, 24, .32); backdrop-filter: blur(2px); }
.dialog-form { display: grid; gap: 0; margin: 0; padding: 28px; }
.dialog-heading h2 { margin: 8px 0 8px; font-size: 28px; }
.dialog-heading p { margin: 0; color: var(--md-on-surface-variant); }
.dialog-fields { display: grid; gap: 4px; margin-top: 20px; }
.dialog-field { margin: 0; }
.dialog-field span { display: block; margin: 0 0 6px; color: var(--md-on-surface); font-weight: 700; }
.dialog-field[hidden] { display: none; }
.dialog-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 24px; }
.dialog-actions button, .dialog-actions md-filled-button, .dialog-actions md-filled-tonal-button,
.dialog-actions md-outlined-button, .dialog-actions md-text-button { margin-top: 0; }
.dialog-form > input[type="hidden"] { display: none; }
.usage-card { padding: 24px; }
.usage-meter { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin: 20px 0; }
.usage-meter > div { display: grid; gap: 5px; padding: 14px; border-radius: 12px; background: var(--md-surface-container); }
.usage-meter span { color: var(--md-on-surface-variant); font-size: 13px; }
.usage-meter strong { color: var(--md-primary); font-size: 18px; }
.usage-actions { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.usage-actions .setting-form { margin-top: 0; }
.dialog-field input[type="checkbox"] { width: auto; min-height: auto; }

/* The controls below are upgraded to the official Material Web elements when
   the local bundle is ready. These host rules keep the no-JS fallback and the
   custom-element layout aligned during that progressive enhancement. */
md-filled-button, md-filled-tonal-button, md-outlined-button, md-text-button, md-icon-button, md-outlined-select {
  --md-sys-typescale-label-large-font: var(--md-ref-typeface-plain);
  vertical-align: middle;
}
md-filled-button.danger {
  --md-filled-button-container-color: var(--md-danger);
  --md-filled-button-label-text-color: #ffffff;
  --md-filled-button-hover-label-text-color: #ffffff;
  --md-filled-button-focus-label-text-color: #ffffff;
  --md-filled-button-pressed-label-text-color: #ffffff;
  --md-filled-button-hover-state-layer-color: #ffffff;
  --md-filled-button-pressed-state-layer-color: #ffffff;
}
md-filled-button.primary { --md-filled-button-container-color: var(--md-primary); }
md-filled-tonal-button.tonal { --md-filled-tonal-button-container-color: var(--md-secondary-container); }
md-outlined-button.outlined { --md-outlined-button-outline-color: var(--md-outline); }
md-text-button.text { --md-text-button-label-text-color: var(--md-primary); }
md-icon-button { --md-icon-button-icon-color: var(--md-on-surface-variant); --md-icon-button-icon-size: 20px; display: inline-flex; align-items: center; justify-content: center; width: 40px; min-width: 40px; height: 40px; min-height: 40px; padding: 0; line-height: 0; }
md-icon-button .theme-icon, md-icon-button.language-button svg { display: grid; place-items: center; width: 20px; height: 20px; line-height: 0; }
md-icon-button .theme-icon svg { display: block; width: 20px; height: 20px; fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }
.setting-form md-outlined-select { min-width: 150px; }
.setting-form md-filled-button, .setting-form md-filled-tonal-button,
.setting-form md-outlined-button, .setting-form md-text-button { margin-top: 0; }
.auth-form md-filled-button, .auth-form md-filled-tonal-button,
.auth-form md-outlined-button, .auth-form md-text-button { justify-self: start; margin-top: 16px; }
.copy-row md-outlined-button, .copy-row md-text-button { flex: 0 0 auto; }
.table-actions md-filled-button, .table-actions md-filled-tonal-button,
.table-actions md-outlined-button, .table-actions md-text-button { min-width: max-content; }

@media (max-width: 840px) {
  .page { padding-inline: 24px; }
  .stats-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .control-grid { grid-template-columns: 1fr; }
}
@media (max-width: 620px) {
  .page { padding: 0 16px 48px; }
  .topbar { min-height: 72px; }
  .ui-controls { margin-left: 0; padding-left: 0; border-left: 0; }
  .hero { padding: 32px 20px; }
  .stats-grid { grid-template-columns: 1fr; }
  .surface, .auth-card, .onboarding { padding: 20px; }
  .table-card > .table-intro, .table-card > form:first-child { padding: 18px 20px; }
  .table-wrap { padding-inline: 20px; }
  .disclosure > summary { padding: 18px 20px; }
  .disclosure > table, .disclosure > p, .disclosure > .table-wrap { margin-inline: 20px; }
.disclosure > table { width: calc(100% - 40px); }
}
`

const appJS = `
(() => {
  "use strict";
  const root = document.documentElement;
  const styleNonce = document.querySelector('meta[name="cwc-style-nonce"]')?.getAttribute("content");
  if (styleNonce) window.litNonce = styleNonce;
  const themeKey = "cwc-theme";
  const localeKey = "cwc-locale";
  const translations = {
    "zh-CN": {
      "Home": "首页", "Docs": "文档", "Documentation": "文档", "GitHub": "GitHub",
      "Connect": "连接", "Connect a computer": "连接电脑", "Connect a workstation": "连接工作站", "Connect my computer": "连接我的电脑",
      "Manage my account": "管理我的账户", "My account": "我的账户", "Operator admin": "管理员控制台", "Admin console": "管理员控制台", "Account entry": "账户入口",
      "Open admin console": "打开管理控制台", "Finish first-run setup": "完成首次设置",
      "Back to home": "返回首页", "Sign in": "登录", "Sign out": "退出登录", "Re-authenticate": "重新认证",
      "Authorize": "授权", "Deny": "拒绝", "Create account": "创建账户", "Register and authorize": "注册并授权",
      "First-run setup": "首次设置", "Create owner and finish setup": "创建所有者并完成设置",
      "Chat with CLI documentation": "Chat with CLI 文档", "Chat with CLI admin": "Chat with CLI 管理员",
      "My Chat with CLI": "我的 Chat with CLI", "Invite created": "邀请已创建",
      "Install": "安装", "Security": "安全", "Ready": "就绪", "Configured": "已配置",
      "Language": "语言", "Theme": "主题", "Automatic": "自动", "English": "English", "中文": "中文",
      "Confirm action": "确认操作", "Cancel": "取消", "Confirm": "确认", "Connect a workstation": "连接工作站",
      "Rename device": "重命名设备", "Choose a display name for this workstation.": "为此工作站设置显示名称。", "New display name": "新的显示名称", "Rename": "重命名",
      "Enable device": "启用设备", "Enter your current account password to re-enable this workstation.": "请输入当前账户密码以重新启用此工作站。", "Current password": "当前密码", "Enable": "启用",
      "Revoke device": "撤销设备", "Type REVOKE to permanently revoke this device.": "请输入 REVOKE 以永久撤销此设备。", "Revoke permanently": "永久撤销",
      "Change password": "修改密码", "Create user": "创建用户", "Create a tenant account with a temporary password.": "使用临时密码创建租户账户。", "Temporary password": "临时密码",
      "Rotate password": "轮换密码", "Set a new password for this user. Existing credentials will be revoked.": "为此用户设置新密码。现有凭据将被撤销。", "New password": "新密码",
      "Delete user": "删除用户", "Type DELETE to permanently delete this user.": "请输入 DELETE 以永久删除此用户。", "Confirmation": "确认文本",
      "Release kill switch": "释放停止开关", "Type RELEASE to release the emergency stop.": "请输入 RELEASE 以释放紧急停止。",
      "Revoke client": "撤销客户端", "Revoke token": "撤销令牌", "Type REVOKE to confirm this revocation.": "请输入 REVOKE 以确认撤销。",
      "Activation code": "激活码", "Add the quota attached to a one-time support code.": "加入一次性支持码附带的额度。", "Quota to add in bytes": "要增加的额度（字节）", "Add Relay traffic quota to this account.": "为此账户增加 Relay 流量额度。", "Quota in bytes": "额度（字节）", "Create a single-use code for the selected quota.": "为选定额度创建一次性代码。",
      "Light": "浅色", "Dark": "深色", "Copied": "已复制", "Copy": "复制",
      "Read-only by default": "默认只读", "Private by design": "隐私优先", "Open source": "开放源代码",
      "Install once. Connect everywhere.": "安装一次，随处连接。",
      "A calm, secure bridge between your AI tools and the workstation where work gets done.": "在 AI 工具与真正执行工作的工作站之间，建立清晰、安全的连接桥梁。",
      "Connect an MCP client to a workstation through a private, outbound Agent connection.": "通过工作站主动建立的 Agent 连接，把 MCP 客户端安全地连接到工作站。",
      "Capabilities stay disabled until the workstation explicitly enables them.": "所有能力默认关闭，只有工作站明确启用后才会生效。",
      "Features": "功能", "Everything you need to work with confidence.": "让你放心工作的完整能力。",
      "A small surface area, thoughtful defaults, and clear control over every capability.": "简洁的界面、谨慎的默认设置，以及对每项能力的清晰控制。",
      "MCP-native workflow": "MCP 原生工作流", "Outbound by default": "默认主动外连", "Guardrails you can see": "清晰可见的护栏",
      "Connect ChatGPT and other MCP clients to bounded filesystem, task, and optional Computer Use tools.": "把 ChatGPT 和其他 MCP 客户端连接到受限的文件系统、任务以及可选的 Computer Use 工具。",
      "The workstation Agent connects outward and reconnects automatically. The Relay never initiates a workstation connection.": "工作站 Agent 主动连接并自动重连；Relay 永远不会主动连接工作站。",
      "Read-only profiles, device-bound OAuth, local approvals, audit metadata, and an emergency kill switch keep authority legible.": "只读 profile、设备绑定 OAuth、本地审批、审计元数据和紧急停止开关，让权限边界清晰可见。",
      "Relay": "Relay", "Security model": "安全模型", "Add a workstation": "添加工作站", "public": "公共", "private": "私有", "public relay": "公共 Relay", "private relay": "私有 Relay",
      "Setup required": "需要设置", "Relay configured": "Relay 已配置", "authorization frozen": "授权已冻结",
      "ready": "就绪", "Version": "版本", "Instance": "实例", "Status": "状态",
      "Public Relay trust boundary": "公共 Relay 信任边界", "Public Relay warning": "公共 Relay 警告",
      "Do not trust a public Relay with sensitive access": "不要将敏感权限交给公共 Relay",
      "A public Relay isolates normal users from each other, but the operator controls the server code and can observe or alter MCP traffic.": "公共 Relay 可以隔离普通用户，但运营者控制服务器代码，可能观察或修改 MCP 流量。",
      "A public Relay isolates normal users from each other, but the operator controls the server code and can observe or alter MCP traffic. This includes instances run by the software author. Self-host a private Relay when confidentiality or high-trust computer access matters.": "公共 Relay 可以隔离普通用户，但运营者控制服务器代码，可能观察或修改 MCP 流量。这也包括软件作者运营的实例。需要保密或高信任电脑访问时，请自建私有 Relay。",
      "Health endpoint": "健康检查端点", "Quick start": "快速开始", "Private Relay": "私有 Relay", "Public Relay": "公共 Relay",
      "Agent configuration": "Agent 配置", "Computer Use": "Computer Use", "Threat model": "威胁模型",
      "Reverse proxy": "反向代理", "Cloudflare": "Cloudflare", "User account": "用户账户", "Administration": "管理", "Account": "账户", "Password": "密码", "Chat with CLI account": "Chat with CLI 账户", "Sign in to manage your connected workstations and authorizations.": "登录以管理已连接的工作站和授权。", "Authorizations": "授权", "Sessions": "会话",
      "Troubleshooting": "故障排查", "Backup and restore": "备份与恢复", "Upgrade and rollback": "升级与回滚",
      "Self-host a private Relay with ChatGPT": "使用 ChatGPT 自建私有 Relay",
      "Get started": "开始使用", "Add a workstation in a few calm steps.": "用几个清晰步骤添加工作站。",
      "A connection you can understand.": "一条可以理解的连接。", "Advertisement": "广告", "Primary navigation": "主导航", "MCP client connected through an outbound Relay to an Agent": "MCP 客户端通过主动外连 Relay 连接到 Agent", "Chat with CLI · Connect with confidence": "Chat with CLI · 自信连接", "Documentation · Chat with CLI": "文档 · Chat with CLI", "Set up Chat with CLI": "设置 Chat with CLI",
      "outbound · scoped · observable": "主动外连 · 有范围 · 可观测",
      "MCP tools, clearly annotated": "个 MCP 工具，清晰标注", "capabilities enabled by surprise": "项意外启用的能力", "small binary to install": "个小型二进制文件",
      "1. Create a safe local Agent config": "1. 创建安全的本地 Agent 配置", "Read-only is the default profile.": "默认 profile 是只读。",
      "2. Connect interactively": "2. 交互式连接", "3. Connect your MCP client": "3. 连接 MCP 客户端", "Run": "运行", "Browser OAuth opens automatically when needed, then the local terminal asks how to approve temporary capabilities for this session.": "需要时会自动打开浏览器 OAuth，然后本地终端会询问如何批准本次会话的临时能力。",
      "No device inventory or host information is exposed on this public page.": "此公共页面不会暴露设备清单或主机信息。",
      "Keep the public Relay available": "一起保持公共 Relay 可用",
      "A companion app can verify a rewarded AdMob view and issue a short-lived, signed usage entitlement.": "伴侣应用可以验证激励式 AdMob 广告，并签发短期签名使用 entitlement。",
      "Open reward app": "打开奖励应用", "Open releases": "打开发行页", "Install documentation": "安装文档",
      "Self-hosting guide": "自托管指南", "Need a quick path?": "想快速开始？",
      "Start here when you are deploying a Relay, pairing a workstation, or connecting an MCP client.": "部署 Relay、配对工作站或连接 MCP 客户端时，可以从这里开始。",
      "Connect a computer · Chat with CLI": "连接电脑 · Chat with CLI", "The installer verifies the release binary against SHA256SUMS and installs to": "安装程序会使用 SHA256SUMS 校验发行版二进制，并安装到",
      "It does not start the Agent or use sudo. Review the script first if you prefer not to pipe network content to a shell.": "它不会启动 Agent，也不会使用 sudo。如果不想将网络内容通过管道传给 shell，请先审阅脚本。",
      "Replace the root with the smallest workspace you want ChatGPT to read. The generated systemd unit is not started automatically.": "将 root 替换为你希望 ChatGPT 读取的最小工作区。生成的 systemd unit 不会自动启动。",
      "OAuth opens automatically if needed.": "需要时会自动打开 OAuth。", "On an invite-only public instance, the OAuth page asks for the single-use invite during account creation. The Agent's immutable device ID is derived from its local Ed25519 key.": "在仅限邀请的公共实例上，OAuth 页面会在创建账户时要求单次邀请。Agent 的不可变设备 ID 源自本地 Ed25519 密钥。",
      "The binary ships with this navigation page. The complete, versioned operator documentation is maintained in the open-source project.": "二进制内置此导航页；完整且带版本的运营文档维护在开源项目中。",
      "Start and connect": "开始与连接", "Operate a Relay": "运营 Relay", "Safety and maintenance": "安全与维护",
      "ChatGPT / MCP": "ChatGPT / MCP", "Self-host with ChatGPT": "使用 ChatGPT 自托管", "Deployment": "部署",
      "English guide": "英文指南",
      "Use the interactive terminal hub after installation:": "安装后使用交互式终端中心：",
      "Pair a workstation with a small, explicit, read-only first step.": "先用一个明确、精简的只读步骤配对工作站。",
      "This Relay operator controls the server software and can observe or alter brokered MCP traffic. Do not connect sensitive workspaces or secrets to any public instance, including one operated by the project author. For high-trust use, connect only long enough to bootstrap your own private Relay.": "此 Relay 运营者控制服务器软件，可能观察或修改转发的 MCP 流量。不要把敏感工作区或密钥连接到任何公共实例，包括项目作者运营的实例。需要高信任时，只用公共 Relay 完成自建私有 Relay 的引导。",
      "1 · Install the verified binary": "1 · 安装已验证的二进制文件", "2 · Create a safe Agent profile": "2 · 创建安全的 Agent profile",
      "3 · Connect and authorize this device": "3 · 连接并授权此设备", "4 · Review and start the Agent": "4 · 审阅并启动 Agent",
      "5 · Add it to ChatGPT": "5 · 将它添加到 ChatGPT", "6 · Prefer self-hosting after bootstrap": "6 · 引导完成后优先自托管",
      "Use the stable account MCP endpoint; OAuth limits device discovery and routing to the signed-in account.": "使用稳定的账户级 MCP 端点；OAuth 会把设备发现和路由严格限制在当前登录账户内。",
      "Account MCP endpoint": "账户级 MCP 端点",
      "Use this stable URL in ChatGPT. OAuth grants access only to this account, and each tool call selects one currently owned device.": "在 ChatGPT 中使用这个稳定地址。OAuth 只授权当前账户，每次工具调用都会明确选择一台当前属于该账户的设备。",
      "Do not run the Agent as root. Review the roots and capabilities before enabling the unit.": "不要以 root 运行 Agent。启用 unit 前请审阅根目录和能力权限。",
      "Use the immutable device ID printed by setup/status.": "使用 setup/status 输出的不可变设备 ID。",
      "Once ChatGPT can work through this computer, it can help deploy a verified private Relay on your VPS. Keep the new Relay's owner password and setup token out of the public Relay path.": "ChatGPT 可以通过这台电脑工作后，还能协助在 VPS 上部署已验证的私有 Relay。不要让新 Relay 的所有者密码和 setup token 经过公共 Relay。",
      "First run": "首次运行", "Create the first administrator and choose how this Relay accepts users. This page permanently disappears after successful setup.": "创建第一个管理员，并选择此 Relay 如何接受用户。设置成功后，此页面会永久消失。",
      "1 · Local token": "1 · 本地 token", "2 · Owner account": "2 · 所有者账户", "3 · Add devices": "3 · 添加设备",
      "Read the protected setup-token file on the Relay host.": "读取 Relay 主机上受保护的 setup-token 文件。", "Create a strong administrator password.": "创建强管理员密码。",
      "Sign in, then pair workstations with immutable IDs.": "登录后，使用不可变 ID 配对工作站。",
      "One-time setup token": "一次性 setup token", "Owner username": "所有者用户名", "Owner password": "所有者密码", "Instance mode": "实例模式", "Review the Relay state and change high-impact controls from one auditable surface.": "在一个可审计的界面中查看 Relay 状态并修改高影响控制项。", "instance": "实例", "Uptime": "运行时间", "Current mode": "当前模式", "Set mode": "设置模式", "Apply mode": "应用模式", "Public": "公共", "Private": "私有", "Open registration": "开放注册", "Allow new users to create accounts without an invite.": "允许新用户无需邀请即可创建账户。", "Open": "开放", "Closed": "关闭", "Close registration": "关闭注册", "Available in public mode": "仅公共模式可用", "Open registration is available only in public mode.": "只有公共模式支持开放注册。", "DCR": "DCR", "Dynamic client registration for Agents.": "Agent 的动态客户端注册。", "MCP access": "MCP 访问", "Allow clients to invoke the workstation MCP surface.": "允许客户端调用工作站 MCP 接口。", "Agent access": "Agent 访问", "Allow workstations to maintain outbound sessions.": "允许工作站保持主动外连会话。", "Emergency stop": "紧急停止", "Block all MCP and Agent authorization immediately.": "立即阻断所有 MCP 和 Agent 授权。", "Enabled": "已启用", "Disabled": "已停用", "Off": "关闭", "Invite-only access": "仅限邀请访问", "Registered devices": "已注册设备", "User accounts": "用户账户", "Review the Relay state": "查看 Relay 状态", "in flight": "处理中", "to bypass recovery.": "以绕过恢复。", "clients": "客户端", "token records": "令牌记录", "Recent security events": "最近的安全事件", "Admin changes are recorded as security events.": "管理员变更会记录为安全事件。", "Keep registration and runtime capabilities closed unless this Relay is intentionally operating them.": "除非明确要运行这些功能，否则请保持注册和运行时能力关闭。", "Create and manage tenant accounts. Password rotation revokes existing credentials for that user.": "创建并管理租户账户。轮换密码会撤销该用户现有的凭据。", "Password for": "账户密码：",
      "Private — recommended": "私有 — 推荐", "Public — multi-user": "公共 — 多用户", "After setup, sign in to": "设置完成后，请登录", "to review security controls before connecting a workstation.": "，审阅安全控制后再连接工作站。",
      "Keep the setup token local.": "将 setup token 保留在本地。", "Do not paste it into chat, logs, tickets, or command arguments. It is single-use and removed after successful initialization.": "不要把它粘贴到聊天、日志、工单或命令参数中。它只能使用一次，初始化成功后会被删除。",
      "Enable public self-registration immediately. Leave this off unless you intentionally operate a public multi-user Relay.": "立即启用公共自助注册。除非你明确运营公共多用户 Relay，否则请保持关闭。",
      "Minimum 12 characters. The Relay stores an Argon2id hash, not this password.": "至少 12 个字符。Relay 只保存 Argon2id 哈希，不保存此密码。",
      "After setup, sign in to /admin to review security controls before connecting a workstation.": "设置完成后，请登录 /admin，审阅安全控制后再连接工作站。",
      "Docs are maintained alongside each version of the source.": "文档与每个源码版本一起维护。",
      "See the instance mode, software version, and authorization health before you connect anything.": "连接任何内容前，先查看实例模式、软件版本和授权状态。",
      "The Relay has not created its owner account yet. Use the one-time token stored locally on the Relay host.": "Relay 还没有创建所有者账户，请使用 Relay 主机本地保存的一次性 token。",
      "Owner setup is complete. Devices and credentials are visible only after administrator sign-in.": "所有者设置已完成；设备和凭据只有管理员登录后才能查看。",
      "OAuth credentials are bound to one user, exact device resource, and scope. New public devices use cryptographic immutable IDs.": "OAuth 凭据绑定到单一用户、精确设备资源和 scope；新的公共设备使用加密生成的不可变 ID。",
      "Install once, then run": "安装一次，然后运行", "chat-with-cli ui": "chat-with-cli ui",
      "Open the interactive terminal hub to set up a workstation, connect it, or run diagnostics.": "打开交互式终端中心，设置工作站、连接工作站或运行诊断。",
      "Chat with CLI account": "Chat with CLI 账户", "Sign in to manage your connected workstations and authorizations.": "登录以管理已连接的工作站和授权。",
      "Do not trust a public Relay with sensitive access.": "不要将敏感权限交给公共 Relay。", "The operator controls the server code and can observe or alter MCP traffic. This service isolates users from each other, not from its operator. Self-host a private Relay for high-trust use.": "运营者控制服务器代码，可能观察或修改 MCP 流量。此服务只隔离用户之间的访问，不能隔离用户与运营者。需要高信任时，请自建私有 Relay。",
      "Public Relay operator is trusted by design.": "公共 Relay 运营者属于信任边界。", "This page can prove that other normal users are isolated from your devices. It cannot prove that the operator is harmless: the operator can run modified Relay code and observe or alter MCP traffic. Do not grant sensitive computer access to any public instance, including one operated by the software author; self-host when trust matters.": "此页面可以证明其他普通用户与你的设备相互隔离，但不能证明运营者没有恶意：运营者可以运行修改后的 Relay 代码，观察或修改 MCP 流量。不要把敏感电脑权限交给任何公共实例，包括软件作者运营的实例；信任重要时请自建 Relay。",
      "Devices": "设备", "Authorizations": "授权", "Sessions": "会话", "MCP URL": "MCP URL", "Actions": "操作", "Device": "设备", "Status": "状态", "Capabilities": "能力", "Client": "客户端", "Resource": "资源", "Expires": "到期时间", "Action": "操作", "Session": "会话", "Created": "创建时间", "Last seen": "最后活动", "current": "当前",
      "PoP bound": "已绑定 PoP", "legacy unbound": "旧版未绑定", "online": "在线", "offline": "离线", "disabled": "已停用", "last seen": "最后活动", "not reported": "未报告", "filesystem read": "文件系统读取", "filesystem write": "文件系统写入", "exec": "执行", "screen read": "屏幕读取", "accessibility read": "辅助功能读取", "computer input": "电脑输入",
      "Only devices owned by your account are shown. Disabling immediately revokes current device tokens; permanent revocation retires the cryptographic identity.": "这里只显示属于你账户的设备。停用会立即撤销当前设备令牌；永久撤销会废弃该加密身份。", "No devices are owned by this account yet. Pair an Agent first.": "此账户还没有设备，请先配对 Agent。", "These are your token families, not globally shared OAuth client registrations. Revoking one cannot revoke another user's access.": "这些是你的令牌族，不是全局共享的 OAuth 客户端注册。撤销一个令牌族不会影响其他用户的访问。", "No active OAuth token families.": "没有活跃的 OAuth 令牌族。", "Changing your password revokes all OAuth credentials and browser sessions for this account. Reconnect devices and apps afterward.": "修改密码会撤销此账户的所有 OAuth 凭据和浏览器会话；之后请重新连接设备和应用。",
      "online agents": "在线 Agent", "registered devices": "已注册设备", "retired identities": "已废弃身份", "users": "用户", "OAuth clients": "OAuth 客户端", "sessions": "会话", "Administration": "管理", "Review the Relay state and change high-impact controls from one auditable surface.": "在一个可审计的界面中查看 Relay 状态并修改高影响控制项。", "Signed in as": "当前登录：", "Version": "版本", "instance": "实例", "Uptime": "运行时间",
      "Authorization is frozen": "授权已冻结", "The Relay detected an incomplete authorization-state transaction. MCP and Agent access remain fail-closed across restarts. Repair storage, repeat the intended revoke/disable action, and persist it successfully; recovery writes force the emergency kill switch on. Restart, verify the security state, then explicitly release the kill switch. Do not delete": "Relay 检测到未完成的授权状态事务。MCP 和 Agent 访问在重启后仍保持故障关闭。请修复存储，重新执行原本要做的撤销/停用操作并成功保存；恢复写入会强制开启紧急停止开关。重启并确认安全状态后，再明确释放停止开关。不要删除", "to bypass recovery.": "以绕过恢复。",
      "Emergency kill switch is active": "紧急停止开关已开启", "MCP and Agent authorization is globally blocked. Releasing it requires recent administrator authentication.": "MCP 和 Agent 授权已被全局阻断；释放它需要近期的管理员认证。", "Legacy bearer-only Agent migration mode is ENABLED": "旧版仅 bearer Agent 迁移模式已启用", "Unbound alpha Agents can connect using only an Agent bearer token. This weakens device impersonation resistance and must be used only long enough to migrate old devices to new Ed25519 identities, then disabled in the Relay configuration.": "未绑定的 alpha Agent 只凭 Agent bearer token 即可连接。这会降低设备冒充防护，只应使用到旧设备迁移到新的 Ed25519 身份为止，然后在 Relay 配置中关闭。",
      "Public": "公共", "Private": "私有", "Open": "开放", "Closed": "关闭", "Enabled": "已启用", "Disabled": "已停用", "Off": "关闭", "Close registration": "关闭注册", "Available in public mode": "仅公共模式可用", "Open registration is available only in public mode.": "只有公共模式支持开放注册。",
      "Keep registration and runtime capabilities closed unless this Relay is intentionally operating them.": "除非明确要运行这些功能，否则请保持注册和运行时能力关闭。", "Allow new users to create accounts without an invite.": "允许新用户无需邀请即可创建账户。", "Dynamic client registration for Agents.": "Agent 的动态客户端注册。", "MCP access": "MCP 访问", "Allow clients to invoke the workstation MCP surface.": "允许客户端调用工作站 MCP 接口。", "Agent access": "Agent 访问", "Allow workstations to maintain outbound sessions.": "允许工作站保持主动外连会话。", "Emergency stop": "紧急停止", "Block all MCP and Agent authorization immediately.": "立即阻断所有 MCP 和 Agent 授权。",
      "Invites": "邀请", "Invite-only access": "仅限邀请访问", "Registered devices": "已注册设备", "User accounts": "用户账户", "Create and manage tenant accounts. Password rotation revokes existing credentials for that user.": "创建并管理租户账户。轮换密码会撤销该用户现有的凭据。", "No active invites.": "没有活跃邀请。", "in flight": "处理中", "No devices have been claimed.": "还没有设备被认领。", "No approved clients.": "没有已批准的客户端。", "No active tokens.": "没有活跃令牌。", "Recent security events": "最近的安全事件", "Admin changes are recorded as security events.": "管理员变更会记录为安全事件。", "clients": "客户端", "token records": "令牌记录",
      "User": "用户", "Username": "用户名", "Role / state": "角色 / 状态", "Created / last login": "创建时间 / 最后登录", "admin": "管理员", "active": "活跃", "never": "从未", "device(s)": "台设备", "Logout all": "全部退出", "Revoke": "撤销", "Revoke client": "撤销客户端", "No events recorded.": "没有记录的事件。", "Password for": "账户密码：",
      "Review the Relay state": "查看 Relay 状态", "Security controls": "安全控制", "Disable DCR": "停用 DCR", "Enable DCR": "启用 DCR", "Disable MCP": "停用 MCP", "Enable MCP": "启用 MCP", "Disable Agent": "停用 Agent", "Enable Agent": "启用 Agent", "Emergency disable now": "立即紧急停用",
      "Connect your first workstation": "连接你的第一台工作站", "No device is registered yet. Start with the read-only profile; nothing is started automatically.": "还没有注册设备。请从只读 profile 开始；任何服务都不会自动启动。", "1. On the workstation": "1. 在工作站上", "2. Connect the immutable device ID": "2. 连接不可变设备 ID", "3. Review unattended mode separately": "3. 单独审阅无人值守模式", "Run chat-with-cli connect. Browser OAuth opens automatically when needed and foreground sessions can require local capability approval.": "运行 chat-with-cli connect。需要时会自动打开浏览器 OAuth，前台会话可能需要本地能力批准。", "The generated systemd service still uses the configured profile only; enable it explicitly only when those persistent capabilities are acceptable.": "生成的 systemd 服务仍只使用已配置的 profile；只有确认长期能力可接受时才明确启用它。",
      "Disable is reversible. Revoke permanently retires the device identity so the same private key can never claim this ID again; reconnecting requires a newly generated device identity.": "停用可以恢复。永久撤销会废弃设备身份，使同一私钥永远无法再次认领此 ID；重新连接需要生成新的设备身份。", "Display name": "显示名称", "Immutable ID / route": "不可变 ID / 路由", "Owner": "所有者", "Connection": "连接", "Capabilities": "能力", "No devices have been claimed.": "还没有设备被认领。",
      "Users": "用户", "Create user": "创建用户", "Username": "用户名", "Role / state": "角色 / 状态", "Created / last login": "创建时间 / 最后登录", "admin": "管理员", "active": "活跃", "never": "从未", "device(s)": "台设备", "Logout all": "全部退出", "Rotate password": "轮换密码", "Delete": "删除", "Browser sessions": "浏览器会话", "Session handles are one-way identifiers; browser cookie values are never displayed.": "会话句柄是单向标识符；浏览器 Cookie 值永远不会显示。", "Log out": "退出登录", "OAuth clients and token metadata": "OAuth 客户端和令牌元数据", "Name / redirects": "名称 / 重定向地址", "No approved clients.": "没有已批准的客户端。", "active token records (metadata only; bearer values are never displayed).": "条活跃令牌记录（只有元数据，绝不显示 bearer 值）。", "Kind": "类型", "No active tokens.": "没有活跃令牌。", "Revoke client": "撤销客户端", "Recent security events": "最近的安全事件", "Time": "时间", "Event": "事件", "User / device": "用户 / 设备", "Result": "结果", "success": "成功", "failure": "失败", "No events recorded.": "没有记录的事件。",
      "new username": "新用户名", "temporary password": "临时密码", "new password": "新密码", "DELETE": "输入 DELETE", "REVOKE": "输入 REVOKE", "type RELEASE": "输入 RELEASE", "Return to admin": "返回管理", "Operator admin": "管理员控制台",
      "Support": "支持", "Relay usage": "Relay 用量", "Support the maintainer": "支持维护者", "MCP and Agent request/response payload bytes are counted at the Relay. Add quota with an activation code or a verified rewarded ad.": "Relay 会统计 MCP 和 Agent 请求/响应载荷流量。可通过激活码或经验证的激励广告增加额度。", "Remaining traffic": "剩余流量", "Used": "已使用", "Granted": "已授予", "Watch an ad for quota": "看广告增加额度", "Redeem activation code": "兑换激活码", "activation code": "激活码", "Rewarded ads are awaiting server-side verifier configuration.": "激励广告正在等待服务端验证器配置。",
      "Relay usage and support": "Relay 用量与支持", "This optional system accounts request and response payload bytes through the Relay. It is disabled by default and never grants authority by itself.": "此可选系统统计通过 Relay 的请求和响应载荷字节数。默认关闭，且不会单独授予任何权限。", "Traffic quota": "流量额度", "Default for new accounts": "新账户默认额度", "Disabled by default": "默认关闭", "Only authenticated, user-owned MCP and Agent traffic is counted. Existing accounts keep their granted quota when this default changes.": "只统计已认证且属于用户自己的 MCP 和 Agent 流量。更改默认值不会改变现有账户已授予的额度。", "Disable traffic quotas": "关闭流量额度", "Enable traffic quotas": "启用流量额度", "default quota in bytes": "默认额度（字节）", "Default quota in bytes": "默认额度（字节）", "Edit advertising settings": "编辑广告设置", "Rewarded ads": "激励广告", "AdMob companion verification": "AdMob 伴侣应用验证", "Needs verifier": "需要验证器", "AdMob must be verified server-side. Store the verifier secret in CHAT_WITH_CLI_ADMOB_VERIFIER_SECRET; it is never shown or persisted in Relay state.": "AdMob 必须由服务端验证。请将验证器密钥放入 CHAT_WITH_CLI_ADMOB_VERIFIER_SECRET；它不会显示或写入 Relay 状态。", "Advertising is optional. AdMob rewards require a server-side verifier secret.": "广告为可选项。AdMob 奖励需要服务端验证器密钥。", "Disable rewarded ads": "关闭激励广告", "Enable rewarded ads": "启用激励广告", "AdSense client ID": "AdSense 客户端 ID", "AdSense slot ID": "AdSense 广告位 ID", "AdMob app ID": "AdMob 应用 ID", "AdMob rewarded unit ID": "AdMob 激励广告单元 ID", "reward endpoint (HTTPS)": "奖励端点（HTTPS）", "Reward endpoint (HTTPS)": "奖励端点（HTTPS）", "Activation codes": "激活码", "Support codes": "支持码", "Create a single-use code that adds traffic quota to one account. The plaintext is shown once and only its hash is persisted.": "创建一个为账户增加流量额度的单次使用代码。明文只显示一次，持久化的只有哈希。", "quota in bytes": "额度（字节）", "Create activation code": "创建激活码", "Code hash": "代码哈希", "Quota": "额度", "No active activation codes.": "没有活跃激活码。", "Account quotas": "账户额度", "Grant quota to users": "为用户增加额度", "Add quota manually for a user. Grants are additive and are recorded as administrator security events.": "为用户手动增加额度。额度按累加计算，并记录为管理员安全事件。", "Remaining": "剩余", "quota to add in bytes": "要增加的额度（字节）", "Add quota": "增加额度", "No user quotas yet.": "还没有用户额度记录。", "Activation code created": "激活码已创建", "This code is shown once. Share it with the intended user and keep it private until then.": "此代码只显示一次。请分享给目标用户，并在此之前妥善保密。", "Claim rewarded usage": "领取广告奖励额度", "The companion app returned a server-verified reward. Confirm below to add it to this account.": "伴侣应用返回了经服务端验证的奖励。请在下方确认，将额度加入此账户。", "Add rewarded quota": "加入广告奖励额度"
    }
  };

  function stored(key, fallback) {
    try { return localStorage.getItem(key) || fallback; } catch (_) { return fallback; }
  }
  function persist(key, value) { try { localStorage.setItem(key, value); } catch (_) {} }
  function locale() {
    const pageLocale = root.dataset.locale || "auto";
    if (pageLocale === "zh-CN" || pageLocale === "en-US") {
      persist(localeKey, pageLocale);
      return pageLocale;
    }
    const selected = stored(localeKey, pageLocale);
    if (selected === "zh-CN" || selected === "en-US") return selected;
    return (navigator.language || "").toLowerCase().startsWith("zh") ? "zh-CN" : "en-US";
  }
  const legacyOriginals = new WeakMap();
  const legacyAttributeOriginals = new WeakMap();
  let legacyPageTitle = null;
  function translate() {
    const language = locale();
    if (legacyPageTitle === null) legacyPageTitle = document.title;
    root.lang = language;
    const dictionary = translations[language] || {};
    document.querySelectorAll("[data-i18n]").forEach((element) => {
      const key = element.dataset.i18n;
      if (!element.dataset.i18nDefault) element.dataset.i18nDefault = element.textContent;
      element.textContent = dictionary[key] || element.dataset.i18nDefault;
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach((element) => {
      const key = element.dataset.i18nPlaceholder;
      if (!element.dataset.i18nDefaultPlaceholder) element.dataset.i18nDefaultPlaceholder = element.placeholder;
      element.placeholder = dictionary[key] || element.dataset.i18nDefaultPlaceholder;
    });
    document.querySelectorAll("[data-i18n-title]").forEach((element) => {
      const key = element.dataset.i18nTitle;
      if (!element.dataset.i18nDefaultTitle) element.dataset.i18nDefaultTitle = element.title;
      element.title = dictionary[key] || element.dataset.i18nDefaultTitle;
    });
    document.querySelectorAll("[data-i18n-aria-label]").forEach((element) => {
      const key = element.dataset.i18nAriaLabel;
      if (!element.dataset.i18nDefaultAriaLabel) element.dataset.i18nDefaultAriaLabel = element.getAttribute("aria-label") || "";
      element.setAttribute("aria-label", dictionary[key] || element.dataset.i18nDefaultAriaLabel);
    });
    document.querySelectorAll("[data-i18n-label]").forEach((element) => {
      const key = element.dataset.i18nLabel;
      if (!element.dataset.i18nDefaultLabel) element.dataset.i18nDefaultLabel = element.getAttribute("label") || "";
      element.setAttribute("label", dictionary[key] || element.dataset.i18nDefaultLabel);
    });
    // Older account/admin/OAuth templates do not carry data attributes yet.
    // Translate only complete, non-code text nodes so commands, URLs, user
    // names, and security values can never be accidentally rewritten.
    const legacy = {
      "Account · Chat with CLI": "账户 · Chat with CLI", "Admin sign in · Chat with CLI": "管理员登录 · Chat with CLI",
      "Admin · Chat with CLI": "管理员 · Chat with CLI", "Invite created · Chat with CLI": "邀请已创建 · Chat with CLI",
      "Authorize chat-with-cli": "授权 chat-with-cli", "Chat with CLI account": "Chat with CLI 账户", "Chat with CLI admin": "Chat with CLI 管理员",
      "Sign in to manage devices, users, sessions, and emergency capability switches.": "登录以管理设备、用户、会话和紧急能力开关。", "Sign in": "登录",
      "Confirm it’s you": "请确认是你本人", "High-risk administration actions require a password check within the last 15 minutes. This refreshes only the current browser session.": "高风险管理操作需要在最近 15 分钟内完成密码验证；这只会刷新当前浏览器会话。",
      "Password for": "账户密码：",
      "My Chat with CLI": "我的 Chat with CLI", "Signed in as": "当前登录：", "Home": "首页", "Docs": "文档",
      "Sign out": "退出登录", "My devices": "我的设备", "Connected authorizations": "已连接的授权",
      "Browser sessions": "浏览器会话", "Change password": "修改密码", "Rename": "重命名", "Enable": "启用", "Disable": "停用",
      "Revoke permanently": "永久撤销", "Revoke my authorization": "撤销我的授权", "Sign out all other sessions": "退出其他所有会话",
      "Change password and revoke credentials": "修改密码并撤销凭据",
      "Sign in and authorize": "登录并授权", "Invite created": "邀请已创建", "Return to admin": "返回管理控制台",
      "Back to home": "返回首页", "Re-authenticate": "重新认证", "Cancel and return to admin": "取消并返回管理控制台",
      "Do not trust a public Relay with sensitive access.": "不要将敏感权限交给公共 Relay。",
      "The operator controls the server code and can observe or alter MCP traffic. This service isolates users from each other, not from its operator. Self-host a private Relay for high-trust use.": "运营者控制服务器代码，可能观察或修改 MCP 流量。此服务只隔离用户之间的访问，不能隔离用户与运营者。需要高信任时，请自建私有 Relay。",
      "Public Relay operator is trusted by design.": "公共 Relay 运营者属于信任边界。",
      "This page can prove that other normal users are isolated from your devices. It cannot prove that the operator is harmless: the operator can run modified Relay code and observe or alter MCP traffic. Do not grant sensitive computer access to any public instance, including one operated by the software author; self-host when trust matters.": "此页面可以证明其他普通用户与你的设备相互隔离，但不能证明运营者没有恶意：运营者可以运行修改后的 Relay 代码，观察或修改 MCP 流量。不要把敏感电脑权限交给任何公共实例，包括软件作者运营的实例；信任重要时请自建 Relay。",
      "Only devices owned by your account are shown. Disabling immediately revokes current device tokens; permanent revocation retires the cryptographic identity.": "这里只显示属于你账户的设备。停用会立即撤销当前设备令牌；永久撤销会废弃该加密身份。",
      "No devices are owned by this account yet. Pair an Agent first.": "此账户还没有设备，请先配对 Agent。",
      "These are your token families, not globally shared OAuth client registrations. Revoking one cannot revoke another user's access.": "这些是你的令牌族，不是全局共享的 OAuth 客户端注册。撤销一个令牌族不会影响其他用户的访问。",
      "No active OAuth token families.": "没有活跃的 OAuth 令牌族。",
      "Changing your password revokes all OAuth credentials and browser sessions for this account. Reconnect devices and apps afterward.": "修改密码会撤销此账户的所有 OAuth 凭据和浏览器会话；之后请重新连接设备和应用。",
      "Device": "设备", "Status": "状态", "Capabilities": "能力", "MCP URL": "MCP URL", "Actions": "操作",
      "Client": "客户端", "Resource": "资源", "Expires": "到期时间", "Action": "操作", "Session": "会话", "Created": "创建时间", "Last seen": "最后活动", "current": "当前",
      "PoP bound": "已绑定 PoP", "legacy unbound": "旧版未绑定", "online": "在线", "offline": "离线", "disabled": "已停用", "last seen": "最后活动", "not reported": "未报告",
      "filesystem read": "文件系统读取", "filesystem write": "文件系统写入", "exec": "执行", "screen read": "屏幕读取", "accessibility read": "辅助功能读取", "computer input": "电脑输入",
      "new name": "新名称", "password to enable": "启用所需密码", "new password": "新密码", "current password": "当前密码", "REVOKE": "输入 REVOKE",
      "Authorization is frozen": "授权已冻结", "The Relay detected an incomplete authorization-state transaction. MCP and Agent access remain fail-closed across restarts. Repair storage, repeat the intended revoke/disable action, and persist it successfully; recovery writes force the emergency kill switch on. Restart, verify the security state, then explicitly release the kill switch. Do not delete": "Relay 检测到未完成的授权状态事务。MCP 和 Agent 访问在重启后仍保持故障关闭。请修复存储，重新执行原本要做的撤销/停用操作并成功保存；恢复写入会强制开启紧急停止开关。重启并确认安全状态后，再明确释放停止开关。不要删除",
      "Emergency kill switch is active": "紧急停止开关已开启", "MCP and Agent authorization is globally blocked. Releasing it requires recent administrator authentication.": "MCP 和 Agent 授权已被全局阻断；释放它需要近期的管理员认证。",
      "Legacy bearer-only Agent migration mode is ENABLED": "旧版仅 bearer Agent 迁移模式已启用", "Unbound alpha Agents can connect using only an Agent bearer token. This weakens device impersonation resistance and must be used only long enough to migrate old devices to new Ed25519 identities, then disabled in the Relay configuration.": "未绑定的 alpha Agent 只凭 Agent bearer token 即可连接。这会降低设备冒充防护，只应使用到旧设备迁移到新的 Ed25519 身份为止，然后在 Relay 配置中关闭。",
      "Public Relay trust boundary": "公共 Relay 信任边界", "This instance isolates users from each other, not users from the operator. An operator controls the server software and can modify it to observe or alter MCP traffic. Do not promise end-to-end privacy; sensitive users should self-host a private Relay.": "此实例只隔离用户之间的访问，不能隔离用户与运营者。运营者控制服务器软件，可以修改它来观察或修改 MCP 流量。不要承诺端到端隐私；敏感用户应自建私有 Relay。",
      "This mode is fixed by the Relay configuration. Change the configured instance mode and restart to alter it.": "此模式由 Relay 配置固定。要更改它，请修改实例模式配置并重启。",
      "Registration is fixed closed by the Relay configuration. Remove the configuration override and restart to change it.": "注册由 Relay 配置固定为关闭。移除配置覆盖并重启后才能更改。", "Fixed by configuration": "由配置固定",
      "online agents": "在线 Agent", "registered devices": "已注册设备", "retired identities": "已废弃身份", "users": "用户", "OAuth clients": "OAuth 客户端", "sessions": "会话",
      "Security controls": "安全控制", "Registration:": "注册：", "DCR:": "DCR：", "MCP:": "MCP：", "Agent:": "Agent：", "Kill switch:": "停止开关：", "enabled": "已启用", "disabled": "已停用", "ACTIVE": "已开启",
      "registration": "注册", "Release kill switch": "释放停止开关", "Emergency disable now": "立即紧急停用", "Invites": "邀请", "Single-use invites allow registration while open self-registration is disabled. Invite plaintext is shown once; only a one-way hash is persisted.": "关闭公开自助注册时，单次邀请仍可允许注册。邀请明文只显示一次，持久化的只有单向哈希。",
      "Create 24-hour invite": "创建 24 小时邀请", "Handle": "句柄", "Uses": "剩余次数", "Created by": "创建者", "No active invites.": "没有活跃邀请。",
      "Connect your first workstation": "连接你的第一台工作站", "No device is registered yet. Start with the read-only profile; nothing is started automatically.": "还没有注册设备。请从只读 profile 开始；任何服务都不会自动启动。",
      "On the workstation": "在工作站上", "Connect the immutable device ID": "连接不可变设备 ID", "Review unattended mode separately": "单独审阅无人值守模式",
      "Run": "运行", "Devices": "设备", "Display name": "显示名称", "Immutable ID / route": "不可变 ID / 路由", "Owner": "所有者", "Connection": "连接", "No devices have been claimed.": "还没有设备被认领。",
      "Users": "用户", "Create user": "创建用户", "Username": "用户名", "Role / state": "角色 / 状态", "Created / last login": "创建时间 / 最后登录", "admin": "管理员", "active": "活跃", "never": "从未", "device(s)": "台设备", "Logout all": "全部退出", "Rotate password": "轮换密码", "Delete": "删除",
      "Browser sessions ·": "浏览器会话 ·", "Session handles are one-way identifiers; browser cookie values are never displayed.": "会话句柄是单向标识符；浏览器 Cookie 值永远不会显示。", "Log out": "退出", "No active browser sessions.": "没有活跃的浏览器会话。",
      "OAuth clients and token metadata ·": "OAuth 客户端和令牌元数据 ·", "Name / redirects": "名称 / 重定向地址", "No approved clients.": "没有已批准的客户端。", "active token records (metadata only; bearer values are never displayed).": "条活跃令牌记录（只有元数据，绝不显示 bearer 值）。", "Kind": "类型", "No active tokens.": "没有活跃令牌。", "Revoke client": "撤销客户端",
      "Recent security events ·": "最近的安全事件 ·", "Time": "时间", "Event": "事件", "User / device": "用户 / 设备", "Result": "结果", "success": "成功", "failure": "失败", "No events recorded.": "没有记录的事件。",
      "Client name:": "客户端名称：", "Client ID:": "客户端 ID：", "Callback:": "回调地址：", "Scope:": "Scope：", "Public Relay operator is inside the trust boundary": "公共 Relay 运营者位于信任边界内",
      "This Relay can observe or modify MCP requests and results, and its operator can run modified server code. User-to-user isolation does not protect you from the operator. Do not use any public instance for secrets or high-trust computer access; self-host a private Relay instead.": "此 Relay 可以观察或修改 MCP 请求和结果，运营者也可以运行修改后的服务器代码。用户之间的隔离不能保护你免受运营者影响。不要将任何公共实例用于密钥或高信任电脑访问；请改为自建私有 Relay。",
      "Unverified dynamic OAuth client": "未验证的动态 OAuth 客户端", "The client name above is self-asserted. Only authorize if the callback origin matches the application you intended to connect.": "上面的客户端名称由客户端自行声明。只有在回调来源与目标应用一致时才授权。", "Verified device identity": "已验证的设备身份", "This Agent proved possession of the Ed25519 private key for device": "此 Agent 已证明持有设备的 Ed25519 私钥",
      "The Relay requires a request-bound signed proof for authorization and a fresh signed proof on every Agent connection.": "Relay 要求授权时提供绑定请求的签名证明，并要求 Agent 每次连接都提供新的签名证明。", "Legacy unbound Agent": "旧版未绑定 Agent", "This device has no verified cryptographic identity. OAuth still enforces account/resource ownership, but a stolen Agent bearer could impersonate this legacy device until it is migrated.": "此设备没有经过验证的加密身份。OAuth 仍会强制执行账户/资源所有权，但被盗的 Agent bearer 可能冒充此旧版设备，直到完成迁移。",
      "Open registration is disabled. A single-use invite from this instance operator is required.": "公开注册已关闭，需要此实例运营者提供的单次邀请。", "Invite code": "邀请代码", "Password (12+ characters)": "密码（至少 12 个字符）", "Register and authorize": "注册并授权",
      "This invite can be used once and expires at": "此邀请只能使用一次，过期时间为", "Shown once.": "只显示一次。", "The Relay stores only a one-way hash of this code. Copy it now.": "Relay 只保存此代码的单向哈希，请现在复制。",
      "Account": "账户", "Password": "密码", "Title": "标题", "Set up Chat with CLI": "设置 Chat with CLI"
    };
    // A few pages still share older server-rendered copy. Reuse the same
    // audited dictionary for data attributes on those pages as well.
    document.querySelectorAll("[data-i18n]").forEach((element) => {
      const key = element.dataset.i18n;
      if (!dictionary[key] && legacy[key]) element.textContent = language === "zh-CN" ? legacy[key] : (element.dataset.i18nDefault || element.textContent);
    });
    const legacyAttributes = {
      "Username": "用户名", "Password": "密码", "current password": "当前密码", "new password": "新密码",
      "new name": "新名称", "new display name": "新的显示名称", "password to enable": "启用所需密码",
      "temporary password": "临时密码", "REVOKE": "输入 REVOKE", "DELETE": "输入 DELETE", "type RELEASE": "输入 RELEASE",
      "Invite code": "邀请代码", "Password (12+ characters)": "密码（至少 12 个字符）"
    };
    if (legacy[legacyPageTitle]) document.title = language === "zh-CN" ? legacy[legacyPageTitle] : legacyPageTitle;
    if (language === "zh-CN" || language === "en-US") {
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      const nodes = [];
      while (walker.nextNode()) nodes.push(walker.currentNode);
      nodes.forEach((node) => {
        const parent = node.parentElement;
        if (!parent || ["CODE", "PRE", "SCRIPT", "STYLE", "TEXTAREA"].includes(parent.tagName) || parent.closest("[data-i18n]")) return;
        if (!legacyOriginals.has(node)) legacyOriginals.set(node, node.nodeValue);
        const original = legacyOriginals.get(node);
        const trimmed = original.trim();
        if (!legacy[trimmed]) return;
        const replacement = language === "zh-CN" ? legacy[trimmed] : trimmed;
        const start = original.indexOf(trimmed);
        node.nodeValue = original.slice(0, start) + replacement + original.slice(start + trimmed.length);
      });
      document.querySelectorAll("input[placeholder], textarea[placeholder], select[title], input[title], textarea[title]").forEach((element) => {
        if (element.hasAttribute("data-i18n-placeholder") || element.hasAttribute("data-i18n-title")) return;
        if (!legacyAttributeOriginals.has(element)) legacyAttributeOriginals.set(element, {placeholder: element.getAttribute("placeholder"), title: element.getAttribute("title")});
        const original = legacyAttributeOriginals.get(element);
        if (original.placeholder !== null) element.setAttribute("placeholder", language === "zh-CN" && legacyAttributes[original.placeholder] ? legacyAttributes[original.placeholder] : original.placeholder);
        if (original.title !== null) element.setAttribute("title", language === "zh-CN" && legacyAttributes[original.title] ? legacyAttributes[original.title] : original.title);
      });
    }
    const pageLocale = root.dataset.locale || "auto";
    const selectedLocale = pageLocale === "zh-CN" || pageLocale === "en-US" ? pageLocale : stored(localeKey, pageLocale);
    document.querySelectorAll("[data-language-menu-toggle]").forEach((button) => {
      button.setAttribute("aria-label", language === "zh-CN" ? "语言" : "Language");
      button.title = language === "zh-CN" ? "语言" : "Language";
    });
    document.querySelectorAll("[data-language-option]").forEach((option) => {
      const selected = option.dataset.languageOption === selectedLocale;
      option.setAttribute("aria-checked", selected ? "true" : "false");
      option.setAttribute("aria-selected", selected ? "true" : "false");
    });
    document.querySelectorAll("[data-theme-toggle] .sr-only").forEach((label) => { label.textContent = language === "zh-CN" ? "主题" : "Theme"; });
    document.querySelectorAll("[data-account-entry]").forEach((entry) => {
      const admin = entry.dataset.accountEntry === "admin";
      const label = admin ? (language === "zh-CN" ? "管理员控制台" : "Admin console") : (language === "zh-CN" ? "我的账户" : "My account");
      entry.setAttribute("aria-label", label);
      entry.title = label;
    });
  }
  const themeIcons = {
    auto: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="13" rx="2"></rect><path d="M8 21h8M12 17v4"></path></svg>',
    light: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"></path></svg>',
    dark: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 15.5A8 8 0 1 1 8.5 4 6.5 6.5 0 0 0 20 15.5z"></path></svg>'
  };
  function applyTheme(value) {
    if (value === "light" || value === "dark") root.dataset.theme = value;
    else delete root.dataset.theme;
    document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
      const current = stored(themeKey, "auto");
      const next = current === "auto" ? "dark" : current === "dark" ? "light" : "auto";
      button.dataset.nextTheme = next;
      const language = locale();
      const themeNames = language === "zh-CN" ? { auto: "自动", light: "浅色", dark: "深色" } : { auto: "automatic", light: "light", dark: "dark" };
      button.setAttribute("aria-label", (language === "zh-CN" ? "主题：" : "Theme: ") + themeNames[current] + (language === "zh-CN" ? "。切换到" : ". Switch to ") + themeNames[next] + (language === "zh-CN" ? "。" : "."));
      const icon = button.querySelector(".theme-icon");
      if (icon) icon.innerHTML = themeIcons[current] || themeIcons.auto;
    });
  }
  function makeControls(host) {
    host.innerHTML = '<div class="language-picker"><button class="icon-button language-button" type="button" data-language-menu-toggle aria-expanded="false" aria-haspopup="menu" aria-label="Language"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"></circle><path d="M3 12h18M12 3c2.5 2.5 3.5 5.5 3.5 9s-1 6.5-3.5 9c-2.5-2.5-3.5-5.5-3.5-9S9.5 5.5 12 3z"></path></svg><span class="sr-only" data-i18n="Language">Language</span></button><div class="language-menu" data-language-menu hidden role="menu"><button type="button" data-language-option="auto" role="menuitemradio" data-i18n="Automatic">Auto</button><button type="button" data-language-option="en-US" role="menuitemradio" data-i18n="English">English</button><button type="button" data-language-option="zh-CN" role="menuitemradio" data-i18n="中文">中文</button></div></div><button class="icon-button" type="button" data-theme-toggle><span class="theme-icon" aria-hidden="true"></span><span class="sr-only">Theme</span></button>';
  }
  function bindControls() {
    document.querySelectorAll("[data-language-menu-toggle]").forEach((button) => {
      if (button.dataset.cwcLanguageBound) return;
      button.dataset.cwcLanguageBound = "true";
      button.addEventListener("click", (event) => {
        event.stopPropagation();
        const menu = event.currentTarget.parentElement?.querySelector("[data-language-menu]");
        if (!menu) return;
        const open = menu.hidden;
        closeLanguageMenus();
        menu.hidden = !open;
        event.currentTarget.setAttribute("aria-expanded", open ? "true" : "false");
      });
    });
    document.querySelectorAll("[data-language-option]").forEach((option) => {
      if (option.dataset.cwcLanguageBound) return;
      option.dataset.cwcLanguageBound = "true";
      option.addEventListener("click", (event) => {
        const value = event.currentTarget.dataset.languageOption || "auto";
        root.dataset.locale = value;
        persist(localeKey, value);
        closeLanguageMenus();
        translate();
        applyTheme(stored(themeKey, "auto"));
      });
    });
    document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
      if (button.dataset.cwcBound) return;
      button.dataset.cwcBound = "true";
      button.addEventListener("click", (event) => { const next = event.currentTarget.dataset.nextTheme || "dark"; persist(themeKey, next); applyTheme(next); });
    });
    if (!root.dataset.cwcLanguageDocumentBound) {
      root.dataset.cwcLanguageDocumentBound = "true";
      document.addEventListener("click", (event) => { if (!event.target.closest(".language-picker")) closeLanguageMenus(); });
    }
  }
  function closeLanguageMenus() {
    document.querySelectorAll("[data-language-menu]").forEach((menu) => {
      menu.hidden = true;
      menu.parentElement?.querySelector("[data-language-menu-toggle]")?.setAttribute("aria-expanded", "false");
    });
  }

  function makeAccountEntry(admin) {
    const entry = document.createElement("a");
    entry.className = admin ? "admin-avatar" : "account-avatar";
    entry.href = admin ? "/admin" : "/account";
    entry.dataset.accountEntry = admin ? "admin" : "account";
    entry.setAttribute("aria-label", admin ? "Admin console" : "My account");
    entry.innerHTML = admin
      ? '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m12 3 8 4v5c0 4.8-3.3 7.8-8 9-4.7-1.2-8-4.2-8-9V7l8-4z"></path><path d="m9 12 2 2 4-4"></path></svg><span class="sr-only" data-i18n="Admin console">Admin console</span>'
      : '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="3.2"></circle><path d="M5 20c.8-3.4 3.1-5.2 7-5.2s6.2 1.8 7 5.2"></path></svg><span class="sr-only" data-i18n="My account">My account</span>';
    return entry;
  }
  function ensureAccountNavigation() {
    if (document.querySelector(".admin-page")) root.dataset.admin = "true";
    if (document.querySelector('form[action="/account/action"]')) {
      document.querySelector(".page")?.classList.add("account-page");
    }
    const navs = Array.from(document.querySelectorAll(".nav"));
    document.querySelectorAll(".topbar").forEach((topbar) => {
      if (topbar.querySelector(".nav")) return;
      const nav = document.createElement("nav");
      nav.className = "nav";
      const controls = topbar.querySelector(":scope > .ui-controls");
      if (controls) nav.appendChild(controls);
      topbar.appendChild(nav);
      navs.push(nav);
    });
    navs.forEach((nav) => {
      let account = nav.querySelector('[data-account-entry="account"]');
      if (!account) {
        const existing = nav.querySelector('a[href="/account"]');
        account = makeAccountEntry(false);
        if (existing) existing.replaceWith(account);
        else nav.appendChild(account);
      }
      if (root.dataset.admin === "true" && !nav.closest(".admin-page") && !nav.querySelector('[data-account-entry="admin"]')) {
        nav.appendChild(makeAccountEntry(true));
      }
    });
  }
  function ensureAccountActions() {
    const header = document.querySelector(".account-page .page-header");
    if (!header || header.dataset.accountActionsBound) return;
    header.dataset.accountActionsBound = "true";
    const copy = document.createElement("div");
    copy.className = "page-header-copy";
    while (header.firstChild) copy.appendChild(header.firstChild);
    const actions = document.createElement("div");
    actions.className = "page-header-actions";
    const connect = document.createElement("a");
    connect.className = "button primary";
    connect.href = "/connect";
    connect.dataset.accountConnect = "true";
    connect.dataset.i18n = "Connect a workstation";
    connect.textContent = "Connect a workstation";
    actions.appendChild(connect);
    header.classList.add("page-header-row");
    header.append(copy, actions);
  }
  function dialogSpec(action, form) {
    if (action === "rename-device") return {title: "Rename device", help: "Choose a display name for this workstation."};
    if (action === "disable-device" && form.querySelector('input[name="password"]')) return {title: "Enable device", help: "Enter your current account password to re-enable this workstation."};
    if (action === "revoke-device") return {title: "Revoke device", help: "Type REVOKE to permanently revoke this device."};
    if (action === "change-password") return {title: "Change password", help: "Changing your password revokes all OAuth credentials and browser sessions for this account. Reconnect devices and apps afterward."};
    if (action === "create-user") return {title: "Create user", help: "Create a tenant account with a temporary password."};
    if (action === "rotate-password") return {title: "Rotate password", help: "Set a new password for this user. Existing credentials will be revoked."};
    if (action === "delete-user") return {title: "Delete user", help: "Type DELETE to permanently delete this user."};
    if (action === "set-kill-switch" && form.querySelector('input[name="confirm"]')) return {title: "Release kill switch", help: "Type RELEASE to release the emergency stop."};
    if (action === "revoke-client") return {title: "Revoke client", help: "Type REVOKE to confirm this revocation."};
    if (action === "revoke-token") return {title: "Revoke token", help: "Type REVOKE to confirm this revocation."};
    if (action === "redeem-activation-code") return {title: "Redeem activation code", help: "Add the quota attached to a one-time support code."};
    if (action === "grant-quota") return {title: "Add quota", help: "Add Relay traffic quota to this account."};
    if (action === "create-activation-code") return {title: "Create activation code", help: "Create a single-use code for the selected quota."};
    if (action === "set-monetization") return {title: "Edit advertising settings", help: "Advertising is optional. AdMob rewards require a server-side verifier secret."};
    return null;
  }
  function dialogFieldLabel(action, input) {
    if (input.name === "target" && action === "create-user") return "Username";
    if (input.name === "value" && action === "rename-device") return "New display name";
    if (input.name === "value" && action === "disable-device") return "Current password";
    if (input.name === "value" && action === "create-user") return "Temporary password";
    if (input.name === "value" && action === "rotate-password") return "New password";
    if (input.name === "value" && action === "change-password") return "New password";
    if (input.name === "value" && action === "redeem-activation-code") return "Activation code";
    if (input.name === "value" && action === "grant-quota") return "Quota to add in bytes";
    if (input.name === "value" && action === "create-activation-code") return "Quota in bytes";
    if (input.name === "default_quota_bytes") return "Default quota in bytes";
    if (input.name === "adsense_client_id") return "AdSense client ID";
    if (input.name === "adsense_slot") return "AdSense slot ID";
    if (input.name === "admob_app_id") return "AdMob app ID";
    if (input.name === "admob_reward_unit_id") return "AdMob rewarded unit ID";
    if (input.name === "usage_unlock_endpoint") return "Reward endpoint (HTTPS)";
    if (input.name === "password") return "Current password";
    if (input.name === "confirm") return "Confirmation";
    return input.name;
  }
  function dialogElement(tag, className, text, key) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (key) element.dataset.i18n = key;
    element.textContent = text || key || "";
    return element;
  }
  function normalizeActionForms() {
    let sequence = 0;
    document.querySelectorAll('form[action="/account/action"], form[action="/admin/action"], form[action="/admin/activation-code"], form[action="/admin/monetization"]').forEach((form) => {
      if (form.dataset.cwcDialogized) return;
      const action = form.querySelector('input[name="action"]')?.value || "";
      const spec = dialogSpec(action, form);
      const visibleInputs = Array.from(form.querySelectorAll("input")).filter((input) => input.type !== "hidden" && !input.disabled);
      const submit = form.querySelector('button[type="submit"], button:not([type])');
      if (!spec || visibleInputs.length === 0 || !submit) return;
      form.dataset.cwcDialogized = "true";
      const dialog = document.createElement("dialog");
      const dialogID = "cwc-action-dialog-" + (++sequence);
      const titleID = dialogID + "-title";
      const helpID = dialogID + "-help";
      dialog.id = dialogID;
      dialog.className = "action-dialog";
      if (action === "set-monetization") dialog.dataset.preserveValues = "true";
      dialog.setAttribute("aria-labelledby", titleID);
      dialog.setAttribute("aria-describedby", helpID);
      const heading = document.createElement("div");
      heading.className = "dialog-heading";
      heading.appendChild(dialogElement("span", "eyebrow", "Confirm action", "Confirm action"));
      const title = dialogElement("h2", "", spec.title, spec.title);
      title.id = titleID;
      const help = dialogElement("p", "", spec.help, spec.help);
      help.id = helpID;
      heading.append(title, help);
      const fields = document.createElement("div");
      fields.className = "dialog-fields";
      visibleInputs.forEach((input) => {
        const label = document.createElement("label");
        label.className = "dialog-field";
        label.appendChild(dialogElement("span", "", dialogFieldLabel(action, input), dialogFieldLabel(action, input)));
        input.remove();
        label.appendChild(input);
        fields.appendChild(label);
      });
      submit.remove();
      submit.classList.add("primary");
      const cancel = document.createElement("button");
      cancel.type = "button";
      cancel.className = "text";
      cancel.dataset.dialogCancel = "true";
      cancel.dataset.i18n = "Cancel";
      cancel.textContent = "Cancel";
      const actions = document.createElement("div");
      actions.className = "dialog-actions";
      actions.append(cancel, submit);
      form.className = "dialog-form";
      form.insertBefore(heading, form.firstChild);
      form.insertBefore(fields, form.firstChild);
      form.appendChild(actions);
      const trigger = document.createElement("button");
      trigger.type = "button";
      const triggerClasses = Array.from(submit.classList).filter((name) => name !== "primary");
      if (!triggerClasses.some((name) => ["danger", "tonal", "outlined", "text"].includes(name))) triggerClasses.push("primary");
      triggerClasses.push("dialog-trigger");
      trigger.className = triggerClasses.join(" ");
      trigger.dataset.dialogTrigger = "true";
      trigger.dataset.dialogTarget = dialogID;
      trigger.innerHTML = submit.innerHTML;
      if (submit.dataset.i18n && !submit.querySelector("[data-i18n]")) trigger.dataset.i18n = submit.dataset.i18n;
      form.replaceWith(trigger);
      dialog.appendChild(form);
      document.body.appendChild(dialog);
    });
  }
  function bindDialogs() {
    document.querySelectorAll("[data-dialog-trigger]").forEach((trigger) => {
      if (trigger.dataset.cwcDialogBound) return;
      trigger.dataset.cwcDialogBound = "true";
      trigger.addEventListener("click", () => {
        const dialog = document.getElementById(trigger.dataset.dialogTarget || "");
        if (!dialog) return;
        if (typeof dialog.showModal === "function") dialog.showModal();
        else dialog.setAttribute("open", "");
        const first = dialog.querySelector('input:not([type="hidden"]):not([disabled])');
        (first || dialog.querySelector("button[type=submit], button:not([type])"))?.focus({preventScroll: true});
      });
    });
    document.querySelectorAll("[data-dialog-cancel]").forEach((button) => {
      if (button.dataset.cwcDialogBound) return;
      button.dataset.cwcDialogBound = "true";
      button.addEventListener("click", () => button.closest("dialog")?.close());
    });
    document.querySelectorAll("dialog.action-dialog").forEach((dialog) => {
      if (dialog.dataset.cwcDialogBound) return;
      dialog.dataset.cwcDialogBound = "true";
      dialog.addEventListener("click", (event) => { if (event.target === dialog) dialog.close(); });
      dialog.addEventListener("close", () => { if (dialog.dataset.preserveValues !== "true") dialog.querySelectorAll('input:not([type="hidden"])').forEach((input) => { input.value = ""; }); });
    });
  }

  function copyElementAttributes(source, target) {
    Array.from(source.attributes).forEach((attribute) => {
      if (!["data-cwc-bound", "data-cwc-dialog-bound", "data-cwc-language-bound"].includes(attribute.name)) target.setAttribute(attribute.name, attribute.value);
    });
  }
  function materialButtonTag(source) {
    if (source.classList.contains("icon-button")) return "md-icon-button";
    if (source.classList.contains("primary") || source.classList.contains("danger")) return "md-filled-button";
    if (source.classList.contains("tonal")) return "md-filled-tonal-button";
    if (source.classList.contains("outlined")) return "md-outlined-button";
    return "md-text-button";
  }
  function upgradeMaterialButtons() {
    document.querySelectorAll("a.button, button").forEach((source) => {
      if (source.closest("md-filled-button, md-filled-tonal-button, md-outlined-button, md-text-button, md-icon-button")) return;
      // Native form controls own submission semantics. Replacing submitters with
      // form-associated custom elements can change which name/value pair is sent.
      if (source.closest("form")) return;
      if (source.tagName === "A" && !(source.getAttribute("href") || "").startsWith("/")) return;
      const target = document.createElement(materialButtonTag(source));
      copyElementAttributes(source, target);
      target.innerHTML = source.innerHTML;
      source.replaceWith(target);
    });
  }
  function upgradeMaterialSelects() {
    document.querySelectorAll("select").forEach((source) => {
      if (source.closest("md-outlined-select")) return;
      // Keep all form controls native. CSS provides the visual treatment while
      // the browser remains the sole owner of successful-control semantics.
      if (source.closest("form")) return;
      const target = document.createElement("md-outlined-select");
      copyElementAttributes(source, target);
      const label = source.getAttribute("aria-label") || source.previousElementSibling?.textContent.trim() || "";
      if (label) target.setAttribute("label", label);
      const selectedValue = source.value;
      Array.from(source.options).forEach((option) => {
        const item = document.createElement("md-select-option");
        if (option.value) item.setAttribute("value", option.value);
        if (option.disabled) item.setAttribute("disabled", "");
        if (option.value === selectedValue || option.selected) item.setAttribute("selected", "");
        const headline = document.createElement("span");
        headline.slot = "headline";
        headline.textContent = option.textContent;
        if (option.dataset.i18n) headline.dataset.i18n = option.dataset.i18n;
        item.appendChild(headline);
        target.appendChild(item);
      });
      source.replaceWith(target);
    });
  }
  function upgradeMaterialComponents() {
    if (!customElements.get("md-filled-button")) return;
    upgradeMaterialSelects();
    upgradeMaterialButtons();
    ensureAccountNavigation();
    ensureAccountActions();
    bindControls();
    bindDialogs();
    bindCopyButtons();
    translate();
    applyTheme(stored(themeKey, "auto"));
  }
  function loadMaterialWeb() {
    if (customElements.get("md-filled-button")) { upgradeMaterialComponents(); return; }
    const script = document.createElement("script");
    script.src = "/assets/material-web.js?v=1";
    script.onload = upgradeMaterialComponents;
    document.head.appendChild(script);
  }
  function copyText(button) {
    const target = document.getElementById(button.dataset.copyTarget);
    if (!target) return;
    const value = target.textContent.trim();
    const done = () => { const original = button.textContent; button.textContent = locale() === "zh-CN" ? "已复制" : "Copied"; setTimeout(() => { button.textContent = original; }, 1400); };
    const fallback = () => { const area = document.createElement("textarea"); area.className = "copy-fallback"; area.value = value; document.body.appendChild(area); area.select(); try { document.execCommand("copy"); done(); } catch (_) {} area.remove(); };
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(value).then(done).catch(fallback);
    else fallback();
  }
  function loadAdSense() {
    const slot = document.querySelector("[data-adsense-client]");
    if (!slot || !slot.dataset.adsenseClient) return;
    const fillSlots = () => document.querySelectorAll(".adsense-unit:not([data-cwc-adsense-filled])").forEach((unit) => {
      unit.dataset.cwcAdsenseFilled = "true";
      try { (window.adsbygoogle = window.adsbygoogle || []).push({}); } catch (_) {}
    });
    const existing = document.querySelector("script[data-cwc-adsense]");
    if (existing) { existing.addEventListener("load", fillSlots, {once: true}); fillSlots(); return; }
    const script = document.createElement("script");
    script.async = true; script.crossOrigin = "anonymous"; script.dataset.cwcAdsense = "true";
    script.src = "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=" + encodeURIComponent(slot.dataset.adsenseClient);
    script.onload = fillSlots;
    document.head.appendChild(script);
  }
  function createRipple(element, event) {
    if (element.disabled || element.getAttribute("aria-disabled") === "true") return;
    const rect = element.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height) * 1.2;
    const ripple = document.createElement("span");
    ripple.className = "ripple";
    ripple.style.width = size + "px";
    ripple.style.height = size + "px";
    ripple.style.left = ((event.clientX || rect.left + rect.width / 2) - rect.left - size / 2) + "px";
    ripple.style.top = ((event.clientY || rect.top + rect.height / 2) - rect.top - size / 2) + "px";
    element.appendChild(ripple);
    ripple.addEventListener("animationend", () => ripple.remove(), {once: true});
  }
  document.querySelectorAll("[data-ui-controls]").forEach(makeControls);
  ensureAccountNavigation();
  ensureAccountActions();
  normalizeActionForms();
  bindControls();
  applyTheme(stored(themeKey, "auto"));
  translate();
  bindDialogs();
  function bindCopyButtons() {
    document.querySelectorAll("[data-copy-target]").forEach((button) => {
      if (button.dataset.cwcBound) return;
      button.dataset.cwcBound = "true";
      button.addEventListener("click", () => copyText(button));
    });
  }
  bindCopyButtons();
  document.querySelectorAll(".button, button, .nav a").forEach((element) => element.addEventListener("pointerdown", (event) => createRipple(element, event)));
  document.querySelectorAll("form").forEach((form) => form.addEventListener("submit", (event) => {
    if (form.dataset.allowDoubleSubmit) return;
    if (form.dataset.cwcSubmitting === "true") {
      event.preventDefault();
      return;
    }
    form.dataset.cwcSubmitting = "true";
    // Never disable the submitter here: disabled successful controls are
    // omitted from form submission, including their security-sensitive name/value.
    const submit = event.submitter;
    if (submit) {
      submit.setAttribute("aria-busy", "true");
      submit.setAttribute("aria-disabled", "true");
    }
  }));
  loadAdSense();
  loadMaterialWeb();
})();
`

func uiLocale(r *http.Request) string {
	if r == nil {
		return "auto"
	}
	selected := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("lang")))
	switch selected {
	case "zh", "zh-cn", "zh-hans", "zh-tw", "中文":
		return "zh-CN"
	case "en", "en-us", "英语":
		return "en-US"
	default:
		return "auto"
	}
}

func (s *Server) handleMonetizationConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	adsenseClientID := strings.TrimSpace(s.cfg.AdSenseClientID)
	adsenseSlot := strings.TrimSpace(s.cfg.AdSenseSlot)
	admobAppID := strings.TrimSpace(s.cfg.AdMobAppID)
	admobRewardUnitID := strings.TrimSpace(s.cfg.AdMobRewardUnitID)
	usageUnlockEnabled := s.rewardedUsageEnabledLocked() && strings.TrimSpace(s.cfg.UsageUnlockEndpoint) != ""
	usageUnlockEndpoint := strings.TrimSpace(s.cfg.UsageUnlockEndpoint)
	usageMeteringEnabled := s.usageMeteringEnabled
	usageDefaultQuotaBytes := s.usageDefaultQuotaBytes
	rewardVerifierConfigured := strings.TrimSpace(s.cfg.AdMobVerifierSecret) != ""
	s.mu.Unlock()
	admobEnabled := admobAppID != "" && admobRewardUnitID != ""
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"adsense":      map[string]any{"enabled": adsenseClientID != "" && adsenseSlot != "", "client_id": adsenseClientID, "slot": adsenseSlot},
		"admob":        map[string]any{"enabled": admobEnabled, "app_id": admobAppID, "reward_unit_id": admobRewardUnitID, "reward_ready": usageUnlockEnabled && admobEnabled && rewardVerifierConfigured},
		"usage":        map[string]any{"enabled": usageMeteringEnabled, "default_quota_bytes": usageDefaultQuotaBytes, "accounting": "authenticated MCP and Agent request/response payload bytes"},
		"usage_unlock": map[string]any{"enabled": usageUnlockEnabled, "endpoint": usageUnlockEndpoint, "redeem_endpoint": s.absolute("/account/admob/redeem"), "verification": "server-side-provider-verification-required", "verifier_configured": rewardVerifierConfigured},
	})
}

func (s *Server) handleUIAsset(w http.ResponseWriter, r *http.Request) {
	var content, contentType string
	switch r.URL.Path {
	case "/assets/app.css":
		content, contentType = appCSS, "text/css; charset=utf-8"
	case "/assets/app.js":
		content, contentType = appJS, "application/javascript; charset=utf-8"
	case "/assets/material-web.js":
		content, contentType = string(materialWebJS), "application/javascript; charset=utf-8"
	default:
		http.NotFound(w, r)
		return
	}
	sum := sha256.Sum256([]byte(content))
	etag := fmt.Sprintf("\"%x\"", sum)
	w.Header().Set("Content-Type", contentType)
	// Always revalidate UI assets. The ETag keeps unchanged reloads cheap while
	// preventing a previous deployment's CSS/JS from surviving a Relay update.
	w.Header().Set("Cache-Control", "public, no-cache")
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write([]byte(content))
}

func uiCSPNonce(r *http.Request) string {
	if r == nil {
		return ""
	}
	nonce, _ := r.Context().Value(uiCSPNonceContextKey{}).(string)
	return nonce
}

func injectUINonce(html string, r *http.Request) string {
	nonce := uiCSPNonce(r)
	if nonce == "" || strings.Contains(html, `name="cwc-style-nonce"`) {
		return html
	}
	meta := `<meta name="cwc-style-nonce" content="` + template.HTMLEscapeString(nonce) + `">`
	return strings.Replace(html, "<head>", "<head>"+meta, 1)
}

func executeTemplateWithUINonce(w http.ResponseWriter, r *http.Request, tmpl *template.Template, data any) error {
	var rendered bytes.Buffer
	if err := tmpl.Execute(&rendered, data); err != nil {
		return err
	}
	_, err := w.Write([]byte(injectUINonce(rendered.String(), r)))
	return err
}

// executeSecurityTemplate keeps authentication and authorization pages native.
// It may share CSS, but deliberately injects no JavaScript: browser-native form
// submission semantics are part of the security protocol on these pages.
func executeSecurityTemplate(w http.ResponseWriter, r *http.Request, tmpl *template.Template, data any) error {
	var rendered bytes.Buffer
	if err := tmpl.Execute(&rendered, data); err != nil {
		return err
	}
	html := rendered.String()
	locale := uiLocale(r)
	if strings.Contains(html, "<html lang=") {
		html = strings.Replace(html, "<html", `<html data-locale="`+locale+`"`, 1)
	} else {
		html = strings.Replace(html, "<html", `<html lang="en" data-locale="`+locale+`"`, 1)
	}
	html = strings.Replace(html, "<head>", `<head><link rel="stylesheet" href="/assets/app.css?v=4">`, 1)
	html = injectUINonce(html, r)
	_, err := w.Write([]byte(html))
	return err
}

// executeUITemplate upgrades the older, page-local templates during the
// rolling UI migration. It adds the same local stylesheet, controls, locale
// hint, and progressive-enhancement script. Security-sensitive forms must use
// executeSecurityTemplate instead.
func executeUITemplate(w http.ResponseWriter, r *http.Request, tmpl *template.Template, data any) error {
	var rendered bytes.Buffer
	if err := tmpl.Execute(&rendered, data); err != nil {
		return err
	}
	locale := uiLocale(r)
	html := rendered.String()
	for {
		start := strings.Index(html, "<style>")
		if start < 0 {
			break
		}
		end := strings.Index(html[start:], "</style>")
		if end < 0 {
			html = html[:start]
			break
		}
		html = html[:start] + html[start+end+len("</style>"):]
	}
	if strings.Contains(html, "<html lang=") {
		html = strings.Replace(html, "<html", `<html data-locale="`+locale+`"`, 1)
	} else {
		html = strings.Replace(html, "<html", `<html lang="en" data-locale="`+locale+`"`, 1)
	}
	html = strings.Replace(html, "<head>", `<head><link rel="stylesheet" href="/assets/app.css?v=4">`, 1)
	if !strings.Contains(html, `data-ui-controls`) {
		html = strings.Replace(html, "<body>", `<body><div class="ui-controls-floating" data-ui-controls></div>`, 1)
	}
	html = strings.Replace(html, "</body>", `<script src="/assets/app.js?v=4" defer></script></body>`, 1)
	html = injectUINonce(html, r)
	_, err := w.Write([]byte(html))
	return err
}
