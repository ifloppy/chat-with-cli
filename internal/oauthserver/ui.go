package oauthserver

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
)

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
.theme-icon { font-size: 17px; line-height: 1; }

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
  .feature-grid, .grid, .stats, .support-card { grid-template-columns: 1fr; }
  .stats { gap: 8px; }
  .card, section, details, form.surface, .meta { padding: 16px; }
  .copy-row { display: block; }
  .copy-button { margin-top: 8px; }
  .nav a { padding-left: 8px; padding-right: 8px; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { scroll-behavior: auto !important; transition-duration: .01ms !important; animation-duration: .01ms !important; }
}
`

const appJS = `
(() => {
  "use strict";
  const root = document.documentElement;
  const themeKey = "cwc-theme";
  const localeKey = "cwc-locale";
  const translations = {
    "zh-CN": {
      "Home": "首页", "Docs": "文档", "Documentation": "文档", "GitHub": "GitHub",
      "Connect": "连接", "Connect a workstation": "连接工作站", "Connect my computer": "连接我的电脑",
      "Manage my account": "管理我的账户", "My account": "我的账户", "Operator admin": "管理员控制台",
      "Open admin console": "打开管理控制台", "Finish first-run setup": "完成首次设置",
      "Back to home": "返回首页", "Sign in": "登录", "Sign out": "退出登录", "Re-authenticate": "重新认证",
      "Authorize": "授权", "Deny": "拒绝", "Create account": "创建账户", "Register and authorize": "注册并授权",
      "First-run setup": "首次设置", "Create owner and finish setup": "创建所有者并完成设置",
      "Chat with CLI documentation": "Chat with CLI 文档", "Chat with CLI admin": "Chat with CLI 管理员",
      "My Chat with CLI": "我的 Chat with CLI", "Invite created": "邀请已创建",
      "Install": "安装", "Security": "安全", "Ready": "就绪", "Configured": "已配置",
      "Language": "语言", "Theme": "主题", "Automatic": "自动", "English": "English", "中文": "中文",
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
      "Relay": "Relay", "Security model": "安全模型", "Add a workstation": "添加工作站",
      "Setup required": "需要设置", "Relay configured": "Relay 已配置", "authorization frozen": "授权已冻结",
      "ready": "就绪", "Version": "版本", "Instance": "实例", "Status": "状态",
      "Public Relay trust boundary": "公共 Relay 信任边界", "Public Relay warning": "公共 Relay 警告",
      "Do not trust a public Relay with sensitive access": "不要将敏感权限交给公共 Relay",
      "A public Relay isolates normal users from each other, but the operator controls the server code and can observe or alter MCP traffic.": "公共 Relay 可以隔离普通用户，但运营者控制服务器代码，可能观察或修改 MCP 流量。",
      "Health endpoint": "健康检查端点", "Quick start": "快速开始", "Private Relay": "私有 Relay", "Public Relay": "公共 Relay",
      "Agent configuration": "Agent 配置", "Computer Use": "Computer Use", "Threat model": "威胁模型",
      "Reverse proxy": "反向代理", "Cloudflare": "Cloudflare", "User account": "用户账户", "Administration": "管理",
      "Troubleshooting": "故障排查", "Backup and restore": "备份与恢复", "Upgrade and rollback": "升级与回滚",
      "Self-host a private Relay with ChatGPT": "使用 ChatGPT 自建私有 Relay",
      "Get started": "开始使用", "Add a workstation in a few calm steps.": "用几个清晰步骤添加工作站。",
      "A connection you can understand.": "一条可以理解的连接。", "Advertisement": "广告",
      "outbound · scoped · observable": "主动外连 · 有范围 · 可观测",
      "MCP tools, clearly annotated": "个 MCP 工具，清晰标注", "capabilities enabled by surprise": "项意外启用的能力", "small binary to install": "个小型二进制文件",
      "1. Create a safe local Agent config": "1. 创建安全的本地 Agent 配置", "Read-only is the default profile.": "默认 profile 是只读。",
      "2. Connect interactively": "2. 交互式连接", "3. Connect your MCP client": "3. 连接 MCP 客户端",
      "No device inventory or host information is exposed on this public page.": "此公共页面不会暴露设备清单或主机信息。",
      "Keep the public Relay available": "一起保持公共 Relay 可用",
      "A companion app can verify a rewarded AdMob view and issue a short-lived, signed usage entitlement.": "伴侣应用可以验证激励式 AdMob 广告，并签发短期签名使用 entitlement。",
      "Open reward app": "打开奖励应用", "Open releases": "打开发行页", "Install documentation": "安装文档",
      "Self-hosting guide": "自托管指南", "Need a quick path?": "想快速开始？",
      "Start here when you are deploying a Relay, pairing a workstation, or connecting an MCP client.": "部署 Relay、配对工作站或连接 MCP 客户端时，可以从这里开始。",
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
      "Do not run the Agent as root. Review the roots and capabilities before enabling the unit.": "不要以 root 运行 Agent。启用 unit 前请审阅根目录和能力权限。",
      "Use the immutable device ID printed by setup/status.": "使用 setup/status 输出的不可变设备 ID。",
      "Once ChatGPT can work through this computer, it can help deploy a verified private Relay on your VPS. Keep the new Relay's owner password and setup token out of the public Relay path.": "ChatGPT 可以通过这台电脑工作后，还能协助在 VPS 上部署已验证的私有 Relay。不要让新 Relay 的所有者密码和 setup token 经过公共 Relay。",
      "First run": "首次运行", "Create the first administrator and choose how this Relay accepts users. This page permanently disappears after successful setup.": "创建第一个管理员，并选择此 Relay 如何接受用户。设置成功后，此页面会永久消失。",
      "1 · Local token": "1 · 本地 token", "2 · Owner account": "2 · 所有者账户", "3 · Add devices": "3 · 添加设备",
      "Read the protected setup-token file on the Relay host.": "读取 Relay 主机上受保护的 setup-token 文件。", "Create a strong administrator password.": "创建强管理员密码。",
      "Sign in, then pair workstations with immutable IDs.": "登录后，使用不可变 ID 配对工作站。",
      "One-time setup token": "一次性 setup token", "Owner username": "所有者用户名", "Owner password": "所有者密码", "Instance mode": "实例模式",
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
      "Open the interactive terminal hub to set up a workstation, connect it, or run diagnostics.": "打开交互式终端中心，设置工作站、连接工作站或运行诊断。"
    }
  };

  function stored(key, fallback) {
    try { return localStorage.getItem(key) || fallback; } catch (_) { return fallback; }
  }
  function persist(key, value) { try { localStorage.setItem(key, value); } catch (_) {} }
  function locale() {
    const pageLocale = root.dataset.locale || "auto";
    const selected = pageLocale === "zh-CN" || pageLocale === "en-US" ? pageLocale : stored(localeKey, pageLocale);
    if (selected === "zh-CN" || selected === "en-US") return selected;
    return (navigator.language || "").toLowerCase().startsWith("zh") ? "zh-CN" : "en-US";
  }
  const legacyOriginals = new WeakMap();
  function translate() {
    const language = locale();
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
    // Older account/admin/OAuth templates do not carry data attributes yet.
    // Translate only complete, non-code text nodes so commands, URLs, user
    // names, and security values can never be accidentally rewritten.
    const legacy = {
      "Chat with CLI account": "Chat with CLI 账户", "Chat with CLI admin": "Chat with CLI 管理员",
      "Sign in to manage devices, users, sessions, and emergency capability switches.": "登录以管理设备、用户、会话和紧急能力开关。",
      "My Chat with CLI": "我的 Chat with CLI", "Signed in as": "当前登录：", "Home": "首页", "Docs": "文档",
      "Sign out": "退出登录", "My devices": "我的设备", "Connected authorizations": "已连接的授权",
      "Browser sessions": "浏览器会话", "Change password": "修改密码", "Rename": "重命名", "Enable": "启用", "Disable": "停用",
      "Revoke permanently": "永久撤销", "Revoke my authorization": "撤销我的授权", "Sign out all other sessions": "退出其他所有会话",
      "Change password and revoke credentials": "修改密码并撤销凭据", "Authorize chat-with-cli": "授权 chat-with-cli",
      "Sign in and authorize": "登录并授权", "Invite created": "邀请已创建", "Return to admin": "返回管理控制台",
      "Back to home": "返回首页", "Re-authenticate": "重新认证", "Cancel and return to admin": "取消并返回管理控制台"
    };
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
    }
    document.querySelectorAll("[data-language-select]").forEach((select) => {
      const pageLocale = root.dataset.locale || "auto";
      select.value = pageLocale === "zh-CN" || pageLocale === "en-US" ? pageLocale : stored(localeKey, pageLocale);
      select.setAttribute("aria-label", language === "zh-CN" ? "语言" : "Language");
    });
    document.querySelectorAll("[data-theme-toggle] .sr-only").forEach((label) => { label.textContent = language === "zh-CN" ? "主题" : "Theme"; });
  }
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
      if (icon) icon.textContent = current === "dark" ? "☾" : current === "light" ? "☀" : "◐";
    });
  }
  function makeControls(host) {
    host.innerHTML = '<label class="sr-only" for="cwc-language">Language</label><select id="cwc-language" data-language-select aria-label="Language"><option value="auto">Auto</option><option value="en-US">English</option><option value="zh-CN">中文</option></select><button class="icon-button" type="button" data-theme-toggle><span class="theme-icon" aria-hidden="true">◐</span><span class="sr-only">Theme</span></button>';
    host.querySelector("select").addEventListener("change", (event) => { root.dataset.locale = event.target.value; persist(localeKey, event.target.value); translate(); });
    host.querySelector("[data-theme-toggle]").addEventListener("click", (event) => { const next = event.currentTarget.dataset.nextTheme || "dark"; persist(themeKey, next); applyTheme(next); });
  }
  function copyText(button) {
    const target = document.getElementById(button.dataset.copyTarget);
    if (!target) return;
    const value = target.textContent.trim();
    const done = () => { const original = button.textContent; button.textContent = locale() === "zh-CN" ? "已复制" : "Copied"; setTimeout(() => { button.textContent = original; }, 1400); };
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(value).then(done).catch(() => {});
    else { const area = document.createElement("textarea"); area.className = "copy-fallback"; area.value = value; document.body.appendChild(area); area.select(); try { document.execCommand("copy"); done(); } catch (_) {} area.remove(); }
  }
  function loadAdSense() {
    const slot = document.querySelector("[data-adsense-client]");
    if (!slot || !slot.dataset.adsenseClient) return;
    const script = document.createElement("script");
    script.async = true; script.crossOrigin = "anonymous"; script.dataset.cwcAdsense = "true";
    script.src = "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=" + encodeURIComponent(slot.dataset.adsenseClient);
    script.onload = () => { try { (window.adsbygoogle = window.adsbygoogle || []).push({}); } catch (_) {} };
    document.head.appendChild(script);
  }
  document.querySelectorAll("[data-ui-controls]").forEach(makeControls);
  applyTheme(stored(themeKey, "auto"));
  translate();
  document.querySelectorAll("[data-copy-target]").forEach((button) => button.addEventListener("click", () => copyText(button)));
  document.querySelectorAll("form").forEach((form) => form.addEventListener("submit", () => { const submit = form.querySelector("button[type=submit], button:not([type])"); if (submit && !form.dataset.allowDoubleSubmit) { submit.disabled = true; submit.setAttribute("aria-busy", "true"); } }));
  loadAdSense();
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
	usageUnlockEnabled := s.cfg.UsageUnlockEnabled && strings.TrimSpace(s.cfg.UsageUnlockEndpoint) != ""
	usageUnlockEndpoint := strings.TrimSpace(s.cfg.UsageUnlockEndpoint)
	s.mu.Unlock()
	admobEnabled := admobAppID != "" && admobRewardUnitID != ""
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"adsense":      map[string]any{"enabled": adsenseClientID != "" && adsenseSlot != "", "client_id": adsenseClientID, "slot": adsenseSlot},
		"admob":        map[string]any{"enabled": admobEnabled, "app_id": admobAppID, "reward_unit_id": admobRewardUnitID},
		"usage_unlock": map[string]any{"enabled": usageUnlockEnabled, "endpoint": usageUnlockEndpoint, "verification": "server-side-provider-verification-required"},
	})
}

func (s *Server) handleUIAsset(w http.ResponseWriter, r *http.Request) {
	var content, contentType string
	switch r.URL.Path {
	case "/assets/app.css":
		content, contentType = appCSS, "text/css; charset=utf-8"
	case "/assets/app.js":
		content, contentType = appJS, "application/javascript; charset=utf-8"
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write([]byte(content))
}

// executeUITemplate upgrades the older, page-local templates during the
// rolling UI migration. It adds the same local stylesheet, controls, locale
// hint, and progressive-enhancement script without changing their form
// fields or security-sensitive server-side rendering semantics.
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
	html = strings.Replace(html, "<html", `<html data-locale="`+locale+`"`, 1)
	html = strings.Replace(html, "<head>", `<head><link rel="stylesheet" href="/assets/app.css">`, 1)
	html = strings.Replace(html, "<body>", `<body><div class="ui-controls-floating" data-ui-controls></div>`, 1)
	html = strings.Replace(html, "</body>", `<script src="/assets/app.js" defer></script></body>`, 1)
	_, err := w.Write([]byte(html))
	return err
}
