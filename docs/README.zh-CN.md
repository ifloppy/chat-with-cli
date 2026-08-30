# Chat with CLI 使用指南

[English](README.md)

`chat-with-cli` 是一个 Go 单二进制工具：MCP 客户端通过 Relay 连接到工作站上的主动外连 Agent。建议从最小权限开始，只在确实需要时扩大能力范围。

## 最快的工作站路径

```bash
curl -fsSL https://raw.githubusercontent.com/ifloppy/chat-with-cli/main/install.sh | sh
chat-with-cli ui
```

安装后的交互式终端中心默认使用社区公共 Relay：
`https://chat-with-cli.iruanp.com`。首次提示时可以改成自己的私有 Relay，也可以在命令中传入
`--relay https://your-relay.example`。安装脚本通过 `SHA256SUMS` 校验二进制，默认安装到
`~/.local/bin`，不会自动启动服务。

脚本化设置：

```bash
chat-with-cli agent setup \
  --relay https://chat-with-cli.iruanp.com \
  --root "$HOME/project" \
  --profile read-only \
  --install-systemd
chat-with-cli connect
chat-with-cli doctor
```

请先检查生成的 systemd 用户服务，确认 OAuth 和权限后再启动：

```bash
systemctl --user daemon-reload
systemctl --user enable --now chat-with-cli-agent.service
```

## 按场景阅读

- [快速开始](quick-start.zh-CN.md) — 本地构建和首次连接。
- [安装](install.md) — 已验证安装、路径和仅审阅更新。
- [Agent 配置](agent.md) — 根目录、权限配置、身份和 systemd。
- [ChatGPT/MCP 兼容性](chatgpt.md) — 端点与 OAuth。
- [私有 Relay](private-instance.md) — 自托管的单所有者模式。
- [公共 Relay](public-instance.md) — 多用户策略和信任边界。
- [部署](deployment.md)、[反向代理](reverse-proxy.md) — 生产环境托管。
- [账户](account.md)、[管理员](admin.md) — 设备和会话管理。
- [安全](security.md)、[威胁模型](threat-model.md) — 安全假设和限制。
- [Computer Use](computer-use.md) — 明确选择后才能使用桌面能力。
- [故障排查](troubleshooting.md) — 常见连接问题。
- [备份恢复](backup-restore.md)、[升级回滚](upgrade.md) — 运维维护。
- [版本流程](release.md) — 发布前的本地候选版本管理。

## 能力配置

| 配置 | 适用场景 | 默认权限 |
| --- | --- | --- |
| `read-only` (`R`) | 首次连接、普通代码阅读 | 仅文件系统读取 |
| `read-write` (`W`) | 本地开发 | 文件写入和 PTY 执行；Linux 默认使用 Landlock |
| `desktop-computer-use` (`D`) | 桌面自动化 | 屏幕/辅助功能读取和计算机输入 |
| `all` (`A`) | 全部工作站能力 | read-write + 桌面自动化；Linux exec 默认使用 Landlock |
| `custom` (`C`) | 逐项控制权限 | 生成配置中的各个 flag |

Relay 不能替工作站授予能力；本地 profile 和前台审批模式才是最终权限边界。不要以 root 运行 Agent，也不要在没有明确意图时暴露 `/` 或整个 home 目录。

## 公共 Relay、流量额度与广告

网页 UI 当前只对外提供 AdSense 展示广告。只有在隐私声明和用户同意流程准备好后，才应配置 AdSense 发布商和广告位。旧的原生 AdMob 伴侣应用/激励奖励实现仍保留在代码中，便于兼容和以后继续开发，但目前处于 parked 状态：管理员页、账户页和首页都不再展示它，公开 monetization 配置接口也会明确报告为 disabled。

启用 `--usage-metering-enabled` 后，Relay 会按账户维护流量额度：认证后的 MCP HTTP 请求/响应字节，以及经 Broker 转发的 Agent WebSocket 载荷字节都会计入额度。额度耗尽后，新的请求会返回 HTTP `402`。每个账户默认 100 MiB，可用 `--usage-default-quota-bytes` 或管理员控制台调整。管理员可以直接给账户增加额度，也可以创建一次性激活码；用户在 `/account` 兑换。额度增加会累加并在重启后保留。计数器和激活码哈希保存在私有的 `usage-state.json` 中，与 `oauth-state.json` 的授权状态分离。普通流量按批次写入并在 Relay 正常关闭时刷新；额度授予和兑换则同步持久化。

同时填入 AdSense publisher client ID 和广告位 ID 后，公共首页会渲染响应式广告。用户侧网页还会检查 AdSense 加载器本身是否可访问：如果 Firefox Enhanced Tracking Protection、uBlock/AdBlock 等导致 `adsbygoogle.js` 无法加载，网页应用会显示不可关闭的恢复提示，要求为本站允许广告后刷新。管理员页、首次设置页、OAuth/安全页面，以及全部 MCP/Agent/API 流量均明确豁免，避免广告故障把管理员锁在门外或破坏协议流量。Google 正常返回 `unfilled` 不会被误判为广告屏蔽；此时只会自动收起空广告位。

Relay 和 `relay setup` 都提供相关选项：

```bash
chat-with-cli relay --help
chat-with-cli relay setup --help
```

非敏感的公开配置也可以从 `/api/monetization/config` 获取，供伴侣应用读取；该接口不会签发 entitlement，也不会暴露验证密钥。

## 界面语言和主题

Relay 页面内置本地的 Material 3 风格设计系统。默认跟随浏览器浅色/深色偏好，顶部控制器可以选择自动、浅色或深色；同一个控制器可以切换 English 和简体中文。`?lang=zh-CN` 可以用于分享一个中文初始页面。不依赖外部字体或 UI CDN。

## 安全提醒

公共 Relay 只能隔离普通用户之间的访问，不能隔离 Relay 运营者。运营者控制服务器代码，可能观察或修改经 Relay 转发的 MCP 流量。涉及密钥、高信任计算机操作或敏感工作区时，请使用私有自托管 Relay。开放互联网前请阅读 [SECURITY.md](../SECURITY.md)。
