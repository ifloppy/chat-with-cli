# 快速开始（中文）

## 1. 安装并打开交互式终端中心

```bash
curl -fsSL https://raw.githubusercontent.com/ifloppy/chat-with-cli/main/install.sh | sh
chat-with-cli ui
```

如果使用自建 Relay，在交互式设置中输入它的 HTTPS 地址；如果直接使用命令，传入
`--relay`。不传时默认 Relay 是 `https://chat-with-cli.iruanp.com`。

## 2. 连接这台工作站

在交互界面直接选择 **Connect this workstation**。首次使用时，它会在同一条流程中完成本机配置，然后在需要时打开 OAuth 并建立 Agent 连接；不需要先“Setup”再回主菜单点“Connect”。需要修改已有 root/profile 等设置时，使用 **Workstation settings**。**Account** 菜单会显示 OAuth 状态，并提供 Login / Logout。

也可以继续使用等价的命令行方式：

```bash
chat-with-cli agent setup \
  --relay https://chat-with-cli.iruanp.com \
  --root "$HOME/project" \
  --profile read-only \
  --install-systemd
```

`--root` 应该是最小的工作目录。命令会生成设备 Ed25519 身份、Agent 配置和一个未启动的 systemd 用户服务。

## 3. OAuth 与连接

```bash
chat-with-cli connect
```

缺少、过期或被 Relay 拒绝的凭据会自动触发 OAuth；远端撤销了仍未过期的本地 token 时也不会再无限重试旧 token。显式 `chat-with-cli login` 会强制重新走浏览器 OAuth，`chat-with-cli logout` 会撤销当前工作站的 token family 并仅删除这台设备的本地凭据。若设备 identity 已被永久 Revoke，交互式 Connect 会保留旧 revoked key、生成新的 Ed25519 identity/immutable ID、更新配置后再进入 OAuth。

纯 SSH/无头 Linux 主机也可以完成 OAuth：当没有 `DISPLAY` 和 `WAYLAND_DISPLAY` 时，CLI 会自动切换为手动模式；也可以用 `chat-with-cli connect --manual-oauth` 或 `chat-with-cli login --manual-oauth` 强制进入。CLI 只向当前 TTY 显示一次授权 URL，你可以在任意设备浏览器里打开并完成登录。最终跳到 `http://127.0.0.1:<port>/callback?...` 时，如果浏览器显示 localhost 无法连接属于正常现象；复制地址栏里的完整最终 URL，粘贴回 CLI 即可继续 PKCE 换取 token。CLI 会严格校验 callback 的 host、port、path、state 和单一 code。

前台连接时可以选择每次请求审批、当前进程全部允许，或仅使用配置文件中的权限。需要后台运行前，请先审阅生成的 unit：

前台 `connect`/`agent` 启动时会打印完整的 34 项 MCP 工具清单和本地能力摘要；每次入站工具调用也会按名称显示，即使选择“全部允许”（`--approval-mode=allow-all`）也不会关闭这条审计输出。参数、文件内容、命令和结果不会打印。

```bash
chat-with-cli doctor
systemctl --user daemon-reload
systemctl --user enable --now chat-with-cli-agent.service
```

## 4. 在 MCP 客户端中添加端点

普通情况下直接使用 Relay 的账户级 MCP 地址：

```text
https://chat-with-cli.iruanp.com/mcp
```

OAuth 登录一次后，`devices_list` 只会列出当前账户拥有的设备；其它工具每次调用都携带设备选择器，因此多个对话并发时不会共享一个容易串台的“当前设备”。如果明确希望某个客户端永远只绑定一台机器，仍可使用 `/mcp/id/<device-id>`。

在 ChatGPT 或其他 MCP 客户端选择 OAuth。不要把 owner 密码、setup token 或 Agent 凭据粘贴到聊天、日志或工单中。

## 5. 何时应自托管

公共 Relay 的运营者处于信任边界内，能够观察或改变 MCP 流量。只要工作区包含密钥或需要高信任 Computer Use，就应按照 [私有 Relay 文档](private-instance.md) 自托管，并阅读 [安全说明](../SECURITY.md)。
