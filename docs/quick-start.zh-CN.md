# 快速开始（中文）

## 1. 安装并打开交互式终端中心

```bash
curl -fsSL https://raw.githubusercontent.com/ifloppy/chat-with-cli/main/install.sh | sh
chat-with-cli ui
```

如果使用自建 Relay，在交互式设置中输入它的 HTTPS 地址；如果直接使用命令，传入
`--relay`。不传时默认 Relay 是 `https://chat-with-cli.iruanp.com`。

## 2. 创建只读 Agent

```bash
chat-with-cli agent setup \
  --relay https://chat-with-cli.iruanp.com \
  --root "$HOME/project" \
  --profile read-only \
  --install-systemd
```

`--root` 应该是最小的工作目录。命令会生成设备 Ed25519 身份、Agent 配置和一个未启动的 systemd 用户服务。

## 3. 登录并连接

```bash
chat-with-cli connect
```

浏览器会自动打开 OAuth 页面。前台连接时可以选择每次请求审批、当前进程全部允许，或仅使用配置文件中的权限。需要后台运行前，请先审阅生成的 unit：

前台 `connect`/`agent` 启动时会打印完整的 31 项 MCP 工具清单和本地能力摘要；每次入站工具调用也会按名称显示，即使选择“全部允许”（`--approval-mode=allow-all`）也不会关闭这条审计输出。参数、文件内容、命令和结果不会打印。

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
