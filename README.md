# Cline2API

轻量级 Cline API 转 OpenAI 兼容接口网关与多账号调度管理面板。

将 Cline 官方客户端协议本地拼接，封装为标准 OpenAI 格式接口（`/v1/chat/completions`, `/v1/models`），支持多账号池轮询调度、Token 自动刷新续期、429 智能冷却退避以及内置 Web 管理面板。

---

## 🌟 核心特性

- **OpenAI 兼容接口**：无缝对接任意支持 OpenAI 格式的客户端（NextChat、LibreChat、OpenWebUI、CPA / CLIProxyAPI、Cursor 等）。
- **多账号轮询与调度**：支持配置多个 Cline 账号，采用 Round-Robin 算法自动轮询调度，并在遇到 429 限流时自动根据 Retry-After 进行冷却退避与切号重试。
- **Token 自动续期**：全自动管理 WorkOS AccessToken，在 Token 过期或即将过期时自动使用 RefreshToken 续期，无需人工介入。
- **协议洗包与防报错**：
  - 自动剥离 `max_tokens`、`frequency_penalty` 等可能导致 Cline 官方接口 500/400 的参数；
  - 非流式（Stream=False）请求底层自动使用 SSE 流式拼装完整响应，避免官方长请求超时或截断。
- **内置 Web 管理面板 (`/admin`)**：
  - **账号看板**：实时查看账号状态、冷却剩余时间、连续失败次数、Token 有效期；
  - **便捷授权**：支持 WorkOS 设备码（Device Code）一键发起 OAuth 登录授权；
  - **批量导入**：支持单行或批量多行直接粘贴导入 RefreshToken 绕过网页风控；
  - **一键启停/删除**：随时剔除异常账号或暂时停用指定账号。
- **免费模型实时探活雷达 (`/admin/models`)**：
  - 1:1 对齐 Cline 官方客户端内置免费模型列表；
  - 提供网页端一键探活、延迟测试与可用性看板。

---

## 🚀 快速开始

### 1. 克隆仓库与安装依赖

```bash
git clone https://github.com/lalytian/cline2api.git
cd cline2api

# 建议在 Python 3.10+ 虚拟环境下运行
pip install -r requirements.txt
```

### 2. 配置文件说明

复制配置模板：

```bash
cp config.example.json config.json
```

编辑 `config.json`：
```json
{
  "api_key": "sk-cline2api-custom-master-key",
  "admin_password": "your_secure_admin_password"
}
```
- `api_key`：对外提供 OpenAI 兼容接口时的 Bearer 鉴权 Key。
- `admin_password`：访问 `/admin` Web 管理面板时使用的管理密码。

### 3. 启动服务

```bash
python gateway.py
```

默认监听在 `127.0.0.1:18091`。

可通过环境变量自定义配置：
```bash
HOST=0.0.0.0 PORT=18091 CLINE2API_DATA_DIR=./ python gateway.py
```

---

## ⚙️ 环境变量支持

| 环境变量 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `HOST` | `127.0.0.1` | 监听地址 |
| `PORT` | `18091` | 监听端口 |
| `CLINE2API_DATA_DIR` | 代码所在目录 | 存放 `config.json` 与 `accounts.json` 的目录 |
| `API_KEY` | 自动生成 | 未提供 `config.json` 时的默认 API 密钥 |
| `ADMIN_PASSWORD` | `admin123` | 未提供 `config.json` 时的默认管理密码 |

---

## 🖥️ Systemd 后台服务配置（Linux）

创建 `/etc/systemd/system/cline2api.service`：

```ini
[Unit]
Description=Cline2API Gateway Service
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/cline2api
ExecStart=/usr/bin/python3 /opt/cline2api/gateway.py
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

加载并启动：
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cline2api
```

---

## 📖 API 调用示例

### 1. 获取模型列表
```bash
curl http://127.0.0.1:18091/v1/models \
  -H "Authorization: Bearer sk-cline2api-custom-master-key"
```

### 2. 对话补全 (Chat Completion)
```bash
curl http://127.0.0.1:18091/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-cline2api-custom-master-key" \
  -d '{
    "model": "cline-free/kimi-k3",
    "messages": [
      {"role": "user", "content": "Hello!"}
    ],
    "stream": true
  }'
```

### 3. CPA (CLIProxyAPI) 接入范例
在 `config.yaml` 的 `openai-compatibility` 列表下添加：
```yaml
- name: Cline2API
  base-url: http://127.0.0.1:18091/v1
  api-key-entries:
  - api-key: sk-cline2api-custom-master-key
  models:
  - name: cline-free/kimi-k3
  - name: cline-free/deepseek-v4.1-flash
  - name: cline-free/muse-spark-1.3-contributor
  - name: cline-free/solar-pro4
  request-retry: 3
```

---

## 🔒 安全与隐私建议

1. **反向代理与 HTTPS**：公网访问时强烈建议通过 Caddy / Nginx 配置反向代理与 SSL 证书。
2. **凭据保护**：`accounts.json` 与 `config.json` 包含关键 RefreshToken 与密码，严禁提交到公共 Git 仓库（已在 `.gitignore` 中默认忽略）。
3. **防火墙规则**：管理面板建议仅允许内网或特定 Tailscale / VPN IP 访问。

---

## 📄 License

MIT License
