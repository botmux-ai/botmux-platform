# Botmux Platform

[Botmux](https://github.com/deepcoldy/botmux) 的中心化平台：**飞书登录 + 反向隧道访问你各台机器上的 botmux dashboard + 团队协作**（团队与协作群、Issue 看板、机器协管者、个人凭据库）。
后端为 Go/Hertz，前端为 React。

## 架构

- 机器通常位于平台无法主动访问的网络里，因此 botmux daemon 始终**出站**向平台建立一条 WebSocket 控制隧道。你在网页上打开某台机器时，平台让该 daemon 拨一条数据连接回来，在上面反代它本地的 dashboard。浏览器全程只与平台的 HTTPS 域名通信。
- 每台机器有独立子域 `https://m-<machineId>.<root-host>/`；`/__open` 把短期 ticket 换成仅对该机器有效的 HttpOnly Cookie。
- 存储：
  - **MongoDB**：机器、用户、团队、设备、Issue、凭据等权威数据。不可用时相关接口 fail-closed 返回 503，不会被当成“空集合”。
  - **Redis**（可选）：多副本部署时的跨 Pod 机器/stream 路由和 token 吊销状态。配置后连接失败会阻止启动，避免各 Pod 形成伪全局路由。单副本可不配。
  - 未配置 MongoDB 时仅适合本地开发：机器、团队在内存中，Issue 和凭据库不可用。
- 根域同时分发一键安装脚本 `GET /install.sh`（及等价的 `/api/install.sh`）。

## 代码结构

```text
cmd/botmux-platform/   Go/Hertz 入口
internal/              auth / store / tunnel / proxy / server 等后端模块
frontend/              React 前端
install.sh             一键安装脚本
scripts/               构建、安装器测试与黑盒 smoke
dist/                  构建产物：bin/botmux-platform、web/、install.sh
```

## 本地开发

需要 Go 1.22+ 和 Node.js 20+。

```bash
npm install
npm run build        # 测试 + 构建后端、前端与安装脚本 + 冒烟
npm start            # http://localhost:8080
```

打开 http://localhost:8080 →「飞书登录」（本地默认是 `DEV_LOGIN` 假身份）→「绑定新机器」拿到 `botmux bind <码>`。
机器子域用 `m-<machineId>.localhost`（主流浏览器自动解析到 127.0.0.1，无需配置 hosts）。

`npm run dev` 跳过测试直接构建并启动后端；前端热更新另开 `npm run dev:frontend`（Vite）。

Botmux Desktop 使用 Cloud PKCE 登录时会直接调用 `POST /v1/desktop/auth/machine-bind`，以 Desktop access token 为授权，按与 `/api/bind` 相同的 owner CAS / retired tombstone 规则签发机器票；网页绑定码仍用于 headless CLI 与手动恢复。

### 测试

```bash
npm test                 # Go 与前端单测
npm run test:installer   # 安装脚本隔离测试
npm run test:smoke       # 黑盒冒烟：模拟 dashboard + daemon，跑通安装产物、绑定、隧道、反代（HTTP + raw WS）和团队操作
```

## 一键安装 Botmux

平台网页的安装弹窗会给出带当前平台地址的命令：

```bash
curl -fsSL <平台地址>/install.sh | BOTMUX_PLATFORM_URL=<平台地址> sh && export PATH="$HOME/.local/bin:$PATH"
```

安装脚本会：

- 复用已有的 Node.js 22/24 LTS；版本不合适时沿用机器上已有的 Node 管理器（fnm / nvm / Homebrew / Volta / mise / asdf）切换，没有任何管理器时安装 fnm。可用 `BOTMUX_NODE_MANAGER` / `BOTMUX_NODE_VERSION` 显式指定。
- 通过系统包管理器（或 macOS 上的 Homebrew）安装 tmux 与 bubblewrap 等依赖。root 与非 root 都安装到当前 `$HOME` 下的用户级目录。
- 复用已安装的 Claude Code；安装或更新 Codex（优先 `CODEX_REGISTRY` 指定的 npm 源，失败再用 OpenAI 官方安装器），并在后台预热首次启动。
- 安装 `lark-cli` 并在收尾提示登录。
- 下载或安装遇到网络失败时，若配置了 `BOTMUX_HTTP_PROXY`（直连名单 `BOTMUX_NO_PROXY`），会经代理重试一次；`BOTMUX_DISABLE_PROXY_FALLBACK=1` 可关闭。

`sh install.sh --help` 查看全部选项。

## 生产部署

前置条件：

- MongoDB；多副本时再加 Redis。
- 一个飞书自建应用，重定向 URL 配置为 `<PUBLIC_BASE_URL>/auth/callback`。
- 根域与 `*.<root-host>` 通配子域的 DNS 和 TLS 证书（机器子域反代所必需）。
- 入口网关透传 WebSocket，并调大空闲超时（控制隧道是长连接；daemon 侧有心跳和断线重连）。

`npm run build` 产出 `dist/bin/botmux-platform`（静态二进制）、`dist/web/` 和 `dist/install.sh`。以 `NODE_ENV=production` 启动，并用 `WEB_DIR` / `BOTMUX_INSTALLER_FILE` 指向前端与安装脚本产物。进程在 listener 可服务后写 statusz `ready`，SIGTERM 时先转为非 ready 再排空长连接。

## 环境变量

| 变量 | 说明 | 默认 |
|---|---|---|
| `PORT` | 监听端口 | 8080 |
| `BOTMUX_LISTEN_ADDR` | 完整监听地址（优先于 `PORT`） | `0.0.0.0:<PORT>` |
| `PUBLIC_BASE_URL` | 对外地址（拼 OAuth 回调和机器子域） | 本地跟随监听端口 |
| `SIGNING_SECRET` | 会话/token 签名密钥 | **生产必填**；本地随机 |
| `FEISHU_APP_ID` / `FEISHU_APP_SECRET` | 平台登录用的飞书自建应用 | **生产必填** |
| `FEISHU_HOST` | 飞书开放平台地址 | `https://open.feishu.cn` |
| `PLATFORM_APP_NAME` | 平台应用的可读名，仅用于提示文案 | 空（显示 app_id） |
| `DEV_LOGIN` | 本地免飞书登录（生产恒关） | 非生产默认 `true` |
| `MONGODB_URI` / `MONGODB_DB` | 权威存储 | 空（内存）/ `botmux` |
| `REDIS_URL` / `REDIS_KEY_NAMESPACE` | 跨 Pod 路由与 token 吊销 | 空（单副本）/ `botmux` |
| `PORT0` / `MY_HOST_IP` / `MY_HOST_IPV6` | 配置 Redis 时，本 Pod 对其他 Pod 可达的端口与地址 | 生产配置 Redis 时必填 |
| `COOKIE_DOMAIN` / `COOKIE_SECURE` | 会话 Cookie 属性 | 由 `PUBLIC_BASE_URL` 推导 |
| `MACHINE_SUBDOMAIN_PREFIX` | 机器子域前缀 | `m-` |
| `STALE_MS` | 多久无心跳判定离线 | 90000 |
| `DASHBOARD_CONN_POOL` | 每机器 HTTP 隧道连接池 | `1` |
| `DASHBOARD_DIRECT` | daemon 上报的私有网络地址探测成功时优先直连 dashboard | `1` |
| `TEAMSYNC_FEISHU_WRITES` | 团队/群写操作总开关；`0` 时冻结团队/群写 API 与协作群的建、改、解散，读取与 team-sync 下发仍可用 | `0` |
| `CREDENTIAL_KEK` | 凭据库信封加密的 KEK，32 字节 hex/base64（`openssl rand -hex 32`） | 空（凭据库关闭） |
| `CREDENTIAL_KEK_LEGACY` | 轮换期的旧 KEK，逗号分隔，只用于解密 | 空 |
| `LARK_CREDENTIAL_SCOPES` | 个人授权向飞书申请的用户权限（空格分隔），总会附加 `offline_access` | 空（平台应用已开通的全部用户权限） |
| `OPENAPI_CORS_ORIGINS` | 对外 OpenAPI 允许的跨域来源（逗号分隔） | 空 |
| `RELAY_SIGNING_SECRET` | Desktop Relay JWT 签名密钥；未配置时不声明 `relay.use` 能力 | 空 |
| `RELAY_TOKEN_ISSUER` / `RELAY_TOKEN_AUDIENCE` | Relay JWT 的 issuer / audience，需与 Relay Director 一致 | `PUBLIC_BASE_URL` / `botmux-relay` |
| `RELAY_TOKEN_TTL_SEC` | Relay JWT 时长（120–3600 秒） | 600 |
| `WEB_DIR` | 前端产物目录 | `dist/web` |
| `BOTMUX_INSTALLER_FILE` | `/install.sh` 返回的脚本 | `install.sh` |
| `STATUSZ_DIR` / `STATUSZ_NAME` | 就绪状态文件位置 | 系统临时目录 / `botmux-platform` |

## 私有扩展

`ext/<name>/` 可放私有部署扩展：一个独立 Go module（替换存储驱动、OpenAPI 验签等），以及可选的前端模块、安装脚本 profile 与冒烟钩子，构建脚本会自动发现。没有扩展时构建的就是本仓库的公开版本。

## License

[MIT](./LICENSE)
