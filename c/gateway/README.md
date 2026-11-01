# C 网关

`openp2p-gateway-c` 0.1.0 是独立的 Linux C 服务端，兼容本仓库 Go 3.25.11 和 C 0.2.0 客户端。运行时无需 Go；客户端和网关的源码分别维护。

网关负责鉴权、节点发现、NAT 探测和连接协调。TCP / QUIC 业务数据在客户端之间传输；网关无需实现 QUIC 数据端点，中继业务数据也由客户端中继节点承担。

## 已实现

- 自定义证书链与私钥的 HTTPS / WSS，TLS 1.2+，兼容两种客户端登录路径。
- uint64 安装 token、CRC64 节点 ID、HMAC-SHA256 TOTP、HS256 JWT 管理鉴权。
- 节点报告、纳秒心跳、在线通知、重复登录替换、超时回收。
- 四个 UDP NAT 探测端口、指定端口回显、两个单字节 TCP NAT 探测端口。
- 对端查询、成对且有有效期的推送授权、发送者校验、应用密钥/内存规则同步。
- TCP 打洞、UDP 打洞 / QUIC 的控制消息转发，私有中继节点选择与 TOTP 分发。
- SD-WAN 配置校验及成员配置分发；异步应用列表、编辑、开关与重启管理请求。
- 有界队列、背压和资源上限；独立事件循环，管理查询不会阻塞其他节点。

首版面向 Linux / IPv4 监听，保留 IPv6 节点元数据和 SD-WAN IPv6 配置校验。节点名为 8–31 位 ASCII 字母、数字、下划线或横线。未实现多租户账号数据库、离线节点持久化、Web 管理页面、OTA 下载或证书热重载。应用管理的实际执行能力取决于客户端。配置/中继协调支持不代表已验证完整 SD-WAN TUN 或中继数据面。

## 构建

Debian 12 / 13 或 WSL Debian：

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build pkg-config \
  libwebsockets-dev libjson-c-dev libssl-dev openssl python3 iproute2
cmake -S c/gateway -B build/c-gateway -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/c-gateway --parallel 4
build/c-gateway/openp2p-gateway-c --version
cmake --install build/c-gateway --prefix "$HOME/openp2p-dev/c-gateway"
```

最低依赖：libwebsockets 4.1、OpenSSL 3.0、json-c 0.16。二进制使用对应发行版的运行库；Debian 13 构建不能视为 Debian 12 通用包。部署时使用匹配构建。

## 本地自签证书

```bash
runtime="$HOME/openp2p-dev/c-gateway-local"
mkdir -p "$runtime"
chmod 700 "$runtime"
bash go/gateway/scripts/generate-cert.sh "$runtime/tls" localhost 127.0.0.1
export OPENP2P_USER=my-admin
read -r -s -p 'Admin password: ' OPENP2P_PASSWORD
printf '\n'
export OPENP2P_PASSWORD
export OPENP2P_TOKEN=$(python3 -c 'import secrets; print(secrets.randbelow(2**64-1)+1)')
build/c-gateway/openp2p-gateway-c \
  --cert "$runtime/tls/server.crt" --key "$runtime/tls/server.key" \
  --bind 127.0.0.1 --apibind 127.0.0.1
```

在另一个终端检查 HTTPS：

```bash
curl --cacert "$HOME/openp2p-dev/c-gateway-local/tls/ca.crt" https://127.0.0.1:10008/healthz
```

不设置 `OPENP2P_TOKEN` 时，按 Go 原算法从管理账号和密码派生。新部署建议显式生成并安全保存随机 token。真实账号、token、配置、证书和私钥放在仓库外，模板为 `.env.example`。只给客户端分发 `ca.crt`，不能分发 CA 私钥。

兼容 Go 的单横线参数 `-bind`、`-apibind`、`-cert`、`-key`、`-port`、`-apiport`、`-sdwan-config`。另提供 `--max-clients`、`--heartbeat-timeout`、调试用 `--run-seconds`。默认只绑定 127.0.0.1，`Ctrl+C` / SIGTERM 正常退出。

## 客户端与管理接口

客户端 `OPENP2P_TOKEN` 与网关一致，避免将真实值写到命令行。Go 和 C CLI 示例：

```bash
build/go/openp2p -node my-go-client -serverhost 127.0.0.1 \
  -cacert "$HOME/openp2p-dev/c-gateway-local/tls/ca.crt" -sharebandwidth 0 -nv
build/c/openp2p-c --node my-c-client --serverhost 127.0.0.1 \
  --cacert "$HOME/openp2p-dev/c-gateway-local/tls/ca.crt"
```

实际部署使用 `--bind 0.0.0.0`，证书 SAN 包含真实网关域名/IP。Android 导入同一 CA，Windows/macOS C CLI 使用 `--cacert`，转发规则沿用原配置。客户端始终验证证书链和主机名。

| 监听 | 默认端口 | 用途 |
| --- | --- | --- |
| TCP / TLS | 27183 | WSS：`/api/v1/login`、`/openp2p/v1/login` |
| TCP | 27180、27181 | TCP NAT 地址回显 |
| UDP | 27180–27183 | UDP NAT 探测 |
| TCP / TLS | 10008 | HTTPS 管理 API，建议只绑定回环地址 |

除健康检查与登录外，API 要求 `Authorization: <JWT>`，也接受 Bearer 格式。登录返回 `token`（JWT）和字符串 `nodeToken`（安装 token）。

| 方法与路径 | 行为 |
| --- | --- |
| `GET /healthz` | 健康检查 |
| `POST /api/v1/user/login` | `{"user":"…","password":"…"}` |
| `GET /api/v1/devices` | 在线节点 |
| `GET /api/v1/device/:name/apps` | 异步查询节点应用 |
| `POST /api/v1/device/:name/app` | 转发应用编辑请求 |
| `POST /api/v1/device/:name/switchapp` | 转发应用开关请求 |
| `GET /api/v1/device/:name/restart` | 转发重启指令 |

应用字段与 Go 网关一致，如 `appName`、`protocol`、`srcPort`、`peerNode`、`dstHost`、`dstPort`。同节点同时仅允许一个待处理应用列表查询，冲突返回 409；10 秒无响应返回 504，等待时节点断线返回 503。

资源上限：256 个节点、128 个 TCP 探测连接；单帧 1 MiB，单节点 64 条 / 4 MiB 发送队列，总发送与 WebSocket 接收分配分别 64 MiB；HTTP 请求体 64 KiB。默认 40 秒无控制消息回收连接，授权 60 秒失效，重复登录清除旧授权。

## 检查

```bash
sudo bash c/gateway/scripts/check.sh
sudo env OPENP2P_C_GATEWAY_BUILD_DIR="$HOME/openp2p-dev/build/c-gateway-asan" \
  bash c/gateway/scripts/check.sh --sanitize
# 先构建 Go 参考客户端与 C 客户端，再运行六节点联调
sudo bash c/gateway/scripts/integration.sh
```

网络测试使用独立 network namespace，需 root、`unshare`、`iproute2`；不会占用现有部署端口。Go 参考客户端使用 Go 1.20.14。完整联调覆盖 C→Go、Go→C、C→C，分别使用 TCP 打洞 / QUIC 传输 TCP/UDP 应用，并检查 35 秒心跳、最后响应数据和网关重启重连。临时证书、随机测试账号及日志保存在私有 `/tmp/openp2p-c-gateway-*` 目录。

实际环境、CI 发行包及测试边界见 [验证记录](VALIDATION-ZH.md)。

## 部署

systemd 模板：`deploy/openp2p-c-gateway.service`。准备专用 `openp2p` 用户，安装程序到 `/opt/openp2p-c/bin`，环境文件为 `/etc/openp2p-c/gateway.env`，TLS 文件放在该目录的 `tls/` 中，确保仅服务账号可读私钥。换证书后重启，客户端会重新鉴权。

Go 与 C 网关使用相同 NAT 端口，切换时只启用一个，保留原服务供回退。本轮提供部署文件，不自动替换现网 Go 服务。

```bash
docker build -t openp2p-c-gateway:0.1.0 c/gateway
docker run --rm --name openp2p-c-gateway \
  --user "$(id -u):$(id -g)" \
  --env-file /path/outside/repository/gateway.env \
  -v /path/to/server.crt:/etc/openp2p/tls/server.crt:ro \
  -v /path/to/server.key:/etc/openp2p/tls/server.key:ro \
  -p 27183:27183/tcp -p 27180-27181:27180-27181/tcp \
  -p 27180-27183:27180-27183/udp -p 127.0.0.1:10008:10008/tcp \
  openp2p-c-gateway:0.1.0
```

环境文件内的证书路径使用容器路径，挂载文件需允许运行账号读取。镜像不含账号、证书或私钥。许可证与第三方来源见 `LICENSE`、`THIRD_PARTY.md`。
