# C 网关

`openp2p-gateway-c` 0.3.0 是独立的 Linux C 服务端，兼容本仓库 Go 3.25.11 和 C 客户端。C 0.4.0 支持主机名自动命名与稳定设备标识。运行时无需 Go；客户端和网关的源码分别维护。

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
- 程序内嵌 Web 控制台：登录、网关状态、节点搜索、转发管理与安装 Token；按客户端能力显示操作。

首版面向 Linux / IPv4 监听，保留 IPv6 节点元数据和 SD-WAN IPv6 配置校验。节点名为 8–31 位 ASCII 字母、数字、下划线或横线。未实现多租户账号数据库、OTA 下载或证书热重载。应用管理的实际执行能力取决于客户端。配置/中继协调支持不代表已验证完整 SD-WAN TUN 或中继数据面。

## 构建

Debian 12 / 13 或 WSL Debian：

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build pkg-config \
  libwebsockets-dev libjson-c-dev libssl-dev libsqlite3-dev openssl python3 iproute2
cmake -S c/gateway -B build/c-gateway -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/c-gateway --parallel 4
build/c-gateway/openp2p-gateway-c --version
cmake --install build/c-gateway --prefix "$HOME/openp2p-dev/c-gateway"
```

最低依赖：libwebsockets 4.1、OpenSSL 3.0、json-c 0.16、SQLite 3.24。二进制使用对应发行版的运行库；Debian 13 构建不能视为 Debian 12 通用包。部署时使用匹配构建。

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

## SQLite 节点存储

新增 SQLite 节点登记，保留离线节点、主机名与首次/最近在线时间。`--database FILE` / `OPENP2P_DATABASE` 指定路径，默认当前目录的 `nodes.sqlite3`。systemd 使用独立 StateDirectory，Docker 需要挂载可写的持久目录或命名卷。

C 0.4 客户端省略节点名后，网关依据主机名自动分配：短于 8 位补随机数字，重名追加数字后缀，通过数据库唯一约束防止冲突，设备标识保证重启后复用。已有显式节点名保留。配置、C 接口与备份方法见 [节点存储和命名](https://github.com/windows0041/openp2p-test/blob/main/c/NODE-STORAGE-ZH.md)。

## Web 控制台

浏览器打开管理 API 的 HTTPS 地址，默认 `https://127.0.0.1:10008/`，使用 `OPENP2P_USER` / `OPENP2P_PASSWORD` 登录。全部页面、样式和脚本嵌入可执行文件，不依赖 Node.js、CDN 或单独的前端进程。

远程管理可使用 SSH 转发，沿用私有 CA，不需要开放公网管理端口：

```bash
ssh -N -L 11008:127.0.0.1:10008 root@gz.itq.cc.cd
# 浏览器访问 https://127.0.0.1:11008/，信任已有网关 CA。
```

控制台支持状态总览、在线/离线节点、全库分页搜索、主机名与最近在线时间、应用列表和新增固定转发。离线节点只读。Go 节点还支持编辑、开关与删除；C 0.3 节点只支持查询、新增，SOCKS5 和已有规则在客户端配置中修改。C 新增规则仅在本次进程有效。操作后重新查询客户端，发送成功不等同于隧道已经建成。

登录凭据仅保存在当前页面内存，刷新或关闭后需重新登录；安装 Token 默认隐藏，可主动显示或复制。页面使用同源请求、CSP 和内容转义；证书和私钥不经 Web 提供。

构建成功后可从本项目 [Releases](https://github.com/windows0041/openp2p-test/releases) 下载原生包、Docker 镜像和 SHA-256 校验文件。发布规则见 [自动构建与发布](https://github.com/windows0041/openp2p-test/blob/main/RELEASING-ZH.md)。

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
| `GET /` | Web 控制台（登录前仅提供静态文件） |
| `GET /healthz` | 健康检查 |
| `GET /api/v1/status` | 网关版本、运行时间、在线节点、容量与队列（需鉴权） |
| `POST /api/v1/user/login` | `{"user":"…","password":"…"}` |
| `GET /api/v1/devices` | 在线节点（兼容原接口） |
| `GET /api/v1/nodes` | SQLite 节点登记，含离线节点；支持 search / limit / offset |
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

Go 与 C 网关使用相同 NAT 端口，切换时只启用一个，保留原服务供回退。`gz.itq.cc.cd` 已更新到 C 0.2.0，Web 访问、Release 校验、公网回归和回退方法见 [Web 更新记录](deploy/WEB-DEBUG-ZH.md)；首次替换与 Go 回退方法见 [原切换记录](deploy/REMOTE-DEBUG-ZH.md)。

```bash
docker build -t openp2p-c-gateway:0.3.0 c/gateway
docker run --rm --name openp2p-c-gateway \
  --user "$(id -u):$(id -g)" \
  --env-file /path/outside/repository/gateway.env \
  -v /path/to/server.crt:/etc/openp2p/tls/server.crt:ro \
  -v /path/to/server.key:/etc/openp2p/tls/server.key:ro \
  -v /path/to/writable-state:/var/lib/openp2p \
  -p 27183:27183/tcp -p 27180-27181:27180-27181/tcp \
  -p 27180-27183:27180-27183/udp -p 127.0.0.1:10008:10008/tcp \
  openp2p-c-gateway:0.3.0
```

环境文件内的证书路径使用容器路径，挂载文件需允许运行账号读取。镜像不含账号、证书或私钥。许可证与第三方来源见 `LICENSE`、`THIRD_PARTY.md`。
