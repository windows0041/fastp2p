# 自建 OpenP2P 网关与自签 TLS 调试

本分支适配当前 `windows0041/openp2p` 客户端 3.25.11。网关独立运行，节点使用这里签发的安装 token，无需连接官方控制台。管理方式为 HTTPS API，未包含 Web 管理页面。

## 已完成的适配

- 使用 `-cert`、`-key` 或 `OPENP2P_TLS_CERT`、`OPENP2P_TLS_KEY` 指定证书链和私钥；HTTPS API 与 WSS 使用同一组证书。
- 客户端增加 `-cacert`，导入私有 CA，同时校验证书链和 SAN 主机名。默认保留 TLS 验证。
- 补齐纳秒时间戳心跳、基础信息确认、LAN 地址查询、新版应用状态推送及 SD-WAN 配置分发。
- NAT 服务兼容新客户端的 UDP 27180/27181，并保留旧端口 27182/27183；公网端口探测会向客户端监听端口回包。
- 管理接口先鉴权再执行，默认关闭 pprof；WebSocket 验证节点 token、限制消息长度，连接关闭后不会继续写入已关闭的队列。
- 同一节点可同时与多个对端进行连接协调，推送权限按节点对保存。

该实现是基于 `gateway-lite` 的独立自建网关。提供的 `openp2p-gateway-edge:3.24.37` 镜像含有不同的边缘同步、数据库等实现，本仓库并非它的完整对应源码。

## 本机 WSL 环境

- Debian 13 / WSL2，用户 `maoyu`。
- Go 1.20.14：`/opt/go1.20.14`；Delve 1.21.2：`~/go/bin/dlv`。
- 源码：`/mnt/d/Codex/openp2p-selfhost/gateway`、`/mnt/d/Codex/openp2p-selfhost/client`。
- 二进制、证书和日志：`~/openp2p-dev/`。

```bash
cd /mnt/d/Codex/openp2p-selfhost/gateway
bash scripts/local-gateway.sh start
bash scripts/local-gateway.sh status
curl --cacert ~/openp2p-dev/certs/local/ca.crt https://127.0.0.1:10008/healthz
```

首次启动生成本地账号，保存在 `~/.config/openp2p-gateway/local.env`，文件权限为 600。网关仅绑定 `127.0.0.1`，日志为 `~/openp2p-dev/logs/local-gateway.log`。停止命令：

```bash
bash scripts/local-gateway.sh stop
```

打开两个 WSL 终端，分别启动节点。每个节点有独立的二进制和配置目录，脚本通过验证 TLS 的管理 API 获取安装 token：

```bash
# 终端 1：目标节点
bash /mnt/d/Codex/openp2p-selfhost/gateway/scripts/local-client.sh my-node-b

# 终端 2：把目标节点的 SSH 服务映射到本地 23322
bash /mnt/d/Codex/openp2p-selfhost/gateway/scripts/local-client.sh my-node-a \
  -appname remote-ssh -peernode my-node-b -dstip 127.0.0.1 -dstport 22 -srcport 23322
```

目标节点需要确有 SSH 服务。按 `Ctrl+C` 停止前台客户端。也可直接运行客户端并指定 `-serverhost`、`-token`、`-cacert`，不使用脚本。

## 生成和替换自己的证书

本机已生成的证书在 `~/openp2p-dev/certs/local`，SAN 包含 `localhost`、`127.0.0.1`、`::1`。私有 CA 的 `ca.key` 留在网关管理员一侧，客户端只需要 `ca.crt`。

为实际服务器生成一组新证书：

```bash
cd /mnt/d/Codex/openp2p-selfhost/gateway
bash scripts/generate-cert.sh certs/my-server gateway.example.com 203.0.113.10
export OPENP2P_USER='your-user'
export OPENP2P_PASSWORD='your-long-random-password'
~/openp2p-dev/bin/openp2p-gateway -bind 0.0.0.0 \
  -cert "$PWD/certs/my-server/server.crt" -key "$PWD/certs/my-server/server.key"
```

将示例域名和 IP 换成实际地址。客户端连接地址必须出现在证书 SAN 中：

```bash
openp2p -node my-node-a -serverhost gateway.example.com -token YOUR_NODE_TOKEN \
  -cacert /absolute/path/to/ca.crt -sharebandwidth 0
```

Windows 使用适配后的 `openp2p-windows-amd64.exe`，`-cacert` 指向 Windows 的绝对文件路径。客户端 `config.json` 的 `CACertFile` 也可保存该路径。

本机 PowerShell 用 Windows 自带 curl 检查私有证书时，可使用 `curl.exe --ssl-revoke-best-effort --cacert D:\Codex\openp2p-dev\dist\ca.crt https://127.0.0.1:10008/healthz`。该参数允许 Schannel 在私有证书未提供吊销服务时继续验证证书链，说明见 [curl 文档](https://curl.se/docs/manpage.html#--ssl-revoke-best-effort)。

换成公有 CA 证书时，服务端 `-cert` 指向完整证书链，`-key` 指向对应私钥；客户端可省略 `-cacert`。仅更换同一 CA 签发的服务端证书时，重启网关即可；更换 CA 时，需要同步更新客户端信任的 CA 文件。

## 管理 API

`nodeToken` 是给节点安装使用的 uint64 字符串，`token` 是给管理 API 使用的 JWT，两者用途不同。

```bash
curl --cacert /path/to/ca.crt https://gateway.example.com:10008/api/v1/user/login \
  -H 'Content-Type: application/json' \
  -d '{"user":"your-user","password":"your-password"}'

curl --cacert /path/to/ca.crt https://gateway.example.com:10008/api/v1/devices \
  -H 'Authorization: YOUR_JWT'

curl --cacert /path/to/ca.crt https://gateway.example.com:10008/api/v1/device/my-node-a/app \
  -H 'Authorization: YOUR_JWT' -H 'Content-Type: application/json' \
  -d '{"appName":"remote-ssh","protocol":"tcp","srcPort":23322,"peerNode":"my-node-b","dstHost":"127.0.0.1","dstPort":22}'
```

还支持 `GET /api/v1/device/:name/apps`、`POST /api/v1/device/:name/switchapp` 和 `GET /api/v1/device/:name/restart`。端口转发规则保存在客户端，网关重启后客户端自动重新连接。保持账号密码不变，或通过 `OPENP2P_TOKEN` 设置独立、稳定的非零 uint64 安装 token。

## 网络端口与中继

| 用途 | 协议和端口 |
|---|---|
| 节点登录及连接协调 | TCP 27183 |
| NAT 探测 | TCP 27180–27181、UDP 27180–27183 |
| 管理 API | TCP 10008 |

网关负责登录、探测和连接协调，数据优先在节点间直传。需要中继时，在公网服务器额外运行一个同账号的 OpenP2P 客户端作为中继节点；网关程序本身不承担业务数据中继。

可用 `-sdwan-config /absolute/path/to/sdwan.json` 分发虚拟组网配置，格式见 `sdwan.example.json`。未配置时返回禁用的组网信息。启用虚拟组网的客户端需要 TUN 和相应网络管理权限；本轮端到端验证针对 TCP/UDP 端口转发，尚未验证跨公网打洞或虚拟网段互通。

## 构建与验证

```bash
# 网关
cd /mnt/d/Codex/openp2p-selfhost/gateway
go build -mod=readonly -o ~/openp2p-dev/bin/openp2p-gateway .
go test -race -count=1 -skip '^TestNetInfo$' .

# 客户端
cd /mnt/d/Codex/openp2p-selfhost/client
go build -mod=readonly -o ~/openp2p-dev/bin/openp2p ./cmd
go test -race -count=1 -skip '^TestNetInfo$' ./core ./cmd ./pkg/upnp
```

`TestNetInfo` 依赖外部网站，不属于离线测试。客户端上游 `example/echo` 把两个独立程序放在同一目录，直接 `go test ./...` 会发生重复 `main` 错误；上述命令测试实际构建目标。

完整的本地集成脚本为 `scripts/local-e2e.py`，通过 `--gateway`、`--client`、`--cert-dir`、`--logs` 指定路径。在临时网络命名空间中运行，检查 TLS、接口鉴权、NAT、两个完整客户端的 TCP/UDP 回传，以及超过一个周期心跳后的稳定性。运行日志在 `~/openp2p-dev/logs/e2e-result.json`。

## Docker

```bash
cd /mnt/d/Codex/openp2p-selfhost/gateway
cp .env.example .env
# 编辑 .env 设置账号密码；默认仅监听 127.0.0.1。
bash scripts/generate-cert.sh certs/local
docker compose up --build -d
```

使用 Linux host 网络。容器用户默认为 UID/GID 1000，挂载的私钥需允许该用户读取。修改 `.env` 中的 `GATEWAY_UID`、`GATEWAY_GID` 时，也要同步调整日志卷的写入权限。只挂载服务端证书与私钥，CA 私钥无需放入容器。Docker 配置已提供，本轮使用 WSL 原生二进制验证，未执行 Docker 构建。
