# gz 公网网关与 xrwmaster / 本机调试部署

2026-11-01 更新：`gz.itq.cc.cd` 已切换到 C 网关 0.1.0，当前程序、systemd 切换配置及回退方法见 [C 网关公网记录](../../../c/gateway/deploy/REMOTE-DEBUG-ZH.md)。以下保留原 Go 部署及客户端入口作为历史记录，原 Go 二进制仍可用于回退。

部署日期：2026-10-31。网关来自本仓库，使用私有 CA 签发的 TLS 证书。客户端保持证书链和主机名验证。

## 原 Go 部署

| 角色 | 主机/节点 | 运行位置 |
|---|---|---|
| 公网网关 | `gz.itq.cc.cd` / `134.175.48.57` | `/opt/openp2p-selfhost/bin/openp2p-gateway` |
| 目标客户端 | `xrwmaster-selfhost` / `192.168.60.5` | `/home/maoyu/openp2p-selfhost-debug`，用户 `maoyu` |
| 本机客户端 | `wsl-local-selfhost` / WSL Debian | `~/openp2p-dev/deploy/gz-20261031/local-client` |
| TCP 打洞对照客户端 | `wsl-tcp-selfhost` / WSL Debian | `~/openp2p-dev/deploy/gz-20261031/tcp-client` |

网关是独立 systemd 服务 `openp2p-selfhost-gateway.service`，运行用户为 `openp2p-gw`，已设置开机启动。两端客户端为用户目录中的后台调试进程，不设开机启动。

目标客户端仅启用应用层转发，未配置 SD-WAN/TUN。`xrwmaster` 的部署内容位于上述用户目录。

## 已验证

- 公网 WSS `gz.itq.cc.cd:27183`：TLS 1.3，自签 CA 及 DNS SAN 校验成功。
- 网关 API 能看到两个节点在线，客户端版本均为 3.25.11。
- 两端观察到的公网 IP 不同，应用报告的链路为 `udppunch`，底层 QUIC，建链日志 RTT 约 19–20 ms。
- 本机到 `xrwmaster` 的 TCP 转发完成 262144 字节随机数据回传校验。
- UDP 转发完成 1000 字节随机数据回传，收到 `xrwmaster` 标识。
- Windows 本机经 `127.0.0.1:24622` 使用 SSH 密钥登录，远端返回 `hostname=xrwmaster`、`user=maoyu`，并验证了远端 SSH 主机密钥。
- 建链后再次进行 TCP/UDP 校验通过，周期心跳正常。
- 独立节点 `wsl-tcp-selfhost` 的所有应用设置 `PunchPriority=3`（`TCPFirst | TCPOnly`），新建 TCP 打洞隧道成功，日志为 `TCP4 Punch ok`，握手 RTT 约 24 ms。
- TCP 打洞隧道上的 262144 字节 TCP 回传、1000 字节 UDP 应用回传及 Windows SSH 登录均通过；原 UDP/QUIC 节点同时保持可用。

本次没有验证中继数据路径、SD-WAN 虚拟网段或 Docker 运行。

## 本机入口

| 本机入口 | xrwmaster 目标 | 用途 |
|---|---|---|
| WSL `127.0.0.1:24600/TCP` | `127.0.0.1:24400` | TCP echo，连接后先返回主机标识 |
| WSL `127.0.0.1:24601/UDP` | `127.0.0.1:24401` | UDP echo，返回主机标识和数据 |
| Windows / WSL `127.0.0.1:24622/TCP` | `127.0.0.1:22` | SSH，需要 xrwmaster 原有 SSH 身份凭据 |

24600、24601、24622 的转发规则只允许本机回环访问。Windows 到 WSL 的 TCP localhost 转发已验证；UDP 测试在 WSL 内进行。

本轮修复了客户端 UDP 监听器忽略回环白名单的问题，并为实际 socket 绑定补充回归测试。UDP 调试端口现明确绑定 `127.0.0.1`，与 TCP 行为一致。

echo 服务由 `go/gateway/deploy/debug-echo.py` 提供，在 xrwmaster 上仅绑定回环地址 24400、24401。SSH 使用该服务器已有的 22 端口服务。

## TCP 打洞对照入口

| 本机入口 | xrwmaster 目标 | 底层路径 |
|---|---|---|
| WSL `127.0.0.1:24610/TCP` | `127.0.0.1:24400` | TCP 打洞 |
| WSL `127.0.0.1:24611/UDP` | `127.0.0.1:24401` | UDP 应用数据通过 TCP 打洞隧道传送 |
| Windows / WSL `127.0.0.1:24632/TCP` | `127.0.0.1:22` | TCP 打洞，SSH 主机密钥及身份验证通过 |

本次使用独立进程和节点名建立 TCP 隧道，不复用原 `wsl-local-selfhost` 的 QUIC 隧道。`PunchPriority=3` 禁止 UDP 隧道回退；网络类型探测本身仍可使用 UDP。

TCP 成功的证据包括客户端日志 `try TCP4 Punch`、`TCP4 Punch ok` 和两端的实际 TCP 连接表。测试时本机 TCP socket 为 `172.22.91.136:37259 -> 120.231.127.85:13592`，xrwmaster 对应 socket 为 `192.168.60.5:35575 -> 120.239.181.4:27130`。这些是测试时的动态 NAT 端口，不是固定配置值。管理 API 将这种 TCP 链路统一显示为 `ipv4`。

测试发现并修复了网关 TCP NAT 探测的协议问题：客户端发送单字节 `1`，此前网关误用 `io.ReadFull` 等待完整 8 字节头，造成探测超时和端口为 0。现已改为收到探测数据后立即回复观察到的 `IP:port`，补充了真实单字节 socket 回归测试，已更新 gz 服务。

TCP 对照节点的管理命令：

```bash
cd ~/openp2p-dev/deploy/gz-20261031/tcp-client
bash client-control.sh status
bash client-control.sh stop
```

验证记录为 WSL 部署目录下的 `wsl-tcp-selfhost-status.json`、`tcp-punch-transfer-result.json`、`ssh-tcp-result.json`。

## 网关管理

以下命令在 gz 服务器执行：

```bash
systemctl status openp2p-selfhost-gateway.service
systemctl restart openp2p-selfhost-gateway.service
journalctl -u openp2p-selfhost-gateway.service -n 50 --no-pager

curl --cacert /etc/openp2p-selfhost/tls/ca.crt https://127.0.0.1:10008/healthz
python3 /opt/openp2p-selfhost/api.py /api/v1/devices
python3 /opt/openp2p-selfhost/api.py /api/v1/device/wsl-local-selfhost/apps
```

管理 API 仅监听 `127.0.0.1:10008`；节点 WSS 监听公网 27183。UFW 新增规则为 TCP 27180–27181、TCP 27183、UDP 27180–27183，注释均为 `OpenP2P selfhost ...`。

配置与证书：

- `/etc/openp2p-selfhost/gateway.env`：账号密码和安装 token，权限 600。
- `/etc/openp2p-selfhost/credentials.json`：管理工具使用的凭据，权限 600。
- `/etc/openp2p-selfhost/tls/server.crt`、`server.key`、`ca.crt`：服务端证书和私钥；私钥为 `root:openp2p-gw`、权限 640。
- CA 私钥只保存在本机 WSL `~/openp2p-dev/deploy/gz-20261031/certs/ca.key`，未上传到服务器。
- 证书 SAN 包含 `gz.itq.cc.cd`、`134.175.48.57`、`localhost`、`127.0.0.1`、`::1`。

本机部署凭据位于 WSL `~/openp2p-dev/deploy/gz-20261031/credentials.json`，不纳入 Git。

## 客户端状态和日志

xrwmaster：

```bash
cd ~/openp2p-selfhost-debug
bash client-control.sh status
tail -f bin/log/openp2p.log
```

本机 WSL：

```bash
cd ~/openp2p-dev/deploy/gz-20261031/local-client
bash client-control.sh status
tail -f bin/log/openp2p.log
```

两端私有 `client.env` 保存节点 token，`bin/config.json` 保存运行配置与转发规则。分享调试日志时，应隐藏应用密钥、token 等字段。

## 停止本轮调试

两端各自执行 `bash client-control.sh stop` 即可停止对应客户端。xrwmaster 的 echo 服务可用下列精确进程匹配停止：

```bash
pkill -f '^python3 /home/maoyu/openp2p-selfhost-debug/debug-echo[.]py$' || true
```

gz 网关停止与取消自启：

```bash
systemctl disable --now openp2p-selfhost-gateway.service
```

如果同时撤销公网调试端口，仅删除本轮新增的规则：

```bash
ufw delete allow proto tcp from 0.0.0.0/0 to any port 27180:27181
ufw delete allow proto tcp from 0.0.0.0/0 to any port 27183
ufw delete allow proto udp from 0.0.0.0/0 to any port 27180:27183
```

运行状态与数据回传验证记录保存在本机 WSL 的部署目录下：`deployment-status.json`、`transfer-result.json`、`ssh-result.json`。

## 部署二进制 SHA-256

两端客户端已更新为同一构建，并分别执行校验：

```text
客户端（xrwmaster、本机 WSL）
2c49aa9b70e07d113451e278091e1c420632c853f1d31981e211ec691a0b77b5

网关（gz）
685695d19092c22c9953a5ae338ce6364d5c3b1a01a92d6d9bbca33e72176a14
```
