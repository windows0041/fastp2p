# gz C 网关切换与公网测试

日期：2026-11-01。`gz.itq.cc.cd`（134.175.48.57，Debian 12 x86_64）已从 Go 网关切换到 C 网关 0.1.0。使用标签 `c-gateway-v0.1.0` 对应的 Debian 12 发行包，运行时不依赖 Go。

## 当前部署

| 项目 | 值 |
| --- | --- |
| systemd 服务 | `openp2p-selfhost-gateway.service`，沿用原自启设置 |
| 实际程序 | `/opt/openp2p-selfhost/c-gateway/0.1.0-5a6b847/bin/openp2p-gateway-c` |
| 运行账号 | `openp2p-gw`，沿用原服务隔离配置 |
| 切换配置 | `/etc/systemd/system/openp2p-selfhost-gateway.service.d/90-c-gateway.conf` |
| 环境及凭据 | `/etc/openp2p-selfhost/gateway.env`、`credentials.json`，沿用原值 |
| 证书及私钥 | `/etc/openp2p-selfhost/tls/`，沿用原证书链和 DNS SAN |
| WSS / NAT 监听 | `0.0.0.0`，原有 TCP/UDP 端口不变 |
| 管理 API | `127.0.0.1:10008`，未对公网开放 |

新增运行依赖 `libwebsockets17`；未调整防火墙、客户端 token、CA 或转发规则。原 Go 程序 `/opt/openp2p-selfhost/bin/openp2p-gateway` 保留，原主服务文件保持原样，通过 systemd drop-in 切换 ExecStart。

发行包 SHA-256：

```text
088787c5a9868da25d392cac5f6ccd7c506ad3d64333da2721d791ceab75b462
```

服务器上 C 可执行文件 SHA-256：

```text
6fd4d28b9ff93f52e726404183af3c76b2598822cdae95d872b797a060de966c
```

## 公网验证

客户端与目标端观察到不同公网 IP。本机 Go 发起端在切换后重启，临时 C 节点在切换后新建，确保使用新网关建立连接。目标端为 `xrwmaster-selfhost`（192.168.60.5，Go 3.25.11）。

| 发起端 | TCP 打洞：TCP / UDP 应用 | QUIC：TCP / UDP 应用 |
| --- | --- | --- |
| WSL Go 3.25.11，两个独立节点 | 通过 / 通过 | 通过 / 通过 |
| WSL C 0.2.0 | 通过 / 通过 | 通过 / 通过 |
| Windows 原生 C 0.2.0 | 通过 / 通过 | 通过 / 通过 |

每个 TCP 应用校验 262144 字节随机数据及远端 banner，每个 UDP 应用校验 1000 字节随机数据及远端前缀。共 12 组组合通过；C 日志确认实际的 `TCP tunnel connected` 和 `QUIC tunnel connected`。Go TCP 对照节点设置 `PunchPriority=3`，不回退到 UDP 隧道。

另外完成：

- 使用私有 CA 校验 `gz.itq.cc.cd` 的证书链和域名，协商 TLS 1.3；不信任 CA 和错误域名均被拒绝。
- UDP 27180–27183 的地址探测、指定端口回显，TCP 27180/27181 的单字节地址探测。
- JWT 管理鉴权、在线节点列表、真实 Go 客户端异步应用列表查询。
- Windows 经 Go 客户端的 QUIC / TCP 打洞入口登录 xrwmaster，校验 SSH 主机密钥、远端主机名与用户。
- 主动重启 C 网关，Go / C 客户端重新登录；C 客户端自动重建两种隧道，重新校验四组转发。
- 本次 WSL C 客户端约 53.6 秒、Windows C 客户端约 32.1 秒恢复全部转发。公网打洞存在超时及自动重试；此数据仅为本次测试，不代表固定恢复时限。
- 恢复后再等待 35 秒，两端的四组转发再次通过；WSL C 与 Windows C 测试程序均正常退出。Go 客户端也在第二次网关重启后完成 TCP / QUIC 两种隧道的 TCP/UDP 回传。

首次在网关重启后固定等待 35 秒便直接发起检查，遇到 TCP 等待超时；日志显示后续隧道仍自动建成。第二轮改为等待实际转发恢复并计时，再验证恢复后的心跳。客户端或网关程序未因此改动。

临时测试的 C 客户端使用独立节点名和回环监听端口。私有 token、配置、证书及原始日志不上传 Git。当前长期客户端仍为 xrwmaster 与本机原有的 Go 调试进程；临时 C 测试程序在测试结束后退出。

不含凭据的结构化结果见 [validation-20261101.json](validation-20261101.json)。

## 运维和回退

在 gz 上查询当前服务：

```bash
systemctl status openp2p-selfhost-gateway.service
readlink /proc/$(systemctl show openp2p-selfhost-gateway.service -p MainPID --value)/exe
curl --cacert /etc/openp2p-selfhost/tls/ca.crt https://127.0.0.1:10008/healthz
python3 /opt/openp2p-selfhost/api.py /api/v1/devices
```

健康检查应返回 `{"status":"ok","implementation":"c","version":"0.1.0"}`。服务仍由 systemd 管理，机器启动后会沿用此 C 程序。

切换前已保存原服务文件及 Go 二进制校验值。需要回到 Go 时，以 root 执行：

```bash
bash /root/openp2p-c-gateway-cutover-20261101T053642Z/rollback.sh
```

此脚本将本轮 drop-in 移出配置目录、重新加载 systemd、重启原 Go 程序，并检查 HTTPS 健康接口。切换阶段已配置启动失败自动调用此脚本；本轮 C 启动成功，未执行主动回切测试。

应用转发和 SSH 的固定入口沿用 [Go 客户端部署记录](../../../go/gateway/deploy/REMOTE-DEBUG-ZH.md)。此处没有验证公网中继数据面、完整 SD-WAN/TUN、其他 NAT 类型或长时间压力。
