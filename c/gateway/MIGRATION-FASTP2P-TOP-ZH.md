# fastp2p.top 迁移验收（2026-11-02）

网关已迁移到 `fastp2p.top / 139.199.4.226`（Debian 12 KVM），使用正式域名证书。原四个客户端已迁移，版本为 2.0.1；旧网关已停止并禁用自动启动，原配置、数据库和二进制保留用于回退。

| 项目 | 迁移结果 |
| --- | --- |
| 旧服务器 | gz.itq.cc.cd / 134.175.48.57，保留回退材料 |
| 新服务 | fastp2p-gateway.service，专用 fastp2p-gw 账号 |
| 证书域名 | fastp2p.top、www.fastp2p.top |
| 叶证书到期 | 2027-01-30 11:59:59 UTC（北京时间 19:59:59） |
| 信任链 | TrustAsia DV TLS RSA CA 2024 → TrustAsia TLS RSA Root CA（交叉签名）→ Certum Trusted Network CA |
| 客户端专用配置 | fastp2p.top:27183，内置公共 Certum 根 |
| 数据 | SQLite schema 2；管理账号哈希、会话密钥、原节点名与 DeviceID、16 位 Token 均经比对保持一致 |
| 管理端 | 仅 127.0.0.1:10008，经 SSH 转发访问 |

新服务器私钥位于 `/etc/fastp2p/tls/server.key`，root 持有、服务组可读；完整证书链和公共根分别为 `server.crt`、`ca.crt`。私钥未进入 Git 或 CI 包。UFW 保留原规则，仅增加 TCP 27180–27181、27183 和 UDP 27180–27183。新服务器原有其他服务保持运行。

最终同步前已停止旧网关写入，并使用 SQLite 备份接口复制一致的数据库。备份目录为旧服务器 `/root/fastp2p-domain-migration-20261102T132256`；客户端旧配置和程序保存在各机私有备份目录。

## 本机解析

Windows WLAN 的路由器 DNS 原先返回 198.18.* 代理虚拟 IP，该路径 TLS 超时。用户已在本机 Windows hosts 中添加：

```text
139.199.4.226 fastp2p.top
```

Windows 与 WSL 均已核对解析为真实 IP；安卓和 xrwmaster 原本即解析到真实 IP。路由器未作修改。以后更换服务器 IP 时应同步修改或移除此 hosts 定向。

## SSH 管理入口

在本机终端使用现有服务器 SSH 登录方式，保持以下转发运行：

```sh
ssh -N -L 127.0.0.1:11008:127.0.0.1:10008 root@139.199.4.226
```

正式证书只包含域名，浏览器应使用 `fastp2p.top` 作为 TLS 名称。Windows 可在另一终端启动专用 Edge 窗口，只把该窗口中的域名映射到本机 SSH 端口：

```powershell
& "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --user-data-dir="$env:TEMP\fastp2p-ssh-admin" --host-resolver-rules="MAP fastp2p.top 127.0.0.1" --no-proxy-server "https://fastp2p.top:11008/"
```

此命令只影响该独立浏览器窗口；系统 hosts 中供 P2P 客户端使用的映射仍保持 139.199.4.226。证书及主机名正常校验，不需要忽略 HTTPS 错误。已通过同样方式验收登录页和健康接口，管理账号密码沿用原值。

## 客户端与转发验收

- Windows、WSL、xrwmaster 和安卓均保留原 DeviceID、节点名及已保存配置。Windows 与 Linux 安装器验证新网关后再保存；安卓安装同签名 CI APK 后显式迁移，设备身份保留且无 Token 重连通过。
- Windows SOCKS5：1080（QUIC）及 1081（TCP 打洞）的 TCP 256 KiB、UDP 1000 字节、SSH 主机密钥与身份、35 秒心跳通过。
- WSL 的两种传输均验证 TCP、UDP、SSH 共六条规则；UDP 在监听所在的 Linux 环境验证。
- 安卓通过 Windows 同网段验证 QUIC/TCP 实际数据通道；签名 APK 由 CI 产出。
- 修复中继跳与本机直连属于同一对端时的互相替换；只有已认证的端点会话才能绑定本机规则，中间跳保持隔离。
- 同一对端、同一传输的规则共享中继请求；等待超过 20 秒会重试。隔离测试覆盖多规则、中继节点自身直连及对端重启恢复。

证书链、域名与私钥匹配已校验，公网 TLS 1.3 连接验证通过；数据库 quick_check 为 ok。客户端固定公共根而非短期叶证书，同域名、同信任链续期无需再次分发客户端。
