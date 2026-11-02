# fastp2p 部署验收（2026-11-02）

## 2.0.0 已部署

网关 `gz.itq.cc.cd` 与四台客户端（Windows、WSL、xrwmaster、安卓）均已升级到 2.0.0，全部在线。回退备份位于服务器 `/root/fastp2p-backup-20261102-*`（含旧二进制、数据库快照、环境变量与凭据文件）。

| 项目 | 2.0.0 行为 |
| --- | --- |
| 隧道载荷 | AES-256-GCM，会话密钥由发起端经网关 TLS 通道分发；每方向独立密钥，64 位序号加滑动窗口防重放 |
| 中继 | 打洞失败两次或双方都是对称 NAT 时，网关提供第三节点，两端各自打洞到中继并配对；中继只转发密文，单节点最多同时中继 4 条会话 |
| LAN 直连 | 两端都有对方私有地址时优先用私有地址和本地端口打洞，不依赖 NAT 发夹；两次不成功仍回退中继 |
| QUIC | 每进程一张 EC P-256 证书，默认安全等级；端点通过密封隧道核对证书指纹，不匹配即断开 |
| 会话配对 | 直连密钥和 ACK 携带握手确认的 64 位 `tunnelID`，同时核对对端和传输；不按 NAT 端口或“最新隧道”猜测；重复推送不重置加密序号 |
| 删除项 | SD-WAN 配置下发、GnuTLS 后端、AES-128-CBC 载荷、appKey 与隧道同步推送 |

实测结果（2026-11-02）：

| 验证 | 结果 |
| --- | --- |
| 四节点认证与在线 | 通过 |
| Windows → xrwmaster TCP 转发（LAN 直连） | 通过，连续 6 次采样 5 次返回对端 SSH banner，一次在链路重建 |
| Windows → WSL TCP 转发（LAN 直连） | 通过 |
| 打洞不可达时自动升级中继 | 通过（`check-escalation.sh`，两个 netns 端点 + 宿主机不转发） |
| 中继承载数据 | 通过（强制中继下 QUIC 回显） |
| 同子网可达后回到直连 | 通过（`check-escalation.sh` 第二阶段） |
| Windows → xrwmaster QUIC 转发 | 修复后通过：两台真机的临时测试节点，三次重连，256 KiB TCP / 1000 字节 UDP，持续 40 秒采样；两端日志无认证失败，规则均保持直连，未挂中继 |

QUIC 规则只有在会话密钥与证书指纹均校验通过后才启用。回归用例复现 NAT 映射端口与旧本地端口碰撞造成的错绑，旧代码失败、修补版通过；另覆盖延迟密钥、旧 ACK、重复/冲突密钥和重试会话隔离。直连重试及切换中继都使用新会话，避免复用 AEAD 密钥和序号。早期 2.0.0 开发包需要统一升级到包含此修复的稳定包。

升级顺序（网关先，客户端后；期间旧客户端会登录失败）：

1. 备份 `/var/lib/fastp2p/nodes.sqlite3`（schema 仍为 2，节点名与 DeviceID 保留）。
2. 停止 `fastp2p-gateway.service`，替换二进制，保留原证书、Token、数据库和环境变量。
3. 启动后确认 `{"event":"ready","version":"2.0.0"}` 与 `curl --cacert ca.crt https://127.0.0.1:10008/healthz`。
4. 逐个升级客户端；已安装的客户端可用同一 16 位 Token 重新 `install`，DeviceID 与节点名不变。
5. 四节点全部在线后，用一个打洞不可达的组合确认 `relay session paired` 出现在中继节点日志中。

下面 1.0.x 的验收记录保留作为回退参考；回退需要同时恢复旧网关二进制、旧客户端和升级前的数据库快照。

## 1.0.x 验收记录

网关和客户端已切换为 C 实现及 `fastp2p1` 协议，QUIC ALPN 为 `fastp2pv1`。主分支只维护 C 版本，旧 Go 代码保留在 Git 历史。

## 已部署版本

| 角色 | 位置 | 版本及运行方式 |
| --- | --- | --- |
| 网关 | gz.itq.cc.cd | 1.0.1，`fastp2p-gateway.service` |
| Linux 客户端 | xrwmaster | 1.0.2，`fastp2p-client.service` |
| Windows 客户端 | 本机 | 1.0.2，后台进程、当前用户登录自启 |
| Linux 开发客户端 | 本机 WSL Debian | 1.0.2，`fastp2p-client.service` |
| Android 客户端 | 实机 | 1.0.2，签名 APK、前台服务、加密配置恢复 |

四个现有设备的 DeviceID 与节点名均保留。最终调试会话核对四节点在线；在线状态会随设备休眠、断网和 WSL 关闭而变化。WSL 的 systemd 服务不会阻止发行版空闲关闭，持续调试时应保持 WSL 会话运行。Windows 客户端独立运行，不依赖 WSL；日常启动使用安装器登记的当前用户登录项。

客户端配置由专用包预置网关地址和公开 CA，安装时只需 **16 位数字 Token，首位非零**。实际 Token、管理密码、签名私钥和 CA 私钥均未进入 Git 或 Release。现有网关自签 CA 与包内 CA 已逐字节核对一致。客户端先验证证书链、主机名和登录结果，再保存配置。

## 管理入口

网关管理服务仅监听服务器 `127.0.0.1:10008`。在本机终端保持 SSH 转发运行：

```sh
ssh -N -L 127.0.0.1:11008:127.0.0.1:10008 root@gz.itq.cc.cd
```

随后访问 <https://127.0.0.1:11008/>。SSH 使用已有服务器登录方式；浏览器需要信任该网关的公开自签 CA。此转发只提供本机访问，不开放公网管理端口。

Web 右上角“账号设置”可修改账号和密码，需输入当前密码。账号保存在 SQLite，环境变量只用于首次初始化。修改后旧会话失效，节点 Token 与连接保持不变。忘记密码时按 [网关说明](README.md) 的 `--reset-admin` 流程恢复。

离线节点可以在列表中确认删除；在线节点拒绝删除。删除登记记录不撤销接入 Token，仍持有效 Token 的设备再次上线会重新登记。

SQLite 位于 `/var/lib/fastp2p/nodes.sqlite3`，schema 2，回滚日志 `DELETE`，程序采用 `synchronous=FULL`。最终 `quick_check` 为 `ok`。升级前程序、数据库与配置快照已保留在服务器私有备份目录；回退旧 schema 的程序时须同步恢复对应数据库快照。

## 端口与验证

网关 WSS 为 TCP 27183；TCP NAT 为 27180–27181；UDP NAT 为 27180–27183。Windows SOCKS5 仅监听本机：1080 使用 QUIC，1081 使用 TCP 打洞，出口均为 xrwmaster。

| 验证 | 结果 |
| --- | --- |
| Windows SOCKS5 经 QUIC / TCP 打洞 | 两种传输的 256 KiB TCP、1000 字节 UDP、SSH 主机密钥与身份验证、35 秒心跳均通过 |
| Android C 数据通道 | QUIC、TCP 实际 ADB 转发均通过 |
| Android 接入与恢复 | 仅 Token 接入、加密配置保存、无 Token 重连通过；升级保留设备身份 |
| Web 实机浏览器 | 登录、16 位 Token、安卓接入链接、账号当前密码校验、一次性离线测试节点删除、桌面及移动布局通过 |
| Linux 服务权限 | root 持有配置和 CA，组只读 0640、目录 0750；服务账号不能写配置 |
| Windows 安装 | 已安装 EXE 的 SHA-256 与发布候选产物一致，当前用户登录项有效 |
| 自动化集成 | 六个真实 C 客户端的 12 种转发组合、网关重启、SQLite 恢复及账号会话撤销通过 |

实机 Web 验证未修改现有管理账号；完整账号更改、重登、重启持久化和忘记密码恢复在隔离集成测试中通过。macOS ARM64 / Intel 在 GitHub 原生 runner 验证，未在用户的 Mac 实机部署。

## 已公开产物

- [客户端 1.0.2](https://github.com/windows0041/fastp2p/releases/tag/fastp2p-client-v1.0.2)：Windows EXE、Linux 可执行文件、macOS 双架构可执行文件、Android APK，以及独立 C SDK 和 SHA256SUMS.txt。
- [网关 1.0.1](https://github.com/windows0041/fastp2p/releases/tag/fastp2p-gateway-v1.0.1)：Debian 12/13 网关包、Docker 镜像归档和 SHA256SUMS.txt。
- [客户端 CI](https://github.com/windows0041/fastp2p/actions/runs/41321183816) 与 [网关 CI](https://github.com/windows0041/fastp2p/actions/runs/41320065551) 均成功，稳定 Release 已公开。

桌面安装及 Android 接入命令见 [项目 README](../../README.md)。部署其他网关或更换地址 / CA 时，应更新公开 `c/common/bootstrap.json` 并重新构建专用客户端；勿将接入 Token 或私钥写入此文件。
