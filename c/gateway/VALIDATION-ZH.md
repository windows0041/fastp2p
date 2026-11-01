# C 网关验证记录

## 0.2.0 Web 控制台与发布

2026-11-01 在 WSL Debian 13 的 ASan/UBSan 网关及真实 C 0.3 客户端上完成浏览器集成测试，使用临时随机账号、自签 CA 和独立端口。测试覆盖登录成功/失败、状态和节点查询、uint64 安装 Token 的精确显示与隐藏、搜索、真实 C 客户端中文规则新增与回读、C 管理能力限制、Go 节点规则编辑/开关/删除、会话过期、节点离线和退出。Go 管理操作使用协议测试对端，真实 Go/C 转发另由六客户端集成测试覆盖。

桌面与 390px 移动视口均检查了页面布局和横向溢出。恶意节点/规则字段作为文本显示，未执行脚本；静态资源检查 MIME、CSP、禁止缓存、管理/WSS 监听分离、私钥路径不可访问。登录 JWT 及安装 Token 不写入浏览器持久存储。

协议测试新增无效 UTF-8、中文/emoji、未转义控制字符及旧版 C 客户端严格 JSON 解码回归。Debian 12 的 json-c 0.16 和 Debian 13 的 json-c 0.18 均纳入 CI。发布脚本覆盖缺失/重复产物、SHA-256 清单、Android SDK 可重现打包、私钥拒绝、先草稿后发布及上传校验失败时不发布。CI 工作流另执行 Docker 版本/TLS 健康检查和六客户端 TCP 打洞/QUIC 重连测试。

构建状态见 [C gateway 工作流](https://github.com/windows0041/openp2p-test/actions/workflows/c-gateway.yml)，成功的原生包与 Docker 镜像见 [Releases](https://github.com/windows0041/openp2p-test/releases)。发布策略见 [发布说明](https://github.com/windows0041/openp2p-test/blob/main/RELEASING-ZH.md)。公网更新记录在部署完成后另行追加，下文保留 0.1.0 的互通基线。

## 0.1.0 互通基线

日期：2026-11-01。此版本为独立 Linux C 网关，运行时不调用 Go。Go 3.25.11 与 C 0.2.0 客户端作为互通测试对端，客户端源码及 Go 网关未修改。

## 环境与构建

- 本机 WSL Debian 13 x86_64：GCC 14、libwebsockets 4.3.5、json-c 0.18、OpenSSL 3.5.7。
- GitHub Actions：Debian 12 / 13 x86_64 独立构建，分别链接该发行版的系统依赖；测试用 C 客户端使用锁定的 OpenSSL 3.5 / ngtcp2 依赖，Go 参考客户端使用 Go 1.20.14。
- 网关和 C 客户端的完整互通测试均开启 AddressSanitizer / UndefinedBehaviorSanitizer；另外构建无 sanitizer 的 Release 网关发行包。
- [CI 与发行包](https://github.com/windows0041/openp2p-test/actions/runs/41273082557)，实现提交 `175ef41`；后续文档提交不改变程序或测试。

## 协议与生命周期

单元测试覆盖 CRC64/ISO、大小端编码、uint64 上限及溢出、严格 JSON、Go 参考 TOTP 测试向量、JWT 签发与校验。隔离 network namespace 的网络测试覆盖：

- 自有 CA 信任校验，HTTPS 与 WSS 监听分离，两种 WSS 登录路径，错误路径/凭据拒绝。
- HS256 JWT 的算法、签名、时效和安装 token 检查；保留大于 JavaScript 精确整数范围的 uint64。
- 四个 UDP NAT 端口与指定端口回显；两个 TCP 端口的单字节探测和观测地址回显。
- TOTP 对端查询、双向且有时限的配对授权、拒绝传递授权和伪造发送者。
- WebSocket 分片、96 KiB 消息、合并协议帧、异常长度帧和队列处理。
- SD-WAN 成员配置筛选，中继节点选择及协调消息。
- 异步应用列表、编辑、开关与重启消息；同节点并发返回 409，等待超时返回 504，节点断线返回 503。
- 重复登录替换旧连接并撤销授权，80 次会话开关后无文件描述符增长，40 次 HTTP keep-alive 请求。
- HTTP 方法、空请求体、错误 JSON、嵌入 NUL 的凭据、超大请求体处理；容量上限与空闲超时。
- SIGTERM 正常退出，未发现 sanitizer 报错。

## Go / C 客户端互通

六个真实客户端使用不同虚拟网络地址连接 C 网关，以避免同机局域网直连捷径。C→Go、Go→C、C→C 各执行以下四项，总计 12 组数据回传全部通过：

| 隧道传输 | 应用 | 每组回传数据 |
| --- | --- | --- |
| TCP 打洞 | TCP | 262144 字节随机数据 |
| TCP 打洞 | UDP | 1000 字节随机数据 |
| UDP 打洞 / QUIC | TCP | 262144 字节随机数据 |
| UDP 打洞 / QUIC | UDP | 1000 字节随机数据 |

另外检查日志中的实际隧道类型、对端断开前最后 TCP 响应完整排空、35 秒心跳后继续转发，以及网关重启后 C 客户端重新鉴权、重建隧道。ASan/UBSan 下正常停止，未发现内存错误。

## 部署产物与范围

CI 输出 `openp2p-c-gateway-debian12-x86_64.tar.gz`、`openp2p-c-gateway-debian13-x86_64.tar.gz`，包含可执行程序、说明、许可证和 systemd 模板。Debian 12 Docker 镜像完成构建、版本检查和使用自有 CA 的 HTTPS 健康检查；未把 Docker 中的端到端 NAT 路径计入上述互通测试。

上述 CI 测试验证控制协议和隔离 Linux 网络中的客户端互通。随后已将 `gz.itq.cc.cd` 切换到同版 C 网关，新增 WSL Go、WSL C、Windows 原生 C 与 xrwmaster Go 节点的公网 TCP 打洞 / QUIC、TCP/UDP 转发、TLS/NAT 及网关重启恢复验证，详见 [公网切换记录](deploy/REMOTE-DEBUG-ZH.md)。未新增 Android、macOS 连接 C 网关的实机回归，未扩展到其他公网 NAT 类型。SD-WAN 配置与中继协调已测，不代表完整 TUN 或中继业务数据路径已测。

运行方法见 [README](README.md)。测试使用随机临时凭据和证书；CI 仅上传不含凭据的布尔结果，不上传原始客户端日志。
