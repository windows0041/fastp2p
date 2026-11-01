# C 客户端验证记录

## 0.4.0 主机名与稳定身份

[跨平台 CI 41298212833](https://github.com/windows0041/openp2p-test/actions/runs/41298212833)，实现提交 `b3abb4b6864023abeed05179f0fefc6368ba8bf4`，Linux、Windows、macOS arm64/x86_64 和 Android 的五个作业全部通过。新增 API 不改变结构体布局，ABI 保持 1；Windows MSVC 消费者、Android APK/lint 和原有 TLS/QUIC/SOCKS5 检查继续通过。

Linux/macOS/Windows 均执行真实 CLI 身份文件测试，覆盖自动生成、再次读取、损坏文件拒绝及显式节点名兼容；POSIX 平台另验证 0600 权限和符号链接拒绝。C API 测试覆盖自动名称、身份查询/设置和无节点字段的 JSON 工厂。

[网关 CI 41298212839](https://github.com/windows0041/openp2p-test/actions/runs/41298212839) 的 Debian 12/13 作业使用真实 C 0.4 客户端，验证短主机名数字补齐、重复主机名唯一分配、客户端重启、网关崩溃恢复和最终名称下的 TCP/QUIC 转发，均开启 ASan/UBSan。Android 共用同一自动命名核心和私有设备标识保存流程；本轮未增加 Android/macOS 的公网设备回归。

配置及库接口见 [节点存储和命名](../NODE-STORAGE-ZH.md)。下文保留此前验证基线。

# C 客户端验证记录

## 0.3.0 SOCKS5（2026-11-01）

公开 ABI 保持 1，增加 `op2p_client_add_socks5`，共导出 12 个 C API。入口和出口均使用 C 0.3.0；普通固定转发继续兼容 Go 3.25.11。

[CI 运行与 SDK 发行包](https://github.com/windows0041/openp2p-test/actions/runs/41284347086)，提交 `7cfe0dfbcd12550d7479f5bb9ba2b9e6fb74c8bb` 的 Linux、macOS arm64、macOS x86_64、交叉构建及 Windows 原生共五个作业全部通过。后续文档及 Android 设备测试代码调整未修改运行时核心。

- Debian 12 原生、WSL Debian 13 ASan/UBSan、Windows 原生、两种 macOS 原生均完成 SOCKS5 端到端测试。覆盖 TCP/QUIC、IPv4/域名、无认证/用户名密码认证、TCP CONNECT、UDP ASSOCIATE、多目标 UDP 和 0/1000/4096 字节数据报。
- 12 个并发 TCP 请求混合成功目标及拒绝连接目标，验证按连接 ID 确认和错误隔离；另覆盖逐字节握手、合并握手与提前发送的 16000 字节数据、错误密码、无可用认证方式、BIND/IPv6/错误保留字拒绝、UDP 来源端口限制、分片丢弃和关联关闭。
- 80 次握手断开循环，Linux 检查文件描述符无增长；各平台保留原有 C ABI 生命周期和句柄检查。Linux/本机 Windows 另验证旧 Go 出口被拒绝，不返回虚假的 CONNECT 成功。
- 关闭并重新启动测试网关，新建 SOCKS5 会话恢复；再等待 35 秒，两个隧道中的 TCP/UDP 代理仍正常。Linux 网关和客户端 sanitizer 检查未发现内存错误。
- 原有 Go→C、C→Go、C→C 共 12 组固定转发、最后 TCP 响应、心跳和网关重启回归全部通过；macOS/Windows 保留原有 Go/C 转发、独立双向 QUIC 与安装后 SDK 消费验证。Windows MSVC 消费者也链接并验证新增 API。

公网测试中，Windows 原生入口通过 `gz.itq.cc.cd` C 网关连接 `c-xrw-socks-exit`，经 TCP 打洞 / QUIC 分别完成 262144 字节 TCP 和 1000 字节 UDP 回传、SSH 主机密钥/账号校验及 35 秒后再次转发。网关和原有 Go 客户端未替换。

Android 双 ABI 构建、lint、12 个公开符号边界和 16 KB ELF/APK 对齐检查通过。已连接的 Android 12 / x86_64 设备通过 Activity → Service → JNI → C 路径连接 WSL C 出口，两个隧道均完成 SOCKS5 TCP/UDP、用户名密码认证、私有 CA、加密配置保存、35 秒后台心跳、停止及重新启动验证；同轮 Go 固定转发四组也通过。arm64 已构建，未新增 ARM 实机运行覆盖。

Android 首轮到 xrwmaster 的固定 TCP 打洞未通过；切换到不同公网地址的 WSL 对端后通过。后续 SOCKS5 测试又修正了 echo 端口配置和 Windows ADB 输出的 UTF-8 解码，最终完整设备测试通过。此处不将首轮同公网地址回流路径记为已验证，也不据此宣称覆盖所有 NAT 拓扑。

实际入口、进程管理与不含凭据的结果见 [SOCKS5 公网部署记录](deploy/SOCKS5-DEBUG-ZH.md)，配置与限制见 [SOCKS5-ZH.md](SOCKS5-ZH.md)。

## 0.2.0 跨平台验证（2026-11-01）

公开接口保持 ABI 1。Windows / Android / macOS 使用固定依赖：OpenSSL 3.5.7、ngtcp2 1.22.1、curl 8.23.0、json-c 0.18；Linux 系统 GnuTLS 后端继续回归。运行时无需 Go，Go 1.20.14 仅用于构建协议参考对端。

Windows x86_64 在本机原生运行 CLI / DLL，已通过协议/加密、地址比较、非阻塞 socket、时钟、ABI / uint64 JSON 工厂及 40 次生命周期句柄计数检查。错误 CA、错误主机名均在 HTTP 登录请求前被拒绝，有效 CA 允许 TLS。独立 QUIC 覆盖 C 和 Go 两种客户端/服务端角色。

Windows 与真实 Go 网关、Go/C 目的节点的 8 组转发均通过。另以独立临时节点经 `gz.itq.cc.cd` 连接 `xrwmaster-selfhost`，验证 TCP 打洞 / QUIC 各自的 TCP 应用 262144 字节、UDP 应用 1000 字节回传；核对两种隧道日志，35 秒后再次转发通过，程序正常退出。

Android 应用安装到 ADB 连接的 Android 12 / API 31 / x86_64 设备，通过真实 Activity → 前台服务 → JNI → C 核心路径运行。经同一公网网关连接远端 Go 节点，四种转发组合均通过，数据量同 Windows；后台心跳 35 秒、主动断开、再次连接、第二次资源释放和平台 CA 导出均通过。arm64-v8a 已构建，尚未在 ARM 设备上运行。

Android APK 同时包含两种 ABI 的独立 C 库和 JNI 库。已检查各库 ELF 架构、11 个公开 C 符号的导出边界、16 KB ELF 与 APK 对齐，以及完整第三方许可证。Gradle 构建与 lint 通过；16 KB 检查属于产物验证，未代替 16 KB 页大小设备上的实际运行。

更新后的 Linux 核心通过常规与 ASan/UBSan 组件测试、独立双向 QUIC，以及六节点完整互通回归。12 组转发、TCP 最后响应数据、35 秒心跳、网关重启重连均通过，退出日志无 Sanitizer / undefined behavior 报错。

macOS arm64 / x86_64 分别在 `macos-15` 与 `macos-15-intel` 原生 runner 上通过构建、安装后 SDK 消费、4 项组件检查、严格 CA/主机名验证、C/Go 双向 QUIC、原生 C WSS 鉴权探针及 C→Go / C→C 的 8 组应用转发。编译与运行中的 ngtcp2 均核对为 1.22.1；修复了 BSD 地址长度/填充比较问题，并固定第三方头文件优先级，防止混入系统版本。

Windows 在 `windows-2022` 原生 runner 上重复通过协议、TLS、QUIC 与 8 组转发，并使用 Visual Studio MSVC 编译独立 CMake 消费项目，链接 MinGW 构建的 DLL，验证 C ABI、JSON 工厂、回调和句柄生命周期。

固定 OpenSSL QUIC 后端还在 Linux 上通过 ASan/UBSan 的 4 项组件检查及 C/Go 双向 QUIC。该项覆盖新后端的内存检查；前述六节点完整 sanitizer 回归使用 Linux 系统 GnuTLS 后端。

四项 CI 作业全部成功，代码提交为 `c0bf49253d31437e92613b087531e078e9fb400e`：[完整运行记录与 SDK 产物](https://github.com/windows0041/openp2p-test/actions/runs/41268179414)。当前平台边界和使用方法见 [PLATFORMS-ZH.md](PLATFORMS-ZH.md)。本轮保留现有 Go 部署，Windows 和 Android 使用独立 C 测试节点，测试后已停止连接。

## 0.1.0 Linux 首版

日期：2026-11-01。C 程序版本 0.1.0，公开接口 ABI 1。参考对端为本仓库 Go 客户端 3.25.11 和自建 Go 网关。测试没有替换现有 Go 部署。

## 开发环境

WSL Debian 13 / x86_64，GCC 14.2、CMake 3.31、libcurl 8.14.1、ngtcp2 1.11.0、GnuTLS 3.8.9、json-c 0.18、OpenSSL 3.5.7。

## 单元和组件检查

- 8 字节小端头、逐字节分片、同次读取多个帧、超长及畸形输入。
- uint64 大于 `2^53` 及最大值的无损解析；超出 uint64 范围时拒绝消息。
- 兼容 AES-128-CBC/PKCS#7 的加解密、无效填充和非法块长度。
- ABI/配置校验、回调内请求停止、重复创建/启停/销毁，文件描述符数量保持一致。
- 有效 CA/主机名允许 TLS；不信任的 CA 和可信 CA 下的错误主机名均在含 token 的 HTTP 登录请求发送之前被拒绝。
- 独立 QUIC 测试覆盖 C 客户端→Go 服务端、Go 客户端→C 服务端，使用 `openp2pv1`、实际 OpenP2P 帧和 Go 原有临时证书形式。

普通构建与 ASan/UBSan 构建的检查均通过。

## 六节点隔离网络互通

使用真实 Go 网关、三种方向及两种隧道：

| 方向 | 隧道 | TCP 应用回传 | UDP 应用回传 |
|---|---|---:|---:|
| C→Go | TCP 打洞 | 262144 字节 | 1000 字节 |
| C→Go | UDP 打洞 / QUIC | 262144 字节 | 1000 字节 |
| Go→C | TCP 打洞 | 262144 字节 | 1000 字节 |
| Go→C | UDP 打洞 / QUIC | 262144 字节 | 1000 字节 |
| C→C | TCP 打洞 | 262144 字节 | 1000 字节 |
| C→C | UDP 打洞 / QUIC | 262144 字节 | 1000 字节 |

Go 发起端运行在不同 network namespace，以 veth 分配不同 IP。测试同时核对隧道日志，避免内网 TCP 捷径被误记为 QUIC 或 TCP 打洞。此处是隔离的路由网络，不将它作为真实公网 NAT 测试。

安装 token 取大于 `INT64_MAX` 的随机 uint64，六个节点登录与应用授权均通过。等待 35 秒后，全部转发再次校验通过。停止并重新启动测试网关后，C 客户端重新登录、重建隧道，C→C 两种隧道的 TCP/UDP 回传再次通过。

另覆盖发送 32768 字节后立即关闭的 TCP 服务：三种方向和两种隧道均在连接关闭前完整交付末尾响应，避免对端断开消息与最后的数据在同次读取时丢失已排队的响应。

同样的完整集成测试已在 ASan/UBSan 构建下通过，进程正常释放资源退出。

## 公网实测

本机 WSL 临时运行独立 C 节点 `c-wsl-selfhost-test`，通过现有 `gz.itq.cc.cd` 网关连接 `xrwmaster-selfhost` Go 节点。

- TCP 打洞隧道：262144 字节随机 TCP 数据回传、1000 字节 UDP 数据回传，均匹配。
- UDP 打洞 / QUIC 隧道：相同大小的 TCP、UDP 随机数据回传，均匹配。
- TCP 回传先验证 `xrwmaster-OPENP2P-ECHO` 标识；UDP 回传验证 `xrwmaster` 前缀。
- 客户端日志分别出现 `TCP tunnel connected`、`QUIC tunnel connected`。首次 TCP 建链曾超时，自动重试后成功完成校验。
- 临时 C 节点在测试结束后停止，现有 Go 网关和客户端保持原部署。

运行 token、CA 文件、客户端日志和原始结果只保存在本机私有运行目录，不纳入仓库。

## 尚未覆盖

Windows/Android、IPv6、对称 NAT 扫描策略、UPnP/NAT-PMP、中继、SD-WAN/TUN、长时间压力测试、故障网络下的吞吐及丢包恢复性能，均不属于本轮已验证范围。Debian 12 的 C 依赖适配和远端 C 客户端部署尚未完成。
