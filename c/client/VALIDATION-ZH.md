# C 客户端验证记录

## 0.2.0 跨平台验证（2026-11-01）

公开接口保持 ABI 1。Windows / Android / macOS 使用固定依赖：OpenSSL 3.5.7、ngtcp2 1.22.1、curl 8.23.0、json-c 0.18；Linux 系统 GnuTLS 后端继续回归。运行时无需 Go，Go 1.20.14 仅用于构建协议参考对端。

Windows x86_64 在本机原生运行 CLI / DLL，已通过协议/加密、地址比较、非阻塞 socket、时钟、ABI / uint64 JSON 工厂及 40 次生命周期句柄计数检查。错误 CA、错误主机名均在 HTTP 登录请求前被拒绝，有效 CA 允许 TLS。独立 QUIC 覆盖 C 和 Go 两种客户端/服务端角色。

Windows 与真实 Go 网关、Go/C 目的节点的 8 组转发均通过。另以独立临时节点经 `gz.itq.cc.cd` 连接 `xrwmaster-selfhost`，验证 TCP 打洞 / QUIC 各自的 TCP 应用 262144 字节、UDP 应用 1000 字节回传；核对两种隧道日志，35 秒后再次转发通过，程序正常退出。

Android 应用安装到 ADB 连接的 Android 12 / API 31 / x86_64 设备，通过真实 Activity → 前台服务 → JNI → C 核心路径运行。经同一公网网关连接远端 Go 节点，四种转发组合均通过，数据量同 Windows；后台心跳 35 秒、主动断开、再次连接、第二次资源释放和平台 CA 导出均通过。arm64-v8a 已构建，尚未在 ARM 设备上运行。

Android APK 同时包含两种 ABI 的独立 C 库和 JNI 库。已检查各库 ELF 架构、11 个公开 C 符号的导出边界、16 KB ELF 与 APK 对齐，以及完整第三方许可证。Gradle 构建与 lint 通过；16 KB 检查属于产物验证，未代替 16 KB 页大小设备上的实际运行。

更新后的 Linux 核心通过常规与 ASan/UBSan 组件测试、独立双向 QUIC，以及六节点完整互通回归。12 组转发、TCP 最后响应数据、35 秒心跳、网关重启重连均通过，退出日志无 Sanitizer / undefined behavior 报错。

macOS 两架构原生测试及 MSVC 消费 DLL 的运行结果随平台工作流记录。当前平台边界和使用方法见 [PLATFORMS-ZH.md](PLATFORMS-ZH.md)。本轮保留现有 Go 部署，Windows 和 Android 使用独立 C 测试节点，测试后已停止连接。

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
