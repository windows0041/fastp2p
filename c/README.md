# C 版本

本目录与 `go/` 分开维护，客户端和网关均为独立 C 实现，运行时不依赖 Go。

- [client/](client/)：0.2.0，Linux / Windows / macOS CLI 和 ABI 1 C 库，以及 Android 应用。实现 TLS/WSS、NAT 探测、TCP 打洞、UDP 打洞/QUIC 及 TCP/UDP 应用转发。
- [gateway/](gateway/)：0.1.0，Linux HTTPS/WSS 网关，提供自有 TLS 证书、鉴权、节点发现、NAT 探测、连接与中继协调、SD-WAN 配置分发、应用管理及 systemd / Docker 部署文件。

客户端通过不透明句柄、ABI 版本和 `struct_size` 提供创建、启动、轮询、停止、销毁、转发规则与事件接口。QUIC 使用 ngtcp2（OpenSSL 3.5 或 Linux GnuTLS 后端），WSS 使用 libcurl。网关使用 libwebsockets、OpenSSL 和 json-c，业务数据不经过网关。

Go 网关和 C 网关均已验证 C→Go、Go→C、C→C 的 TCP/QUIC 隧道及 TCP/UDP 转发，并检查心跳、重连和内存错误。`gz.itq.cc.cd` 已切换到 C 网关，本机 Go、WSL C、Windows C 客户端与 xrwmaster Go 节点完成公网转发及重连测试。具体覆盖及限制见 [客户端验证](client/VALIDATION-ZH.md)、[网关验证](gateway/VALIDATION-ZH.md) 和 [公网切换记录](gateway/deploy/REMOTE-DEBUG-ZH.md)。
