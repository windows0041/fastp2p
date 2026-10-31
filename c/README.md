# C 版本

本目录与 `go/` 分开维护。Linux C 客户端首版已实现；网关仍使用已经验证的 Go 实现。

- [client/](client/)：`openp2p-c` 和 `libopenp2p.so.1`，已实现 TLS/WSS、NAT 探测、TCP 打洞、UDP 打洞/QUIC 及 TCP/UDP 应用转发。
- [gateway/](gateway/)：预留后续 C 网关实现，目前尚未实现。

客户端通过不透明句柄、ABI 版本和 `struct_size` 提供创建、启动、轮询、停止、销毁、转发规则与事件接口。QUIC 使用 ngtcp2/GnuTLS，WSS 使用 libcurl，JSON 使用 json-c，加密使用 OpenSSL；客户端运行时不依赖 Go。

已用现有 Go 网关验证 C→Go、Go→C、C→C 的 TCP/QUIC 隧道及 TCP/UDP 转发，完成内存检查、心跳和重连测试，也完成本机 C 客户端到现有公网网关/远端 Go 节点的打洞与数据回传。当前没有 C 网关，因此没有将 C 网关计入互通覆盖。使用方法及尚未支持的功能见 [客户端说明](client/README.md)。
