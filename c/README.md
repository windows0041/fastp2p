# C 版本迁移计划

本目录与 `go/` 分开维护。目前尚未开始 C 实现，没有可运行的客户端或网关。

- `client/`：以稳定的 `libopenp2p` C 接口为目标，先做 Linux 客户端核心。
- `gateway/`：后续实现兼容现有客户端协议的 C 网关。

迁移顺序：先整理协议和生命周期接口，同时验证 C QUIC 与现有 Go QUIC 的互通；然后实现 Linux 客户端的 WSS 登录、自签 CA 校验、心跳、NAT 探测、TCP 打洞和应用转发；再实现 C 网关，逐步补齐 UDP/QUIC、Windows 和 SD-WAN。

保留 Go 版本作为兼容性基准，验证 C 客户端连接 Go 网关、Go 客户端连接 C 网关，以及 C 客户端连接 C 网关。QUIC 库选型需要先验证 UDP socket/端口控制、`openp2pv1` ALPN 和自定义流协议。
