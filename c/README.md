# C 版本

fastp2p 当前只维护本目录的 C 客户端与 C 网关，版本 2.0.0。Go 源码与旧部署记录仅保留在 Git 历史中。

- [client/](client/)：Linux / Windows / macOS 单文件 CLI、ABI 1 C SDK、无配置界面的 Android APK；安装时通过 FP1 Token 验证网关身份。
- [gateway/](gateway/)：SQLite、主机名分配、HTTPS/WSS、Web、NAT 探测、连接协调、中继候选选择及 systemd / Docker 部署。

客户端通过不透明句柄、ABI 版本和 `struct_size` 提供创建、启动、轮询、停止、销毁、转发规则与事件接口。QUIC 使用 ngtcp2 的 OpenSSL 后端，WSS 使用 libcurl。网关使用 libwebsockets、OpenSSL 和 json-c，业务数据不经过网关。

当前测试全部使用 C 客户端，覆盖 TCP 打洞、QUIC、TCP/UDP、SOCKS5、中继、心跳及重连。见 [客户端验证](client/VALIDATION-ZH.md) 和 [网关验证](gateway/VALIDATION-ZH.md)。新协议需要统一升级旧节点，2.0.0 与 1.x 不互通。
