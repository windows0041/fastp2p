# C 客户端验证

- `ctest`：C API 生命周期、协议、平台、身份文件、SOCKS5 解析、TLS 拒绝。
- `tests/quic_native.py`：真实 C QUIC 客户端/服务端、fastp2pv1 ALPN、精确流帧。
- `tests/enrollment_integration.py`：一个 FP1 安装、私有配置、无参数重连、错误 CA/主机名/密钥拒绝且保留旧配置；Windows 检查 DPAPI。
- `scripts/check-socks.sh`：真实 C 网关和客户端，TCP/UDP、TCP 打洞/QUIC、认证、并发、断连恢复。
- `scripts/integration.sh`：六个 C 客户端、隔离网络中的 12 种转发组合、心跳和网关重启。
- `tests/android_artifact.py`：双 ABI、导出边界、许可证、16KB 对齐。
- Android `LiveInstrumentation`：私有 Token 接入、加密保存、无 Token 恢复。

`gateway_fixture.py` 仅作为 Windows/macOS 测试用 Python TLS/WSS 夹具；生产与 Linux 集成测试使用 C 网关。历史 Go/C 互通记录对应旧标签，不代表新协议兼容旧客户端。
