# C 客户端验证

- `ctest`：C API 生命周期、协议、平台、身份文件、SOCKS5 解析、TLS 拒绝、会话密钥派生与重放窗口。
- `ctest -R session-binding`：NAT 映射端口碰撞、64 位隧道 ID、旧密钥延迟到达、握手前密钥、重复/冲突推送、旧 ACK、QUIC 证书就绪门槛及重试密钥隔离。旧的端口绑定实现会在该回归用例失败。
- `tests/quic_native.py`：真实 C QUIC 客户端/服务端、fastp2pv2 ALPN、精确流帧。
- `tests/enrollment_integration.py`：16 位 Token 与可信网关配置安装、私有配置、无参数重连、错误 CA/主机名/密钥拒绝且保留旧配置；Windows 检查 DPAPI。
- `scripts/check-socks.sh`：真实 C 网关和客户端，TCP/UDP、TCP 打洞/QUIC、认证、并发、断连恢复。
- `scripts/check-relay.sh`：三个真实 C 客户端，源端强制走中继，验证 TCP 与 QUIC 都能经第三节点完成配对并回显，且中继日志出现两次 `relay session paired`。
- 同一检查还让中继节点保有到目标的直连规则，验证新中继跳不替换现有直连，也不接管本机应用；会话绑定单测覆盖中继中间跳隔离和按逻辑对端复用端点。
- `scripts/check-escalation.sh`：两个端点分别在独立 network namespace 且宿主不转发，彼此打洞必然失败；不施加任何强制，验证客户端在两次尝试后自动请求中继、中继完成配对并承载回显流量。
- `scripts/integration.sh`：六个 C 客户端、隔离网络中的 12 种转发组合、心跳和网关重启。
- `tests/android_artifact.py`：双 ABI、导出边界、许可证、16KB 对齐。
- Android `LiveInstrumentation`：私有 Token 接入、加密保存、无 Token 恢复。

`gateway_fixture.py` 仅作为 Windows/macOS 测试用 Python TLS/WSS 夹具；生产与 Linux 集成测试使用 C 网关。历史 Go/C 互通记录对应旧标签，不代表新协议兼容旧客户端。2.0.0 与 1.x 不互通。

多条同一对端/传输规则共享中继请求；单测验证请求去重及超时释放。中继集成测试覆盖共享规则和对端重启后的恢复。
