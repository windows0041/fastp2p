# C 网关验证

`scripts/check.sh --sanitize` 在隔离网络中验证认证、JWT、TLS、TCP/UDP NAT、WSS 分片、连接协调、管理请求、容量/超时、SQLite 持久化及重启恢复。

`integration.sh` 使用六个真实 C 客户端验证 TCP 打洞、QUIC、TCP/UDP 转发、心跳和网关重启。

`check-registry.sh` 验证主机名、数字补齐、重名隔离、稳定身份、SQLite 崩溃恢复、canonical 名称的 TCP/QUIC 转发。

`tests/web_ui.py` 使用浏览器验证登录、安装 Token、搜索分页、节点详情、规则操作、权限与移动屏幕。CI Debian 12/13 均启用 ASAN/UBSAN。

旧部署记录保存在 Git 历史，新协议部署结果以实际验证为准。

账号/删除集成测试覆盖自定义账号、错误当前密码、旧会话和延迟请求撤销、重启持久化、哈希存储、在线删除拒绝、离线删除和设备再次登记。浏览器测试覆盖账号修改重登、离线删除确认与列表刷新。

生产部署版本、实机测试、管理入口及发布记录见 [2026-11-02 部署验收](DEPLOYMENT-ZH.md)。
