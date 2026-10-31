# 代码来源

本仓库于 2026-10-31 从本机已完成适配的工作副本建立独立快照。

| 目录 | 上游仓库 | 基础提交 | 本地适配 |
|---|---|---|---|
| `go/client/` | https://github.com/windows0041/openp2p | `a33f36f`，版本 3.25.11 | 私有 CA 参数 `-cacert`、TLS 信任验证、UDP 回环绑定及 socket 回归测试 |
| `go/gateway/` | https://github.com/openp2p-cn/gateway-lite | `2fcb575` | 可替换 TLS 证书、现代客户端协议、鉴权、连接生命周期、多节点协调、TCP NAT 探测兼容、SD-WAN 配置分发及调试脚本 |

两个目录拥有独立的 Go 模块和许可证。新仓库建立自己的 Git 历史，上游完整提交历史保留在原本的本地克隆中。未导入原客户端 Android 签名文件或网关示例证书与私钥。

2026-10-31 整理为 `go/client`、`go/gateway`、`c/client` 和 `c/gateway`。C 目录目前只包含迁移说明，不作为已实现功能发布。

2026-11-01 实现 `c/client` Linux 首版，包含独立 C 命令行客户端、ABI 1 的共享库、协议/加密适配及互通测试。以现有 Go 实现为协议参考，QUIC 适配参考 ngtcp2 v1.11.0 的公开示例，保留其 MIT 声明。C 客户端许可证与第三方来源见 `c/client/LICENSE` 和 `c/client/THIRD_PARTY.md`；C 网关仍未实现。

提供过的 `openp2p-gateway-edge:3.24.37` 镜像用于分析参考，未作为源码或二进制纳入本仓库；公开 `gateway-lite` 并非其完整对应源码。
