# 代码来源

本仓库于 2026-10-31 从本机已完成适配的工作副本建立独立快照。

| 目录 | 上游仓库 | 基础提交 | 本地适配 |
|---|---|---|---|
| `client/` | https://github.com/windows0041/openp2p | `a33f36f`，版本 3.25.11 | 私有 CA 参数 `-cacert`、TLS 信任验证、回环测试 |
| `gateway/` | https://github.com/openp2p-cn/gateway-lite | `2fcb575` | 可替换 TLS 证书、现代客户端协议、鉴权、连接生命周期、多节点协调、SD-WAN 配置分发及本地脚本 |

两个目录拥有独立的 Go 模块和许可证。新仓库建立自己的 Git 历史，上游完整提交历史保留在原本的本地克隆中。未导入原客户端 Android 签名文件或网关示例证书与私钥。

提供过的 `openp2p-gateway-edge:3.24.37` 镜像用于分析参考，未作为源码或二进制纳入本仓库；公开 `gateway-lite` 并非其完整对应源码。
