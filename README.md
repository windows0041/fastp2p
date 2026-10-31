# OpenP2P 自建网关与客户端

本仓库包含适配自建 TLS 网关的 OpenP2P 客户端和网关，分别放在两个独立的 Go 模块中。

```text
openp2p-selfhost/
├── client/                 # OpenP2P 客户端，module openp2p
│   ├── cmd/                # 客户端入口
│   ├── core/               # P2P、端口转发、SD-WAN、TLS 信任
│   ├── config.example.json # 不含真实 token 的配置示例
│   └── go.mod
├── gateway/                # 自建网关，module openp2p-gateway
│   ├── scripts/            # 证书生成、本地运行、集成测试
│   ├── docker/             # 网关 Dockerfile
│   ├── compose.yaml
│   ├── SELFHOST-ZH.md      # 部署、换证书和管理 API 说明
│   └── go.mod
└── UPSTREAM.md             # 来源及基础提交记录
```

## 开发环境

WSL Debian 中使用 Go 1.20.14 和 Delve 1.21.2。客户端及网关独立构建，各自使用自己的 `go.mod` 和 `go.sum`。

```bash
cd /mnt/d/Codex/openp2p-selfhost/client
go build -mod=readonly -o "$HOME/openp2p-dev/bin/openp2p" ./cmd

cd ../gateway
go build -mod=readonly -o "$HOME/openp2p-dev/bin/openp2p-gateway" .
```

## 本地使用

```bash
cd /mnt/d/Codex/openp2p-selfhost/gateway
bash scripts/local-gateway.sh start
bash scripts/local-gateway.sh status

# 在另一个终端启动节点
bash scripts/local-client.sh my-node-a
```

默认网关仅监听本机，节点连接端口为 27183，HTTPS 管理 API 端口为 10008。运行数据保存在 `~/openp2p-dev`，账号配置保存在 `~/.config/openp2p-gateway/local.env`。客户端使用 `-cacert` 信任自签 CA，并继续验证主机名。

完整操作见 [网关使用和换证书说明](gateway/SELFHOST-ZH.md)，客户端参数见 [客户端使用说明](client/USAGE-ZH.md)。

## 验证

```bash
cd /mnt/d/Codex/openp2p-selfhost/client
go test -mod=readonly -race -count=1 -skip '^TestNetInfo$' ./core ./cmd ./pkg/upnp

cd ../gateway
go test -mod=readonly -race -count=1 -skip '^TestNetInfo$' .
```

客户端上游的 `example/echo` 包含两个独立程序，直接 `go test ./...` 会遇到重复 `main`；上述命令验证实际使用的目标。`TestNetInfo` 依赖外部网站，因此离线验证时排除。

已有本地双客户端 TCP/UDP 转发、自签 TLS 校验和心跳稳定性验证。公网打洞、中继路径、虚拟网段及 Docker 构建尚未完成端到端验证。

## 配置与证书

真实 `config.json`、`.env`、证书、私钥、Android 签名密钥和构建产物不纳入版本控制。按 [证书生成说明](gateway/SELFHOST-ZH.md) 生成自己的证书，Android 构建时使用自己的签名密钥。

客户端和网关分别保留各自的 MIT [客户端许可证](client/LICENSE)、[网关许可证](gateway/LICENSE)。
