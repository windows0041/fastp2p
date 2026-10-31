# openp2p-test

OpenP2P 自建网关与客户端。Go 版本是已经完成本地和跨公网联调的基线；C 版本使用独立目录，目前仅保留迁移说明，尚未实现。

```text
openp2p-test/
├── go/
│   ├── client/       # Go 客户端，独立 module openp2p
│   ├── gateway/      # Go 网关，独立 module openp2p-gateway
│   └── scripts/      # Go 构建与检查
├── c/
│   ├── client/       # C 客户端及 libopenp2p 计划
│   └── gateway/      # C 网关计划
└── UPSTREAM.md       # 来源、版本和本地适配记录
```

## 构建 Go 版本

已验证环境：WSL Debian、Go 1.20.14、GCC。现有 quic-go 依赖使用这套 Go 工具链；先使用已验证版本构建。

```bash
git clone https://github.com/windows0041/openp2p-test.git
cd openp2p-test
bash go/scripts/check.sh
```

脚本运行 Go 竞态检查和测试，并将 Linux 客户端及网关构建到 `build/go/`。脚本需要 Go、GCC 及可下载 Go 模块的网络；也可使用已准备好的模块缓存。

手动构建：

```bash
mkdir -p build/go
(cd go/client && go build -mod=readonly -trimpath -o ../../build/go/openp2p ./cmd)
(cd go/gateway && go build -mod=readonly -trimpath -o ../../build/go/openp2p-gateway .)
```

## 本地自签证书调试

```bash
mkdir -p "$HOME/openp2p-dev/bin"
cp build/go/openp2p build/go/openp2p-gateway "$HOME/openp2p-dev/bin/"
bash go/gateway/scripts/local-gateway.sh start
bash go/gateway/scripts/local-gateway.sh status

# 在另一个终端启动客户端
bash go/gateway/scripts/local-client.sh my-node-a
```

默认网关仅监听本机，节点 WSS 端口为 27183，HTTPS 管理 API 端口为 10008。首次启动生成本地 CA、服务端证书和管理账号。运行数据位于 `~/openp2p-dev`，账号位于 `~/.config/openp2p-gateway/local.env`。客户端通过 `-cacert` 信任自己的 CA，同时校验证书链和主机名。

完整操作见 [网关部署与换证书](go/gateway/SELFHOST-ZH.md) 和 [客户端参数](go/client/USAGE-ZH.md)。网关负责登录、NAT 探测和连接协调；业务数据在客户端之间直传，需要中继时另外部署客户端作为中继节点。

## 已验证范围

- 私有 CA、服务端证书及主机名验证，HTTPS 管理 API、WSS 登录和周期心跳。
- 跨公网 UDP 打洞及 QUIC，独立节点的 TCP 打洞。
- TCP/UDP 应用转发、随机数据回传，以及通过隧道进行 SSH 身份验证。
- UDP 回环地址绑定、单字节 TCP NAT 探测的实际 socket 回归测试。

验证方法见 [远程调试记录](go/gateway/deploy/REMOTE-DEBUG-ZH.md)。中继数据路径、SD-WAN 虚拟网段和 Docker 构建尚未完成端到端验证。

上游 `example/echo` 在同一目录包含两个独立的 `main`，直接运行 `go test ./...` 会报重复定义；检查脚本测试实际使用的构建目标。`TestNetInfo` 依赖外部网站，离线检查时排除。

## C 版本

目标是提供稳定的 C 库接口，先实现 Linux 客户端核心，并尽早验证 QUIC 与 Go 客户端互通。当前 C 目录只有 [迁移范围说明](c/README.md)，不包含可运行的 C 实现。

## 配置与许可证

真实 token、账号密码、运行配置、证书、私钥、Android 签名密钥及构建产物不纳入版本控制。使用 [客户端配置示例](go/client/config.example.json) 和 [网关环境变量示例](go/gateway/.env.example) 配置自己的环境。

客户端与网关分别保留上游 MIT [客户端许可证](go/client/LICENSE)、[网关许可证](go/gateway/LICENSE)。来源和镜像分析范围见 [UPSTREAM.md](UPSTREAM.md)。
