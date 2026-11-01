# openp2p-test

OpenP2P 自建网关与客户端。Go 版本保留已完成本地和跨公网联调的基线；C 版本提供独立的 Linux 网关，以及 Linux、Windows、macOS 客户端 CLI / C 库和 Android 应用，各端使用独立目录并与 Go 版本互通。

```text
openp2p-test/
├── go/
│   ├── client/       # Go 客户端，独立 module openp2p
│   ├── gateway/      # Go 网关，独立 module openp2p-gateway
│   └── scripts/      # Go 构建与检查
├── c/
│   ├── client/       # 跨平台 C 核心、桌面 CLI / SDK、Android 应用
│   └── gateway/      # Linux C 网关、协议测试、systemd / Docker 部署
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

C 客户端 0.4.0 保持 ABI 1，提供 Linux `libopenp2p.so.1`、Windows `openp2p.dll`、macOS `libopenp2p.1.dylib` 及桌面 `openp2p-c`。新增 [SOCKS5 代理](c/client/SOCKS5-ZH.md)，经 TCP 打洞 / QUIC 使用指定 C 节点作为出口，支持 TCP、UDP、出口 DNS 和可选认证。Android 应用包含 arm64-v8a / x86_64 的同一套 C 核心，支持 CA 导入、加密保存 token 与配置、前台连接服务、应用转发和 SOCKS5，运行时不依赖 Go。

各平台实现私有 CA 验证、WSS 登录/心跳/重连、NAT 探测、TCP 打洞、UDP 打洞/QUIC 和 TCP/UDP 应用转发。构建和使用见 [C 客户端说明](c/client/README.md) 与 [平台和 SDK 说明](c/client/PLATFORMS-ZH.md)，实际测试覆盖见 [客户端验证记录](c/client/VALIDATION-ZH.md)。C 客户端的 SD-WAN/TUN 和中继数据面尚未实现。

Windows、Android 和 macOS 两种架构的 SDK / 调试包见 [0.2.0 验证与构建产物](https://github.com/windows0041/openp2p-test/actions/runs/41268179414)。Android 已在连接的 Android 12 x86_64 设备上经自建公网网关与远端 Go 节点联调；arm64 已构建，尚未在 ARM 设备上运行。

当前 [0.4.0 SDK 下载](https://github.com/windows0041/openp2p-test/releases/tag/c-client-v0.4.0) 增加主机名自动命名和稳定身份，网关 [0.3.0 下载](https://github.com/windows0041/openp2p-test/releases/tag/c-gateway-v0.3.0) 包含 SQLite 节点存储，服务器已更新，详见 [SQLite 部署记录](c/gateway/deploy/SQLITE-DEBUG-ZH.md)。

此前 [0.3.0 SDK 下载](https://github.com/windows0041/openp2p-test/releases/tag/c-client-v0.3.0) 增加 Debian 12 原生 Linux 包，对应[五项 CI 作业](https://github.com/windows0041/openp2p-test/actions/runs/41284347086)全部通过。本机已启用 SOCKS5 `127.0.0.1:1080`（QUIC）和 `1081`（TCP 打洞），使用 xrwmaster C 节点作为出口；Android 同轮 SOCKS5 设备测试通过，详见 [代理部署记录](c/client/deploy/SOCKS5-DEBUG-ZH.md)。

C 网关 0.3.0 增加 SQLite 节点存储和主机名唯一命名，保留离线节点与在线时间，支持全库分页搜索。配置与 C 接口见 [节点存储和命名](c/NODE-STORAGE-ZH.md)。内嵌 Web 控制台，支持登录、网关状态、节点搜索和转发管理。默认与管理 API 共用 `https://127.0.0.1:10008/`，远程可通过 SSH 转发访问。Go 节点支持增删改和开关；C 0.3 节点支持查询和新增，已有规则与 SOCKS5 在客户端配置中修改。

网关实现自定义 TLS 证书、HTTPS/WSS、JWT 管理鉴权、节点发现与心跳、TCP/UDP NAT 探测、打洞控制消息、应用管理、SD-WAN 成员配置和中继节点协调。通过 C→Go、Go→C、C→C 的 TCP 打洞 / QUIC 及 TCP/UDP 应用联调，业务数据仍由客户端直传。构建、自签证书与部署见 [C 网关说明](c/gateway/README.md)，测试范围和发行包见 [网关验证记录](c/gateway/VALIDATION-ZH.md)。`gz.itq.cc.cd` 已切换到 C 网关，完成本机 Go / WSL C / Windows C 与 xrwmaster 的公网联调，原 Go 程序保留供回退，详见 [切换记录](c/gateway/deploy/REMOTE-DEBUG-ZH.md)。

## 下载与自动发布

GitHub 编译并测试通过后，将网关原生包、Docker 镜像和跨平台 C 客户端 SDK 发布至本项目 [Releases](https://github.com/windows0041/openp2p-test/releases)，附 `SHA256SUMS.txt`。`main` 自动发布预览版，`c-gateway-v*` / `c-client-v*` 标签发布对应正式版。规则和下载用法见 [发布说明](RELEASING-ZH.md)。

## 配置与许可证

真实 token、账号密码、运行配置、证书、私钥、Android 签名密钥及构建产物不纳入版本控制。使用 [客户端配置示例](go/client/config.example.json) 和 [网关环境变量示例](go/gateway/.env.example) 配置自己的环境。

客户端与网关分别保留上游 MIT [客户端许可证](go/client/LICENSE)、[网关许可证](go/gateway/LICENSE)。来源和镜像分析范围见 [UPSTREAM.md](UPSTREAM.md)。
