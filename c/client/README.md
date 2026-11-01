# C 客户端

C 客户端 0.3.0 提供 Linux、Windows、macOS 的命令行程序与 C 动态库，以及 Android 原生应用和 JNI 绑定。运行时不依赖 Go，固定转发兼容本仓库 Go 客户端 3.25.11 和自建网关，公开接口版本保持 ABI 1。新增 SOCKS5 入口使用 C 0.3.0+ 节点作为出口。平台安装、交叉编译及 SDK 集成见 [平台说明](PLATFORMS-ZH.md)。

## 已实现

- 私有 CA / 系统 CA 的 TLS 证书链、主机名验证，以及 WSS 登录。
- 节点基本信息上报、周期心跳、时间偏差计算、网关断线重连。
- UDP NAT 探测、单字节 TCP NAT 探测、本地端口复用、TCP 打洞。
- UDP 锥形 NAT 打洞后，在同一个 UDP socket 上建立 QUIC，使用 `openp2pv1` ALPN。
- TCP / QUIC 隧道中的 TCP、UDP 应用转发，兼容现有应用密钥与数据帧。
- SOCKS5 TCP CONNECT、UDP ASSOCIATE、出口 DNS 和可选用户名密码认证；见 [SOCKS5 配置和 C 接口](SOCKS5-ZH.md)。
- 对端连接请求、应用密钥与内存应用同步、管理 API 查询转发状态及新增转发规则。
- 有界消息队列、超时、连接释放、事件回调和调用者驱动的运行循环。

当前范围是 IPv4 / 同账号私有网络。每条转发规则显式选择 TCP 或 QUIC；没有实现 Go 版本全部自动选路策略。复杂对称 NAT 的端口扫描、UPnP/NAT-PMP、IPv6、中继、SD-WAN/TUN、自动更新和桌面系统服务安装尚未实现。远程管理目前支持新增规则与查询状态，尚不支持完整的编辑、删除和开关语义。UDP 应用单个数据报上限为 4096 字节。

网关 TLS 始终校验证书链和主机名。P2P QUIC 则沿用现有 Go 客户端的临时自签对端证书策略，不使用网关 CA 校验 P2P 对端证书；应用数据保持原有 AES-CBC 格式，以便与 Go 版本互通。

## 构建与检查

已验证环境为 WSL Debian 13、GCC 14。系统依赖版本：libcurl 8.14.1、ngtcp2 1.11.0、GnuTLS 3.8.9、json-c 0.18、OpenSSL 3.5.7。

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build pkg-config python3 openssl \
  libcurl4-openssl-dev libngtcp2-dev libngtcp2-crypto-gnutls-dev \
  libgnutls28-dev libjson-c-dev libssl-dev

# 从仓库根目录运行
bash c/client/scripts/check.sh
build/c/openp2p-c --version
```

构建结果为 `build/c/openp2p-c`、`build/c/libopenp2p.so.1` 及其版本链接。开发检查包括协议输入、uint64 精度、加密、ABI、重复启停的文件描述符计数，以及证书拒绝测试。

本实现要求 libcurl >= 8.14 且启用 `ws` / `wss`，ngtcp2 >= 1.11。Debian 12 默认依赖版本不满足要求；可使用锁定依赖构建或 Debian 12 原生 SDK，方法见平台说明。

地址和未定义行为检查：

```bash
bash c/client/scripts/check.sh --sanitize
```

## 连接自己的网关

从 Go 网关的登录 API 获取 `nodeToken`，方法见 [网关说明](../../go/gateway/SELFHOST-ZH.md)。C 客户端的安装 token 使用无损 uint64 解析；优先从环境变量 `OPENP2P_TOKEN` 读取，其次读取配置的 `network.Token`。

```bash
mkdir -p "$HOME/openp2p-dev/c-client"
cp c/client/config.example.json "$HOME/openp2p-dev/c-client/config.json"
chmod 600 "$HOME/openp2p-dev/c-client/config.json"

# 编辑配置中的节点名、网关地址、CA 路径、对端节点和转发规则。
# 隐藏输入 token，避免把实际值写入命令行参数。
read -r -s -p 'Node token: ' OPENP2P_TOKEN
printf '\n'
export OPENP2P_TOKEN
build/c/openp2p-c --config "$HOME/openp2p-dev/c-client/config.json"
```

可用 `--serverhost`、`--port`、`--node`、`--cacert` 覆盖配置。`--publicipport` 指定对端直连 TCP 监听端口，省略时自动分配。`--run-seconds N` 用于有时限的调试，`Ctrl+C` 正常释放资源并退出。

配置中的 `Protocol` 指应用类型，`UnderlayProtocol` 指隧道类型，两者独立。例如 UDP 应用可以通过 TCP 打洞隧道传送。`UnderlayProtocol` 为 `tcp` 或 `quic`；省略时兼容读取 `PunchPriority` 的 TCPOnly 位，否则选择 QUIC。此处没有自动回退。

`BindIP` 默认 `127.0.0.1`。需要开放转发入口时显式设置绑定地址。私有 CA 文件只含公钥证书，不需要客户端持有服务端私钥或 CA 私钥。

## C 库接口

公开头文件为 [include/openp2p.h](include/openp2p.h)，完整可编译示例为 [examples/embed.c](examples/embed.c)。

```c
op2p_config cfg = {
    .struct_size = sizeof(cfg),
    .abi_version = OP2P_ABI_VERSION,
    .gateway_host = "127.0.0.1",
    .node = "my-c-client",
    .token = node_token,
    .ca_file = "/path/to/ca.crt",
    .on_event = on_event,
};
op2p_client *client = NULL;
int result = op2p_client_create(&cfg, &client);
/* 检查 result；按需调用 op2p_client_add_forward。 */
if (result == OP2P_OK) result = op2p_client_start(client);
while (result == OP2P_OK && app_running)
    result = op2p_client_step(client, 10);
op2p_client_destroy(client);
```

接口使用不透明句柄、`struct_size` 和 ABI 版本，不向调用方暴露第三方库结构。共享库只导出 `op2p_*` 符号，ELF 平台带符号版本。字符串由库复制；事件中的消息指针仅在回调期间有效。新增 `op2p_client_create_json` 接受统一配置及十进制 token 字符串，供移动端和其他语言绑定无损传递 uint64。

同一实例的调用由一个线程拥有。回调允许请求停止，不能重入轮询、销毁实例或修改转发规则。`step` 等待网络事件不超过指定值与 10 ms 的较小者；DNS 解析在启动及连接应用目的地址时同步进行。库不调用进程级 TLS 清理，不关闭调用方的其他网络连接。

`add_forward` 会立即保留本地监听端口；`stop` 关闭实例持有的连接及监听器，保留规则以便再次 `start`；`destroy` 释放实例。网关或对端故障通过事件报告，网关和本地转发隧道会自动重连。每个实例最多 32 条隧道、64 条本地/对端应用记录、256 条应用连接；每条传输队列有 4 MiB 上限，排队溢出会关闭对应连接。

编译和安装示例：

```bash
cmake --build build/c --target example-embed
cmake --install build/c --prefix "$HOME/openp2p-dev/c-sdk"
"$HOME/openp2p-dev/c-sdk/bin/openp2p-c" --version
```

## 与 Go 版本互通验证

独立 QUIC 双向测试只使用 Go 程序作为测试对端，不将 Go 链接进 C 客户端。测试构建依赖现有 Go 1.20.14 工具链：

```bash
bash c/client/scripts/check.sh --interop
bash c/client/scripts/check.sh --sanitize --interop
```

完整集成测试需要 Go 客户端/网关二进制、Linux network namespace 和 root：

```bash
bash go/scripts/check.sh
sudo bash c/client/scripts/integration.sh

# 使用 ASan/UBSan 构建做相同联调
sudo env OPENP2P_C_BUILD_DIR="$PWD/build/c-asan" \
  bash c/client/scripts/integration.sh
```

测试在独立 network namespace 中创建测试网关和客户端，通过 veth 为 Go 发起端分配独立 IP，避免 Go 的同公网 IP 内网直连捷径掩盖实际隧道类型。临时证书和日志保存在脚本打印的 `/tmp/openp2p-c-tests.*` 目录中；测试不会替换现有部署。

已通过的测试与公网记录见 [VALIDATION-ZH.md](VALIDATION-ZH.md)。

代码采用 [MIT 许可证](LICENSE)。第三方依赖与 ngtcp2 示例声明见 [THIRD_PARTY.md](THIRD_PARTY.md)。
