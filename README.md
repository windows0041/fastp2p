# fastp2p C 客户端

本仓库包含客户端、C SDK 和 Android 应用。网关服务和 Web 控制台在独立的 [fastp2p-gateway 仓库](https://github.com/windows0041/fastp2p-gateway)。客户端安装包见 [GitHub Releases](https://github.com/windows0041/fastp2p/releases)。

C11 核心提供 WSS 协调、QUIC、TCP 打洞、中继回退、TCP/UDP 转发和 SOCKS5。隧道帧用 AES-256-GCM 保护：发起端生成 256 位会话密钥并经网关的 TLS 通道送达对端，两个方向各自派生密钥，接收端维护重放窗口。公开接口位于 `include/fastp2p.h`，符号前缀 `fastp2p_`，ABI 1。调用者独占客户端对象并驱动 `fastp2p_client_step`；回调属于驱动线程，销毁前停止调用。

QUIC 接收采用有界环形缓冲，帧编码复用发送队列。[缓冲优化基准与验证](docs/performance-20261112.md) 包含可选基准的构建方法和适用范围。

TCP/UDP 分开检测映射并选择重试策略。新版 TCP 打洞支持双方同时连接、同源端口重试和监听回退；网关控制台分别显示两种协议的结果。[TCP 打洞与检测说明](docs/tcp-punch.md) 包含配置、兼容方式和隔离 NAT 测试方法。

UDP 和 TCP 的 NAT 等级分别使用映射和入站过滤的观测。默认通过 `stun.fastp2p.top:3478` 做 UDP STUN 过滤探测，通过 `stun.fastp2p.top:3479` 做 TCP 回连探测。UDP 探测把实际回包的源地址和端口与请求目标比较。TCP 探测需要同地址换端口和换地址两项结果。

过滤证据不足时，客户端会在 30 秒后重测。测出等级后每 10 分钟更新，短暂超时会保留最近确认的等级，满 20 分钟未重新确认会回到过滤待判定。可通过 `network.UDPSTUNServers` 和 `network.TCPNatProbe` 指定探测服务。自建 UDP 服务需支持 CHANGE-REQUEST。 [NAT 穿越说明](NAT-TRAVERSAL-ZH.md) · [自建探测服务](scripts/stun/README.md)

## 安装与运行

```sh
fastp2p run
fastp2p stop
fastp2p --version
fastp2p --licenses
```

安装 Token 为 16 位数字，网关地址、端口和公开 CA 已预置于专用客户端包。安装先完成 TLS 主机名校验及网关认证，成功后原子保存配置。错误凭据不会替换旧配置。支持 `--token`、`FASTP2P_INSTALL_TOKEN`、`--node`、`--config`、`--no-service`。

在网关控制台选择 Linux 并复制安装命令。脚本会识别 CPU，从网关通过 HTTPS 下载程序，并校验长度、SHA-256 和版本。下载程序需要 curl 或支持 TLS 的 GNU wget。程序安装到 `/usr/local/fastp2p/bin/fastp2p`。OpenWrt 和 ImmortalWrt 将配置存放在 `/etc/fastp2p-client/config/fastp2p.conf`，其他 Linux 系统使用 `/var/lib/fastp2p/config/fastp2p.conf`。手动下载脚本时请保留文件名中的 Token。

该脚本要求客户端 2.0.4 或更新版本：先在私有临时目录验证接入和合并配置，通过后才停止旧服务。替换后以服务账号加载完整配置、验证监听端口及网关认证，并检查系统服务持续运行，再提交安装；失败时恢复旧文件、目录权限及原有开机启动状态。旧客户端持有的数据父目录会安全迁移为 root 持有，配置子目录仍由客户端账号持有。同目录的其他文件（例如停用网关的数据库）保持内容与文件所有者不变。若旧网关仍在使用该目录，请先迁移网关，安装器会在卸载客户端前报错。

安装成功后清理安装器管理的旧程序：Linux 删除历次 `.backups` 中的程序副本和旧路径的可执行文件，保留配置、证书和诊断日志；失败时先恢复旧程序，保留故障备份。客户端 2.0.5 起，Linux/macOS 远程升级在新程序认证上线并稳定运行 5 秒后删除 `.old`；Windows 升级辅助程序在新服务启动成功后清理旧 EXE，运行中的辅助 EXE 由新客户端在文件释放后清理。Windows 服务安装还会清理旧用户目录中的程序，保留该目录的配置。清理只匹配已知程序文件，跳过仍在工作的下载进程及目录、符号链接，不扫描下载目录中的用户安装包。Android 的旧应用由系统替换，安装成功回调清理缓存 APK。

安装和保活逻辑由 `scripts/linux-installer.sh` 和 `scripts/fastp2p-service.sh` 提供。脚本根据系统选择 systemd、procd 或 OpenRC，并使用独立服务账号。当前官方 Release 提供 x86_64、aarch64、armv7（硬浮点）、riscv64 和 mips64el（64 位小端用户空间）。安装脚本以网关提供的包为准，缺包时会列出可用架构并退出，旧服务保持运行。容器可直接运行对应架构的原始可执行文件。

在网关控制台点击「下载 Linux 通用安装脚本」。保留下载文件名，将下面引号内的示例替换为实际文件名执行；架构和 Token 会自动读取，无需额外输入。脚本固定下载时各架构的最新版；若旧包已清理，请重新下载脚本：

```sh
sudo sh './fastp2p-<下载文件名中的16位数字>'
```

Debian/Ubuntu/CentOS 等 systemd 系统查看服务和日志：

```sh
sudo systemctl status fastp2p-client --no-pager
sudo journalctl -u fastp2p-client -n 50 --no-pager
```

Alpine/OpenRC 用 `rc-service fastp2p status`，OpenWrt 用 `/etc/init.d/fastp2p status`。安装完成后程序在后台运行，不需要保持安装终端在线。

macOS 在网关控制台的「安装客户端 → Mac」下载通用安装脚本。保留文件名，在终端执行 `sh ./fastp2p-macos-<16位数字>.sh`，无需 sudo。脚本支持 macOS 13 及以上，自动下载 Apple Silicon 或 Intel 版本，保留原节点身份和配置。安装后 LaunchAgent 随当前用户登录启动。

Windows 双击带 Token 文件名的 EXE，经 UAC 授权后卸载旧服务并安装到 `%ProgramFiles%/fastp2p`，机器级 DPAPI 加密配置在 `%ProgramData%/fastp2p/config/fastp2p.conf`。高级 CLI 的当前用户配置在 `%LOCALAPPDATA%/fastp2p/config/fastp2p.conf`，使用当前用户 DPAPI。旧 `client.dat` 会迁移，备份保存在新配置目录。macOS 安装为当前用户的 LaunchAgent，最低 macOS 13。高级调试使用 `fastp2p install --token-file token.txt --no-service` 后手动运行。

Windows 开机服务和 `run --background` 不创建终端窗口；后台日志写入配置文件同目录的 `fastp2p.conf.log`。手动从终端运行前台命令时连接现有终端，管道和文件重定向继续可用。只有双击安装并完成 UAC 授权后，才创建安装进度终端和结果提示。服务崩溃或启动时 DNS/网络暂不可用导致退出时，Windows 服务管理器会按恢复策略重启客户端。

高级调试使用 `--config FILE`，参考 `config.example.json`、`config.socks5.example.json`。重复安装保留原有转发和 SOCKS5 规则；Web 新增规则保存在网关数据库，节点重连后恢复。

### TCP 业务端口

客户端在 `1024–9999` 中按设备身份选择可用的 TCP 端口，IPv4 和 IPv6 使用同一端口。已安装的客户端首次上线后将它保存为 `network.PublicIPPort`。如需指定端口，可以在配置中设置 `PublicIPPort`，也可以用 `--publicipport PORT` 启动。

在网关「设备详情」查看业务端口，在该设备的防火墙放行对应的 TCP 入站端口。若需要从公网 IPv4 访问位于路由器后的设备，可在路由器上把相同的公网 TCP 端口转发到设备的业务端口。双方都支持该功能时会先尝试业务端口直连，超时后继续打洞。

设置 `FASTP2P_FORCE_RELAY=1` 可跳过打洞直接请求中继，用于验证中继链路；它只影响带该变量启动的进程，不写入配置。

## 构建与 SDK

在 Linux 或 WSL 的客户端仓库根目录运行。构建需要 C 编译器、CMake、Ninja、Python 3 和 pkg-config。

```sh
python3 scripts/build-deps.py linux-x86_64
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DFASTP2P_DEPS_ROOT="$HOME/fastp2p-dev/cross/prefix/linux-x86_64"
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

主程序静态链接项目核心与锁定的 TLS/QUIC/HTTP/JSON 依赖，系统 C 库仍由操作系统提供。SDK 包另外包含共享库、头文件、示例、CMake 配置；使用 `find_package(fastp2p CONFIG REQUIRED)` 和 `fastp2p::fastp2p`。

Windows 使用 MinGW，macOS 原生构建，Android 使用 NDK 和 Java/JNI 系统封装。完整依赖许可证已嵌入单文件客户端，运行 `--licenses` 查看。 [平台和发行包](PLATFORMS-ZH.md) · [本地验证与 CI](VALIDATION-ZH.md)

专用构建从仓库根目录的 `common/bootstrap.json` 读取公开的 `host`、`port` 和 `ca`。新安装匹配内置网关和 CA 时，客户端直接从内存加载 CA，配置文件只保存证书指纹。现有的 `CACertFile` 配置和自定义网关证书文件仍可使用。自行部署网关时，可以修改该文件，或通过 CMake 参数 `FASTP2P_BOOTSTRAP_FILE` 选择另一份公开配置。SDK 中的副本名为 `gateway-public.json`。接入 Token 和私钥应存放在私有配置中。

Linux 的 config 目录由独立 fastp2p 服务账号持有（0700），fastp2p.conf 为 0600，支持网关下发时原子替换。父目录与服务控制脚本仍由 root 持有；安装器执行特权文件操作时临时锁定配置目录。直接以 root 运行默认配置的 CLI 也会降为服务账号。重复接入不会重写相同的 CA 文件。

启动先读取 fastp2p.conf（Linux 内容沿用 JSON；Windows 文件由 DPAPI 加密）。网关控制台不再接受手动字段下发：操作员只需维护转发与 SOCKS5 规则，网关把规则渲染成 `apps`/`socks5` 期望字段并在改动、停用、删除时同步给在线节点（离线节点上线后自动应用）。客户端收到期望字段后按键递归合并（对象逐层合并，数组/标量/null 按整字段替换，未下发的键保留），先验证候选配置，再私密保存、自动重载并重连；端口冲突、启动失败或 25 秒内无法通过网关认证时恢复旧配置。失败版本会被记住，规则改动后重新下发可重试。保留的 .previous 是上次配置备份，_fastp2pManaged 为内部状态，不能远程编辑。

网关同时保存每个节点的期望字段、递增版本号及 queued/saved/applied/failed 确认状态。离线修改会在上线后送达；转发规则界面也同步到配置文件。C 库提供可选的配置回调，由 CLI/宿主处理保存和重载；SDK 默认不写文件。显式命令行连接参数或 FASTP2P_TOKEN 环境覆盖属于调试会话，不宣称支持文件配置重载；系统服务应由安装器生成并从配置文件启动。

安卓从旧网关迁移时，先安装新专用 APK，停止已有客户端进程，再执行 `adb shell am start -n top.fastp2p.cclient/.InstallActivity --es token YOUR_16_DIGIT_TOKEN --ez migrate true`。此标记只允许采用已签名 APK 中内置的目标地址和 CA，不接受 Intent 提供的服务器或证书；新网关验证成功后才替换已加密的配置，保留 DeviceID 和已有规则。普通安装入口仍拒绝跨网关覆盖。

### NAT 等级的来源与显示

控制台显示的是两个独立的结论，**不要混读**：

| 列 | 字段 | 判定依据 |
|---|---|---|
| `UDP` | `natLevel` 1–7 | 映射探测 + 公共/自建 STUN 的过滤探测 |
| `TCP` | `tcpNatLevel` 1–4 | 映射探测 + **回调 SYN** 过滤探测 |

`natLevel` 的取值：

| 值 | 含义 |
|---|---|
| 1 / 2 / 3 | 全锥 / 地址受限 / 端口受限（过滤探测有证据时才给）|
| 4 | 对称（映射随目标变化，过滤探测已无意义）|
| 5 | 锥形但过滤无法判定（不猜）|
| 6 | **无 NAT**：STUN 报告的映射与本机地址一致 |
| 7 | 无 NAT 但过滤全丢：对称 UDP 防火墙 |
| 0 | 未测得 |

`tcpNatLevel` 的取值：1 两个回调都通 / 2 只有同地址新端口通 / 3 都不同（端口受限）/ 4 映射对称。STUN 的 `CHANGE-REQUEST` 对 TCP 不存在，所以 TCP 过滤改用真实回调：客户端用**同一本地端口**既拨出（建立映射）又监听，再由探测服务器分别从**同 IP 的另一端口**和**另一个公网 IP** 回连，看哪个能握手。配置项 `network.TCPNatProbe`（如 `"stun.fastp2p.top:3479"`）。探测未完成时该列为空，控制台回退显示映射语义（`映射稳定` / `映射随目标`），不会谎报等级。

### 自建 STUN 与 TCP 探测服务器

`scripts/stun/` 下有两个可直接部署的工具：

- `stun-responder.py`：支持 RFC 3489 `CHANGE-REQUEST` 的 UDP STUN。普通请求同 socket 回包；换端口从 `端口+1` 回包；换地址从**另一块本地地址**回包，并在响应里带 RFC 5780 的 `OTHER-ADDRESS`（0x802C）告诉客户端备用地址——有它，配置里只写一个地址就够，换地址探测仍然可信。
- `tcp-probe-server.py`：TCP 回调探测。先告知对端映射地址，再依次从同 IP 新端口、另一公网 IP 发起连接，报告哪个成功。

主机需要两个公网地址，且上游必须同时放行**两个地址的进出**：只把地址配上而出口被过滤时，用该地址作源发包会丢包，换地址应答就不会到达（现象是 STUN 侧 `change-ip` 永远无回包）。UDP 用 `3478`、TCP 用 `3479`，防火墙需同时放行这两种协议。
