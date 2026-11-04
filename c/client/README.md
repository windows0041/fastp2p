# fastp2p C 客户端

C11 核心提供 WSS 协调、QUIC、TCP 打洞、中继回退、TCP/UDP 转发和 SOCKS5。隧道帧用 AES-256-GCM 保护：发起端生成 256 位会话密钥并经网关的 TLS 通道送达对端，两个方向各自派生密钥，接收端维护重放窗口。公开接口位于 `include/fastp2p.h`，符号前缀 `fastp2p_`，ABI 1。调用者独占客户端对象并驱动 `fastp2p_client_step`；回调属于驱动线程，销毁前停止调用。

## 安装与运行

```sh
sh fastp2p-<16位Token>
fastp2p run
fastp2p stop
fastp2p --version
fastp2p --licenses
```

安装 Token 为 16 位数字，网关地址、端口和公开 CA 已预置于专用客户端包。安装先完成 TLS 主机名校验及网关认证，成功后原子保存配置。错误凭据不会替换旧配置。支持 `--token`、`FASTP2P_INSTALL_TOKEN`、`--node`、`--config`、`--no-service`。

Linux 从网关控制台下载带 Token 文件名的自包含脚本，用 `sh 文件名` 或 `bash 文件名` 安装。程序安装到 `/usr/local/fastp2p/bin/fastp2p`，配置为 `/var/lib/fastp2p/config/fastp2p.conf`；无需在设备上安装 curl、Python 或 Bash。脚本先校验内置程序及网关，再卸载旧服务、迁移旧配置及证书、保留节点身份与规则、替换程序，失败时恢复旧文件。不要改动文件名中的 Token。

该脚本要求客户端 2.0.4 或更新版本：先在私有临时目录验证接入和合并配置，通过后才停止旧服务。替换后以服务账号加载完整配置、验证监听端口及网关认证，并检查系统服务持续运行，再提交安装；失败时恢复旧文件、目录权限及原有开机启动状态。旧客户端持有的数据父目录会安全迁移为 root 持有，配置子目录仍由客户端账号持有。同目录的其他文件（例如停用网关的数据库）保持内容与文件所有者不变。若旧网关仍在使用该目录，请先迁移网关，安装器会在卸载客户端前报错。

安装和保活逻辑在独立的 `scripts/linux-installer.sh`、`scripts/fastp2p-service.sh` 中，C 核心不包含发行版判断。脚本根据实际服务管理器选择 Debian/Ubuntu/CentOS 等的 systemd、OpenWrt 的 procd、Alpine 的 OpenRC，使用独立非 root 账号，开启开机启动和崩溃重启；未检测到支持的管理器时明确报错。下载时仍需选择设备对应的 CPU 架构；没有对应编译包的设备需要另行移植。进程由容器管理时，使用原始可执行文件前台运行及容器重启策略。

Linux x86_64 设备先用 `uname -m` 确认输出为 `x86_64`，在网关控制台选择 `linux-x86_64` 的「下载安装脚本」。保留下载文件名，将下面引号内的示例替换为实际文件名执行；Token 会自动读取，无需额外输入：

```sh
sudo sh './fastp2p-<下载文件名中的16位数字>'
```

Debian/Ubuntu/CentOS 等 systemd 系统查看服务和日志：

```sh
sudo systemctl status fastp2p-client --no-pager
sudo journalctl -u fastp2p-client -n 50 --no-pager
```

Alpine/OpenRC 用 `rc-service fastp2p status`，OpenWrt 用 `/etc/init.d/fastp2p status`。安装完成后程序在后台运行，不需要保持安装终端在线。

Windows 双击带 Token 文件名的 EXE，经 UAC 授权后卸载旧服务并安装到 `%ProgramFiles%/fastp2p`，机器级 DPAPI 加密配置在 `%ProgramData%/fastp2p/config/fastp2p.conf`。高级 CLI 的当前用户配置在 `%LOCALAPPDATA%/fastp2p/config/fastp2p.conf`，使用当前用户 DPAPI。旧 `client.dat` 会迁移，备份保存在新配置目录。macOS 安装为当前用户的 LaunchAgent，最低 macOS 13。高级调试使用 `fastp2p install --token-file token.txt --no-service` 后手动运行。

高级调试使用 `--config FILE`，参考 `config.example.json`、`config.socks5.example.json`。重复安装保留原有转发和 SOCKS5 规则；Web 新增规则保存在网关数据库，节点重连后恢复。

设置 `FASTP2P_FORCE_RELAY=1` 可跳过打洞直接请求中继，用于验证中继链路；它只影响带该变量启动的进程，不写入配置。

## 构建与 SDK

```sh
python3 c/client/scripts/build-deps.py linux-x86_64
cmake -S c/client -B build/c -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DFASTP2P_DEPS_ROOT="$HOME/fastp2p-dev/cross/prefix/linux-x86_64"
cmake --build build/c --parallel
ctest --test-dir build/c --output-on-failure
```

主程序静态链接项目核心与锁定的 TLS/QUIC/HTTP/JSON 依赖，系统 C 库仍由操作系统提供。SDK 包另外包含共享库、头文件、示例、CMake 配置；使用 `find_package(fastp2p CONFIG REQUIRED)` 和 `fastp2p::fastp2p`。

Windows 使用 MinGW，macOS 原生构建；Android 使用 NDK 和轻量 Java/JNI 系统封装，网络核心仍为 C。[平台说明](PLATFORMS-ZH.md) · [验证](VALIDATION-ZH.md)。完整依赖许可证已嵌入单文件客户端，运行 `--licenses` 查看。

专用构建的公开配置位于 c/common/bootstrap.json，只包含 host、port、ca，不含 Token 或私钥。自行部署其他网关时替换该文件，或用 CMake 参数 FASTP2P_BOOTSTRAP_FILE 选择另一份公开配置。安装器高级调试可用同名环境变量读取受信任的本地配置文件；不会从未验证的网络端点获取 CA。

Linux 的 config 目录由独立 fastp2p 服务账号持有（0700），fastp2p.conf 为 0600，支持网关下发时原子替换。父目录与服务控制脚本仍由 root 持有；安装器执行特权文件操作时临时锁定配置目录。直接以 root 运行默认配置的 CLI 也会降为服务账号。重复接入不会重写相同的 CA 文件。

启动先读取 fastp2p.conf（Linux 内容沿用 JSON；Windows 文件由 DPAPI 加密）。控制台每个新版桌面/Linux 节点的「配置」可下发 JSON 字段：对象递归合并，数组/标量/null 按整字段替换，未下发的键保留。客户端先验证候选配置，再私密保存、自动重载并重连；端口冲突、启动失败或 25 秒内无法通过网关认证时恢复旧配置。失败版本会被记住，修改后重新下发可重试。保留的 .previous 是上次配置备份，_fastp2pManaged 为内部状态，不能远程编辑。

网关同时保存每个节点的期望字段、递增版本号及 queued/saved/applied/failed 确认状态。离线修改会在上线后送达；转发规则界面也同步到配置文件。C 库提供可选的配置回调，由 CLI/宿主处理保存和重载；SDK 默认不写文件。显式命令行连接参数或 FASTP2P_TOKEN 环境覆盖属于调试会话，不宣称支持文件配置重载；系统服务应由安装器生成并从配置文件启动。

安卓从旧网关迁移时，先安装新专用 APK，停止已有客户端进程，再执行 `adb shell am start -n top.fastp2p.cclient/.InstallActivity --es token YOUR_16_DIGIT_TOKEN --ez migrate true`。此标记只允许采用已签名 APK 中内置的目标地址和 CA，不接受 Intent 提供的服务器或证书；新网关验证成功后才替换已加密的配置，保留 DeviceID 和已有规则。普通安装入口仍拒绝跨网关覆盖。
