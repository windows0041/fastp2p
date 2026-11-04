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

Linux 从网关控制台下载带 Token 文件名的自包含脚本，用 `sh 文件名` 或 `bash 文件名` 安装。程序安装到 `/usr/local/fastp2p/bin/fastp2p`，数据目录为 `/var/lib/fastp2p/client`，配置在 `/etc/fastp2p/client.json`；无需在设备上安装 curl、Python 或 Bash。脚本先校验内置程序及网关，再卸载旧服务、保留节点身份与配置、替换程序，失败时恢复旧文件。不要改动文件名中的 Token。

安装和保活逻辑在独立的 `scripts/linux-installer.sh`、`scripts/fastp2p-service.sh` 中，C 核心不包含发行版判断。脚本根据实际服务管理器选择 Debian/Ubuntu/CentOS 等的 systemd、OpenWrt 的 procd、Alpine 的 OpenRC，使用独立非 root 账号，开启开机启动和崩溃重启；未检测到支持的管理器时明确报错。下载时仍需选择设备对应的 CPU 架构；没有对应编译包的设备需要另行移植。进程由容器管理时，使用原始可执行文件前台运行及容器重启策略。

Windows 双击带 Token 文件名的 EXE，经 UAC 授权后卸载旧服务并安装到 `%ProgramFiles%/fastp2p`，机器级 DPAPI 加密配置在 `%ProgramData%/fastp2p`。高级 CLI 仍可选择当前用户安装。macOS 安装为当前用户的 LaunchAgent，最低 macOS 13。高级调试使用 `fastp2p install --token-file token.txt --no-service` 后手动运行。

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

Linux 系统服务的配置和 CA 由 root 持有，fastp2p 组可读（0640），目录权限 0750；服务进程不能写入。重复接入不会重写相同的 CA 文件。

安卓从旧网关迁移时，先安装新专用 APK，停止已有客户端进程，再执行 `adb shell am start -n top.fastp2p.cclient/.InstallActivity --es token YOUR_16_DIGIT_TOKEN --ez migrate true`。此标记只允许采用已签名 APK 中内置的目标地址和 CA，不接受 Intent 提供的服务器或证书；新网关验证成功后才替换已加密的配置，保留 DeviceID 和已有规则。普通安装入口仍拒绝跨网关覆盖。
