# fastp2p C 客户端

C11 核心提供 WSS 协调、QUIC、TCP 打洞、中继回退、TCP/UDP 转发和 SOCKS5。隧道帧用 AES-256-GCM 保护：发起端生成 256 位会话密钥并经网关的 TLS 通道送达对端，两个方向各自派生密钥，接收端维护重放窗口。公开接口位于 `include/fastp2p.h`，符号前缀 `fastp2p_`，ABI 1。调用者独占客户端对象并驱动 `fastp2p_client_step`；回调属于驱动线程，销毁前停止调用。

## 安装与运行

```sh
fastp2p install --token-file token.txt
fastp2p run
fastp2p stop
fastp2p --version
fastp2p --licenses
```

安装 Token 为 16 位数字，网关地址、端口和公开 CA 已预置于专用客户端包。安装先完成 TLS 主机名校验及网关认证，成功后原子保存配置。错误凭据不会替换旧配置。支持 `--token`、`FASTP2P_INSTALL_TOKEN`、`--node`、`--config`、`--no-service`。

Windows 安装到 `%LOCALAPPDATA%/fastp2p`，DPAPI 加密配置，HKCU Run 随用户登录启动。Linux root 安装到 `/usr/local/bin/fastp2p`，配置 `/etc/fastp2p/client.json`，使用独立 `fastp2p` 用户的 systemd 服务。非 root 使用 `--no-service` 后手动 `run`。macOS 安装为当前用户的 LaunchAgent，最低 macOS 13。

高级调试使用 `--config FILE`，参考 `config.example.json`、`config.socks5.example.json`。重复安装保留原有转发和 SOCKS5 规则；Web 新增规则目前只在运行进程中生效，持久化请更新配置。

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

安卓从旧网关迁移时，先安装新专用 APK，停止已有客户端进程，再执行 `adb shell am start -n cc.itq.fastp2p.cclient/.InstallActivity --es token YOUR_16_DIGIT_TOKEN --ez migrate true`。此标记只允许采用已签名 APK 中内置的目标地址和 CA，不接受 Intent 提供的服务器或证书；新网关验证成功后才替换已加密的配置，保留 DeviceID 和已有规则。普通安装入口仍拒绝跨网关覆盖。
