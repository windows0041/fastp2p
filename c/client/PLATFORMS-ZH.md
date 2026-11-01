# C 客户端平台与集成

C 核心版本 0.3.0，公开 C ABI 1，固定转发协议兼容仓库中的 Go 3.25.11 客户端及自建网关。各平台复用同一份 C 核心，无 Go 运行时。新增 [SOCKS5](SOCKS5-ZH.md) 使用 C 0.3.0+ 出口；平台验证结果见 [VALIDATION-ZH.md](VALIDATION-ZH.md)。

0.3.0 的 Linux Debian 12 x86_64、Windows x86_64、macOS arm64/x86_64 SDK 及 Android 调试包见 [完整 CI 与发行产物](https://github.com/windows0041/openp2p-test/actions/runs/41284347086)。Linux 原生发行包为 `openp2p-c-linux-debian12-x86_64.tar.gz`，包含 CLI、共享库、CMake 导入和 SOCKS5 示例；TLS/QUIC/JSON 依赖已静态链接进共享库，使用匹配的 Linux x86_64 / glibc 运行环境，不需要依赖 Debian 12 较旧的系统 curl/ngtcp2。

| 平台 | 架构与最低版本 | 入口 |
| --- | --- | --- |
| Linux | x86_64；已验证 Debian 13 / WSL | CLI、`libopenp2p.so.1` |
| Windows | x86_64，Windows 10 1903+ | CLI、`openp2p.dll`、C SDK |
| macOS | arm64 / x86_64，macOS 13+ | CLI、`libopenp2p.1.dylib`、C SDK |
| Android | arm64-v8a / x86_64，Android 8.0+ / API 26 | 原生应用、JNI、`libopenp2p.so` |

Android 设备联调使用 Android 12 x86_64。arm64 构建包含在 APK 中。macOS 使用两个架构各自的原生 GitHub Actions runner；最低版本是编译目标，实际系统覆盖以验证记录为准。Windows 首版为命令行与 C 库。macOS 包尚未使用 Apple Developer ID 签名或公证，Android 包为开发调试签名。

## 桌面使用

SDK 解压后保留 `bin/`、`lib/`、`include/` 的相对位置。Windows 将 DLL 与 EXE 放在同一目录；macOS 的 CLI 通过相对 rpath 加载同包动态库。

复制 `config.example.json` 到仓库外目录，填写自己的网关、节点名、CA 路径、对端和转发规则。token 优先使用环境变量，避免出现在命令行参数中。私有 CA 只需要公钥证书，不能把 CA 私钥复制给客户端。

PowerShell：

```powershell
$secret = Read-Host 'Node token' -AsSecureString
$env:OPENP2P_TOKEN = [System.Net.NetworkCredential]::new('', $secret).Password
& .\bin\openp2p-c.exe --config C:\path\to\config.json
Remove-Item Env:OPENP2P_TOKEN
```

macOS / Linux：

```bash
read -r -s OPENP2P_TOKEN
export OPENP2P_TOKEN
./bin/openp2p-c --config "$HOME/openp2p/config.json"
unset OPENP2P_TOKEN
```

`--version` 打印核心和 ABI 版本，`Ctrl+C` 正常退出。`UnderlayProtocol` 为 `tcp` 或 `quic`，`Protocol` 为应用的 `tcp` 或 `udp`。监听默认仅绑定 `127.0.0.1`，需要公开入口时显式填写 `BindIP`。

## C / C++ 集成

包含 `include/openp2p.h`，链接平台动态库。实例、字符串及回调的所有权规则保持 ABI 1；所有实例函数须在一个拥有线程上调用。示例见 `examples/embed.c`。

新接口 `op2p_client_create_json` 接受 UTF-8 JSON、十进制 token 字符串及可选 CA 路径。Java / JavaScript 等绑定应传 token 字符串，不能先转换成有符号整数或浮点数。返回的句柄仍使用原有 `start/step/stop/destroy` 生命周期。

桌面 SDK 支持 CMake：

```cmake
find_package(openp2p 0.2 CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE openp2p::openp2p)
```

配置时传 `-DCMAKE_PREFIX_PATH=/path/to/sdk`。Windows 包中的 `libopenp2p.dll.a` 用于 MinGW，`openp2p.lib` 用于 MSVC。应用退出前在拥有线程上销毁句柄；不能从 UI 线程直接销毁仍在运行的网络实例。

## Android 应用

安装 `openp2p-c-android-debug.apk` 后，填写网关地址、WSS 端口、节点名称和 token，导入 PEM 格式的网关 CA，再编辑转发规则并连接。规则为空时可以作为被连接的对端节点。应用提供本机 TCP/UDP 端口转发，未实现 VPN/TUN。

应用通过用户主动启动的前台服务运行。通知栏可断开；切换到后台继续连接，不设置开机自动启动。系统或设备厂商仍可能终止后台进程。token 使用 Android Keystore 的 AES-GCM 密钥加密保存；配置和公钥 CA 保存在应用私有目录，禁止备份。系统信任库通过 AndroidCAStore 导出供 libcurl 校验，以兼容较新 Android 的 Conscrypt CA 存储位置。

JNI 由 Java 工作线程拥有 C 句柄，并在该线程依次完成配置、轮询、停止及销毁。APK 内的 `libopenp2p.so` 还提供同一套公开 C 接口。NDK 集成可直接使用头文件和对应 ABI 的动态库；Java 绑定代码位于 `android/jni` 和 `android/app/src/main/java`。

## 源码构建

固定源码版本和 SHA-256 位于 `deps.lock.json`。依赖与构建缓存位于仓库外的 `~/openp2p-dev/cross`；构建器会校验下载内容，配方变化会触发重新配置。

Windows 在 WSL / Linux 交叉编译：

```bash
sudo apt-get install gcc-mingw-w64-x86-64 cmake ninja-build make perl python3
python3 c/client/scripts/build-deps.py windows-x86_64
cmake -S c/client -B build/windows -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE="$PWD/c/client/cmake/windows-x86_64.cmake" \
  -DOP2P_DEPS_ROOT="$HOME/openp2p-dev/cross/prefix/windows-x86_64"
cmake --build build/windows --parallel 4
cmake --install build/windows --prefix "$PWD/dist/windows-x86_64"
```

在 Windows 的 Visual Studio Developer Command Prompt 中生成 MSVC 导入库：

```cmd
lib /machine:x64 /def:c\client\platform\windows\openp2p.def /out:dist\windows-x86_64\lib\openp2p.lib
```

macOS 原生构建，安装 Xcode Command Line Tools、CMake、Ninja、Python 3.12+、Perl 和 make。Apple Silicon 选择 `macos-arm64`，Intel 选择 `macos-x86_64`：

```bash
target=macos-arm64
python3 c/client/scripts/build-deps.py "$target"
cmake -S c/client -B build/macos -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 \
  -DOP2P_DEPS_ROOT="$HOME/openp2p-dev/cross/prefix/$target"
cmake --build build/macos --parallel 3
ctest --test-dir build/macos --output-on-failure
cmake --install build/macos --prefix "$PWD/dist/$target"
```

Android 在 WSL / Linux 构建。安装 JDK 21、CMake 3.31.6、Ninja、Python 3.12+、Perl、make；通过 Android SDK 安装 platform 36、build-tools 36.0.0 和 NDK 30.0.16248370：

```bash
export ANDROID_HOME="$HOME/openp2p-dev/android-sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/30.0.16248370"
export OP2P_CMAKE_DIR=/usr  # 含 bin/cmake 3.31.6 的目录；也可由 SDK 管理 CMake
bash c/client/scripts/build-android.sh
```

APK 位于 `c/client/android/app/build/outputs/apk/debug/`。依赖使用 OpenSSL 3.5 的 QUIC TLS 接口、ngtcp2、curl 和 json-c；Linux 原有系统 GnuTLS 后端仍保留。Windows WSS 使用 Schannel 系统信任库；macOS 使用 OpenSSL 与系统 SecTrust 集成。QUIC 对端证书保持现有 Go 协议策略，与网关严格 CA/SAN 验证分开。

工作流 `.github/workflows/c-platforms.yml` 在 macOS 两架构原生构建和测试，在 Linux 构建 Android/Windows，再在 Windows 原生运行测试并检查 MSVC 消费 C SDK。产物可在对应 Actions 运行的 Artifacts 中下载。详细测试依赖 Go 1.20.14 作为协议参考对端，发布的 C 核心不依赖 Go。

0.2.0 的四项作业已全部通过：[验证运行及下载](https://github.com/windows0041/openp2p-test/actions/runs/41268179414)。Android 本机调试包使用本地 `~/.android/debug.keystore`，CI 调试包使用 runner 生成的调试密钥；两者签名可能不同，持续安装更新应使用同一把签名密钥。

## 当前边界

各平台保留 Linux 首版的 IPv4 应用转发范围。复杂对称 NAT 扫描、UPnP/NAT-PMP、IPv6 数据通道、中继、SD-WAN/TUN、完整远程规则编辑、自动更新和 C 网关尚未实现。单规则显式选择 TCP 或 QUIC，未加入所有 Go 自动选路策略。
