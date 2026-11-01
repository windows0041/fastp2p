# 平台

| 平台 | 核心与入口 | 自动运行 |
| --- | --- | --- |
| Linux x86_64 | C11 / CLI / C SDK | root 安装 systemd；普通用户手动 run |
| Windows x86_64 | C11 / 单文件 EXE / C DLL SDK | 当前用户 HKCU Run，后台进程 |
| macOS 13+ ARM64/x86_64 | C11 / CLI / dylib SDK | 用户 LaunchAgent |
| Android 8+ ARM64/x86_64 | C 核心 + JNI/Java 前台服务 | 系统通知、开机恢复 |

客户端默认无配置 GUI，安装时接收 16 位数字 Token 并自动验证网关身份。Windows 使用 DPAPI；Android 使用 Keystore/AES-GCM；手动运行的 POSIX 配置权限 0600。

Android 构建需要 Java 21、SDK 36、NDK 30.0.16248370、CMake 3.31.6。运行 `bash c/client/scripts/build-android.sh`。设置 `FASTP2P_ANDROID_KEYSTORE` 和 `FASTP2P_ANDROID_KEYSTORE_PASSWORD` 时生成固定签名 release APK，否则生成开发调试 APK。

Windows 工具链为 `c/client/cmake/windows-x86_64.cmake`。macOS 使用对应架构的锁定依赖。依赖版本和源文件散列位于 `deps.lock.json`。

Linux 系统服务的配置和 CA 由 root 持有，fastp2p 组可读（0640），目录权限 0750；服务进程不能写入。重复接入不会重写相同的 CA 文件。
