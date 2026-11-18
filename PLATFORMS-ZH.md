# 平台

| 平台 | 核心与入口 | 自动运行 |
| --- | --- | --- |
| Linux x86_64 (glibc) | C11 / CLI / C SDK | 网关脚本安装到 /usr/local/fastp2p；普通用户可手动 run |
| Linux 静态 musl | C11 / CLI | 安装脚本选择 systemd、procd 或 OpenRC |
| Windows x86_64 | C11 / 单文件 EXE / C DLL SDK | 安装器注册 Windows 服务 |
| macOS 13+ ARM64/x86_64 | C11 / CLI / dylib SDK | 用户 LaunchAgent |
| Android 8+ ARM64/x86_64 | C 核心 + JNI/Java 前台服务 | 系统通知、开机恢复 |

CI 发布 x86_64、aarch64、armv7、riscv64 和 mips64el 五种 Linux static-pie musl 包，文件名为 `fastp2p-linux-static-<arch>.tar.gz`。每种架构单独构建 OpenSSL、curl、ngtcp2 和 json-c。仓库根目录下的 `scripts/build-musl.sh <arch>` 可用于本地构建。

客户端默认无配置 GUI，安装时接收 16 位数字 Token 并自动验证网关身份。Windows 使用 DPAPI；Android 使用 Keystore/AES-GCM；手动运行的 POSIX 配置权限 0600。

Android 构建需要 Java 21、SDK 36、NDK 30.0.16248370、CMake 3.31.6。运行 `bash scripts/build-android.sh`。设置 `FASTP2P_ANDROID_KEYSTORE` 和 `FASTP2P_ANDROID_KEYSTORE_PASSWORD` 时生成固定签名 release APK，否则生成开发调试 APK。

Windows 工具链为 `cmake/windows-x86_64.cmake`。Windows DLL SDK 在 Actions 的 `windows-validation` 产物中。macOS 使用对应架构的锁定依赖。依赖版本和源码摘要记录在 `deps.lock.json`。

Linux 安装器将 `/var/lib/fastp2p/config` 交给服务账号，目录权限为 0700，`fastp2p.conf` 为 0600，供网关规则同步时原子更新。CA 文件由 root 持有，fastp2p 组可以读取（0640）。
