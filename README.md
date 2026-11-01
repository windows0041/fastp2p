# fastp2p

使用自己的网关建立点对点连接。客户端核心和网关均使用 C，主分支只维护 C 版本。

支持 QUIC、TCP 打洞、TCP/UDP 端口转发和 SOCKS5。网关提供 HTTPS Web 控制台及 SQLite 节点注册表。节点名来自主机名，不足 8 位补随机数字，重名分配唯一后缀，重连后保持稳定。

## 下载与安装

[GitHub Releases](https://github.com/windows0041/fastp2p/releases) 提供以下产物：

| 平台 | 客户端 | 自动运行 |
| --- | --- | --- |
| Windows x86_64 | `fastp2p-windows-x86_64.exe` | 当前用户登录后启动 |
| Linux x86_64 | `fastp2p-linux-x86_64` | root 安装 systemd 服务 |
| macOS ARM64 / x86_64 | `fastp2p-macos-*` | 用户 LaunchAgent |
| Android ARM64 / x86_64 | `fastp2p-android.apk` | 前台服务及开机恢复 |

桌面客户端无需旁带项目 DLL/共享库，SDK 单独提供。Linux 产物面向 Debian 12 或更新的 glibc 环境。使用同一 Release 的 SHA256SUMS.txt 校验下载。

在网关 Web 登录后取得 16 位数字安装 Token。专用客户端包已预置网关地址和公开 CA。客户端先校验证书链、主机名和网关登录，再保存配置。不要公开 Token。

Windows：

```powershell
.\fastp2p-windows-x86_64.exe install --token-file .\token.txt
```

Linux：

```sh
chmod +x fastp2p-linux-x86_64
sudo ./fastp2p-linux-x86_64 install --token-file token.txt
```

也支持 `install --token` 和 `FASTP2P_INSTALL_TOKEN`。非 root Linux 使用 `--no-service` 安装后手动 `run`。Windows 配置使用 DPAPI 加密；手动运行的 POSIX 配置权限为 0600。

Android 安装 APK 后，在设备浏览器打开网关“安装 Token → 安卓接入”，或通过 ADB：

```sh
adb install -r fastp2p-android.apk
adb shell am start -n cc.itq.fastp2p.cclient/.InstallActivity --es token 'YOUR_16_DIGIT_TOKEN'
```

Android 无配置表单，保留系统要求的服务通知及停止入口。普通 APK 安装器不能附加业务 Token，需要随后调用接入入口。已有信任配置不会被外部 Intent 静默替换；更换网关前在系统设置中清除应用数据；同一网关更新 Token 可保留设备身份。

## 源码

- `c/client/`：C 核心、CLI、安装器、Android 系统封装。
- `c/gateway/`：Linux C 网关、Web、SQLite。
- `c/common/`：安装 Token 编解码。
- `scripts/tls/`：自签证书生成工具。
- `.github/workflows/`：C 构建、测试和发布。

[网关部署](c/gateway/README.md) · [客户端与 C SDK](c/client/README.md) · [SOCKS5](c/client/SOCKS5-ZH.md) · [发布](RELEASING-ZH.md) · [节点存储](c/NODE-STORAGE-ZH.md)

新协议为 `fastp2p1`，QUIC ALPN 为 `fastp2pv1`，旧客户端需要统一升级。Go 源码保留于 Git 历史和旧标签，不参与主分支构建、测试和发布。上游来源及必要版权声明见 UPSTREAM.md、LICENSE 和 THIRD_PARTY.md。

Linux 系统服务的配置和 CA 由 root 持有，fastp2p 组可读（0640），目录权限 0750；服务进程不能写入。重复接入不会重写相同的 CA 文件。
