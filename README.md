# fastp2p

使用自己的网关建立点对点连接。客户端核心和网关均使用 C，主分支只维护 C 版本。

支持 QUIC、TCP 打洞、中继回退、TCP/UDP 端口转发和 SOCKS5（**Web 控制台可直接给在线节点下发 SOCKS5 代理规则、自定义本地端口和可选用户名密码**，详见 [SOCKS5 说明](c/client/SOCKS5-ZH.md)）。**每个在线客户端都可以充当中继**；打洞失败或双方都在对称 NAT 后时，网关挑选第三节点，两个端点各自打洞到中继并配对。候选按可连通性排序：与对端不在同一公网地址的优先（不需要 NAT 发夹），其次是端点无关映射（NAT 1）、更大的共享带宽，最后是最近最少被使用的节点；对称 NAT 节点不参与。单条转发规则也可以指定中继：配置文件写 `RelayNode`，控制台在添加转发时选择「中继节点」，留空则自动选择。隧道载荷使用 AES-256-GCM，会话密钥由发起端经网关的 TLS 通道分发，中继只转发不透明帧。网关提供 HTTPS Web 控制台及 SQLite 节点注册表。节点名来自主机名，不足 8 位补随机数字，重名分配唯一后缀，重连后保持稳定。

## 下载与安装

[GitHub Releases](https://github.com/windows0041/fastp2p/releases) 提供以下产物：

| 平台 | 客户端 | 自动运行 |
| --- | --- | --- |
| Windows x86_64 | `fastp2p-windows-x86_64.exe` | Windows 服务（开机自启、失败自动重启） |
| Linux（静态） | `fastp2p-linux-static-{x86_64,aarch64,armv7,i686,riscv64,s390x,ppc64le,mips64el}.tar.gz` | root 安装 systemd 服务 |
| macOS ARM64 / x86_64 | `fastp2p-macos-{arm64,x86_64}.tar.gz` | 用户 LaunchAgent |
| Android ARM64 / x86_64 | `fastp2p-android.apk` | 前台服务及开机恢复 |

桌面客户端无需旁带项目 DLL/共享库，Linux SDK 单独提供（`fastp2p-sdk-linux-x86_64.tar.gz` 是链接本项目的 C 应用用的开发包）。Linux 客户端只有一套静态 musl 构建：static-pie，不依赖目标机 libc，Debian、Ubuntu、Alpine 以及路由器和 NAS 用的是同一个文件。使用同一 Release 的 SHA256SUMS.txt 校验下载。

在网关 Web 登录后取得 16 位数字安装 Token。专用客户端包已预置网关地址和公开 CA。客户端先校验证书链、主机名和网关登录，再保存配置。不要公开 Token。

Windows 下载的是一个 `fastp2p-windows-x86_64.exe`。**用安装 Token 给它重命名**（例如
`fastp2p-9864596884675924.exe`），然后双击：系统弹出 UAC 授权框，确认后打开一个终端窗口显示安装进度，
结束用弹窗报告结果，点「确定」终端自动关闭。安装器从文件名读取 Token，注册为 Windows 服务并设为开机自启。
详见 [Windows 安装说明](c/client/WINDOWS-INSTALL-ZH.md)。

Linux：

```sh
tar xzf fastp2p-linux-static-x86_64.tar.gz
sudo ./fastp2p-linux-static-x86_64/bin/fastp2p install --token-file token.txt
```

也支持 `install --token` 和 `FASTP2P_INSTALL_TOKEN`。非 root Linux 使用 `--no-service` 安装后手动 `run`。Windows 配置使用 DPAPI 加密；手动运行的 POSIX 配置权限为 0600。

Android 安装 APK 后，在设备浏览器打开网关“安装 Token → 安卓接入”，或通过 ADB：

```sh
adb install -r fastp2p-android.apk
adb shell am start -n top.fastp2p.cclient/.InstallActivity --es token 'YOUR_16_DIGIT_TOKEN'
```

Android 无配置表单，保留系统要求的服务通知及停止入口。普通 APK 安装器不能附加业务 Token，需要随后调用接入入口。普通安装链接不能替换已有网关；迁移时先安装新网关专用的签名 APK，再由操作者携带 Token 和 `--ez migrate true` 调用同一接入入口。目标地址和 CA 只能来自 APK 内置配置，校验证书及登录成功后才保存，保留 DeviceID 和规则。同一网关更新 Token 无需迁移标记。

## 源码

- `c/client/`：C 核心、CLI、安装器、Android 系统封装。
- `c/gateway/`：Linux C 网关、Web、SQLite。
- `c/common/`：安装 Token 编解码。
- `scripts/tls/`：自签证书生成工具。
- `.github/workflows/`：C 构建、测试和发布。

[网关部署](c/gateway/README.md) · [客户端与 C SDK](c/client/README.md) · [SOCKS5](c/client/SOCKS5-ZH.md) · [发布](RELEASING-ZH.md) · [节点存储](c/NODE-STORAGE-ZH.md)

[2026-11-02 部署验收与管理入口](c/gateway/DEPLOYMENT-ZH.md)

协议为 `fastp2p2`，QUIC ALPN 为 `fastp2pv2`。2.0.0 与 1.x 不互通，网关和全部客户端需要一起升级；1.x 的 CBC 隧道载荷和 SD-WAN 配置下发已删除。Go 源码保留于 Git 历史和旧标签，不参与主分支构建、测试和发布。上游来源及必要版权声明见 UPSTREAM.md、LICENSE 和 THIRD_PARTY.md。

Linux 系统服务的配置和 CA 由 root 持有，fastp2p 组可读（0640），目录权限 0750；服务进程不能写入。重复接入不会重写相同的 CA 文件。

2.0.1 起，网关专用客户端预置 `fastp2p.top:27183`，信任 Certum Trusted Network CA 公共根证书。网关证书续期时只要域名及信任链保持不变，无需重发客户端。证书私钥不进入仓库或客户端包。
