# SOCKS5 公网调试部署

日期：2026-11-01，C 客户端 0.3.0、ABI 1。现有 `gz.itq.cc.cd` C 网关 0.1.0 与三个 Go 调试节点保持原部署，新增独立 C 节点进行代理联调。

## 可使用的本机入口

| SOCKS5 地址 | P2P 隧道 | 出口 |
| --- | --- | --- |
| Windows `127.0.0.1:1080` | QUIC / UDP 打洞 | xrwmaster：`c-xrw-socks-exit` |
| Windows `127.0.0.1:1081` | TCP 打洞 | xrwmaster：`c-xrw-socks-exit` |

两个入口均支持 SOCKS5 的 TCP CONNECT、UDP ASSOCIATE 和出口 DNS，当前仅绑定回环地址、未启用本地代理认证。未设置系统全局代理。

```powershell
curl.exe --proxy socks5h://127.0.0.1:1080 https://example.com/
```

入口为隐藏运行的原生命令行进程，配置与日志位于 `D:\Codex\.deploy-tools\runtime\c-socks5-client`。安装 token 来自现有本机私有环境，在进程环境中传递，JSON 中不存实际 token。

停止或重新启动入口：

```powershell
powershell -ExecutionPolicy Bypass -File D:\Codex\.deploy-tools\runtime\c-socks5-client\stop.ps1
powershell -ExecutionPolicy Bypass -File D:\Codex\.deploy-tools\runtime\c-socks5-client\start.ps1
```

此调试入口未设置开机启动；重新启动脚本需要现有本机 WSL 凭据文件。一般独立部署按 [SOCKS5 使用说明](../SOCKS5-ZH.md) 设置自己的配置和环境变量即可。

## xrwmaster 出口

`maoyu` 用户目录：`/home/maoyu/openp2p-c-socks5-debug`。使用 Debian 12 原生 C SDK，程序为 `linux-debian12-x86_64/bin/openp2p-c`。节点名 `c-xrw-socks-exit`，沿用私有 CA 和同账号安装 token，不占用公网 SOCKS5 监听端口。

```bash
cd /home/maoyu/openp2p-c-socks5-debug
bash stop.sh
bash start.sh
```

该用户目录中的 C 调试进程未设置开机启动，原 Go 客户端仍单独运行。

## 实测

Windows 入口与 xrwmaster 出口具有不同公网 IP。通过两个代理端口分别校验：

- 目标 `localhost:24400`，验证 `xrwmaster-OPENP2P-ECHO` 标识及 262144 字节随机 TCP 回传。
- UDP ASSOCIATE 目标 `localhost:24401`，校验 1000 字节随机数据、远端 `xrwmaster` 前缀和响应地址头。
- 目标 `localhost:22` 的 SSH 登录，校验已有 xrwmaster SSH 主机密钥、远端主机名及用户。
- 等待 35 秒后再次检查两种隧道中的 TCP/UDP 转发，核对实际 TCP / QUIC 隧道日志。

不含凭据的结果见 [socks5-public-20261101.json](socks5-public-20261101.json)。上述 `localhost` 在出口解析，目标服务实际位于 xrwmaster。

## Android 设备验证对端

Android 12 / x86_64 设备使用不同公网地址的 WSL 对端进行验证。WSL 新增节点 `c-wsl-socks-exit`，位于 `~/openp2p-dev/deploy/gz-20261031/socks-wsl-exit`，配有仅监听回环地址的 TCP 24280 / UDP 24281 echo 测试服务。

```bash
cd ~/openp2p-dev/deploy/gz-20261031/socks-wsl-exit
bash control.sh status
bash control.sh stop
bash control.sh start
```

设备测试配置中的 SOCKS5 本地端口为 24980（TCP 打洞）、24990（QUIC），均带测试用用户名密码。Activity / 前台服务 / JNI 路径验证两个隧道下的 TCP/UDP、认证、加密配置保存、后台心跳、停止和重新启动；最终测试结束时 Android 服务已停止，设备保留私有测试配置。WSL 测试出口及 echo 进程保留，未设开机启动。

首次同公网地址的目标路径没有通过，不将其计入已验证范围。上述是特定公网拓扑的功能验证，未进行长期压力、全部 NAT 类型或 Android ARM 实机测试。
