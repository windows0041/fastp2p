# C 网关 Web 控制台与自动发布实测

日期：2026-11-01。`gz.itq.cc.cd` 已从 C 0.1.0 更新至 C 0.2.0，使用 GitHub 正式版构建产物；管理 API / Web 继续只监听回环地址。

## 访问

在本机终端建立 SSH 转发，使用自己现有的服务器 SSH 身份：

```bash
ssh -N -L 11008:127.0.0.1:10008 root@gz.itq.cc.cd
```

保持终端连接，在浏览器打开 `https://127.0.0.1:11008/`，信任原有网关 CA，使用原网关管理账号和密码登录。管理端口未开放公网。账号与安装 Token 沿用服务器仓库外的私有配置，不写入文档或 Release。

网关证书包含 127.0.0.1 SAN；SSH 改变的是本地端口，不改变 TLS 证书校验的主机名。HTTP 健康检查和管理请求已使用原有 CA 校验证书链及主机名；浏览器自动化仅在临时 QA 配置中接受私有 CA，未修改系统信任库。

页面支持网关状态、节点搜索、应用列表和新增固定转发。Go 节点支持编辑、开关、删除；C 0.3 节点支持查询和新增，已有规则与 SOCKS5 需在客户端配置中修改。C 新增规则仅保留于当前客户端进程。安装 Token 默认隐藏，登录信息仅保存在页面内存。

## 已发布产物

- [C Gateway 0.2.0](https://github.com/windows0041/openp2p-test/releases/tag/c-gateway-v0.2.0)：Debian 12 / 13 x86_64 原生包、amd64 Docker 镜像包、`SHA256SUMS.txt`，共 4 个文件。
- [正式版构建](https://github.com/windows0041/openp2p-test/actions/runs/41293287366)：源提交 `5dc855b687080d3467d344d8f99fd6bd79c72d3f`，Debian 12/13 的协议、六客户端 TCP 打洞 / QUIC、浏览器测试及 Docker 检查全部通过，工作流自动发布。
- [main 自动预览版](https://github.com/windows0041/openp2p-test/releases/tag/c-gateway-dev-41293287472-5dc855b)：同轮 main 工作流独立构建、测试并发布，验证日常自动发布路径。
- [C Client 0.3.0](https://github.com/windows0041/openp2p-test/releases/tag/c-client-v0.3.0)：Linux、Windows、macOS arm64/x86_64、Android SDK 和校验文件，共 6 个文件。从此前已通过的 [CI 41284347086](https://github.com/windows0041/openp2p-test/actions/runs/41284347086) 取回原产物，用发布脚本补发；客户端运行时代码与版本标签相同。后续由客户端工作流自动发布。

下载的 Debian 12 Release 包 SHA-256：

```text
c92c138fa84ebc47c63ca42d12ca3c4233741b8250b22ac6abf970e8783ff6e2
```

同时核对 GitHub asset digest、文件大小和发行版内的校验清单。安装后的可执行程序 SHA-256：

```text
153dc98b9afb94546b5e2359556b130994f6a91b3a04c1840422ee8c85522071
```

## 服务器更新与回退

- 服务：`openp2p-selfhost-gateway.service`，专用服务账号不变。
- 当前程序：`/opt/openp2p-selfhost/c-gateway/0.2.0-5dc855b/bin/openp2p-gateway-c`。
- systemd 覆盖：`/etc/systemd/system/openp2p-selfhost-gateway.service.d/90-c-gateway.conf`。
- API / Web：`127.0.0.1:10008`；客户端 WSS、TCP/UDP NAT 端口保持原部署参数。
- 原 C 0.1.0、Go 程序、原有证书和私有配置保留。切换时备份原 C 覆盖文件，启动/健康检查失败会自动恢复。

本次更新回退至原 C 0.1.0：

```bash
sudo bash /root/openp2p-c-gateway-web-update-20261101T093548Z/rollback.sh
```

本次运行未触发回退，也未为验证回退额外中断服务。更早的 Go 网关回退方法见 [原切换记录](REMOTE-DEBUG-ZH.md)。

## 更新后的实际验证

- systemd 为 active，`NRestarts=0`；HTTPS 健康检查返回 C 0.2.0。
- 浏览器经临时 SSH 回环转发登录，6 个已有 Go/C 节点在线；读取 Windows C 节点的 SOCKS5 `1080` / `1081` 规则，页面按能力限制编辑操作。
- 桌面与 390px 手机视口无整体横向溢出，退出清空登录状态，浏览器无脚本异常。
- WSL Go → xrwmaster Go：TCP 打洞和 QUIC 各验证 TCP 262144 字节、UDP 1000 字节回传。
- Windows C SOCKS5 → xrwmaster C 出口：TCP 打洞和 QUIC 各验证 TCP 262144 字节、UDP 1000 字节、出口 DNS、SSH 主机密钥与远端身份，35 秒后继续正常转发。

公网浏览器检查只查询已有规则，未修改生产转发配置。规则增删改、中文 C 规则下发及安全边界另由独立临时环境的浏览器/协议测试覆盖，见 [验证记录](../VALIDATION-ZH.md)。
