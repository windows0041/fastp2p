# SQLite 网关部署与主机名联调

日期：2026-11-01。`gz.itq.cc.cd` 已从 C 网关 0.2.0 更新为 0.3.0，使用 GitHub 正式包。保留现有手工节点名、账号、证书及客户端转发配置。

## 版本与产物

- [C Gateway 0.3.0](https://github.com/windows0041/openp2p-test/releases/tag/c-gateway-v0.3.0)：Debian 12/13 原生包、Docker 镜像及 SHA-256 清单，共 4 个文件。
- [网关正式构建](https://github.com/windows0041/openp2p-test/actions/runs/41298681017)：提交 `c144f4d95a24c161e7a30cbe0b28e5a974514542`。Debian 12/13 的协议、SQLite、真实自动命名客户端、六节点转发与浏览器测试通过，Docker 通过。发布作业重试后成功，运行时未修改。
- [C Client 0.4.0](https://github.com/windows0041/openp2p-test/releases/tag/c-client-v0.4.0)：Linux、Windows、macOS arm64/x86_64、Android SDK 和校验文件，共 6 个文件；[正式构建](https://github.com/windows0041/openp2p-test/actions/runs/41298680976) 的五个构建/测试作业与发布作业全部成功。

已同时核对下载包的 GitHub asset digest、长度及发行校验清单。服务器安装包 SHA-256：

```text
97f725ff5486d539b2c8503b182fd5e0f449d0c8634208793b62fd66d1bae959
```

安装后的可执行程序 SHA-256：

```text
5bfc5fc54afb840d19ce1807f3a700c80cf9ea4d7fd5585fb4ccb597d39c55e5
```

## 实际数据位置

- 程序：`/opt/openp2p-selfhost/c-gateway/0.3.0-c144f4d/bin/openp2p-gateway-c`。
- 服务：`openp2p-selfhost-gateway.service`，账号 `openp2p-gw`。
- SQLite：`/var/lib/openp2p-selfhost/nodes.sqlite3`，0600，属主/组 `openp2p-gw`。
- systemd 使用 `StateDirectory=openp2p-selfhost`，目录模式 0700；服务仍启用 `ProtectSystem=strict`。
- 系统 SQLite 3.40.1，数据库 schema 1；`PRAGMA quick_check` 返回 `ok`。

节点信息、稳定设备标识及在线时间写入数据库。管理密码、安装 Token、TLS 私钥和转发配置未迁入节点数据库。数据库记录从启用此版本开始积累。

## 公网验证

原有 6 个 Go/C 节点重新连接，新数据库正常登记。两份本机 WSL C 0.4 ASan 客户端使用实际主机名 `redmibook` 和不同的私有身份文件，得到：

```text
redmibook
redmibook-8969015274
```

重启第一份客户端，返回原名称；两个测试客户端退出后，数据库保留各自的主机名、节点名和在线时间，均标记离线。现有节点名未改动。最终共 8 条登记记录，6 个在线、2 个离线；上述两条是保留的联调记录。

真实浏览器通过临时 SSH 回环转发登录：在线 Windows C 节点的 SOCKS5 规则正常查询，离线自动命名节点能查看登记信息，转发按钮禁用。桌面和 390px 手机视口均无整体横向溢出，退出清空页面会话。API/Web 仍只监听 `127.0.0.1:10008`。

更新后回归：WSL Go → xrwmaster Go 的 TCP 打洞及 QUIC 各通过 TCP 262144 字节、UDP 1000 字节回传；Windows C SOCKS5 → xrwmaster C 出口的两种传输各通过 TCP/UDP、出口 DNS、SSH 主机密钥与账号校验，以及 35 秒后继续转发。

短主机名补位、满容量重连、网关 SIGKILL 恢复、分配名称后的 TCP/QUIC 转发及超过 100 条历史记录的分页搜索由独立环境测试覆盖，未为验证崩溃额外强杀公网网关。

## 访问、备份与回退

保持原 SSH 转发后，刷新整个网页并重新登录，加载新控制台：

```bash
ssh -N -L 11008:127.0.0.1:10008 root@gz.itq.cc.cd
# https://127.0.0.1:11008/，沿用原 CA 和管理账号。
```

已用 SQLite backup API 在线生成私有快照：`/root/openp2p-c-gateway-sqlite-update-20261101T104922Z/nodes-after-validation.sqlite3`，8 条记录，完整性检查为 `ok`。该文件与真实数据库均未上传仓库或 Release。

回退至此前 C 0.2.0，恢复原 systemd 覆盖文件，保留 SQLite 数据：

```bash
sudo bash /root/openp2p-c-gateway-sqlite-update-20261101T104922Z/rollback.sh
```

本次未触发回退。命名规则、身份文件与 C 库接口见 [节点存储和命名](../../NODE-STORAGE-ZH.md)；此前 Web 更新见 [0.2.0 记录](WEB-DEBUG-ZH.md)。
