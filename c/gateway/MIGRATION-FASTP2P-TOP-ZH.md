# fastp2p.top 迁移准备（2026-11-02）

当前状态：新网关已部署并完成公网 TLS 预检，尚未执行最终停机同步及全部客户端切换；旧网关继续服务。

| 项目 | 已准备内容 |
| --- | --- |
| 旧服务器 | gz.itq.cc.cd / 134.175.48.57 |
| 新服务器 | fastp2p.top / 139.199.4.226，Debian 12 KVM |
| 服务 | fastp2p-gateway.service，专用 fastp2p-gw 账号 |
| 证书 | fastp2p.top、www.fastp2p.top；叶证书有效至 2027-01-30 11:59:59 UTC |
| 信任链 | TrustAsia DV TLS RSA CA 2024 → TrustAsia TLS RSA Root CA（交叉签名）→ Certum Trusted Network CA |
| 客户端专用配置 | fastp2p.top:27183，内置公共 Certum 根；未内置短期叶证书 |
| 节点与管理账号 | SQLite 在线备份已复制供预检；正式切换前还需停旧写入并最终同步 |
| Token | 沿用现有 16 位值，不在仓库、证书包分发或客户端中公开 |

新服务器私钥仅位于 `/etc/fastp2p/tls/server.key`，root 持有、服务组可读；完整证书链和公共根分别为 `server.crt`、`ca.crt`。证书私钥未进入 Git 或 CI 包。原证书和原数据库保留在旧服务器作为回退材料。新服务器原有其他服务未变动。

UFW 已保留原规则并增加 TCP 27180–27181、27183 和 UDP 27180–27183，未禁用防火墙。Web/API 仍只绑定回环地址 10008；是否公开域名 HTTPS 管理入口待确认。

证书链、域名、私钥配对已校验；通过公网 IP 建立连接并使用 `fastp2p.top` 作为 TLS SNI 时，证书验证成功。xrwmaster 的临时客户端已成功通过新域名认证。客户端和网关的 2.0.1 构建、测试及安卓签名包已由 CI 产出；最终稳定发布与实机整体迁移验收尚未完成。

## 待解决的本地网络路径

Windows 的 WLAN DNS 由 192.168.60.1 提供，对 fastp2p.top 返回 198.18.* 代理虚拟 IP，该路径 TLS 握手超时；直连 139.199.4.226 且保留域名 TLS 校验则成功。xrwmaster 和安卓已解析为真实 IP。未降低证书或主机名校验。

拟仅为该域名增加 `DOMAIN,fastp2p.top,DIRECT` 并将 `fastp2p.top` 排除在 fake-IP 之外；此操作涉及路由器配置，等待明确授权。尚未修改路由器，也未修改 Windows 全局 hosts/DNS。

## 正式切换步骤

1. 确认本机使用新域名能正常进行 TLS 和 WSS 认证；确定 Web 保持 SSH 私有访问还是开放域名 HTTPS。
2. 新旧网关短暂停止，使用 SQLite 备份接口复制旧服务器最终状态，保留管理账号哈希、JWT 会话密钥、节点名及 DeviceID；新网关启动后恢复节点在线状态。
3. 桌面/Linux 用新版专用包和原 Token 执行安装器，验证成功后保存新域名和公共 CA，保留规则与设备身份。
4. 安卓安装同签名 CI APK，停止原客户端后携带原 Token 和 `--ez migrate true` 接入。该标记仅接受新版 APK 内置的目标，验证成功才提交；无此标记仍拒绝跨网关覆盖。
5. 验证原四节点、Windows SOCKS5、TCP 打洞、QUIC、安卓数据通道、账号与数据库，再停用旧网关自动启动。

证书续期时保持域名和上述信任链不变即可；客户端不固定叶证书，因此更换同链的服务器证书无需再次分发专用包。
