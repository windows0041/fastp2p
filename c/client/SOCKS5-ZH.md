# SOCKS5 代理

fastp2p C 客户端提供本地 SOCKS5 入口，经 P2P TCP 打洞或 QUIC 隧道，使用指定 C 节点作为出口。支持 TCP CONNECT、UDP ASSOCIATE 和可选用户名密码认证；域名由出口解析。

入口、出口与网关均需 fastp2p **2.0.0 或更新版本**，使用同一自建网关。1.x 客户端不再兼容。

## 使用

### 方式一：Web 控制台下发（推荐）

登录网关 Web 控制台，选中要作为**入口**的在线节点，点「添加转发」，应用协议选
**SOCKS5 代理（动态目标）**：

- **本地入口端口**：自定义，例如 `1080`（这就是本机 SOCKS5 监听端口）
- **出口 / 对端节点**：作为代理出口的在线节点
- **SOCKS5 用户名 / 密码**：可选；两者必须同时填或同时留空（留空 = 不启用认证）
- **P2P 隧道**、**中继节点**：与固定转发一致

SOCKS5 的目标地址由每次请求动态指定、在出口解析，因此表单里的「目标地址 / 目标端口」
会被隐藏。

规则保存在**网关数据库**中：

- 节点在线时立即生效，离线时在下次连接后自动应用；
- 客户端重启后从网关重新拉取，不依赖本地配置文件；
- 控制台可随时编辑、停用、启用、删除；编辑 SOCKS5 认证规则时密码留空表示保留原密码。

某个节点一旦在控制台被添加过规则，它的规则就由网关托管；从未被添加过规则的节点
仍使用自己配置文件里的 `apps` / `socks5`（兼容既有部署）。

### 方式二：客户端配置文件

出口节点正常启动 C 客户端即可，不需要开放 SOCKS5 公网端口或配置转发规则。例如出口的配置：

```json
{
  "network": {"Node":"c-socks5-exit","Token":0,"ServerHost":"gz.itq.cc.cd"},
  "CACertFile":"/absolute/path/to/ca.crt"
}
```

在出口安全设置 `FASTP2P_TOKEN`，运行 `fastp2p --config exit.json`。入口复制 [config.socks5.example.json](config.socks5.example.json)，填写 CA、网关和出口节点名，设置相同 token 后启动：

```bash
fastp2p --config entry.json
curl --proxy socks5h://127.0.0.1:1080 https://example.com/
```

Windows 使用 `fastp2p.exe`、`curl.exe`。浏览器或其他应用配置 SOCKS5 地址 `127.0.0.1:1080`，启用通过代理解析 DNS。`socks5h` 表示把域名传给代理；目标地址始终由出口连接，因此 `127.0.0.1` 指出口节点本机。

`UnderlayProtocol` 为 `tcp` 或 `quic`，省略时为 QUIC。这是 P2P 隧道类型，与代理中的 TCP/UDP 应用独立；UDP ASSOCIATE 也可使用 TCP 打洞隧道。打洞失败时链路自动改走第三节点中继，代理配置不需要改动。入口默认只监听本机回环，`BindIP` 可显式指定其他 IPv4 地址。

同一配置可同时包含 `apps` 固定转发和 `socks5` 数组；可设置多个不同本地端口，选择不同出口。`Enabled:false` 暂停一条代理规则。

## 认证

不设置用户名和密码时，仅使用无认证协商。设置认证后只接受用户名密码方式，不回退到无认证：

```json
{
  "Name":"authenticated-proxy",
  "SrcPort":1080,
  "PeerNode":"c-socks5-exit",
  "Username":"my-user",
  "PasswordEnv":"FASTP2P_SOCKS_PASSWORD",
  "UnderlayProtocol":"quic"
}
```

在启动入口的进程环境中提供该密码。也可用 `Password` 在私有配置中提供；`PasswordEnv` 优先，指定的环境变量不存在或为空时配置失败。用户名和密码需同时存在，每项为 1–255 字节；密码不会写入事件日志。配置文件放在仓库外并限制读取权限。

Android 应用新增“SOCKS5 代理”JSON 数组入口，使用同样字段。通过应用内配置设置 `Password`，完整配置和 token 使用 Android Keystore AES-GCM 保存。可供同设备支持 SOCKS5 的应用连接；此功能不会自动创建系统 VPN 或接管所有应用流量。

## C 接口

ABI 保持 1，已有结构和函数签名不变，新增函数 `fastp2p_client_add_socks5`，字符串在调用时复制：

```c
fastp2p_socks5 proxy = {
    .struct_size = sizeof(proxy),
    .local_port = 1080,
    .peer_node = "c-socks5-exit",
    .transport = FASTP2P_TRANSPORT_QUIC,
};
int result = fastp2p_client_add_socks5(client, &proxy, NULL);
```

在创建实例后添加代理，随后沿用 `start` / `step` / `stop` / `destroy`。监听器、活动连接及 UDP 关联均由实例拥有；停止时关闭，重新启动时恢复监听。JSON 工厂、CLI 和 Android JNI 使用相同的配置解析。

## 行为与限制

- IPv4 监听；目标支持 IPv4 和 ASCII/IDNA 域名的 IPv4 解析。IPv6 地址类型返回 8，BIND 返回 7。
- 只有出口连接成功并返回对应请求 ID 后，TCP CONNECT 才返回成功。出口 DNS 失败返回 4，连接失败返回 5。多个目标并发连接不会共用成功确认。
- UDP 每个数据报包含独立目标地址，可在同一关联中访问不同目的地址；响应头包含实际远端 IPv4 和端口。
- UDP 关联由 TCP 控制连接持有，控制连接关闭后释放 UDP socket 和子流；只接受控制连接同源 IP，并校验请求的源端口或固定首个有效 UDP 源端口。
- 不支持 UDP 分片，非零 FRAG 数据报丢弃；单个 UDP 载荷最多 4096 字节，每个关联最多 32 个目标流，子流空闲 300 秒回收。所有代理和固定转发共享每实例 256 条连接上限及原有队列限制。
- 握手限时 10 秒，等待 P2P 隧道最多 45 秒，等待出口连接确认最多 15 秒。网关/隧道中断时，已有 TCP 代理连接关闭；客户端自动重连后，应用可新建 SOCKS5 会话。UDP 关联可在隧道恢复后创建新目标流。
- 出口 DNS 沿用现有同步系统解析器；未增加异步 DNS 线程或 IPv6 数据面。

实现参考 [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) 和 [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929)，上述范围不包含 BIND、IPv6、UDP 分片或 GSSAPI 认证。

## 验证

构建 C 客户端、C 网关和 Go 参考客户端后，在 Linux / WSL 运行：

```bash
sudo bash c/client/scripts/check-socks.sh
```

该脚本在独立 network namespace 中验证 TCP/QUIC、域名和 IPv4、可选认证、并发目标和错误关联、分片/合并握手、提前发送的数据、UDP 多目标与来源限制、连接回收、拒绝旧出口、网关重启及恢复后 35 秒心跳。测试证书、随机凭据和原始日志保存在私有 `/tmp/fastp2p-socks-tests.*` 目录，不修改公网部署。

原生 Windows / macOS 的同类验证由 `tests/socks_integration.py` 和 CI 执行，使用临时本地网关。实际通过的环境见 [验证记录](VALIDATION-ZH.md)。
