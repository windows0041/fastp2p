# SQLite 节点存储与主机名命名

C 网关 0.3.0 和 C 客户端 0.4.0 增加节点持久化及自动命名，保持客户端 ABI 1、原有 Go/C 转发协议与显式节点名兼容。

## 自动节点名

客户端不配置 `network.Node` 或设为 `""` 时，读取本机主机名：Linux/macOS/Android 使用 `gethostname`，Windows 使用 DNS 主机名 API。名称中的非 ASCII 字母、数字、下划线和横线转换为横线，最多保留 31 位。

网关用 SQLite 事务分配最终名称：

1. 优先使用清理后的主机名；少于 8 位时，用随机数字补到 8 位。
2. 与已登记的在线或离线节点重名时，使用主机名前缀、横线和 10 位随机数字，总长不超过 31 位。
3. 数据库对节点名、协议节点 ID、设备标识设置唯一约束，分配遇到冲突会重试。这里的全局唯一指同一自建网关数据库管理的全部节点。

示例：`pc` → `pc123456`；`xrwmaster` → `xrwmaster`；第二台同名机器 → `xrwmaster-1234567890`。示例数字仅作说明。

客户端生成并保存 32 位十六进制 `DeviceID`。网关按该标识复用已分配的名字，客户端重启、断线重连或网关重启后不重新随机命名；主机名改变时也保留原节点名，更新主机名元数据。不同安装应使用各自的设备标识，不要跨机器复制自动身份文件。

已经显式配置的 8–31 位节点名保留，避免破坏现有转发规则；Go 客户端继续使用原名称。自动分配后的名称由 WSS 登录响应返回，C 核心在启动业务连接前更新自己的节点 ID，并记录 `node name: ...` 事件。旧网关可接受客户端生成的候选名称，但集中唯一分配需要 C 网关 0.3.0+。

## CLI、Android 与 C 库

CLI 省略 `--node` 且配置中没有固定名称时自动命名：

```bash
openp2p-c --serverhost my-gateway.example --cacert /path/to/ca.crt
# 多实例或服务账号可显式指定各自的身份文件：
openp2p-c --serverhost my-gateway.example --cacert /path/to/ca.crt \
  --identity-file /path/outside/repository/node-a.identity
```

使用配置文件时，默认在其旁边保存 `<配置文件>.identity`。无配置文件时，Linux/macOS 使用 `$XDG_STATE_HOME/openp2p-c/`，未设置时使用 `$HOME/.local/state/openp2p-c/`；Windows 使用 `%LOCALAPPDATA%/openp2p-c/`。文件名区分网关地址和端口，同一默认身份对应一个客户端实例，多实例需分别指定身份文件。

配置也可显式提供自动身份，例如：

```json
{"network":{"AutoNode":true,"ServerHost":"my-gateway.example"}}
```

也可用 `network.DeviceID` 显式提供已保存的 32 位小写十六进制标识；CLI 和 Android 通常无需填写，由程序自行保存。安装 Token 和 CA 仍按原有方式配置。Android 节点名留空时走同一 C 核心，设备标识保存在应用私有配置中；手工填入名称则保持固定名称。

C 库 `.node = NULL` / 空字符串启用自动命名。调用者读取并持久保存 `op2p_client_device_id()`；后续实例在 `start` 前调用 `op2p_client_set_identity()`。`op2p_client_node()` 在登录后返回网关分配的最终名称。三个新增函数不改变已有结构体布局，ABI 保持 1；返回字符串由库拥有，不能释放。库自身不写用户配置文件。

设备标识用于名称复用，登录仍需正确的安装 Token，并验证网关 TLS 证书链和主机名。

## 网关数据库

通过 `--database FILE` 或 `OPENP2P_DATABASE` 指定数据库，未设置时使用当前目录的 `nodes.sqlite3`。systemd 模板使用 `/var/lib/openp2p-c/nodes.sqlite3`，由 `StateDirectory` 创建专用目录；Docker 默认 `/var/lib/openp2p/nodes.sqlite3`，部署时挂载可写的持久目录或命名卷。

数据库使用 SQLite schema 1、应用 ID `0x4f503250`，拒绝覆盖其他应用的数据库或打开更高版本 schema。单个数据库由一个活动网关实例维护；回滚日志和 `synchronous=FULL` 保证事务提交，写锁等待有上限。节点表包含：

- 唯一节点名、字符串形式的 uint64 节点 ID、可选设备标识和主机名。
- 公网/内网 IP、IPv6、MAC、系统、协议版本、NAT 类型、共享带宽。
- 首次登记、最近在线、最近离线时间及最后保存的在线状态。

上线、信息上报和断线时保存，在线期间最多每 30 秒保存一次最近活动时间。启动时清除旧在线标记，由客户端重连恢复在线状态；Web 的在线状态以当前连接为准。突然断电时，最近在线时间最多落后于最后一次周期保存，不能将该值视为精确的掉线时刻。

Web 展示在线和离线节点，支持分页、全库搜索、主机名和最近在线时间；离线节点禁止发送转发操作。`GET /api/v1/nodes` 返回登记记录，支持 `search`、`limit`（1–256）、`offset`，需要管理 JWT。原 `GET /api/v1/devices` 保持仅返回在线节点，以兼容现有工具；`status` 新增 `nodeStorage` / `totalNodes`。

数据库不存储安装 Token、管理密码、JWT、证书、私钥或客户端业务转发规则。历史记录从启用此版本后开始积累。

在线备份使用 SQLite backup API，例如 Python `sqlite3.Connection.backup()`；停机后可复制数据库文件。不要在网关运行时直接复制数据库文件作为一致性备份。原理参考 [SQLite 事务文档](https://www.sqlite.org/lang_transaction.html)。

## 验证

```bash
sudo bash c/gateway/scripts/check.sh --sanitize
sudo bash c/gateway/scripts/check-registry.sh
sudo bash c/gateway/scripts/integration.sh
```

新测试覆盖 SQLite 唯一约束、短名称补位、同名设备、保存和重新读取身份、离线分页/搜索、满容量重连和进程崩溃恢复。真实 C 客户端测试在隔离 UTS/network namespace 中设置短主机名及重复主机名，并用分配后的名称完成 TCP / QUIC 转发；不会修改主机的真实名称。浏览器测试覆盖离线只读状态及超过 100 个历史节点的跨页搜索。
