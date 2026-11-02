# fastp2p C 网关

Linux C11 网关提供 HTTPS/WSS、NAT 探测、连接协调、中继候选选择、Web 和 SQLite。与 fastp2p 2.x 客户端配套，协议 `fastp2p2`。数据通过客户端之间的 QUIC 或 TCP 隧道传输；只有打洞不可用时才经第三节点中继，且中继看不到明文。

## 构建

静态构建（推荐，产出一个不依赖发行版运行库的可执行文件）：

```sh
bash c/gateway/scripts/build-static.sh x86_64
```

本地开发也可以直接链接系统库（Debian 12/13）：

```sh
sudo apt-get install build-essential cmake ninja-build pkg-config python3 \
  libwebsockets-dev libjson-c-dev libssl-dev libsqlite3-dev
cmake -S c/gateway -B build/c-gateway -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/c-gateway --parallel
```

## 部署

```sh
bash scripts/tls/generate-cert.sh /private/tls gateway.example.com 127.0.0.1
```

复制 `.env.example` 到私有环境文件，配置强管理密码、16 位数字接入 Token（首位非零）、证书和数据库路径。`FASTP2P_PUBLIC_HOST` 必须是客户端可达、且出现在服务器证书 SAN 中的地址。`FASTP2P_CA_FILE` 指向公开 CA，用于专用客户端的公开信任配置；公有 CA 可省略并使用客户端系统信任库。

加载私有环境变量后启动：

```sh
build/c-gateway/fastp2p-gateway --bind 0.0.0.0 --apibind 127.0.0.1
```

默认 WSS TCP 27183；TCP NAT 27180–27181；UDP NAT 27180–27183；Web/API HTTPS 127.0.0.1:10008。远程管理通过 SSH 转发访问。Web 可查看在线/离线节点、搜索分页、转发规则和安装 Token。中继候选排除两个端点本身、对称 NAT 节点和协议主版本不同的节点，并按最久未使用优先分配；客户端最多同时中继 4 条会话，超限即拒绝加入，端点随即改用其他候选。

SQLite 使用回滚日志和同步写入，文件权限 0600；通过 SQLite 在线备份接口备份。旧 C 数据库可以保留记录升级 application_id；回退旧程序前应恢复升级前数据库快照。

Docker 从仓库根目录构建：

```sh
docker build -f c/gateway/Dockerfile -t fastp2p-gateway:local .
```

挂载 TLS 证书、公开 CA 及可写 `/var/lib/fastp2p`，设置相同环境变量。容器管理端的宿主机映射只绑定回环地址。systemd 示例见 `deploy/fastp2p-c-gateway.service`。

## 管理账号与节点删除

首次启动使用 FASTP2P_USER / FASTP2P_PASSWORD 初始化管理账号；可自行指定，不使用固定默认账号密码。之后以 SQLite 中保存的账号为准，修改环境变量不会覆盖已保存的设置。

Web 右上角“账号设置”可修改账号和密码，需要输入当前密码，新密码至少 8 位。设置以 PBKDF2-SHA256 加盐哈希保存，修改后旧管理会话失效，需重新登录；客户端接入 Token 与连接保持不变。

忘记密码时，先停止网关服务，设置新的 FASTP2P_USER / FASTP2P_PASSWORD，携带原有证书、Token 与数据库配置运行 fastp2p-gateway --reset-admin，然后重启服务。此操作重置管理账号，不删除节点或轮换客户端 Token。

离线节点的操作列提供“删除”，确认后移除 SQLite 登记记录及名称保留；在线节点不能删除。删除记录不撤销安装 Token，仍持有有效 Token 的设备再次上线会重新登记。

数据库 schema version 2，升级保留节点并新增账号表。回退 1.0.0 前需恢复升级前数据库备份。

专用客户端包通过 c/common/bootstrap.json 预置本网关地址和公开 CA，用户只需输入 16 位数字 Token。更换服务器 CA 或地址后需要重新构建专用客户端。
