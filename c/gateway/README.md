# fastp2p C 网关

Linux C11 网关提供 HTTPS/WSS、NAT 探测、连接协调、Web 和 SQLite。与 fastp2p 1.x 客户端配套，协议 `fastp2p1`。数据通过客户端之间的 QUIC 或 TCP 隧道传输。

## 构建

Debian 12/13：

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

复制 `.env.example` 到私有环境文件，配置强管理密码、非零 uint64 接入密钥、证书和数据库路径。`FASTP2P_PUBLIC_HOST` 必须是客户端可达、且出现在服务器证书 SAN 中的地址。`FASTP2P_CA_FILE` 指向公开 CA，供安装 Token 携带；公有 CA 可省略并使用客户端系统信任库。

加载私有环境变量后启动：

```sh
build/c-gateway/fastp2p-gateway --bind 0.0.0.0 --apibind 127.0.0.1
```

默认 WSS TCP 27183；TCP NAT 27180–27181；UDP NAT 27180–27183；Web/API HTTPS 127.0.0.1:10008。远程管理通过 SSH 转发访问。Web 可查看在线/离线节点、搜索分页、转发规则和安装 Token。

SQLite 使用 WAL，文件权限 0600；通过 SQLite 在线备份接口备份。旧 C 数据库可以保留记录升级 application_id；回退旧程序前应恢复升级前数据库快照。

Docker 从仓库根目录构建：

```sh
docker build -f c/gateway/Dockerfile -t fastp2p-gateway:local .
```

挂载 TLS 证书、公开 CA 及可写 `/var/lib/fastp2p`，设置相同环境变量。容器管理端的宿主机映射只绑定回环地址。systemd 示例见 `deploy/fastp2p-c-gateway.service`。
