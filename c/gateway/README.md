# fastp2p C 网关

Linux C11 网关提供 HTTPS/WSS、NAT 探测、连接协调、中继候选选择、Web 和 SQLite。与 fastp2p 2.x 客户端配套，协议 `fastp2p2`。数据通过客户端之间的 QUIC 或 TCP 隧道传输；只有打洞不可用时才经第三节点中继，且中继看不到明文。

## Release 下载加速

在环境文件中设置 `FASTP2P_RELEASE_DOWNLOAD_PREFIX=https://gh-proxy.org/`，控制台同步时会优先通过该加速入口查询版本信息和下载公开 Release 文件。下载内容需与 API 元数据和校验清单中的大小、SHA-256 一致，加速异常时尝试直连官方 API。加速请求直接连接加速站。该配置下元数据和文件都由加速站转发，摘要校验验证下载一致性，发布者身份仍依赖这条获取链路。

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

数据库核心 schema version 4。包下载租约与待删除文件使用附加表，不改变节点身份或规则。同步 GitHub 最新稳定客户端成功后，自动清理较低版本的镜像包和手动上传包；相同或更高版本保留。正在下载/已下发升级的版本暂缓清理，后台每分钟重试过期租约和删除失败项；同步失败保留现有包。

Linux 的控制台下载接口返回带 16 位 Token 文件名的自包含 shell 安装脚本，包含选中架构的原始 ELF 与独立的系统服务脚本。Token 只放在下载文件名，不进入共享缓存。客户端远程升级接口仍提供原始可执行文件；无需把发行版安装逻辑加入 C 网络核心。修改安装脚本后须重新构建网关（Docker 构建上下文使用仓库根目录）。

专用客户端包通过 c/common/bootstrap.json 预置本网关地址和公开 CA，用户只需输入 16 位数字 Token。更换服务器 CA 或地址后需要重新构建专用客户端。

## 客户端配置下发

新版 Linux/Windows/macOS CLI 的「配置」按钮可编辑网关管理的 JSON 字段，按键值递归合并到客户端 config/fastp2p.conf，未下发字段保留，数组整体替换。客户端自动重载，确认新连接成功才显示 applied；失败会恢复原配置并反馈 failed。Windows 保持 DPAPI 加密。SDK/Android 需由宿主注册配置处理回调后才支持此功能。

接口为登录后 GET/POST `/api/v1/device/<节点名>/config`，POST 请求体 `{ "fields": { "network": { "PublicIPPort": 12345 } } }`。SQLite 的 node_configs 记录期望字段、版本及状态，离线时排队，上线后重发。转发规则和文件配置共用同一份期望状态；删除离线节点也会清理其规则及下发配置。
