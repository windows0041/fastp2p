# 自建 NAT 探测服务

`fastp2p` 的 NAT 等级完全由这里的两台小服务支撑：STUN 判定 UDP 的入站过滤，回调探测判定 TCP 的过滤。它们刻意做成**不依赖第三方**——公共 STUN 大多忽略 `CHANGE-REQUEST`，只按 RFC 5389 从同一五元组回包，用它们判定会把全锥网络误报成端口受限。

## `stun-responder.py` — UDP，支持 CHANGE-REQUEST

```
stun-responder.py [--port 3478] [--address 1.2.3.4 ...] [--verbose]
```

套接字布局与参考实现（[jselbie/stunserver](https://github.com/jselbie/stunserver)）一致，是 **2×2 矩阵**，每个请求由其中一个回应：

| 角色 | 地址 / 端口 | 何时使用 |
|---|---|---|
| PP | 主地址 / 主端口 | 普通请求 |
| PA | 主地址 / 备端口（`端口+1`） | `CHANGE-REQUEST` 换端口 |
| AP | 备地址 / 主端口 | `CHANGE-REQUEST` 换地址 |
| AA | 备地址 / 备端口 | 换地址 + 换端口 |

响应属性按参考实现的顺序输出（有些客户端写死了这个顺序）：

```
MAPPED-ADDRESS        0x0001
RESPONSE-ORIGIN       0x802B
OTHER-ADDRESS         0x802C
XOR-MAPPED-ADDRESS    0x0020
```

`OTHER-ADDRESS` 指向 **AA**（备地址 + 备端口），并且**只有四个套接字全部有效时才发送**——告诉客户端一个无法应答的地址，会让它报出根本不存在的端口受限。

`RESPONSE-PORT`（RFC 5780 §4.5，`0x8032`）也支持：客户端可以让服务器把应答发到**它自己指定的端口**，这是 UDP 过滤探测的第二种手段。

**这是关键**：客户端据此知道"服务器确实实现了换地址"，于是"没收到回包"才成为"我的 NAT 丢了它"的证据，而不是"服务器不支持该属性"。没有它，判定只能停在"NAT1/2"不猜。

只应答格式合法的 BINDING 请求，不回显任意载荷，不能被当作通用 UDP 反射器。

自检（无需外网，起两台回环地址）：`python3 scripts/stun/test-responder.py`——覆盖四个角色、属性顺序、`OTHER-ADDRESS` 的发送条件与 `RESPONSE-PORT` 重定向。

## `tcp-probe-server.py` — TCP，回调 SYN

```
tcp-probe-server.py [--listen 3479] [--address 1.2.3.4 ...] [--timeout 2]
```

TCP 没有 `CHANGE-REQUEST` 等价物（RFC 3489/5780 的过滤测试只针对 UDP），所以过滤用真实连接测：

1. 控制连接上先告诉对端"你的映射是 `X:P`"；
2. 对端回 `probe`，服务器依次尝试连回 `X:P`——**先同 IP 的另一源端口**，再**另一块公网地址**；
3. 汇报哪个握手成功。

对端必须用**同一本地端口**既拨出又监听（同时打开），否则 NAT 转换回来的 SYN 没有进程接收。

## 对端配置

```json
{
  "network": {
    "UDPSTUNServers": ["stun.example.com:3478"],
    "TCPNatProbe": "stun.example.com:3479"
  }
}
```

只写一个 STUN 条目即可——备用地址来自 `OTHER-ADDRESS`。把两个 IP 都列进去反而有害：换地址应答会来自"我们已经联系过"的地址，NAT 本来就放行，会误判成全锥。

## 主机要求

- **两个公网地址**（换地址探测的前提），且上游必须同时放行两个地址的**进出**。只把地址配上而出口被过滤时，用该地址作源发包会丢包，现象是 `change-ip` 永远无回包。
- 防火墙放行 `3478/udp`、`3479/tcp`。
- 建议以 systemd 常驻；若换地址用浮动 IP，另加一个 oneshot 单元在开机时把它绑上。

本仓库生产环境使用的地址是 `stun.fastp2p.top`（`64.90.4.239` 主地址，`64.178.99.142` 备用）。
