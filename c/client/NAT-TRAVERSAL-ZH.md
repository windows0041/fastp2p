# NAT 类型检测与打洞策略（借鉴 EasyTier）

本文记录对 [EasyTier](https://github.com/EasyTier/EasyTier) 的阅读结论（commit `24e0303`），以及 fastp2p 当前的差距和改造建议。EasyTier 为 Rust 实现，涉及文件：

| 文件 | 作用 |
| --- | --- |
| `easytier-core/src/connectivity/stun/client.rs` | NAT 类型判定（`UdpNatTypeDetector`） |
| `easytier-core/src/connectivity/hole_punch/udp/common.rs` | NAT 归类与「方法矩阵」 |
| `easytier-core/src/connectivity/hole_punch/udp/client.rs` | 主动方打洞流程 |
| `easytier-core/src/connectivity/hole_punch/udp/server.rs` | 被动方按指令发打洞包 |
| `easytier-core/src/connectivity/hole_punch/udp/socket_array.rs` | 多本地端口阵列（对称 NAT 用） |

## 一、NAT 类型判定

### 1.1 类型集合

EasyTier 用 9 个值，实际判定路径只会产出其中 7 个：

| 值 | 含义 |
| --- | --- |
| `OpenInternet` | 公网直连，映射地址等于本地地址 |
| `NoPat` | 有 NAT 但不改端口 |
| `FullCone` | 完全锥形 |
| `Restricted` | IP 受限锥形 |
| `PortRestricted` | IP+端口受限锥形 |
| `SymmetricEasyInc` / `SymmetricEasyDec` | 对称 NAT，但映射端口可预测（递增/递减） |
| `Symmetric` | 对称 NAT，端口随机 |
| `Unknown` | 探测不足 |

### 1.2 判定算法（UDP，`nat_type_udp`）

从**同一个本地套接字**向多个 STUN 服务器发请求，收集每个服务器看到的映射地址：

1. **少于 2 个服务器应答** → `Unknown`，不做结论。
2. **锥形判定**：所有服务器报告的映射地址完全相同 → 端点无关映射（cone）。
   - 若某个服务器从**不同 IP** 回包被收到（`has_ip_changed_resp`）：说明 NAT 放行了未通信过的源地址
     - 映射 IP 是公网且端口未改 → `OpenInternet`
     - 端口未改但 IP 变 → `NoPat`
     - 否则 → `FullCone`
   - 否则若某个服务器从**同 IP 不同端口**回包被收到（`has_port_changed_resp`）→ `Restricted`
   - 否则 → `PortRestricted`
3. **对称判定**：不同服务器看到不同映射地址。
   - 公网 IP 多于 1 个、可用应答 ≤ 1、或映射端口跨度 > 15 → 直接判 `Symmetric`
   - 否则做**额外绑定测试**：另绑一个本地端口取映射端口
     - 新端口比此前最大端口大且差值 < 100 → `SymmetricEasyInc`
     - 新端口比此前最小端口小且差值 < 100 → `SymmetricEasyDec`
     - 否则 → `Symmetric`
4. 判定完成后 10 分钟重测一次；未判定成功则 10 秒后重试。

对应常见中文编号（README 提到 NAT4-NAT4）：NAT1 ≈ Open/NoPat/FullCone，NAT2 ≈ Restricted，NAT3 ≈ PortRestricted，NAT4 ≈ Symmetric。

## 二、打洞方法矩阵

`UdpNatType::get_punch_hole_method(self, other)` 决定由**谁当主动方**：

| 本端 \ 对端 | Cone | EasySym | HardSym | Unknown |
| --- | --- | --- | --- | --- |
| **Cone** | ConeToCone | 不可（对方主动） | 不可 | ConeToCone |
| **EasySym** | SymToCone | EasySymToEasySym | 不可 | SymToCone |
| **HardSym** | SymToCone | 不可 | 不可 | SymToCone |
| **Unknown** | ConeToCone | 不可 | 不可 | ConeToCone |

要点：

- **对称方永远主动**（`can_punch_hole_as_client` 只有在 `self.is_sym()` 或双方都是 EasySym 时才为真）。
- 双方都是锥形（含 NAT2-2、NAT2-3、NAT3-3）统一走 **ConeToCone**，不区分受限级别。
- 双方都是 EasySym 时，**PeerId 小的一方**当主动方，避免双向同时发起。
- HardSym 对 HardSym 返回不可行；README 宣称的 NAT4-NAT4 依赖下面第三节的「端口阵列 + 随机喷洒」概率命中。

## 三、四类执行流程

### 3.1 ConeToCone（覆盖 NAT2-2 / NAT2-3 / NAT3-3）

1. 主动方向对端（经信令）请求**打开/复用打洞监听器**，拿到对端的映射地址。
2. 主动方绑定打洞套接字，用 STUN 得到自己的映射地址。
3. 立刻向对端映射地址发一个打洞包。
4. 通过信令让对端向**自己的映射地址**发打洞包：`packet_count_per_batch=2`、`packet_batch_count=5`、`packet_interval_ms=400`（即 5 轮、每轮 2 个、间隔 400ms）。
5. 主动方 `connect()` 重试 2 次，每次循环每 200ms 补发一个打洞包，直到握手成功。

本质就是**双方同时向对方映射地址发包**，把两侧 NAT 的过滤表同时打开。fastp2p 现有的 `punchts` 同步机制属于这一类，但没有「对端按批次补发」这一步。

### 3.2 SymToCone（覆盖 NAT2-4 / NAT3-4）

主动方是对称侧，流程同上，差别在于对称侧的映射端口每次都变，所以它需要**让对端往一批预测端口上喷洒**：

- 若对称侧是 EasySym：RPC `SendPunchPacketEasySym{base_port_num, max_port_num=50, is_incremental}`；
  对端按方向枚举 `base+1..base+50` 或 `base-1..base-50` 全部发一遍。
- 对端若也是 EasySym 并且要主动打我们，会额外做 `apply_peer_easy_sym_port_offset(base, inc)`，即故意偏移 ±20 个端口，避免双方预测到同一段。

### 3.3 EasySymToEasySym

PeerId 小的一方当主动方；双方都预测对端端口窗口（±50 枚举），主动方偏移 20 保证覆盖不同区间。

### 3.4 HardSym 的随机喷洒（NAT4 相关）

被动侧持有 **1..65535 的全局打乱端口表**（`shuffled_port_vec`），每次 RPC `SendPunchPacketHardSym{round, port_index}`：

- 第 1 轮随机取 600~800 个端口，各发一个打洞包，做 2 遍；
- 轮次越多，窗口越小：`max_k2 = (max_k2 * 2 / round).max(180)`；
- 返回 `next_port_index` 作为下一轮的游标。

主动侧则维护一个**本地端口阵列**（`UdpSocketArray`，可配置上限），从所有本地端口同时向对端映射地址发包，然后用 `try_fetch_punched_socket(tid)` 看哪个本地端口收到了回包——哪个通了就用哪个连接。这就是「N×M 生日碰撞」，用端口数量换成功率。

## 四、fastp2p 的差距

| 能力 | EasyTier | fastp2p 现状 |
| --- | --- | --- |
| NAT 分类 | 7 种（含 cone 细分与 EasyInc/Dec） | 二值：`nat_port == local_port ? 1 : 2`，失败记 314 |
| 判定依据 | 多 STUN 服务器比对映射 + 额外绑定测试 | 单一 STUN 映射与本地端口比较 |
| 锥形对锥形 | 双方同时发 + 对端按批次补发 | 有时间同步的同时发起，无补发 |
| 对称对锥形 | 预测端口窗口（±50）让对端喷洒 | 无，直接判失败转中继 |
| 双 EasySym | 低 PeerId 主动 + 偏移 20 | 无 |
| 对称 NAT | 本地端口阵列 + 随机喷洒 | 无 |
| 中继回退 | 有 | 有（本次已加排序与手动指定） |

也就是说：**NAT2-2、NAT2-3、NAT3-3 这三类 fastp2p 理论上已能打通**（都属于同时发起的锥形对锥形），失败多与「只有一次同步发包、没有补发窗口」有关；而 **NAT2-4 / NAT3-4 以及 HardSym 组合 fastp2p 完全没有实现**，只能落到中继。

## 五、改造建议（按收益排序）

1. **把二值分类换成 EasyTier 的判定**：多 STUN 服务器比对映射地址 → cone/对称；再用「另绑一个端口看映射端口差」判 EasyInc/Dec。这一步只改探测，不改协议，风险最低。
2. **锥形对锥形加补发窗口**：协商时让对方在 2 秒内每 400ms 补发一次（共 5 轮），而不是只发一次。可直接复用现有 gateway 的 `main 3 sub 1/2` 打洞协商，增加 `count/interval` 字段。
3. **对称侧预测端口窗口**：对称侧把「自己下一次映射可能落在的区间」和方向告诉对端，对端在 `base±50` 上喷洒。fastp2p 已有 `main 3 sub 2` 回包可承载这些字段。
4. **本地端口阵列**：为对称 NAT 场景预留 N（建议 8~16）个打洞套接字，哪个先收到回包就用哪个。注意 fastp2p 是单线程事件循环，端口阵列要纳入 `step()` 的 fd 集合。
5. 协议字段扩展需要同步升级 `fastp2p2` 的协商消息，网关侧无需改动（打洞包走端点直连）。

以上 2~4 项会改变打洞协商的字段，属于协议演进；建议先做第 1 项（纯探测）并补一个「我方 NAT 类型 + 对端 NAT 类型 → 是否值得尝试打洞」的决策表，让中继回退更快，再视需要在下一版协议里加喷洒能力。
