# Windows 客户端安装包

## 用法

把安装包命名为 `fastp2p-<16位token>.exe`，双击，在 UAC 提示里点"是"。

安装包从**自己的文件名**里读出 token，不需要另外输入或粘贴。

## 它做了什么

1. 从文件名中取 16 位数字作为接入密钥；
2. 申请管理员权限（创建服务必须）；
3. 用该密钥连接网关，验证证书、主机名与密钥；
4. 把配置写到 `%ProgramData%\fastp2p\client.dat`（机器级 DPAPI 加密）；
5. 把这个 exe 复制到 `%ProgramFiles%\fastp2p\fastp2p.exe`；
6. 注册 Windows 服务 `fastp2p`，设为自动启动，并配置失败后自动重启
   （5 秒 / 10 秒 / 30 秒，一天后重置计数）；
7. 立即启动该服务。

## 运维

| 操作 | 命令 |
| --- | --- |
| 查看状态 | `sc query fastp2p` |
| 停止 | `sc stop fastp2p` |
| 启动 | `sc start fastp2p` |
| 卸载 | `fastp2p.exe uninstall`（需要管理员） |
| 运行日志 | `%ProgramData%\fastp2p\client.dat.log` |

## 安全说明

机器级 DPAPI 加密对**本机任何用户**都可解密，所以真正的保护来自目录 ACL：
`%ProgramData%\fastp2p` 被限制为只有 SYSTEM 和 Administrators 可以访问，
并且在写入配置之前就已完成限制。

## 已知限制

- 文件名里的 16 位数字必须在任何位置连续出现；改名时请注意不要破坏它。
- 文件名里**没有**这 16 位数字时，双击会按普通客户端启动（使用已有配置），
  不会进入安装流程。
- 可执行文件未做代码签名，首次运行时 Windows SmartScreen 可能提示确认。
