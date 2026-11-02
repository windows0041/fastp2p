# fastp2p 构建与发布

主分支只构建 C 客户端与 C 网关，不安装 Go，不使用 Go 参考实现测试。

`c-platforms.yml` 构建 Windows 压缩包、Linux 8 个架构的 static-pie musl 压缩包（x86_64、aarch64、armv7、i686、riscv64、s390x、ppc64le、mips64el）、macOS 双架构压缩包、Android 双 ABI 签名 APK，并额外打包 Linux C SDK。`c-gateway.yml` 在 Debian 12/13 容器内跑完整测试，并另外构建 x86_64 与 aarch64 静态网关压缩包和 amd64 Docker 镜像。发布产物一律为压缩包，不再附带裸可执行文件。

所有平台通过后，main 生成开发 Release。当前稳定标签分别为 `fastp2p-client-v2.0.1` 和 `fastp2p-gateway-v2.0.1`，必须匹配对应 CMake VERSION。先将提交合入并推送 main，再推标签。已公开的 2.0.0 标签保留不变。

发布脚本只接受明确列出的产物，全部上传并核对 SHA-256 后才公开草稿。已公开资产不自动覆盖，每个 Release 附 SHA256SUMS.txt。客户端压缩包内提供 EXE、ELF、APK，无需下载 SDK。

2.0.0 稳定版以隧道握手的 `tunnelID` 绑定直连会话密钥和 ACK，QUIC 证书绑定通过后才启用规则。早期 2.0.0 开发包使用端口配对，需要一起升级全部客户端；不要将开发版与稳定版混用。每次直连重试及切换中继都生成新会话，避免重复初始化 AEAD 序号。

Android release 使用 Actions Secrets `FASTP2P_ANDROID_KEYSTORE_BASE64`（PKCS12）和 `FASTP2P_ANDROID_KEYSTORE_PASSWORD`，别名 `fastp2p`。固定私钥离线备份并复用，在 runner 临时目录解密。实际安装 Token 和签名私钥不进入发布包。

桌面 EXE 和 macOS 程序尚未进行平台代码签名/公证；Android 使用项目固定 APK 签名。

专用客户端预置 c/common/bootstrap.json 的网关地址和公开 CA，只需 16 位数字 Token 安装。更新域名或 CA 后应重新构建全部客户端。公开配置不得包含 Token、管理密码或私钥。

2.0.1 专用配置指向 fastp2p.top，内置公共根而非短期服务器叶证书。Android 设备迁移需显式 `migrate=true`，仍以新 APK 的内置地址与 CA 校验网关，成功后保存并保留设备身份。CI 另上传同签名 `android-device-validation` 测试 APK，用于私有真机迁移与重连验收；不作为生产客户端发布。
