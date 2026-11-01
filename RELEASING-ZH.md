# fastp2p 构建与发布

主分支只构建 C 客户端与 C 网关，不安装 Go，不使用 Go 参考实现测试。

`c-platforms.yml` 构建 Windows EXE、Linux 可执行文件、macOS 双架构可执行文件、Android 双 ABI 签名 APK，并额外打包桌面 C SDK。`c-gateway.yml` 构建 Debian 12/13 原生网关和 amd64 Docker 镜像。

所有平台通过后，main 生成开发 Release。稳定标签分别为 `fastp2p-client-v1.0.0` 和 `fastp2p-gateway-v1.0.0`，必须匹配对应 CMake VERSION。先将提交合入并推送 main，再推标签。

发布脚本只接受明确列出的产物，全部上传并核对 SHA-256 后才公开草稿。已公开资产不自动覆盖，每个 Release 附 SHA256SUMS.txt。客户端主产物直接提供 EXE、ELF、APK，无需下载 SDK。

Android release 使用 Actions Secrets `FASTP2P_ANDROID_KEYSTORE_BASE64`（PKCS12）和 `FASTP2P_ANDROID_KEYSTORE_PASSWORD`，别名 `fastp2p`。固定私钥离线备份并复用，在 runner 临时目录解密。实际安装 Token 和签名私钥不进入发布包。

桌面 EXE 和 macOS 程序尚未进行平台代码签名/公证；Android 使用项目固定 APK 签名。
