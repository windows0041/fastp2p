# GitHub 构建与 Releases

发行位置为本项目的 [Releases](https://github.com/windows0041/openp2p-test/releases)。C 网关和 C 客户端分别构建、测试、发布，不向其他仓库上传文件。

## 自动发布规则

| 触发 | 结果 |
| --- | --- |
| 相关代码推送到普通开发分支 | 构建、测试，保留 Actions artifacts；不发布 Release |
| 相关代码推送到 `main`，且所有测试成功 | 自动创建独立开发版 Release（prerelease），标签包含运行 ID 和提交摘要 |
| 推送 `c-gateway-vX.Y.Z` | 网关矩阵、Docker、浏览器测试通过后，发布正式网关 Release |
| 推送 `c-client-vX.Y.Z` | 客户端全部平台测试通过后，发布正式客户端 Release |

正式标签版本必须与对应 CMake 项目版本一致，且标签的运行时代码必须与测试构建一致。标签发布示例：

```bash
git tag -a c-gateway-v0.2.0 -m "C gateway 0.2.0"
git push origin c-gateway-v0.2.0
```

普通分支和版本标签均会触发原有工作流；不需要手工创建 Release。`workflow_dispatch` 仍可用于手动构建，是否发布取决于所选分支/标签。

## 发行文件

网关 Release：

- `openp2p-c-gateway-debian12-x86_64.tar.gz`
- `openp2p-c-gateway-debian13-x86_64.tar.gz`
- `openp2p-c-gateway-docker-amd64.tar.gz`（`docker save` 镜像包）
- `SHA256SUMS.txt`

客户端 Release：

- `openp2p-c-linux-debian12-x86_64.tar.gz`
- `openp2p-c-windows-x86_64.zip`
- `openp2p-c-macos-arm64.tar.gz`
- `openp2p-c-macos-x86_64.tar.gz`
- `openp2p-c-android-sdk.zip`（调试 APK、原生库、头文件与说明）
- `SHA256SUMS.txt`

Linux 原生包使用匹配发行版的运行环境。Docker 包导入示例：

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
gzip -dc openp2p-c-gateway-docker-amd64.tar.gz | docker load
```

镜像不包含管理账号、安装 token、用户证书或私钥。运行参数见 [网关说明](c/gateway/README.md)。Android 调试包由构建机的调试密钥签名，与本机 APK 可能不同；在已安装应用上覆盖更新时需要使用相同签名。

## 发布完整性

发布作业依赖该产品的所有构建与测试作业成功，使用 GitHub 内置 `GITHUB_TOKEN`，仅发布作业获得 `contents: write`。无需在仓库中保存个人令牌。

`scripts/publish-release.py` 只收集明确列出的发行包，拒绝缺失或重复文件，生成 SHA-256 校验文件。先创建草稿，逐项上传并核对 GitHub 返回的文件大小与 SHA-256，全部完成后才公开发布；失败时保留草稿供重试。已经发布的发行包不会被脚本覆盖或删除。

开发版标签由工作流创建，不会递归触发新的构建。历史开发版和正式版不自动清理。
