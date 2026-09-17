# 给 Mac 端 AI 的任务说明

请先阅读 `AGENTS.md`、`docs/releases/0.1.19.md` 和 `installer/macos/README.md`，然后完成下面任务。

## 可直接复制给 AI 的提示词

```text
这是 Sf Endpoint AI Proxy 0.1.19 的 macOS 源码包。不要改协议、端口、默认网关、捕获上限、
保留策略或 Qoder 只发现不写入的边界。请在当前 Mac 上：

1. 判断 CPU 是 arm64 还是 x86_64，确认已安装 global.json 要求的 .NET 10 SDK。
2. 执行 chmod +x installer/macos/*.sh installer/macos/preinstall installer/macos/postinstall。
3. 先运行 dotnet restore，再运行对应 RID 的 Release build 和测试；不要跳过失败。
4. 执行 installer/macos/Build-Pkg.sh 生成当前架构的 PKG 和 SHA-256。
5. 用 pkgutil --expand-full 静态检查 Payload、LaunchDaemon plist、preinstall/postinstall，确认包内
   没有 Token、HMAC Key、SPKI 私钥、证书私钥或捕获正文。
6. 如果机器提供 Developer ID Application、Developer ID Installer 和 notarytool Keychain profile，
   使用环境变量签名并运行 Notarize-Pkg.sh；否则明确标记为未签名、未公证，不能假装完成。
7. 只有得到允许后，才在可回滚测试 Mac 上安装。安装后验证 launchctl、healthz、自动挂载、
   文件 owner/group/mode 保持、请求转发、GZip、诊断和远程 Disable/Enable。
8. 最后交付 PKG 路径、字节数、SHA-256、CPU 架构、签名/公证状态、测试结果和未验证项。

不要把真实凭据写回仓库。不要在日常办公 Mac 上直接试装；真实配置写入只允许隔离测试机。
```

## 交付判定

- Apple Silicon 与 Intel 必须分别构建，不能把单架构包称为 Universal。
- 未签名包仅供隔离验收；正式分发必须同时完成应用签名、Installer 签名与 Apple 公证。
- 当前 Windows 侧只能做交叉发布和静态检查，最终 PKG 必须由 macOS 的 `pkgbuild` 产生。
- 版本仍为 0.1.19；控制 API、数据库 Schema 和诊断 Schema v2 与 Windows 端保持兼容。
