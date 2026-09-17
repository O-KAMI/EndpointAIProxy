# macOS 0.1.22 安装交付验收 · 2026-09-17

## 本次 IOA 实际推送结果

Apple Silicon / macOS 26.6.2 上，IOA 已以 root 调用系统安装器，包文件 SHA256 与交付文件一致。
文件复制及 preinstall 执行完成，启动客户端时 AMFI 拒绝 ad hoc / 未知证书链的程序，
AppleSystemPolicy 明确拒绝进程运行。postinstall 等待约 60 秒就绪失败后 bootout 新服务，
PackageKit 返回 PKInstallErrorDomain Code=112（postinstall）。当前无产品安装收据、
无产品 LaunchDaemon、18080 本地健康接口不可达。本次不能标记为安装通过。

IOA 显示推送成功与系统安装失败不一致；尚未取得 IOA 内部退出码处理证据，
不能断言具体产品缺陷。需核对任务成功判定，补充收据、服务和本地健康检查。
产品独立安装日志为 root 可读，本次未读取；以上结论来自系统安装和统一安全日志。
先对程序/运行库及 PKG 分别完成 Developer ID 签名，再公证、附加票据及小范围复测。
仅对 PKG 签名或放宽健康检查不能修复程序运行信任问题。

## 本机已完成

环境：macOS 26.6.2 / Apple Silicon / 隔离 .NET SDK 10.0.101。

| 检查 | 结果 | 边界 |
|---|---|---|
| 两种架构最终 PKG 连续构建两次 | PASS | 每种架构两次均成功；未签名、未公证 |
| 实际 PKG 解包静态验收 | PASS | 版本 0.1.22、架构、root BOM、最终脚本字节一致、原凭据一致、脚本凭据 0600、无 AppleDouble |
| zsh 语法 / plist 校验 | PASS | 不运行安装流程 |
| 隔离安装脚本测试 19 项 | PASS | 重写副本的固定路径；root、launchctl、进程与网络为模拟，不改真实环境 |
| 跨平台 .NET 测试 30 项 | PASS | 原有策略签名、策略版本、动态网关切换、机器密钥与路由测试 |
| 受信任 SDK host 运行 arm64 程序集 | PASS | 临时 SQLite、健康版本 0.1.22；控制同步关闭、auto-attach=false、临时 profile；非独立 apphost 验收 |
| 独立 arm64 apphost 原生启动 | BLOCKED | SIGKILL；系统日志明确显示 AMFI 拒绝 ad-hoc/未知证书链，AppleSystemPolicy 不允许进程运行 |
| 有效代码签名身份 | MISSING | 本机 Keychain 查询结果为 0；未更改系统安全设置 |

SDK 默认 ad-hoc 签名的主程序及 hostfxr/hostpolicy/coreclr 的 codesign 静态校验通过，
但静态签名完整性不等于系统认可签发者。受信任 SDK host 运行通过进一步区分了
程序集启动能力与自定义 apphost 的系统信任问题。
尚无法交付受信任签名版本；需提供 Developer ID Application / Installer 证书及私钥，
公证需相应 Apple 账号/Keychain 配置。签名构建路径已提供，但因缺少身份尚未实际验证。

## 安装脚本故障测试

19 个场景：首次安装（控制面离线仍成功）、0.1.21 覆盖及重复安装、错误架构、
错误磁盘、错误凭据、配置符号链接、并发安装、服务停止失败、bootout 后残留进程、
同名但不同路径的 LaunchDaemon、服务注册失败、配置权限失败、本地健康失败、
健康响应版本不符、进程执行路径不符、首次失败停用、文件复制中断后的手动恢复、
诊断 ZIP 脱敏及文件范围、日志保留 20 次。

回归测试真实执行 preinstall/postinstall 脚本的隔离副本，确认失败不会被当作成功，
旧文件与配置恢复、身份状态不被清理、日志保留且不导出凭据。
曾捕获 zsh 函数内部失败不能可靠触发外层 EXIT trap 的问题；现已用显式返回码处理修复，
服务启动失败的回归测试断言旧程序恢复，并检查脱敏错误 member/调用行号。

复现命令（当前交付根目录）：

```sh
python3 installer/macos/tests/test_installer.py
dotnet test tests/Sf.EndpointAI.PortableTests/Sf.EndpointAI.PortableTests.csproj -c Release --runtime osx-arm64 -m:1 -nodeReuse:false -p:NuGetAudit=false
python3 installer/macos/tests/validate_pkg.py private/EndpointAIDLP-Client-0.1.22-osx-arm64.pkg private/client-credentials.json arm64
python3 installer/macos/tests/validate_pkg.py private/EndpointAIDLP-Client-0.1.22-osx-x64.pkg private/client-credentials.json x86_64
```

测试工具使用 /private/tmp/endpointai-mac-build 作为保护的临时构建根目录，先创建该目录；
不在开发机运行 installer 或 run-service.sh（后者默认开启真实自动挂载）。
使用已发布 binary 的 smoke 工具时必须保持工具中明确设置的临时 profile、
SF_PROXY_CONTROL_ORIGIN 为空及 auto-attach=false。

## 发布前必须完成的隔离终端验收

- Apple Silicon 和 Intel 原生终端：IOA root 静默推送、标准用户登录时无窗口/密码提示。
- 首次安装、0.1.21 升级、重复安装、安装失败后重装、成功后的重启启动。
- 当前企业策略是否接受签名/公证材料；不可用全局关闭安全策略代替验收。
- root:wheel 0600 控制配置、InstallerLogs 0700/0600、日志 ZIP 不泄露秘密。
- 设备身份及代理状态保留、注册/心跳/AES 通信、签名策略同步、网关切换/回退。
- 凭据缺失、权限错误、服务启动失败、端口占用、安装任务中断后的恢复与日志收回。
- 失败恢复后包收据与实际运行版本可能不同，以运行版本确认，并重新安装新版。

服务端、Windows 安装包、现有生产密钥均无需更新。上述未完成项目不得标记为已通过，
当前 PKG 仅用于受控试装，不标记为可批量推送。
