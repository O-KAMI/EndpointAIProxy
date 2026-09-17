# EndpointAIDLP macOS 0.1.22 · IOA 推送

## 安装

IOA 必须以 root 身份执行，不能使用登录用户身份。按硬件架构分配对应 PKG。
文件名无空格，不需要引号、静默参数、日志参数或额外凭据文件。

Apple Silicon：

```sh
/usr/sbin/installer -pkg EndpointAIDLP-Client-0.1.22-osx-arm64.pkg -target /
```

Intel：

```sh
/usr/sbin/installer -pkg EndpointAIDLP-Client-0.1.22-osx-x64.pkg -target /
```

以上命令要求 IOA 工作目录包含 PKG；其他目录可使用不含空格的绝对路径。
安装程序不调用 sudo、不请求密码、不打开 GUI、不重新启动电脑。Installer 返回 0
表示安装及本地服务检查成功；任何非 0 都按失败处理，保留 IOA 的原始退出码。
非 0 不能按 Windows MSI 的 1603/3010 规则解释。

支持 macOS 14 及以上、对应原生 CPU 架构；PKG 自包含 .NET，不要求目标终端安装 SDK。
控制面暂时不可达不会导致安装失败，安装日志记为 sync_pending，客户端继续重试。
后台服务自动启动，安装完成后到生产控制台确认注册、心跳与策略版本。

## 日志与无参数收集

每次安装的阶段日志自动生成，无需安装命令参数：

```text
/Library/Application Support/SF/EndpointAIProxy/InstallerLogs/install-<安装ID>.jsonl
```

目录仅 root 可访问，日志文件权限 0600，最多保留 20 次（保留正在安装/待恢复的一次）。
记录阶段、结果、返回码、错误类型、调用位置、版本和架构；不记录凭据、完整环境或模型正文。
错误位置是安装包装器的调用位置，原始底层错误详情不直接输出以免泄露配置。
如果连 root 日志目录都无法建立，或系统在脚本执行前拒绝安装，使用 IOA 结果和系统安装日志定位。

安装工具已落盘时，由 IOA 以 root 执行：

```sh
/usr/local/sbin/sf-endpointai-installer-logs
```

第一次安装失败、收集工具未落盘时，解压同交付的 MacInstallerTools ZIP，把三个脚本
放在同一目录，然后由 IOA 以 root 执行：

```sh
/bin/zsh Collect-MacInstallerLogs.sh
```

输出诊断 ZIP 路径，位于 InstallerLogs，权限 0600。收集最近 20 次产品阶段日志、
最新一次安装以来的产品系统安装事件摘要、包收据版本、服务与健康状态。
无阶段日志时，系统事件回看最近 24 小时。不会收集整个系统日志、控制配置、密钥文件、
运行时模型请求或回滚备份。系统日志摘要只保留事件类别，不复制任意原始输出。
诊断 ZIP 最多保留 20 份，由 IOA 收回后提供用于排查。

## 升级与恢复

安装前先校验，再备份本产品程序、启动文件、工具及控制配置；确认旧服务停止后才覆盖。
控制配置原子写入、root:wheel 0600，保留设备身份、代理状态和用户配置。
新版服务需通过进程路径、运行版本及连续两次健康检查，等待上限约 60 秒。
配置或启动失败会尝试恢复旧文件及旧服务；恢复失败保留备份并记录 recovery_required。

PKG 不是 MSI 事务：复制文件阶段失败、断电或安装任务被杀时，不保证自动恢复。
备份只覆盖本产品程序、启动配置及控制配置，不覆盖用户 Agent 配置、设备数据库或模型捕获。
若失败发生于服务启动后，真实用户配置的挂载/解除仍由客户端原有状态与恢复机制管理。

先在 IOA 中确认该安装任务及文件复制已结束，再用 root 执行无参数恢复命令：

```sh
/usr/local/sbin/sf-endpointai-installer-recover
```

工具被覆盖或未落盘时，使用交付 ZIP 中的脚本：

```sh
/bin/zsh Recover-MacInstallation.sh
```

恢复工具拒绝仍在运行的安装脚本及重复恢复。不要在 IOA 安装任务仍在复制文件时运行恢复。
恢复完成后可能仍有新版包收据；以运行版本及服务状态确认结果，再重新推送新版 PKG。
成功安装或成功恢复会删除临时凭据备份，失败日志继续保留；恢复失败不会删除备份。
首次安装失败会停用并移除本次产品程序和启动文件，不删除设备数据或用户文件。

## 私有材料与验收

PKG 含当前生产客户端凭据，仅作内部部署材料；可被解包，不能上传公共 GitHub。
未生成新密钥，不携带管理员 Token、数据库密码或服务端配置。
现有 Windows 安装包和生产服务端无需更新，动态网关切换保持原行为。

此次 PKG 未签名、未公证。只先做 IOA root 路径的隔离试装，不关闭系统安全设置。
本开发 Mac 的 AMFI/AppleSystemPolicy 已实际拒绝 SDK 默认 ad-hoc 签名的客户端 apphost，
导致进程在启动日志产生前收到 SIGKILL；由已受信任的 SDK host 运行同一程序集时健康检查通过。
这不是所有终端都会失败的证明，但不能视为可批量推送。root 安装身份不保证应用被系统信任。
当前 Keychain 没有有效代码签名身份，需要 Developer ID Application 及 Developer ID Installer
证书和相应私钥才能交付受信任签名版本；公证另需 Apple 开发者账号配置。
如果 IOA/安全策略要求签名，提供企业认可证书后再构建签名版本。
Apple MDM 原生分发另需设备可验证的包签名。

尚未完成 IOA 实际推送、标准用户登录时的无窗口验证、Intel 原生运行及真实覆盖升级。
Apple Silicon / Intel 隔离终端全部验收后再批量推送，不能把构建或模拟测试当成推送验收。
检查清单和本机结果见 MACOS-ACCEPTANCE-0.1.22.md。

## 构建

在当前交付根目录，准备 .NET 10 SDK 和现有 private/client-credentials.json：

```sh
CLIENT_CREDENTIALS_FILE="$PWD/private/client-credentials.json" ARCH=arm64 zsh installer/macos/Build-Pkg.sh
CLIENT_CREDENTIALS_FILE="$PWD/private/client-credentials.json" ARCH=x86_64 zsh installer/macos/Build-Pkg.sh
```

DOTNET 可指定 SDK 执行文件路径。构建机需要 NuGet 可达或完整预热缓存。
APP_SIGN_IDENTITY、INSTALLER_SIGN_IDENTITY 可指定签名身份，不写证书或密码进源码。
代码签名启用 Hardened Runtime 并为服务提供 allow-jit entitlement；不启用生产调试权限。
依据 [Microsoft .NET macOS 发布说明](https://learn.microsoft.com/en-us/dotnet/core/deploying/macos)。
输出位于 artifacts/macos/<rid>/。含凭据的交付件只保存在受控私有目录，不提交 Git。
