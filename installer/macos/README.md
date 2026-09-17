# macOS 0.1.22 PKG

安装、IOA 命令、内置日志、恢复与签名要求见
[当前交付说明](../../docs/README-MACOS-0.1.22.md)。
已完成检查和真实推送验收边界见
[验收记录](../../docs/MACOS-ACCEPTANCE-0.1.22.md)。

Build-Pkg.sh 输出两种架构的自包含 PKG，必须指定现有私有客户端凭据；
可通过 APP_SIGN_IDENTITY 和 INSTALLER_SIGN_IDENTITY 使用受信任证书签名。
服务代码签名使用 service.entitlements.plist 的 allow-jit 权限，不启用生产调试权限。

preinstall/postinstall 与 InstallerSupport.sh 负责校验、备份、停服、配置、健康检查及恢复。
Collect-MacInstallerLogs.sh 与 Recover-MacInstallation.sh 均无参数，需 root 执行；
独立交付时三个脚本必须放在同一目录。

仅在隔离终端验证真实安装。run-service.sh 默认启用自动挂载，不在开发机执行。
