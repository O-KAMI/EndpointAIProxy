# Windows Go 0.2.22 独立验收交付

本包不签名，未在构建机安装。先核对交付 `manifest.json`、MSI 与服务 SHA-256。
不得覆盖 0.2.21 冻结 MSI 或用其八小时结果代替本候选。

按包内 `INDEPENDENT-TERMINAL-ACCEPTANCE.md` 完成准备和生命周期步骤，显式指定本包的
`EndpointAIDLP-Client-0.2.22-go-win-x64.msi` 及其摘要。升级使用 `Upgrade-Client.cmd`，
IOA 使用既有静默安装和检测入口；禁止为通过验收删除客户端身份、缓存或用户配置。

针对性行为、已知 DSH 阻断及回传格式见
[0.2.22 复测清单](CLIENT-0222-ADDITIONAL-ACCEPTANCE.md)。
Win11 已有 0.2.21 报告只作对照；本候选仍需干净首装、旧 .NET 升级、IOA、多用户、
Windows 10/11、重启/卸载与配置恢复，缺环境记 BLOCKED。

八小时原生观察使用包内 `scripts/Observe-WindowsSoak.ps1`，参数绑定当前 MSI、服务摘要、
准备阶段输出目录和明确的受测用户 SID。每分钟按两秒扫描预算记录捕获正文、压缩/partial、
日志、SQLite/WAL、配置备份、诊断目录及磁盘可用空间。未完成扫描是未知，不是零。
采样文件是 bytes；资源平台期和实际业务路径均须人工复核。

独立合成工具与说明见 [合成长稳](WINDOWS-GO-0222-ACTIVE-SOAK.md)。
原生业务与合成观察都必须持续八小时，保持唤醒；合成测试不替代真实业务、IOA 或容量验收。
