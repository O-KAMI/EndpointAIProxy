# 2026-09-18 源码同步记录

主分支以 GitHub `O-KAMI/EndpointAIProxy` 的 `c64b4c0e442a12eb72031801ea4d7aa4bfbb6c44` 为基线，保留最新 Windows/macOS 客户端及安装脚本，再加入本地控制台与分析改动。本地原始 Git 历史保留在 `archive/local-before-github-sync-20260918`，不推送该备份分支，不覆盖远端历史。

- `src/Sf.EndpointAI.ControlServer`：ASP.NET Core/SQLite 原型控制台，策略、资产、分析三个视图，增加聚合及下钻 API。
- `server`：生产 Python/MySQL 服务端 0.1.22 源码、模板、测试与配置示例，与原型服务端分开部署。
- `deployment`：Python 0.1.22 升级脚本、测试与说明，包含 systemd 生命周期识别修正。
- `scripts/Collect-WhitelistDiagnostics.*`：Windows 只读白名单诊断工具及实际缓存策略核对。

本次提交仅包含源文件及公开模板，不包含实际生产凭据、数据库、日志、离线依赖轮子、安装包或生成的交付 ZIP。交付目录不作为主源码仓库。

## 本机验证

- Python 服务端：隔离 MySQL 8.4、原始 .NET 客户端互操作及 HTTP 工作流，113 passed / 1 skipped。跳过项是原有独立部署快照测试；本次升级备份测试已执行。
- Python 升级脚本：18 passed。
- ASP.NET 服务端：以 macOS 运行时构建通过；在临时跨平台测试项目中执行现有 ControlStoreTests、AnalyticsServiceTests，32 passed。
- Windows 诊断脚本：PowerShell 解析无语法错误；原生 SQLite 读取器通过隔离缓存策略读取及不存在数据库的只读拒绝测试。

完整 Windows locked-mode 门禁未通过本机执行：当前 macOS 的目标平台与部分锁文件运行时不一致，Windows 依赖下载还遇到 TLS 失败。未为本机验证改写远端 Windows 锁文件，未执行 Windows 原生 MSI 构建/安装或真实异常终端诊断。源码同步不代表已完成生产部署或确认白名单故障根因。
