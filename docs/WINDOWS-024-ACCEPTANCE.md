# Windows 0.2.4：IOA 验收候选

2026-10-28 推广口径更新：Windows 推广包不签名，当前候选仍须以最终 MSI 摘要绑定
8 小时长稳、独立终端和 IOA 结果；本文件中的四小时结果为历史证据，不自动满足新门禁。

本轮目标为 Windows 10/11 x64 内部静默部署，默认模型网关为
`http://zbx-coding-aigw.intsit.sfcloud.local:80`，启用 DSH，默认包含 Codex。
允许内部未签名候选；是否完成发布验收由最终 MSI 摘要对应的门禁清单决定。
构建通过不等于可全量推广。当前没有可用的干净隔离终端，干净首装及 IOA 试点由用户收到包后执行。

## 本轮变更与证据边界

- Desktop 账户模式增加精确版本 `0.2.1-rc.3`，保留 `0.2.1-rc.2`。CLI/API Key 的 alpha.5 门禁不扩展。
  校验 Desktop 和四个内嵌插件的包名与版本、完整宿主参数及规范 desktop profile；未知版本、混装插件和未知覆盖层继续拒绝。
- 官方 rc.3 安装包来自 DeepSeek nightly feed，SHA-512 已按 feed 校验；固定源码 tag 为
  [dsh-v0.2.1-rc.3](https://github.com/deepseek-ai/deepseek-harness/releases/tag/dsh-v0.2.1-rc.3)。
  rc.2/rc.3 的打包 desktop-host 和账户平台插件逐字节一致；rc.3 模型插件仍使用 baseURL、账户认证头及 /models 目录。
  不改 DSH 程序文件、账户登录、凭据存储或模型设置。包身份核查不代表 rc.3 真实账户对话已通过。
- 独立验收基线记录 MSI 版本、目标用户 SID、注册 profile 和实际 Codex 配置路径；SYSTEM 必须明确指定目标用户。
  证据目录仅授予固定目标用户、Administrators、SYSTEM，不按当前阶段执行者改换权限。
  原始配置、事件和 MSI 日志仍只在受限目录保存；旧 schema 1 基线不能复用。
- `/healthz` 增加 `gatewayOrigin`，表示当前实际生效策略的网关。仅检查服务命令行不能证明策略已切换。
- 包含 `Install-Silent.cmd` 和 `Test-DeploymentStatus.ps1`；安装成功后再校验版本、载荷摘要、监听归属、
  安装提交、有效网关及控制同步。失败不自动卸载或重装。
- 版本升至 0.2.4，沿用服务名、升级身份和状态布局。原 0.2.3 r15 保留，不覆盖其 MSI 或继承其发布通过结论。

2026-10-26 用户确认 r15 的 Codex 桌面 DeepSeek 对话可用；独立报告确认 r15 覆盖升级、重启、暂停恢复、
卸载及重装。r15 独立机 DSH rc.3 未接管，SYSTEM 下目标用户及 ACL 问题需在新脚本上复核。
本机 r15 repair、SYSTEM 静默重复安装、受控回滚和四小时长稳是历史基线，不能计作 0.2.4 通过。

## IOA 安装与检测

整包必须通过受控内网分发；MSI 含部署凭据，不能上传公共服务或共享原始日志。
入口自动选择原生 64 位 Windows PowerShell 5.1，兼容 32 位 IOA 启动进程。
IOA 以 SYSTEM 执行，不要求目标用户为管理员。
安装前校验独立提供的整包 SHA-256，再核对 `manifest.json`、MSI 和 `.sha256`。
保留原包、原始用户配置摘要及受限恢复材料。不要清空已有客户端来伪造首装。

```text
Install-Silent.cmd
```

该入口默认覆盖升级；同一 ProductCode 重复执行使用修复安装，不先卸载。
日志默认写入 `%ProgramData%\SF\EndpointAIProxy\InstallerLogs\ioa-<id>`。
`0` 表示安装及就绪检测通过；`3010` 表示待重启，不能记为验收通过；其他值表示失败。
入口仅判断安装就绪，不等同于应用对话或发布放行。也可直接使用标准 MSI 命令：

```text
msiexec.exe /i "EndpointAIDLP-Client-0.2.4-go-win-x64.msi" /qn /norestart
```

IOA 独立检测规则（工作目录为解压后的整包）：

```powershell
.\Detect-Installed.cmd
```

检测返回 0 且 JSON 的 checks 全为 true 才就绪。它核对实际服务文件摘要，不能用 MSI 注册或分发成功替代。
`effectiveGatewayMatches=false` 时，先核对控制端有效策略。缓存/全局策略仍指向旧网关时，即使 MSI 的默认地址为新网关，
请求仍可能按旧策略转发。先仅为试点设备设置新网关覆盖并核验实际请求；不得提前修改全局或其他设备。
`controlOnline=false` 时排查控制链路，代理缓存可用不能替代控制上线。

## 独立验收与回传

先在目标交互用户会话记录 Prepare，保存该用户 SID；SYSTEM 安装/卸载阶段传入同一 SID。
所有阶段使用同一 MSI、同一 SHA-256 和同一输出目录。自定义 CODEX_HOME 只在 Prepare 明确指定，后续沿用基线。

```powershell
$package='D:\EndpointAI-024'
$msi=Join-Path $package 'EndpointAIDLP-Client-0.2.4-go-win-x64.msi'
$sha=(Get-Content -LiteralPath ($msi+'.sha256') -Raw).Trim().Split()[0]
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$out=Join-Path $env:USERPROFILE 'EndpointAIProxyAcceptance\0.2.4-r3'
$test=Join-Path $package 'scripts\Test-IndependentTerminal.ps1'
& $test -Phase Prepare -MsiFile $msi -ExpectedMsiSha256 $sha -OutputDirectory $out -TargetUserSid $sid
# 将上面的实际 SID 和输出绝对路径交给 IOA；SYSTEM 中不要重新计算当前账号 SID。
# 只有真正的干净机器才在 Install 添加 -RequireCleanInstall。
& $test -Phase Install -MsiFile $msi -ExpectedMsiSha256 $sha -OutputDirectory $out -TargetUserSid $sid
# 回到目标用户会话运行 Codex / Paused / Resumed；暂停恢复由控制端下发并保存回执。
& $test -Phase Codex -MsiFile $msi -ExpectedMsiSha256 $sha -OutputDirectory $out -TargetUserSid $sid
```

SYSTEM 不执行目标用户的 Codex CLI。普通用户的真实 UI 对话、DSH rc.3 账户模型列表/两轮上下文、
Claude SSE、实际新网关请求关联、原配置及用户后续修改的保留均须另附证据。
真实重启后运行 AfterReboot；后续单独执行 Uninstall，核对服务移除、端口释放和目标用户配置恢复，再重装同一包。
只回传 `sanitized-report.json`、`deployment-status.json` 和脱敏业务证据。
`prepared.json`、配置备份、原始事件/捕获和 MSI 日志留在受限终端，不随报告上传。

## 放行门禁与恢复

最终门禁必须绑定同一 MSI：Windows 10/11 x64 干净首装、管理员与 SYSTEM 路径、普通用户与首次登录、
0.1.22 和 r15 覆盖升级、repair/重复安装、真实重启、卸载重装、失败回滚；Codex CLI/桌面、Claude、
DSH rc.2/rc.3、CC Switch、控制启停、取消/错误、离线恢复与命令过期；新网关四小时及资源平台期。
最后两小时固定负载且不重启；窗口 RSS/Private Bytes 中位数范围不超过 max(8 MiB,10%)，句柄与线程不持续增长。
原有 401/503 按请求关联归因；实际业务失败未解决时不放行。

IOA 先 3 台覆盖两种系统和首装/升级，再 20 台观察 24 小时；每台结果均可解释，且无未解决的安装、
配置恢复或代理故障后才可全量。阶段脚本仍固定 releaseAcceptance=pending，不能通过改脚本字段绕过发布评审。

修复：同一包执行 `Upgrade-Client.cmd -MsiFile "<原MSI>"`；正常卸载：
`msiexec.exe /x "<原MSI>" /qn /norestart`。卸载失败不删除服务/状态或覆盖用户后续配置。
回退须先停服并保留一致性快照，用 Go 完成解除接管，再使用已保留且核对摘要的旧 MSI 和匹配恢复材料；
禁止直接降级覆盖、删除数据库重新注册或自动以旧快照覆盖安装提交后的新状态。

源码事实入口：[项目地图](../CONTEXT.md)、[0.2.3 历史记录](WINDOWS-023-ACCEPTANCE.md)、
[验收脚本](../scripts/Test-IndependentTerminal.ps1)、[部署检测](../scripts/Test-DeploymentStatus.ps1)。
