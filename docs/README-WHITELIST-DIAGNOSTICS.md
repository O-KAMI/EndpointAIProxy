# Windows 白名单异常一键诊断

依据 GitHub `O-KAMI/EndpointAIProxy` 默认分支 `main`，提交 `c64b4c0e442a12eb72031801ea4d7aa4bfbb6c44`（2026-09-18 获取）。源码快照另附，不替换原有源码工作区，不包含生产凭据。本包是诊断工具，不是 MSI 构建材料或安装包。

截图中的策略 v3 已包含 HTTP 和 HTTPS CCR 地址。仅凭截图不能确认异常终端已应用 v3，也不能确认历史 HTTP 403 是当前路由结果。

## 执行

将诊断工具 ZIP 解压至 Windows 终端，例如 `C:\Temp\EndpointAIDLP-WhitelistDiagnostics`。在**管理员 Windows PowerShell**执行：

```powershell
Set-Location 'C:\Temp\EndpointAIDLP-WhitelistDiagnostics'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Collect-WhitelistDiagnostics.ps1
```

也可在管理员 CMD 中运行 `Collect-WhitelistDiagnostics.cmd`。脚本不会自行提权。

默认目标是 `http://claudecode.sf-express.com/ccr`，对照版本是 3，日志范围为最近 72 小时。如果策略已变更或需要其他范围：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Collect-WhitelistDiagnostics.ps1 -SinceHours 24 -ExpectedPolicyVersion 3 -TargetBaseUrl 'http://claudecode.sf-express.com/ccr'
```

如果安装路径或数据目录自定义，可显式指定实际位置：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Collect-WhitelistDiagnostics.ps1 -ClientExe 'D:\实际安装目录\Sf.EndpointAI.Client.Service.exe' -DataRoot 'D:\实际数据目录'
```

默认从 `SfEndpointAIProxy` 服务确定客户端程序；默认数据目录为 `%ProgramData%\SF\EndpointAIProxy`。不读取或导出注册表凭据。需要 Windows 10/11 的 `winsqlite3.dll`、Windows PowerShell 5.1 和 0.1.22 客户端。检测到其他程序版本时，仍收集版本、实时健康和缓存策略，但跳过未经此次代码核实的维护入口，明确标为部分采集。SQLite 不可用或字段缺失也会明确标为部分采集。

## 返回的数据

脚本输出最终 ZIP 路径与 SHA256，默认保存到：

```text
C:\ProgramData\SF\EndpointAIProxy\WhitelistDiagnostics\EndpointAIDLP-whitelist-diagnostics-*.zip
```

目录仅管理员和 SYSTEM 可访问。请通过受控内部渠道提供**最终 ZIP**（无需上传安装目录、数据库或配置备份）。

- `collection.json`：采集时间、客户端版本和哈希、服务状态、截图对照规则。
- `health.json`：实时生效策略版本、同步状态、客户端运行状态。
- `cached-policy-sanitized.json`：只读获取的缓存白名单、版本、时间、目标匹配结果。
- `whitelist-assessment.json`：版本对照、匹配判断、缺失项和诊断限制。
- `client-bundle/*.zip`：内置脱敏诊断包，含 Agent/CC Switch 配置摘要、路由、请求结果摘要、运行日志及网络连通信息。

不导出原始数据库、原始配置、Token、签名、密钥或请求/响应正文。包内仍有内部设备、域名、网络和配置元数据，限内部分析。内置诊断会进行有界网络连通探测，不发送带模型凭据的真实请求。

脚本不修改策略、Agent 配置或服务状态，不重启服务、不安装软件、不自动上传。只写诊断输出；诊断子进程超时仅结束本脚本启动的维护进程。

## 如何判断

1. 缓存/实时版本未达到截图 v3：先查看策略同步、验签和应用错误。缓存版本本身不证明配置已恢复。
2. 缓存白名单未包含目标：检查实际下发内容；HTTP 和 HTTPS 分别匹配，路径区分大小写，末尾斜杠被规范化。
3. 两个版本一致且目标命中，但当前配置仍是本地 `/r/` 地址：核对配置恢复/挂载协调日志、CC Switch 当前 Provider，以及 Agent 是否保留旧进程配置。
4. 根据最近请求的时间与 RequestId 追踪 403；区分历史结果、已退休路由、本地拒绝和上游返回。不要仅凭服务器红色标签判断当前仍在代理。

最新源码内置 `CCR_ALLOWLIST_DECISION_MISMATCH` 检查采用默认 HTTPS 白名单，没有使用自定义下发规则；它不是本次 HTTP 白名单的判定依据。以本工具补充的实际缓存规则、实时版本和当前配置为准。

如果内置诊断不产出包，或状态为 Partial，保留最终包分析错误和缺失项，不将缺失数据认定为正常。采集跨多个实时快照，过程中策略变化可能造成版本不一致。

## 验证范围

已针对最新源码核对维护参数、服务名、安装/数据路径、SQLite 表及策略字段。已执行 PowerShell 解析检查和原生 SQLite 读取器的隔离数据测试；读取不存在的数据库会拒绝且不会创建数据库。尚未在 Windows 异常终端实际运行，未确认故障根因，也未构建或验证新的 MSI。
