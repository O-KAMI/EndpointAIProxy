# Windows Go 0.2.21 独立终端验收

本轮增加控制事件队列的内存/持久深度、读取状态和时间线采样；保留默认关闭的两阶段凭据更新。
当前生产 HTTP 配置仍使用原路径；队列指标和凭据能力的验收边界见
[补充验收](CLIENT-0221-ADDITIONAL-ACCEPTANCE.md)。Windows 包仍不签名，控制服务的
可选 schema 6 不允许直接回退至 r75 或更早程序。

该包包含受保护的客户端配置，仅通过授权渠道发送给验收人员，不上传公共服务。
先独立核对 MSI SHA-256 与交付记录：包内摘要文件本身不能替代受信任渠道提供的摘要。
本次 Windows 包按要求不签名；静态检查通过不等于安装、IOA 或推广通过。

在独立 Windows 10/11 x64 上，分别准备干净首装终端与已有旧客户端的升级终端。
不要为了伪造干净环境删除现有服务、配置或状态。覆盖升级前保留旧安装包、用户配置
及一致性备份，按现有控制端流程确认终端可恢复。目标交互用户准备 Codex 及可用的
原始业务配置；如原配置已被接管，按旧版控制流程先恢复基线。

在目标用户的 Windows PowerShell 5.1 中，从整包目录读取并核对实际摘要；将
`$trustedSha` 替换为经独立受信任渠道核对的值，同一次验收始终使用同一 MSI、
输出目录和目标用户 SID：

```powershell
$package = 'D:\EndpointAI-Acceptance' # 改为实际私有目录
$msi = Join-Path $package 'EndpointAIDLP-Client-0.2.21-go-win-x64.msi'
$trustedSha = '<独立渠道提供的 64 位 SHA-256>'
if ((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash -ine $trustedSha) { throw 'MSI digest mismatch' }
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$out = Join-Path $env:USERPROFILE 'EndpointAIProxyAcceptance\0.2.21'
$test = Join-Path $package 'scripts\Test-IndependentTerminal.ps1'
& $test -Phase Prepare -MsiFile $msi -ExpectedMsiSha256 $trustedSha -OutputDirectory $out -TargetUserSid $sid
```

仅在终端符合授权和隔离条件后，以管理员或 IOA SYSTEM 身份执行安装阶段；SYSTEM
必须使用准备阶段记录的交互用户 SID 和同一输出目录，不能用 SYSTEM 自己的 SID。
真正的干净首装在 Install 阶段另加 `-RequireCleanInstall`，旧客户端覆盖升级不加：

```powershell
& $test -Phase Install -MsiFile $msi -ExpectedMsiSha256 $trustedSha -OutputDirectory $out -TargetUserSid $sid
```

保留 msiexec 退出码，3010 单列为待重启；IOA 投递成功不等于安装及服务健康成功。
在目标用户会话继续执行 `Codex`、`Paused`、`Resumed` 阶段；暂停和恢复由控制端
对该测试终端下发，保留命令 ID 与回执。检查真实对话、网关请求关联、SSE 和错误
传播；真实重启后执行 `AfterReboot`。独立执行 `Uninstall` 并核对原配置恢复，
之后可用同一包验证重装。另验同包修复、重复安装、SYSTEM 静默和受控失败回滚。

如需复现单个阶段，替换 `-Phase` 为上面的阶段名，其他参数保持不变。排查配置冲突时
不得用旧备份直接覆盖用户安装后的修改，不得删除数据库或重新注册来掩盖故障。
只回传 `sanitized-report.json`、脱敏的检测结果、系统版本、MSI 摘要、IOA 退出码、
控制回执及业务/SSE 结果；原始安装日志、请求正文、凭据及配置备份留在受限终端。

当前控制端目标是 15 万安装、10 万在线及 8 小时长稳；独立终端生命周期通过并不能
替代隔离容量和长稳门禁。Windows 未签名是已确认的发行约束，Mac 正式签名及公证要求不变。
客户端当前长稳门禁同为 8 小时；较短采样不能记为长稳通过。

补充的 `scripts\Observe-WindowsSoak.ps1` 可在**已授权的独立 Windows 终端**对
已安装服务进行 8 小时只读观察，不安装、不重启服务，也不产生业务请求。先完成
上述 `Prepare` 和安装阶段；在目标用户的管理员 PowerShell 5.1 中使用同一 MSI、
输出目录和 SID，将两个摘要替换为从独立可信渠道取得的值：

```powershell
$serviceSha = '<独立渠道提供的服务程序 64 位 SHA-256>'
& (Join-Path $package 'scripts\Observe-WindowsSoak.ps1') -MsiFile $msi `
  -ExpectedMsiSha256 $trustedSha -ExpectedServiceSha256 $serviceSha `
  -OutputDirectory $out -TargetUserSid $sid
```

脚本记录服务和监听进程、二进制摘要、健康状态、私有内存、工作集和 CPU 时间，
并每 30 秒写一次脱敏样本；正常运行约 8 小时。输出中的 `observation-completed`
只表示观察时间完成，须审核不健康样本、采样间隔及资源变化；人为重启、业务、
SSE、控制回执及故障恢复仍需另行验收。`-SmokeSeconds 30` 仅用于验证工具，不能
算长稳。断电或中断可能没有最终摘要，必须保留现有样本并重新安排完整观察。
最近控制同步超过 10 分钟、比采样时间超前超过 60 秒、缺少时间或存在控制错误时，
样本不标记为健康。默认 30 秒采样时，间隔超过 90 秒或时钟明显跳变会使
`samplingContinuityValid` 为假，`duration8hCompleted` 也为假；需保持终端唤醒。
仍须人工检查时间线和资源趋势，该阈值不能代替现场链路故障诊断。
该工具尚未在独立终端执行，不能据其存在宣称 Windows 长稳通过。

本候选支持在固定服务器证书公钥的 HTTPS 上承载既有加密协议；现有 HTTP 凭据仍可用。HTTPS 尚未在现网启用或验证。切换地址或证书固定值会改变设备身份绑定，必须先在隔离环境验证受控凭据恢复和回退，不能删除状态或批量重新注册来掩盖问题。不要在未完成入口、证书与恢复验证时修改生产地址。

命令恢复验收：仅在隔离控制端构造已过期且本地状态为执行中的命令，重启及重复下发后确认客户端不再执行；在控制台核验结果未知并人工处理。没有隔离故障注入条件则标记待验，不要对现网命令操作。


## 重注册响应丢失验证

本版本在已保存原设备 Token 的情况下，请求支持该能力的候选控制端保留 Token，避免响应丢失后凭据失效。仅在隔离控制端上验证：先保持客户端本地凭据，构造带有效原 Token 的重注册并丢弃第一次响应，重试后确认原 Token 仍可认证；无效或已吊销 Token 必须拒绝。不得在现网清除设备状态或人为更换凭据。0.2.21 还会在首次注册前持久化随机设备凭据，并在支持该能力的候选控制端上复用该凭据重试。旧控制端不理解该字段，首次响应丢失时仍不能自动恢复；须先部署并验证新控制端。实际原生端到端故障注入尚未验收。


## 设备绑定封装验收边界

0.2.21 包含两代默认关闭的设备绑定封装候选。V2 使用服务端独立主密钥和设备验证值派生每台设备密钥，客户端只在固定服务端公钥的 HTTPS 上主动声明能力并接受；当前 HTTP 交付配置不会启用。隔离验收需覆盖新旧服务端密钥重叠、逐批切换、不降级、令牌撤销与恢复、断网、重启及回滚。客户端会以平台保护机制持久保存密钥代号、设备密钥和令牌摘要，重启后继续使用；恢复失败、证书固定值或令牌变化会阻止控制连接，业务侧仍使用有效离线缓存。该机制无法防止有权限者删除或回滚整个本地状态库；受控恢复流程尚待验收。服务端主密钥与数据库验证值同时泄露、密钥配置不一致、旧密钥提前删除和额外数据库负载仍需专项评估。V2 是集中主密钥派生，不是设备独立私钥或硬件设备证明。

旧 .NET 客户端不支持 HTTPS 与原 AES 封装组合；必须保留兼容的旧 HTTP 路径并规划退役，不要直接迁入新入口。不得在现网清库、重注册、修改 TLS 或盲目删除旧密钥来代替隔离验证。


首次注册恢复需搭配支持 `initialDeviceToken` 的候选控制端；服务端先在隔离环境验证，再考虑按既定流程部署。旧控制端可继续服务，但无法保证首次注册丢失响应后的自动恢复。


## 精简心跳兼容验收

0.2.21 在服务端明确宣告支持后，通过独立精简心跳接口省略未变化的用户和代理清单；服务端保留上次确认的清单。旧服务返回未支持时，客户端使用原有加密身份重新发送完整心跳。隔离验收应覆盖新旧服务混合、服务回退、设备绑定封装、控制端重启、清单变化和正常活动更新，并核对用户、代理与端点没有丢失。若出现资产缺失、错误或重试尖峰，暂停推广。正式环境未启用前不得将本地模拟测试当作完成验收。
