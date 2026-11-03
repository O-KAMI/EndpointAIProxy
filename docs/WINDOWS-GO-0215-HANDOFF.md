# Windows Go 0.2.15 独立终端验收

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
$msi = Join-Path $package 'EndpointAIDLP-Client-0.2.15-go-win-x64.msi'
$trustedSha = '<独立渠道提供的 64 位 SHA-256>'
if ((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash -ine $trustedSha) { throw 'MSI digest mismatch' }
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$out = Join-Path $env:USERPROFILE 'EndpointAIProxyAcceptance\0.2.15'
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
尚无成功控制同步时间或存在控制错误时，样本不标记为健康；同时记录最近成功
同步时间，需结合配置的心跳间隔人工检查其是否过旧。
该工具尚未在独立终端执行，不能据其存在宣称 Windows 长稳通过。

本候选支持在固定服务器证书公钥的 HTTPS 上承载既有加密协议；现有 HTTP 凭据仍可用。HTTPS 尚未在现网启用或验证。切换地址或证书固定值会改变设备身份绑定，必须先在隔离环境验证受控凭据恢复和回退，不能删除状态或批量重新注册来掩盖问题。不要在未完成入口、证书与恢复验证时修改生产地址。

命令恢复验收：仅在隔离控制端构造已过期且本地状态为执行中的命令，重启及重复下发后确认客户端不再执行；在控制台核验结果未知并人工处理。没有隔离故障注入条件则标记待验，不要对现网命令操作。


## 重注册响应丢失验证

本版本在已保存原设备 Token 的情况下，请求支持该能力的候选控制端保留 Token，避免响应丢失后凭据失效。仅在隔离控制端上验证：先保持客户端本地凭据，构造带有效原 Token 的重注册并丢弃第一次响应，重试后确认原 Token 仍可认证；无效或已吊销 Token 必须拒绝。不得在现网清除设备状态或人为更换凭据。首次注册响应丢失以及旧控制端忽略该选项仍不能自动恢复，需按受控流程处理；实际原生端到端故障注入尚未验收。


## 设备绑定封装验收边界

0.2.15 包含两代默认关闭的设备绑定封装候选。V2 使用服务端独立主密钥和设备验证值派生每台设备密钥，客户端只在固定服务端公钥的 HTTPS 上主动声明能力并接受；当前 HTTP 交付配置不会启用。隔离验收需覆盖新旧服务端密钥重叠、逐批切换、不降级、令牌撤销与恢复、断网、重启及回滚。密钥代号的防降级状态目前只在客户端进程内保存；服务端主密钥与数据库验证值同时泄露、密钥配置不一致、旧密钥提前删除和额外数据库负载仍需专项评估。V2 是集中主密钥派生，不是设备独立私钥或硬件设备证明。

旧 .NET 客户端不支持 HTTPS 与原 AES 封装组合；必须保留兼容的旧 HTTP 路径并规划退役，不要直接迁入新入口。不得在现网清库、重注册、修改 TLS 或盲目删除旧密钥来代替隔离验证。
