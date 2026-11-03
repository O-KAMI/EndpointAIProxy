# Windows Go 0.2.6 独立终端验收

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
$msi = Join-Path $package 'EndpointAIDLP-Client-0.2.6-go-win-x64.msi'
$trustedSha = '<独立渠道提供的 64 位 SHA-256>'
if ((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash -ine $trustedSha) { throw 'MSI digest mismatch' }
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$out = Join-Path $env:USERPROFILE 'EndpointAIProxyAcceptance\0.2.6'
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
