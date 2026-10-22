# 独立终端验收：同一候选 MSI

当前 0.2.3 候选因控制端拒绝 DSH AgentType 11 而阻断推广。下面是解除阻断后由验收人员执行的入口，
不是生产推广命令。不要把受限 MSI、原始安装日志、Codex 事件或配置备份上传到公共服务。

## 准备

在独立 Windows x64 终端准备已登录且正常工作的 Codex、可恢复的原配置和旧安装包。
使用同一候选目录，核对单独提供的 MSI SHA-256。不要从本机重新构建另一个 MSI。
用目标交互用户执行 Prepare 和 Codex；安装、卸载阶段使用该用户的管理员 PowerShell。
SYSTEM 安装另外由 IOA 或系统身份执行，保留退出码及收据，不能用管理员身份结果替代。

```powershell
$msi = 'D:\EndpointAI-Acceptance\EndpointAIDLP-Client-0.2.3-go-win-x64.msi'
$sha = '<替换为候选目录 SHA-256 文件中的 64 位摘要>'
$out = 'D:\EndpointAI-Acceptance\evidence'
$test = 'D:\EndpointAI-Acceptance\scripts\Test-IndependentTerminal.ps1'
& $test -Phase Prepare -MsiFile $msi -ExpectedMsiSha256 $sha -OutputDirectory $out
& $test -Phase Install -RequireCleanInstall -MsiFile $msi -ExpectedMsiSha256 $sha -OutputDirectory $out
& $test -Phase Codex -MsiFile $msi -ExpectedMsiSha256 $sha -OutputDirectory $out
```

Prepare 记录启动时间、原配置摘要及服务是否存在，私有备份仅保存在受限目录。
干净首装要求 Prepare 和 Install 时均没有旧服务、相关 MSI 注册及遗留数据目录；
检测到旧安装时应另行执行覆盖升级验收，不能删除已有数据来伪造干净环境。
脚本不修改登录材料，也不自动重启电脑。它使用已安装 Codex CLI 的当前配置发出带唯一 nonce 的请求，
不覆盖 provider，不指定替代模型，并限制为只读、临时会话。
命令参数依据[官方 Codex 文档](https://learn.chatgpt.com/docs/developer-commands#codex-exec)和本机 CLI 帮助核对。

## 补齐证据

1. 用 nonce 和时间窗口关联本地捕获及预期网关请求，记录脱敏 request ID、状态码、模型、目标网关和
   Content-Type。CLI 的 JSONL 事件只能证明一次运行完成，不能独自证明流量经过代理或使用 SSE。
2. 从既有控制端下发暂停，保存命令 ID、服务状态和成功回执；执行 `-Phase Paused`。
   确认已解除接管、请求按原配置工作。恢复后保存新命令及回执，再执行 `-Phase Resumed`。
3. 检查取消、SSE 中断与错误传播，保留请求关联，不在报告中粘贴响应正文或认证头。
4. 人工执行真实重启，登录后执行 `-Phase AfterReboot`；脚本验证启动时间变化及服务自动运行。
5. 保存诊断并执行 `-Phase Uninstall`。验证服务移除、Codex 恢复及账户可用，再安装同一 MSI 验证重装。
   若用户中途修改配置，摘要不一致应人工检查，禁止用备份直接覆盖后来修改。
6. 同包修复、重复安装、SYSTEM 静默安装和受控失败回滚分别保留独立证据，不能合并为一次安装成功。

所有安装使用 `/qn /norestart`。0 表示成功；3010 表示安装成功但待重启，需独立记录；其他码失败。
回退只使用已保留的旧 MSI 与一致性备份，先核对摘要、停止候选服务，再按回退说明恢复。

## 回传

只回传每个阶段的 `sanitized-report.json` 及人工补充的脱敏请求、控制回执、SSE 和生命周期记录。
原始 `*.private.*` 文件留在该终端。脚本固定输出 `releaseAcceptance=pending`，阶段成功不会自动放行。
只有最终 MSI 摘要一致、本机全部验收通过且独立终端证据齐全，才可解除 IOA 推广门禁。
