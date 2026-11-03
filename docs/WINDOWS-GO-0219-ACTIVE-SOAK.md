# Windows 0.2.19 独立合成长稳

本材料仅供独立 Windows x64 验收终端使用，需要 Python 3.13 或更新版本。它不是
安装包，也不含真实凭据。测试启动从最终 MSI 提取的服务程序、合成控制进程和
合成上游，在私有临时目录生成测试用户配置；不应在生产终端或真实用户配置上运行。
它使用本机 127.0.0.1:18080。若端口已有服务占用，工具会停止，不能通过停止或
修改现有业务服务来强行运行。先确保测试终端与环境获得授权且可回滚。

使用受保护的独立目录解压本材料，并按组织允许的方法从最终验收 MSI 提取服务
可执行文件。先通过独立可信渠道核对 MSI SHA-256、服务程序 SHA-256 和本材料
ZIP SHA-256；本次 0.2.19 服务程序摘要为
`df963b1769ac20dbcfd2b6458ea2af7507d2d8f1dadb9c7173948e2915a1985c`。
不要将真实客户端凭据放入测试目录或合成控制进程。路径均由操作人按实际填写，
下面使用的报告文件、进度文件和同名 JSONL 均须此前不存在：

```powershell
$tool = 'D:\EndpointAI-Soak-Tools'     # 改为已解压的私有目录
$client = 'D:\Private\Sf.EndpointAI.Client.Service.exe'  # 从最终 MSI 提取
$expected = 'df963b1769ac20dbcfd2b6458ea2af7507d2d8f1dadb9c7173948e2915a1985c'
if ((Get-FileHash -LiteralPath $client -Algorithm SHA256).Hash -ine $expected) { throw 'Service digest mismatch' }
python (Join-Path $tool 'soak.py') --go $client --control-helper (Join-Path $tool 'soak-control.exe') `
  --hours 8 --sample-seconds 10 --restarts 3 --output (Join-Path $tool 'soak-report.json')
```

记录 `soak-report.json`、进度和时间线；报告中的 `binary_sha256` 必须与上述
服务摘要一致，`duration_8h_completed`、请求、捕获、重启与错误均须核对。
新版工具还记录 `workload_elapsed_seconds` 和 `sampling_continuity`：默认 10 秒采样时，
采样间隔超过 70 秒或时钟出现明显跳变会判失败，应保持终端唤醒并重新运行。
控制同步超过 10 分钟、时间异常或出现控制错误也会判失败。
这些检查有助于发现中断，仍需人工检查时间线和系统休眠记录。
不足 8 小时只算短测；不能用报告的单一 `passed` 字段替代逐项审核。该脚本会
主动对合成上游发起普通及 SSE 请求，测试隔离缓存与控制交互，不注册系统服务。
有需要可按参数提供合成 DSH runtime；未配置时不能声称 DSH 路径已覆盖。

此前仅在本机验证了 Windows 进程采样、临时目录 ACL 和单独合成控制进程，因
本机 18080 已被现有服务占用，未运行完整脚本，更未执行 8 小时。独立终端首轮
先运行短测（使用 `--hours 0.02` 和新的输出文件）；失败时停止并记录脱敏错误，
通过后另用新文件进行 8 小时。短测不得作为长稳证据。

这项合成长稳不替代 [Windows 独立安装、IOA 和业务验收](WINDOWS-GO-0219-HANDOFF.md)
或正在安装的服务的 [8 小时只读观察](WINDOWS-GO-0219-HANDOFF.md)。回传最终包及
服务摘要、系统版本、脱敏报告和业务结果；真实凭据、请求正文、未经审查日志和
配置备份留在受限终端。
