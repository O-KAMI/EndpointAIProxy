# Windows 0.2.22 独立合成长稳

只在授权的独立终端运行。确认 127.0.0.1:18080 未被现有服务占用；有冲突即停止，
不要为合成测试改停真实服务。使用从最终候选 MSI 安全解包、摘要一致的 Go 服务程序。

合成工具包包含 `soak.py`、`benchmark.py` 和 `soak-control.exe`，需要 Python 3。
在受限目录以新报告路径执行（占位路径由测试人员填写）：

```powershell
python .\soak.py --go '<本包服务 exe>' --control-helper .\soak-control.exe --hours 8 --sample-seconds 10 --restarts 3 --output '<新报告路径>.json'
```

先以 `--hours 0.02` 和另一个报告路径短测。工具创建带标记的临时合成 profile，不使用真实配置。
报告须为 passed、`duration_8h_completed=true`、程序摘要与最终 MSI 载荷一致；回传报告和时间线。
采样中断、睡眠或时钟跳变必须保留，不能删除失败区间重算通过。

与[原生复测](CLIENT-0222-ADDITIONAL-ACCEPTANCE.md)分开记录。两者都不能证明十万在线容量。
