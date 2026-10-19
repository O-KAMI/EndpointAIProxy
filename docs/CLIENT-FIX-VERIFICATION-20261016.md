# 客户端审查修复与验证：2026-10-16

本次更新 Go 0.2.0 候选源码及生产 Python 控制日志代码，未安装系统服务、未部署生产、未改变外部加密协议或 SQLite schema。历史 .NET 回退源码保留。

## 修复结果

| 编号 | 已实现行为 | 验证与限制 |
|---|---|---|
| R1 | Codex TOML 完整语法校验，通过解析器字节范围只替换目标字符串；支持 literal/basic string、quoted/dotted key、section 与 inline table；不可可靠处理时写入前失败 | 配置回归、race 通过；新增锁定 go-toml/v2 v2.2.4 |
| R2 | 补建配置的 owner 来自可信用户 profile；拒绝符号链接及路径逃逸，已有文件保留 metadata；Windows 保留继承 DACL | Unix fixture、Windows 编译通过；真实 root 跨 UID 与 SYSTEM 权限仍待验 |
| R3 | Mac 卸载持安装锁，先确认停服，再解除接管，最后删除；失败返回非零并保留/恢复注册与恢复材料 | bundle/wrapper/plain、detach 失败及恢复失败脚本回归；真实 root 安装卸载待验 |
| R4 | 心跳先执行，各控制阶段独立到期/重试；策略失败不再阻断心跳、事件和命令；回执失败保留待重试 | 加密模拟控制、坏签名与命令回归通过；协议、持久状态不变 |
| R5 | 关闭请求准入，等待 HTTP drain/abort 与 handler 收尾，再关闭日志消费者；控制任务与日志生命周期分离 | 在途 SSE 停服回归通过；系统强制 kill 不保证最后诊断日志落盘 |
| R6 | 读取最新证据窗口，按记录时间保留最新项；指定 ID 扩大有界搜索，输出覆盖范围与截断理由 | >8 MiB、>200 条失败、GZip、指定 ID 及预算回归通过 |
| O1/O2 | 本地 ID 在前置校验前生成；记录固定阶段、错误类别、系统码、HTTP 状态和耗时；前置失败不捕获正文 | DNS/TLS/连接/超时/取消、前置错误等测试通过 |
| O3/O6 | 控制失败/恢复与逐项配置结果进入本地日志，控制信封 ID、服务端 ID 分开关联；路径、用户和路由做安全摘要 | 控制、配置与导出回归通过；不写任意原始错误字符串 |
| O4/O5 | 捕获失败保留最后阶段与原因；诊断日志丢弃/写入失败独立计数；健康与诊断导出保留安全状态字段 | 磁盘/权限、队列溢出、脱敏及哈希关联测试通过 |
| O7/O8 | 启动输出安全结构化原因；Windows SCM 使用具体退出码并尝试既有 EventLog source；Mac 日志采集识别新 Go 包名 | 启动、平台与采集测试通过；Windows 实际事件日志可用性待验 |

## 日志定位与性能边界

请求失败使用本地 `requestId` 关联摘要；路由在运行日志与导出中使用一致 SHA256。`stage/errorClass/errorCode/osErrorCode/httpStatusCode/timeout` 表示客户端实际观察到的失败。控制日志使用 `controlRequestId/serverRequestId`，不能当作模型请求 ID。上游 500 的内部原因、网络设备丢包等仍需对应服务或网络证据。

成功请求继续保留既有业务捕获摘要，运行日志改为分钟聚合；失败日志按固定类别限频，保留首次/末次与抑制次数。诊断日志独立消费者，压缩/清理另有 worker；普通队列 4096、优先队列 256，有界且非阻塞。捕获正文的 Flush/Sync/Close/Rename 与同步摘要保持不变，未以降低捕获可靠性换取性能。

`auditDiagnostics` 暴露 `auditFailureCount/lastAuditFailure/logDroppedCount/logWriteFailureCount/logSuppressedCount/logQueueDepth`；日志丢弃不再将正文捕获标为降级。诊断包的 `evidence/search-coverage.json` 说明已搜索文件、范围、预算及是否完整；未找到且搜索不完整不能判定请求不存在。普通文件默认尾部 8 MiB，指定 ID 搜索共享 64 MiB 预算，GZip 按解压字节计入；每类最新文件及记录数量仍有上限。

摘要中的 `CaptureFinalizeMilliseconds` 测量正文文件完成阶段、在摘要写入前取值；运行记录的同名值包含整个 Complete（含摘要写入）。两者用途不同，不应直接当作同一延迟分布。

新增性能预算仍是验收目标：p95 增量 ≤1 ms、CPU 增量 ≤1 个百分点、RSS 增量 ≤8 MiB。同机 A/B 包含本轮全部修复，不能严格归因于日志；空闲采样不能证明负载 CPU/RSS 预算。旧 .NET +5 ms 门禁仍独立保留，尚未稳定通过。

Python 既有控制日志补充认证后的信封/业务关联、阶段与耗时，不新增表或模型逐请求采集。异常只记录类型、安全系统码和本项目栈位置，不保存任意异常文本、私有路径或 locals。新增实际 appdeploy 路径轮转模板，见 [部署说明](../server/deploy/LOG-ROTATION.md)；模板未安装，不能认定生产轮转已生效。

## 本轮性能实测

两轮平衡顺序 Go→Go 对比使用相同签名程序、完整同步捕获、JSON/SSE 并发 1/8/32，各版本每轮 576 条捕获，均无降级。报告为 `artifacts/go-client/verification/go-comparison-20261016.json`，复现入口 `go-client/scripts/benchmark-go-comparison.py`。

第一轮候选相对旧 Go：空闲 RSS +1.13 MiB，空闲 CPU +0 个百分点；p95 完整响应最大增量 +5.23 ms（JSON/8）。反序第二轮 RSS −8.14 MiB、空闲 CPU +0 个百分点；最大增量 +22.58 ms（JSON/32）。其余场景有正有负，存在明显顺序/负载波动。**p95 ≤1 ms 预算没有稳定通过**；这比较了全部修复，不能断言增量由日志造成。负载 CPU/RSS 未测，不作通过结论；没有关闭捕获或放松持久化。

## 已执行验证

- Go 全模块 `go test -race ./...`、`go vet ./...` 通过；Windows amd64 全模块交叉构建通过；amd64 全模块 Rosetta 测试通过。
- Python 锁定测试环境：88 passed、34 skipped。跳过项涉及未启用的 MySQL/.NET 等集成条件，不能视为已通过。
- Mac 安装/卸载隔离脚本 32 项通过，85.059 秒。前次完整测试有 1 项失败，保留原报告；受控延迟证明测试将健康预算压成 3 秒会误失败，修正为原生 60 秒并增加回归。原失败日志不足，不能断言一定同因。
- ARM64/amd64 新程序构建及开发签名静态检查通过；ARM64 本机启动、72.71 秒 smoke、128 条成功捕获、3 次进程重启通过。此轮不是 4 小时长稳。
- 新版本完整 4 小时长稳尚待执行。旧版 14,422.35 秒/23,040 条捕获结果只属于旧程序，不能外推到本轮修复。

证据位于仓库 `artifacts/go-client/verification/`：`go-tests-20261016.txt`、`rosetta-tests-20261016.txt`、`server-tests-20261016.txt`、`macos-installer-tests-20261016-after-fixture-fix.txt`、`macos-installer-ready-timeout-probe-20261016.json`、`soak-smoke-20261016-review-fixes.json`。构建载荷位于 `artifacts/go-client/0.2.0-review-fixes-20261016/`。签名程序目录为 `development-arm64-20261016-review-fixes` 与 `development-intel-20261016-review-fixes`。

## 交付与待验

Windows 新源码包使用日期后缀 `EndpointAIProxy-Go-Windows-0.2.0-source-20261016-reviewed.zip`，保留旧包历史。包含锁定 vendor、许可证、测试、MSI 构建材料以及地图与审查文档，无真实凭据或证书。地图面向完整仓库，裁剪包未附带的服务端/旧 .NET/Mac/证据链接须回完整仓库查看。

Windows 原生 PowerShell/MSI、SYSTEM/DPAPI/ACL、IOA、升级失败回退、系统重启及卸载；Mac root 跨 UID、真实安装/升级/卸载/系统重启；真实 Intel 硬件；新版本 4 小时长稳及稳定性能预算仍待验。开发签名不是正式发行签名/公证。当前源码缺陷已修复，不代表正式替换验收完成。
