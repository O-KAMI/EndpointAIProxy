# EndpointAIDLP Server 0.1.24

生产 Python 3.13.15 + MySQL 控制服务，保持 HTTP 8080 和 AES-256-GCM 客户端通信。本版发布 DSH 兼容扩展及安全控制日志，修复命令终态回执幂等性。控制台保留数据分析、策略管理和资产管理。保留策略版本冲突检查、网关编辑、终端详情、远程操作及审计。

2026-10-16 控制日志补充安全关联 ID、阶段、耗时与脱敏异常类别；appdeploy 路径轮转模板见 [部署说明](deploy/LOG-ROTATION.md)，尚未安装。

本版保留数据库结构、既有客户端协议和凭证，仅追加 DSH Agent 契约；不新增模型请求采集、逐请求日志和历史趋势。现有加密客户端继续使用，无须重新安装。

使用同级交付目录的 EndpointAIDLP-Server-0.1.24-update.zip、update-server-0.1.24.py 和 SHA256SUMS-SERVER-0.1.24.txt。具体命令见同级 README-SERVER-UPGRADE-0.1.24.md。

脚本适用于 appdeploy 账户以 start.py 启动、未由 systemd 托管的现有 /app/EndpointAIDLP-Server-0.1.23、0.1.22 或 0.1.21，新版安装到 /app/EndpointAIDLP-Server-0.1.24。支持 Linux x86_64 / aarch64 离线依赖。准备失败不停止旧服务；切换失败尝试恢复旧服务；保留原目录，持久化回退来源，不配置开机自启动。

app.py 是 Gunicorn 入口；start.py 加载私有 launch-env.json。start.py --check 只检查配置和现有数据库。本次不要执行 init-db、migrate-db 或生成新凭证。

统计口径见 [CONSOLE_ANALYTICS.md](docs/CONSOLE_ANALYTICS.md)，本版验证记录见 [ACCEPTANCE-0.1.24.md](docs/ACCEPTANCE-0.1.24.md)。Linux 真实服务器的切换仍须按现场结果验收。

### DSH 客户端兼容扩展（0.1.24，未部署）

服务端契约在原 AgentType 0–10 后追加 `deepseekHarness`（数值 11），保留旧客户端枚举及 schema version 2；资产 family 为 `deepseekHarness`，控制台与分析显示 DSH。模型协议由每个 provider 的配置决定，分别上报 `anthropicMessages`、`openAiResponses`、`chatCompletions`，不按 Codex 推断。现有 JSON 资产列承载扩展，不新增表或执行数据库迁移。

客户端 DSH 接管默认关闭。启用前须先部署这项服务端兼容扩展，并在外部模型网关确认 `DeepSeekHarness` Agent 标识；源码解析测试通过不代表生产控制面或网关已接受。客户端仅在显式启用时发送 DSH 心跳资产；禁用后保留本地恢复状态，维护解除接管仍恢复 DSH。回退旧 .NET 前，应先用新 Go 客户端成功解除 DSH 接管。

### 命令完成回执

同设备、同命令、同 `succeeded`/`failed` 终态以及相同 `resultCode`/`resultSummary` 的重复回执返回 202，不更新首次完成时间。不同设备、命令或冲突结果仍被拒绝；原 `expired`/`cancelled` 不被覆写。观察时间不同不改变相同结果的幂等性。

完整仓库执行 `python server/tools/package_delivery.py --output-dir artifacts/server/0.1.24-<date>`，输出新的离线升级交付包；已有输出拒绝覆盖。旧 0.1.23 包不含 DSH 扩展，不可继续用于启用 DSH。
