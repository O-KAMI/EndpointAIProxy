# EndpointAIDLP Server 0.1.26 灰度候选

2026-11-04 已在用户授权的既有灰度 Linux 控制服务器完成 **0.1.25/schema 3 →
0.1.26/schema 5** 升级、停服备份及恢复副本验证、原业务摘要核对和派生索引维护。
Linux 完整回归 537 通过、39 跳过，最终更新包两项升级/回退及失败恢复演练通过。
部署代码包含 r77 后的旧 SQLite 搜索兼容修复；schema 6、凭据轮换和新传输身份未启用。
显式灰度路径必须匹配源码/依赖/升级器摘要，普通发行仍阻断；详见
[灰度记录](docs/GRAY-LINUX-VALIDATION-20261104.md)及[升级边界](../deployment/README-SERVER-UPGRADE-0.1.26.md)。
Linux 指控制服务器，与 Win/Mac 客户端无关。普通账号已开启 `Linger=yes`，用户服务和
每小时日志调度已安装，受控服务重启通过；主机重启、入口 TLS 和 10 万在线仍待验。
8 小时低负载灰度观察于 2026-11-04 14:21 开始，运行中，不能计为通过。

当前功能、包摘要和实际验证统一见[当前交付结果](../docs/OPTIMIZATION-CURRENT-RESULT.md)，
逐项缺口见[完成度核对](../docs/OPTIMIZATION-COMPLETION-AUDIT-20261103.md)。

## 本地待验扩展

当前交付结论以仓库地图及 [规模优化当前结果](../docs/OPTIMIZATION-CURRENT-RESULT.md) 为准。
工作树新增默认关闭的 [设备凭据两阶段更新](docs/CREDENTIAL-ROTATION-CANDIDATE.md)，
需要设备传输 V2 和显式激活 schema 6。本机断点回归已通过，旧交付包不包含；schema 6
激活后不能直接降回 r75 或更早程序，普通发行入口仍受完整验收门禁限制；本机断点与
备份恢复的实际结果见上述候选记录，不能代替生产运行或容量证明。

2026-10-28 的规模优化源码、兼容边界及未完成门禁见
[规模优化记录](docs/SCALE-IMPLEMENTATION-20261028.md)。尚未生产部署，不代表容量或发行通过。

2026-10-28 [域名白名单、地址分流与工号展示](docs/DOMAIN-ROUTING.md)已在工作树实现，
使用现有 schema 3 JSON 数据布局。新能力需要升级 Go 客户端；.NET 保留旧策略。
已完成本机隔离回归，未部署、未形成新的离线安装/升级包；下文历史部署说明不代表新扩展已上线。

[单终端策略覆盖](docs/DEVICE-POLICY.md)的 0.1.25/schema 3 部署记录见项目地图。
下文 0.1.24/schema 2 仅为历史说明；新扩展必须先通过隔离数据库与迁移门禁。

## 历史版本 0.1.24（不代表当前候选或现网状态）

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
