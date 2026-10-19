# Win/Mac 客户端审查与日志诊断报告

原审查日期：2026-10-15；修复更新：2026-10-16。范围：Go 0.2.0 Win/Mac 客户端、旧 .NET 兼容边界及生产 Python 0.1.23 控制日志关联；不审查外部模型网关内部实现。

## 修复状态（2026-10-16）

R1–R6 与 O1–O8 已在源码实现修复，并补充针对性回归。结果、代码行为、日志定位边界和待验项目见 [修复验证报告](CLIENT-FIX-VERIFICATION-20261016.md)。下文保留 10 月 15 日原始审查证据与建议，行号和“当前/未实施”表述仅描述当时快照，不代表修复后状态。

## 原审查结论与证据边界

已确认 3 项 P1，另有控制容错、停服日志和诊断证据等 P2 问题。当前不能宣布正式替换完成。
现有日志能确认部分请求、路由、结果与状态码，但不足以稳定区分 DNS/TLS/超时、磁盘/权限、控制阶段及配置恢复原因。建议补充结构化诊断，不通过增加同步日志 I/O 换取定位能力。

原审查阶段交付为报告、地图及改造建议，**没有修复业务代码，没有改变捕获可靠性，没有安装或部署**。
下列隔离复现来自同次审查阶段的临时 overlay/合成样例，未修改仓库源码；本次文档落地不重复执行这些测试。
代码行号是核查快照，后续变更可能移动，应同时依据函数与触发条件定位。

## 已确认缺陷

### R1 / P1：合法 Codex TOML 被接管器改坏（Win/Mac）

- 位置：[transform.go](../go-client/internal/configuration/transform.go)，`assignmentRE` 第 77 行、`Codex` 第 111–113、150–159 行。
- 触发：原配置使用合法 TOML literal string，例如 `openai_base_url = 'https://upstream.example/v1'`。
- 证据：解析器只识别双引号；隔离复现返回 nil error，却保留原键并追加第二个 `openai_base_url`，原上游被错误记录为默认值。生成结果包含重复键，已不是有效 TOML。
- 影响：自动接管可能让 Codex 无法读取配置，并破坏正确恢复所需的原上游信息。这一限制也存在于旧 .NET 实现，不能因此忽略候选版问题。
- 建议：正确识别目标字段的 TOML 字符串/key/section；不能可靠解析时在写入前拒绝，绝不把未识别赋值当作字段不存在。
- 后续验收：顶层单引号 URL、单引号 `model_provider`、quoted provider section、重复键、注释/换行；失败时原文件不变。

### R2 / P1：补建配置归服务账号所有（Mac root 服务）

- 位置：[atomic.go](../go-client/internal/configuration/atomic.go)，`ApplyFile` 第 50、56–69 行；[manager.go](../go-client/internal/configuration/manager.go) 的 CC Switch ordinary 模式创建路径。
- 触发：CC Switch 有当前 provider，但用户 live 配置不存在，root LaunchDaemon 自动补建。
- 证据：隔离样例创建成功，文件权限 0600、所有者为运行 UID；新目录为运行 UID、0700，只有已有文件才执行 metadata 保留。真实 root 跨 UID 测试未执行；按此创建路径会生成用户不可访问的 root 文件/目录。
- 影响：Agent 或用户无法读取、修改自己的配置。同 UID fixture 无法验证此条件。
- 建议：为新建用户目录/文件显式指定目标 profile 的身份与可访问权限；已有目录/文件保持其原有权限策略，不扩大开放权限。
- 后续验收：真实 root→普通用户场景；已有/缺失目录、文件分别覆盖，解除接管和失败回退保持正确所有者。

### R3 / P1：运行中卸载未可靠解除接管（Mac）

- 位置：[uninstall.sh](../installer/macos/uninstall.sh) 第 9–14 行；[main.go](../go-client/cmd/endpointai/main.go) 的 `maintenance` 第 392–401 行。
- 触发：服务占用 18080 时运行卸载。脚本先执行 detach，Go 维护入口因此返回 `CLIENT_MUST_BE_STOPPED`；脚本用 `|| true` 吞掉错误，然后停止并删除服务注册。
- 影响：Claude/Codex 配置可能继续指向已停止的本地代理。
- 证据修正：当前开发 PKG 在 [Build-Pkg.sh](../installer/macos/Build-Pkg.sh) 第 65–67 行生成平铺 launcher wrapper。因此**不是“bundle 布局必然找不到程序”**；确定问题是顺序与吞错。
- 建议：解析实际程序，先停服并确认退出，再解除接管；恢复失败返回非零并保留必要注册/恢复材料，不输出成功卸载结论。
- 后续验收：运行中服务、bundle+wrapper、平铺程序、用户并发修改、detach 失败和恢复失败。现有 21 项安装脚本隔离测试没有覆盖 `uninstall.sh`。

### R4 / P2：策略失败连带阻止心跳与远程命令（Win/Mac）

- 位置：[app.go](../go-client/internal/app/app.go)，`Sync` 第 448–480 行；[routes_client.py](../server/controlserver/routes_client.py) 的 heartbeat 命令下发。
- 触发：策略请求持续 503、超时或验签失败，但 heartbeat 本身可用。`Sync` 在策略失败时提前返回，`nextPolicy` 仍到期，每次重试再次先失败。
- 隔离复现：第一次同步成功后只破坏策略签名，让 policy/heartbeat 都到期；结果 policyFetches=2、heartbeats=1，第二次心跳未调用，缓存状态仍 enabled。
- 影响：资产/事件和远程启停领取一起停摆。属于继承串行同步设计的容错缺陷，不将其描述为 Go 新增安全漏洞。
- 建议与验收：隔离 policy/heartbeat/events 的结果与重试；坏签名仍拒绝应用，正常心跳及其禁用命令必须继续可达。

### R5 / P2：停服丢失在途请求的最后运行日志（Win/Mac）

- 位置：[main.go](../go-client/cmd/endpointai/main.go) 第 288、307–312 行；[audit.go](../go-client/internal/audit/audit.go) 第 399 行。
- 触发：根 Context 取消同时终止 Audit worker，HTTP `Shutdown` 随后才等待请求收尾；之后的 `Observe` 入队无人消费。
- 隔离复现：随机 loopback 端口，SSE 首块后取消服务，再延迟约 200 ms 让上游正常完成；连续 3/3 次捕获 summary 有 1 条 SUCCESS，而 `REQUEST_COMPLETED` 运行日志为 0 条。
- 影响：丢失运行日志，**不是全部捕获/审计丢失**，同步 summary 仍成功。
- 建议与验收：分离后台控制任务与 Audit 生命周期；HTTP drain/abort、handler 收尾后再 flush/close 日志，覆盖停服中的 SSE 和普通请求。

### R6 / P2：诊断可能漏掉最新故障或指定请求（Win/Mac）

- 位置：[evidence.go](../go-client/internal/diagnostics/evidence.go) 第 82、219–249 行；[audit.go](../go-client/internal/audit/audit.go) 的当日 summary 写入与清理豁免。
- 触发：单个 JSONL/GZip 超过 8 MiB。采集仅从头读取该上限，summary/failures 也只保留较早的 200 项。
- 隔离复现：超过 8 MiB 的合成摘要末尾追加指定 ID 的 502，`recent-summary` 和 `failures` 都没有目标，Truncated=true；250 条成功再追加 502 时，recent-summary 仍只含前 200 条，failure 列表在该较小样例中能包含错误。
- 影响：错误可能存在于本地文件却不进入诊断包；“未找到”不能视为“未发生”。
- 建议与验收：按真实时间保留最新有界窗口；当前文件有界倒读，指定 ID 搜索标明预算与已搜索范围；覆盖 >8 MiB、>200 条失败、同日多文件和 GZip，不靠文件名随机部分推断时间顺序。

## 其他日志与诊断缺口

| 编号 | 当前行为与位置 | 定位影响 |
|---|---|---|
| O1 | [proxy.go](../go-client/internal/proxy/proxy.go) 第 219–228、275–282 行将连接/流错误合并为通用码 | DNS、拒绝连接、TLS、超时、reset/EOF 无法区分 |
| O2 | [proxy.go](../go-client/internal/proxy/proxy.go) 第 140–177 行在创建 ID/capture/Observe 前处理状态库、路由、禁用、白名单和目标失败 | 调用端收到错误，本地却没有此次请求的结果记录 |
| O3 | [client.go](../go-client/internal/control/client.go) 第 109–111 行抹平 HTTP/TLS/传输错误；[app.go](../go-client/internal/app/app.go) 第 548–575 行只留 generic error 和内存事件 | 控制离线时无足够本地证据，重启后内存事件丢失 |
| O4 | [audit.go](../go-client/internal/audit/audit.go) 多处只设置 sticky degraded bool | 无法知道创建、写入、同步、更名、压缩还是清理失败；日志丢弃也混入同一状态 |
| O5 | [collect.go](../go-client/internal/diagnostics/collect.go) 第 249 行、[evidence.go](../go-client/internal/diagnostics/evidence.go) 第 120–163 行过滤已有安全字段 | 最后控制错误/同步时间、policyVersion、items/failed、DroppedCount 等导出后消失 |
| O6 | [app.go](../go-client/internal/app/app.go) 第 225–229 行只记接管总成败，未保留逐项 Result 原因 | 无法事后区分并发写、权限、CC Switch 模式和补偿结果 |
| O7 | [main.go](../go-client/cmd/endpointai/main.go) 第 453–455 行将已有启动原因统一为 CLIENT_START_FAILED；Windows SCM 通用退出码 | 端口占用、数据根不可用、密钥丢失和状态库失败不易区分 |
| O8 | [Collect-MacInstallerLogs.sh](../installer/macos/Collect-MacInstallerLogs.sh) 第 78 行匹配仍含固定旧包版本 | 仅包含 Go 新包名且没有 bundle ID 的系统安装日志行可能遗漏 |

这些缺口已做源码核对；安全字段过滤另有合成验证。既有相关测试通过不代表这些异常场景已覆盖。

## 故障与可定位边界

| 故障 | 当前能知道 | 当前不能稳定知道 / 所需补充 |
|---|---|---|
| 上游 4xx/5xx | 已进入转发路径的请求 ID、路由、状态、捕获及结果 | 远端内部原因需对应上游日志，不能由客户端状态码推断 |
| DNS/TCP/TLS/超时 | 连接失败及部分时长 | 缺少阶段、类型、安全系统错误码 |
| SSE 中断/客户端取消 | 部分正文、bytes、结果码及阶段时间 | stream 具体错误消失；主动取消与 socket 写失败缺少区分 |
| 无效路由、禁用、状态库失败 | 调用端固定响应 | 缺少前置失败的本地关联记录 |
| 控制失败 | generic 健康状态、有限内存事件 | 缺少操作阶段、传输/业务/签名分类和服务端关联 ID |
| 配置接管/恢复失败 | 备份、状态、部分管理接口 Result | 后台运行日志只保留总失败，不足以还原具体操作 |
| 磁盘/审计失败 | auditState=Degraded | 缺少操作、错误类型、时间、次数；不能仅靠 bool 确认根因 |
| 启动/安装失败 | 部分 MSI/PKG 阶段、退出码、系统服务证据 | 顶层启动原因被抹平，安装证据覆盖仍有缺口 |
| 性能异常 | 总时长、已有阶段时间和外部压测 | 没有足够 capture finalize、队列和细分网络计时 |

控制关联特别说明：Go 的 [Transport](../go-client/internal/protocol/transport.go) 生成 envelope UUID，Python 没有记录该 ID；响应中的业务 `X-Request-ID` 虽被 transport 保留，调用层多处忽略，错误路径还会丢弃 headers。
锁定 Flask/Werkzeug 版本的隔离验证表明，内层 `test_request_context` 复用 app context 的 g，内层 trace 覆盖外层 trace；成功 dispatch 的服务端内外两行日志可以共享内层 ID。**不能错误声称服务端内外 ID 必不相同**；确定缺口是客户端与服务端缺乏被保留的关联信息。
客户端模型代理 ID、控制 envelope ID、服务端业务 ID 是三种身份，补充日志时应分别命名。

## 日志补充建议：性能优先

以下为后续设计，**尚未实施或测得性能通过**。采用用户确认的取舍：诊断事件允许有计数的限频/丢弃，业务捕获可靠性保持不变。

### 记录哪些信息

- 启动、停止、失败、恢复、策略/命令/配置变更保留结构化事件；成功请求明细已有 capture summary，运行日志按分钟聚合，避免再写一份完整成功明细。
- 固定字段包括组件、阶段、错误类别、HTTP 状态、安全数值 OS error、时间/耗时、请求或操作 ID、策略/运行版本以及变更/回退结果。对象字段需类型与长度上限，不接受任意自由文本。
- 网络原因用 typed error 分类为 DNS、TCP、TLS、响应头、流读取、客户端写入及取消/超时；控制区分 enroll/policy/heartbeat/events/command-receipt。保留现有对外错误码与加密协议，不将内部错误链直接暴露给调用者。
- 本地审计故障保存最后操作、错误类别、时间和累计数；日志自身写失败用独立内存计数/健康字段，不递归调用失败 logger。运行日志丢弃与业务捕获失败分开表达。
- 前置代理失败也分配本地 ID，但不为其开启完整正文捕获；正常原厂透传及现有转发头语义不因诊断改变。
- 服务端在既有控制请求日志中增加经过校验的 envelope ID、业务 ID、固定阶段及耗时；不新增数据库表、模型请求采集或信封字段，不改签名/序列化契约。

### 开销与隐私边界

- 新增诊断不在请求线程执行同步写盘、压缩、系统命令、DNS 反查或远程上报。继续使用有界异步队列，日志写入与 GZip/目录清理分开消费者，不引入无限 goroutine/缓冲。
- 重复失败按固定类别与操作限频，保留累计次数和首次/末次时间；拥塞时生命周期/失败优先于成功细节，丢弃数量可见。不能宣称“失败绝不丢”又保证非阻塞。
- 先利用已有 ID/枚举/时刻，补充 capture finalize 和队列计时；默认聚合，详细追踪只针对诊断需要。不要以全量高频 httptrace、原始异常堆栈或重复正文换取定位能力。
- 禁止输出任意 `err.Error()`、token、密钥、cookie、完整 URL query、原始路径或正文；标识和路径按已有诊断方式 hash。每次增加字段同时更新导出白名单及敏感信息负例。
- 当前捕获在转发路径直接写入，Complete 同步 Flush/Sync/Close/Rename 后写穿 summary；并非“所有日志都已异步”。`durationMilliseconds` 在 Complete 前计算，也不包含该最终落盘耗时。不能从现有总时长断言捕获没有性能成本。

### 诊断证据与持久化

优先保留最新的有界记录；指定 ID 查找须明确已搜索的时间/文件范围及截断原因，预算耗尽不输出确定的“请求不存在”。
增加日志丢弃数量、最后控制同步信息、策略版本和逐项配置结果等安全字段。
保留已有正文持久化语义；运行日志收尾须等待 HTTP handler 完成后 flush/close。
服务端使用 WatchedFileHandler 支持外部轮转但不会自行限制大小；应核对真实日志路径与账户，不直接套用不匹配的 logrotate 模板。本轮不变更现场轮转或部署。

### 性能验收建议

“完全零开销”无法保证，下表为待实测预算，不是已有结果。

| 指标 | 新增诊断相对同一 Go 基线的目标 |
|---|---|
| p95 转发延迟 | 增量 ≤1 ms |
| CPU | 占单核 CPU 增量 ≤1 个百分点 |
| RSS | 增量 ≤8 MiB |
| 请求路径 | 不新增诊断同步 I/O，不因日志队列满而等待 |
| 可靠性 | 业务捕获无新增丢失/降级；诊断丢弃有独立计数 |

在相同正文捕获设置、固定上游和相同机器负载下做 A/B，覆盖 JSON/SSE、并发 1/8/32、慢盘及队列溢出；平衡测量顺序并保留重复结果。
新增诊断预算与旧 .NET 对比的 +5 ms 门禁分别验收，不能用关闭捕获/放松同步来达标。

## 当前验证与待验

事实来源：[功能矩阵](GO-CLIENT-PARITY.md)、[最终验收记录](GO-CLIENT-VERIFICATION.md)、[Windows 交付说明](WINDOWS-GO-DELIVERY.md)。

| 状态 | 已有证据与限制 |
|---|---|
| 已有通过 | ARM64 隔离普通用户环境运行 14,422.35 秒，23,040 条成功捕获、零降级、3 次进程重启；Rosetta 测试及现有相关单元测试通过 |
| 复现的问题 | 本文 R1、R4、R5、R6 有针对性隔离样例；R2 验证了创建时 owner=运行 UID，root 跨 UID 实测待补；R3 有确定源码触发路径 |
| 性能未达标 | 冻结程序正常顺序复测，8/32 并发 JSON 完整响应 p95 增量约 +8.52/+65.92 ms；反序结果反转，仍有 SSE 场景略超标。不能确认全部延迟都由日志造成 |
| 平台待验 | Windows 原生 MSI/PowerShell 5.1、SYSTEM/DPAPI/ACL、安装升级回滚/重启卸载及 IOA；真实 Intel；Mac root 系统服务安装/系统重启/卸载 |
| 未实施 | 本文缺陷修复、日志补充、现场轮转调整及新增性能预算验收 |

4 小时普通用户 fixture 和静态安装包检查不能覆盖 root 所有者、真实卸载、故障分类、慢盘或诊断容量问题。正式替换仍由现有失败项、本文 P1 及平台待验共同阻止。

后续验证清单：

1. 单引号 TOML、重复键及无法可靠解析时原文件不变。
2. root 创建普通用户文件/目录，运行中卸载，用户并发修改及恢复失败。
3. 仅策略失败但心跳正常、命令可达；在途 SSE 与普通请求停服。
4. >8 MiB 日志、>200 条故障、滚动/GZip 分片、指定 ID 搜索和明确截断范围。
5. DNS/TLS/超时/取消、权限/磁盘错误、队列溢出及安全字段导出。
6. 凭据/正文/URL 参数敏感信息负例，以及 JSON/SSE 并发 1/8/32 的日志前后 A/B 与两端原生验收。

## 文档维护与验收

项目入口为 [CONTEXT.md](../CONTEXT.md)。保持源码相对链接、日期、版本和验证边界一致。
本报告的修复建议与性能预算不能被复制成“已实现/已通过”；后续修复应链接具体代码与新验证结果，保留首次失败及不足证据。
临时审查样例不是已提交的回归测试，不能替代后续修复测试。本文不包含真实凭据、设备身份或请求正文。
