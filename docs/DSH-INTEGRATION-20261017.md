# DSH 接入与验收记录（实施 2026-10-17，复核 2026-10-18）

Go 候选版本为 0.2.1。该版本增加 DSH 发现、受控配置接管及 Python 控制面兼容；尚未获得生产替换验收。旧 .NET 0.1.22 没有 DSH 恢复能力，回退前必须由 Go 成功解除接管。

## 已实现边界

官方源码核查固定在 `1517a4dbca0a2789ff1d41ba439600f8547d23fa`，DSH `0.2.1-alpha.5`。实际 npm 测试锁解析到 `@earendil-works/pi-ai` **1.3.0**，并非仅凭研究时的间接版本假设。复现依赖锁见 [测试 runtime](../go-client/testdata/dsh-runtime/package-lock.json)。这些 Node 依赖只用于验证，不进入客户端载荷。

| 能力 | 实现与边界 |
|---|---|
| 发现 | 官方 npm manifest、经过包 bin 校验的 Node 入口、profile manifest、Desktop 包及 runtime 组合证据；不持久化完整命令行或环境 |
| DeepSeek API Key | `llm-deepseek` 明确静态 `baseURL`；Messages、Files；保留凭据引用与全部 config |
| 自定义网关 | `llm-pi-ai` 的明确静态 provider、api/models、API Key 引用；HTTP/SSE Chat Completions、Responses、Messages；按已验证 SDK 版本限制 |
| 独立搜索 | `web-search-deepseek` 的明确静态 `baseURL`，单独路由，使用 Messages wire API |
| 安全恢复 | YAML 节点修改、备份/CAS/原子替换/权限保留；用户、根、profile、插件/provider 独立路由；恢复根和待退休路由保存在受保护备份目录 |
| 控制面 | AgentType 追加整数 11 / `deepseekHarness`，既有整数值不变；资产 family 与 wire API 独立；Python 模型、统计和控制台同步识别，无数据库 schema 迁移 |

**缺少显式 baseURL 时首版仅发现。** 服务无法证明实际启动进程的环境变量或 dotenv 覆盖，因此不会代填官方默认地址。用户需在已有插件完整 config 中明确地址；不能追加仅含 baseURL 的覆盖行。DeepSeek 官方默认根为 `https://api.deepseek.com/anthropic`，搜索为独立配置。账户登录、OAuth、WebSocket、特殊 catalog provider、依赖厂商 URL 识别的自定义地址、动态表达式、未知版本、非空 home patch 或未知启动 overlay 均拒绝自动接管。

默认根为用户 `.dsh`；可信部署可提供 `SF_PROXY_DSH_HOMES` JSON 绝对路径数组。自动修改仍限于该用户目录边界。目录外自定义根仅发现。Desktop 的配置和覆盖来源不能确认时也仅发现；尚未做真实 Desktop 端到端验收。

## 启用、升级与回退

DSH 默认关闭。`SF_PROXY_ENABLE_DSH=true` / `--enable-dsh=true` 为部署启动选项，`SF_PROXY_DSH_HOMES` / `--dsh-homes` 指定可信根。不得从扫描到的任意环境或命令行值直接授权修改目录。

1. 先部署本仓库兼容 Python 控制面，并在真实网关确认 Agent 标识、HMAC、路径和查询兼容。
2. 安装 Go 0.2.1 并完成健康/状态/原有 Agent 验证，再通过既有受控服务配置方式开启 DSH。MSI 不自动开启，避免安装事务回滚到不支持 DSH 的旧程序时遗留接管配置。
3. 分开观察 installed/running、配置接管结果和真实请求捕获；资产存在或写配置成功不是代理成功。
4. 回退、卸载前先停止服务，再由 Go 维护命令解除接管，确认成功后才能移除 Go。运行进程有无法检查的 overlay、并发保存或配置损坏时保留路由与恢复证据，不能强删状态。关闭新接管开关不等于已恢复配置。

维护入口及服务内解除接管都先合并并校验保存的恢复根，再检查运行进程。profile/provider 改名或可靠确认删除后，只有无任何已知引用且完整检查成功才退休旧路由；YAML 写入/回滚失败、扫描失败、未知 overlay 等会阻止退休。这个约束也适用于关闭 DSH 开关后的恢复操作。

## 请求、日志与性能

保留原始上游用于白名单、签名与恢复。DeepSeek 专用路径去重仅作用于该插件路由，避免原上游已带 `/v1` 时产生重复；自定义 provider 和搜索继续使用各 SDK 的路径规则。multipart、查询、原始正文、流式、取消及认证头保留。网关归因使用 `DeepSeekHarness`、`x-sf-userid`、`x-request-id`；不新增请求正文解析或同步诊断写盘。

日志沿用失败分类、请求关联与现有捕获；诊断新增有界 profile 文件元数据，不导出 YAML 内容、完整命令行或凭据。复杂多插件配置问题仍需核对脱敏配置和 DSH 自身运行证据，不能承诺所有根因都由客户端日志独立证明。

**真实网关联调尚有已知限制：** 当前网关 `ApplyOriginalBaseURL` 清除查询参数，会影响 Files 列表的分页参数。客户端及本次模拟上游会保留查询，但这不能证明该网关路径通过。本轮未修改外部网关；启用前必须由网关侧解决或确认该限制。

## 实际证据与待验

证据位于 `artifacts/go-client/verification/`；它们是本地生成物，不是生产部署证明。

- `go-tests-dsh-r3-20261017.txt`、`go-vet-dsh-r3-20261017.txt`：冻结源码全量 Go race/vet。
- `dsh-build-r3-20261017.txt`：Windows x64、Mac arm64/x64 服务及 Windows helper 交叉构建。
- `dsh-cli-composition-20261017.json`：固定真实 DSH CLI 的版本与 boot-free 配置组合；不冒充完整 CLI 模型启动。
- `dsh-sdk-parity-arm64-r3-20261017.json`：真实已锁定 DSH 插件/SDK 对模拟上游的 18 场景，含三种模型协议、搜索、Files、工具调用、错误和取消，接管前后路径/正文/关键认证头比较，以及配置接管与管理接口恢复。维护命令因普通用户权限返回 5，管理员卸载验收仍待验。
- `dsh-sdk-parity-intel-r3-20261017-retry.json`：Intel 签名程序在 Apple Silicon 的 Rosetta 下通过同一 18 场景及配置恢复；不是 Intel 真机。首次尝试因端口被正在运行的 smoke 占用而拒绝，未停止任何服务。
- `python-tests-dsh-r3-20261017-venv.txt`：Python 服务端 92 passed / 34 skipped；跳过项仍待对应环境验证。
- `go-rosetta-dsh-r3-20261017.txt`：Intel Go 内部模块测试通过。
- `dsh-smoke-r3-20261017.json`：72.81 秒、240 请求、2 次重启，通过；不是四小时长稳。
- `dsh-source-offline-20261017.txt`：源码 ZIP 解压到带空格的新目录，禁用依赖联网的 tests/vet/Windows build；清单逐文件 SHA256 与 YAML 许可证已校验。
- 开发签名输出 `development-arm64-20261017-dsh-r3`、`development-intel-20261017-dsh-r3`：使用用户指定新描述文件。开发签名不等于正式发行签名、公证或 IOA 验收。

待验：Windows 原生发现/SYSTEM 权限/MSI/IOA、Mac root 跨 UID/原生安装和卸载、真实 Intel 重启与性能、真实 Desktop、真实网关及服务器联调、账户登录。本轮四小时功能长稳已完成，详见下一节；性能门禁仍待验。历史二进制的结果不覆盖本次变化。

## 本轮长稳、性能与交付状态

四小时功能长稳已完成，输出为 `dsh-soak-4h-r3-20261017.json`；2026-10-18 复核报告状态为 `passed`，`duration_4h_completed=true`，实际运行 **14,417.04 秒（4 小时 17 秒）**。23,040 次请求成功、对应 23,040 条完整捕获、退化记录 0；3 次重启后设备身份及凭据保持，DSH/Claude/Codex 配置接管与恢复、Request ID 关联、过期捕获/日志清理均通过。917 次模拟心跳，包含一次注入的策略不可用故障；全部子进程已清理。完成时间为 2026-10-17 22:17:35（北京时间）。

该测试绑定冻结签名 ARM64 程序 SHA256 `edcb259a514970c25564d724ea337768a7be5fb75a3c1ddd377a2087a1a9cd5c`，本次再次校验一致。采用临时 profile、模拟加密控制面和合成 HTTP 上游；真实 SDK 场景另见 parity 报告，不注册系统服务或修改真实用户配置。

**功能通过不等于全部资源门禁通过。** RSS 范围 30.67–57.25 MiB，跨重启的首末四分位中位数增加约 17.98 MiB；按最后一个进程段单独看，首末四分位中位数为 52.16 / 50.80 MiB，末段未继续增长。缺少 heap profile，不能认定已证明没有泄漏，也不能直接据此认定发生泄漏。磁盘峰值 52.34 MiB，最终约 49.45 MiB，包含按要求保留的捕获证据，未达到容量清理上限；过期清理使用另设 fixture 验证。分段复核见 `dsh-soak-review-20261018.json`。本工具的自动通过条件不包含 RSS 趋势和跨版本延迟阈值，仍需独立性能验收。

`go-comparison-dsh-20261017.json` 对前轮 0.2.0 修复候选与本轮 0.2.1 做两轮相反顺序比较（同捕获设置，JSON/SSE，并发 1/8/32）。空闲 RSS 增量分别 +1.67 / -0.11 MiB，空闲 CPU 增量约 -0.10 / 0 个百分点。p95 完整请求耗时增量范围为 -36.04 至 +9.49 ms，部分场景超过 +1 ms，**未通过稳定延迟门禁**。该结果比较整个候选变化，不能单独归因日志；负载 CPU/RSS 和 DSH 开启后的成本仍待专门测量。既有相对 .NET 的 +5 ms 门禁继续独立保留，不能用这次 Go/Go 比较替代。

本次更新的 Windows 交付入口为 `artifacts/EndpointAIProxy-Go-Windows-0.2.1-20261018-source.zip` 及同名 `.sha256`，包含锁定 vendor/YAML 许可证、DSH 测试复现脚本和固定 npm 测试锁；不带 Node runtime、真实凭据、证书或用户数据。根 `Build-MSI.cmd` 仍默认只构建，不安装。0.2.1 用于保持从 0.2.0 的升级版本顺序；服务端版本仍为 0.1.23。

独立只读复查 r3 已通过：真实 Node overlay、原 profile rename 复现与相关配置回归通过，无新阻断项。四小时功能长稳已通过；原生部署及性能门禁尚未完成，不能宣布正式替换完成。

## 复现入口

在隔离测试目录安装锁定的测试 runtime（不得安装进真实用户 DSH 配置目录）：

```sh
cd go-client/testdata/dsh-runtime
npm ci --ignore-scripts --no-audit --no-fund --registry=https://registry.npmmirror.com
```

随后使用 [verify-dsh.py](../go-client/scripts/verify-dsh.py) 的 `--runtime` 指向该目录，`--go` 指向已签名测试程序，`--output` 指向未使用的新报告路径。该脚本绑定 18080，端口被占用会拒绝执行，不会停止正式服务。测试仅使用合成配置、合成凭据和 loopback 模拟上游。

配置实现及引用检查入口：[dsh.go](../go-client/internal/configuration/dsh.go)、[兼容门禁](../go-client/internal/configuration/dsh_compat.go)；发现入口：[discovery/dsh.go](../go-client/internal/discovery/dsh.go)；代理入口：[proxy.go](../go-client/internal/proxy/proxy.go)。

## Mac PKG 静态补充验证

`pkg-go-development-0.2.1-arm64.json` 与 `pkg-go-development-0.2.1-x86_64.json` 均通过静态展开检查：版本/架构、root 安装声明、开发签名 app、脚本和合成凭据位置、载荷没有 .NET 动态库。包体分别 5,378,550 / 5,884,476 bytes。安装包本身未签名，使用合成控制凭据，仅用于隔离测试；未安装，不能交给 IOA 作为生产部署包。正式 PKG 仍由指定人员使用正式配置及发行签名流程构建。

源码最终清单校验见 `dsh-source-final-check-20261017.json`：2230 个文件的内容哈希校验通过；2071 个源码/依赖/构建输入与已离线通过测试的日期后缀归档一致。2026-10-18 新源码包包含本次更新文档和四小时结果；旧 ZIP 保留原快照，不覆盖历史证据。
