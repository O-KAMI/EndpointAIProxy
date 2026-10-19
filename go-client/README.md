# EndpointAIProxy Go 客户端候选版 0.2.2

此模块提供 Windows x64、macOS arm64/x64 共用的 Go 后台客户端。旧 .NET 0.1.22
源码、默认构建入口和回退材料继续保留；候选实现尚不等于已批准替换生产客户端。

## 实现与兼容

- 共用协议、策略、路由、SQLite、配置接管、捕获和日志核心；平台层负责用户、进程、
  服务、权限、密钥保护和诊断。
- 保留 `127.0.0.1:18080`、`/r/{routeId}`、`/healthz`、`--maintenance=detach-all`、
  `--maintenance=collect-diagnostics`、已有 `SF_PROXY_*` 部署配置和服务/数据目录。
- 沿用 AES-GCM/HKDF 控制协议、原始策略正文 HMAC、.NET 命令序列化签名、网关元数据签名。
- 沿用旧 SQLite schema、整数枚举、设备身份、路由 ID、策略缓存、凭据和命令回执。
  Windows 使用 DPAPI；macOS 使用原 `machine.key` 和原密文布局。缺失已有状态的密钥会阻止启动。
- Claude JSON、Codex TOML、CC Switch provider/endpoint 支持备份、并发检测和恢复；
  Qoder 只发现。用户后续修改不会被强制覆盖，恢复失败时保留原上游记录。
- 支持原厂/网关切换、精确 BaseURL 白名单、SSE/取消、资产上报、远程启停与重放恢复。
- 网关工号使用 `x-sf-userid`，客户端生成的请求编号使用 `x-request-id`，覆盖来访同名值。
  其他元数据头及 HMAC 字段值/顺序不变；原厂透传行为保持不变。
  网关读取新工号头，缺失时兼容旧客户端的 `X-SF-AI-User-Id`。
- 捕获组合上限 50 MiB；捕获保留 7 天/512 MiB。运行日志按 20 MiB 分片，保留 7 天，
  按 50/45 MiB 高低水位清理。关闭的文件交给单一后台压缩任务。
- Mac 诊断使用原生系统命令；单项失败不丢失健康证据。诊断 schema v2 包含有界、脱敏的
  请求摘要、压缩日志、配置/路由/资产元数据、失败捕获摘要、清单与校验和，不导出正文或密钥。

## 审查修复与排障

2026-10-16 已修复 TOML 字符串、用户配置 owner、Mac 卸载顺序、策略失败隔离、停服日志收尾和最新诊断窗口。运行日志成功请求按分钟聚合，失败分类/限频；日志消费者独立于压缩维护，丢弃计数通过 `auditDiagnostics` 导出。请求 ID、控制信封 ID 分开关联，搜索覆盖见 `evidence/search-coverage.json`。

代码、验证与剩余平台/性能门禁见 [修复报告](../docs/CLIENT-FIX-VERIFICATION-20261016.md)，跨会话入口为 [项目地图](../CONTEXT.md)。原始捕获包含正文，不能直接公开共享；诊断包不导出正文或密钥。

## 构建与验证

工具链由 `go.mod` 固定最低版本，依赖由 `go.mod`/`go.sum` 固定。

```sh
cd go-client
GOPROXY=https://goproxy.cn,direct go mod download
go test -race ./...
go vet ./...
sh scripts/build.sh
```

输出位于 `artifacts/go-client/0.2.2/`，含三种架构的服务和 Windows 无窗口安装辅助程序。
没有 .NET runtime payload。测试只使用临时数据；原生服务安装另在隔离终端验收。

真实 C# / Go 双向数据兼容验证：

```sh
DOTNET=/path/to/dotnet DOTNET_REFERENCE_DIR=/path/to/old-client-publish \
  python3 scripts/interop-dotnet.py
```

此工具直接编译既有 C# 代码，使用现有 SQLite 程序集且关闭 NuGet 源，验证两种方向的
密文、身份、路由、凭据、策略、操作状态及命令回执，不接触真实用户配置。

## 安装与开发签名

Windows Go WiX 项目位于 `installer/Sf.EndpointAI.Go.Setup`，沿用 MSI 升级身份及安装
事务。Windows 原生 MSI 构建、安装、回滚和 DPAPI 运行仍须在 Windows 隔离机完成。

Mac 使用既有 `installer/macos/Build-Pkg.sh`，明确设置 `CLIENT_IMPLEMENTATION=go`。
正式发行采用 Developer ID 程序/安装包签名和公证；Apple Development 证书对应另一条
限定注册设备的开发验证路径。

`scripts/sign-development.py` 接收外部描述文件、P12 和程序，验证设备与证书匹配后创建
带描述文件的 `.app`，使用临时钥匙串签名并实际执行 `--version`。密码默认从环境或安全
提示读取；仅在输入文件名确实携带现有密码提示时显式使用 `--use-filename-password-hint`。
临时钥匙串和搜索列表在结束后清理，不把 P12、私钥或密码复制到源码/交付目录。

已有开发签名 `.app` 可以通过 `DEVELOPMENT_APP_BUNDLE` 打入开发 PKG，安装器验证
包内实际进程路径；维护和卸载仍经原有命令入口。开发 PKG 的 Installer 签名和正式发行
公证另行处理，不能把开发设备授权等同于全公司终端分发授权。

时间戳服务不可用时，开发设备验证可显式指定 `--without-timestamp`，报告记录此限制；
默认仍请求可信时间戳。此次使用的新描述文件与当前 Apple Silicon Mac、所给证书匹配，
证书自身到期时间早于描述文件，不能只依据描述文件有效期判断可分发期限。

`scripts/package-fixture.py` 能用合成凭据构建、解包并静态验收候选 PKG。
**它产生的是测试材料，不连接真实控制面，不用于生产推送。** 正式包通过受控渠道提供部署配置。

## 资源与长稳验收

`scripts/benchmark.py` 顺序运行旧 .NET SDK 宿主和已签名 Go 程序，在同一隔离环境测量
RSS、CPU、启动以及 1/8/32 并发的普通/SSE 请求。报告明确标明宿主差异和关闭控制面、
自动接管的测量边界；不能替代真实部署后的资源验收。

先构建 `cmd/soak-control`，再运行：

```sh
go build -o /path/to/soak-control ./cmd/soak-control
python3 scripts/soak.py --go /path/to/signed/executable \
  --control-helper /path/to/soak-control --output /path/to/report.json
```

默认运行 4 小时，使用临时 profile、加密模拟控制面、模拟网关和持久身份，覆盖并发
JSON/SSE、配置发现/接管/恢复、心跳与资产/事件、捕获压缩、保留清理及三次重启。
新请求头和捕获请求编号逐条关联；报告记录实际程序 SHA256、RSS/CPU/磁盘趋势。
`--hours` 较短时明确标为 smoke，绝不计为 4 小时通过。恢复用关闭自动接管后的认证
管理接口检查临时文件；管理员维护命令和真实系统服务安装仍须单独验收。

当前捕获使用 64 KiB 缓冲，响应缓冲池减少重复分配；摘要采用与旧版一致的写穿语义，
正文和配置仍执行完整磁盘同步。GZip 与旧版一致使用快速压缩。
并发完成回归检查摘要无交叉写入、无丢失，且引用的正文已经完整关闭。
性能隔离实验将主要开销定位于捕获路径；SQLite 和 GZip 并非本次主要瓶颈。
早前同机六场景曾满足 +5 ms，但最终冻结程序复测的普通请求超标；反转测量顺序后差距反转，
SSE 也出现轻微超标，延迟门禁尚未稳定达标。不能挑选通过的一次宣布正式替换完成。
历史 0.2.1 Apple Silicon 已完成含 3 次重启的 4 小时功能长稳；原生部署及延迟仍须验收。完整仓库中的实测记录见
[`GO-CLIENT-VERIFICATION.md`](../docs/GO-CLIENT-VERIFICATION.md)。

发布前还需完成 Windows、Intel Mac 原生验收、真实 IOA、正式签名/公证、覆盖升级/卸载
和目标平台 4 小时门禁；历史 0.2.1 ARM64 功能长稳已通过，0.2.2 r3 需重新验证。客户端运行与数据库必须保持单实例；回退先停 Go，再用原安装恢复流程
恢复 .NET，不能对仍在运行的服务强制执行 MSI 降级。

## DSH

0.2.1 新增受控 DSH 发现和接管，默认关闭。启用顺序、版本/地址限制、测试复现和回退要求见 [DSH 接入记录](../docs/DSH-INTEGRATION-20261017.md)。新开关关闭后仍保留恢复能力；不能直接回退旧 .NET 而跳过解除接管。

## 0.2.2 修复与覆盖升级

当前修复、标准覆盖/受控重装、状态保护和性能门禁见 [本轮验收](../docs/CLIENT-SERVER-022-024-20261018.md)。默认直接覆盖旧 C#，不是默认先卸载；安装提交前暂停接管与控制变更。Windows 原生、真实 Intel 和性能/四小时最终结果仍按报告区分。

2026-10-18 r3 已完成五轮 .NET +5 ms 与四小时功能门禁，见 [资源复核](../docs/CLIENT-PERFORMANCE-022-R3.md)。RSS 后段增长、独立日志预算及原生安装门禁继续待验，不能继承功能通过宣称全面发行通过。
