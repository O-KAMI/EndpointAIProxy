# EndpointAIProxy

项目入口：[项目地图](CONTEXT.md) · [当前交付结果](docs/OPTIMIZATION-CURRENT-RESULT.md) · [逐项完成度与未通过门禁](docs/OPTIMIZATION-COMPLETION-AUDIT-20261103.md)。文档于 2026-11-04 同步；最近一轮本机验证为 2026-11-03。

Go client candidate **0.2.21 r2** is available in [`go-client/`](go-client/README.md).
The [earlier feature matrix](docs/GO-CLIENT-PARITY.md) records the migration baseline; current acceptance boundaries are in the current delivery result above. The .NET 0.1.22 build and
rollback path remain available. DSH support is opt-in; see [integration and acceptance boundaries](docs/DSH-INTEGRATION-20261017.md). Candidate builds do not establish production rollout acceptance.

EndpointAIProxy routes supported AI agent traffic through a local endpoint proxy. It includes a shared Go Windows/macOS client, Python/MySQL control server, installer definitions, and tests. The older .NET client and ASP.NET control-plane prototype remain separate compatibility materials.

Production addresses, credentials, certificates, and private deployment bundles are intentionally excluded from this public source tree. Configure the control origin, gateway origin, enrollment material, and signing keys through your private deployment process. Example values use the reserved `example.invalid` domain.

Build with the .NET SDK version selected by `global.json`. Windows MSI and macOS package workflows require their native build environments. Do not commit credentials, private certificates, captured request bodies, generated artifacts, or installer packages containing private configuration.

Current client acceptance materials: **0.2.21 r2**. See [Windows handoff](docs/WINDOWS-GO-0221-HANDOFF.md), [Mac handoff](docs/MACOS-GO-0221-HANDOFF.md), and [additional acceptance](docs/CLIENT-0221-ADDITIONAL-ACCEPTANCE.md). Windows is intentionally unsigned. Native Windows/IOA and Mac signing, notarization, installation and eight-hour soak results remain pending. The .NET 0.1.22 [deployment](docs/README-MACOS-0.1.22.md) and [verification](docs/MACOS-ACCEPTANCE-0.1.22.md) documents describe the historical fallback.

The Python/MySQL control server source is maintained in [`server/`](server/README.md). The current isolated source candidate is **0.1.26 r77**, with schema 5 by default and optional schema 6 for device credential rotation. The last recorded production baseline is 0.1.25/schema 3; this closeout did not inspect or change production. The candidate includes local administrator roles, policy and command batches, database pagination and monitoring support. Formal update packaging remains gated on isolated Linux upgrade and rollback acceptance. Offline wheels and generated release archives are supplied separately.

For Windows allowlist troubleshooting, run the [one-click diagnostic collector](docs/README-WHITELIST-DIAGNOSTICS.md) with administrator privileges. It combines the client's sanitized diagnostic bundle with read-only cached-policy inspection and live policy-version checks.

The unsigned Apple Silicon package failed an actual IOA root installation: macOS rejected the ad hoc-signed executable, then the postinstall readiness check failed and removed the new service. IOA's reported distribution success did not establish installation success. Developer ID application/package signing, notarization, and native deployment verification remain required before rollout. This repository contains source and placeholders only; supply deployment credentials privately.

15 万安装、10 万在线及 120 秒策略/启停收敛仍未验收；宽泛实时搜索也保留性能缺口。缺少隔离 Linux 环境及独立终端回传，不能把候选代码、本机测试或交叉编译表述为推广通过。Go 0.2.2 / Python 0.1.24 的[实施记录](docs/CLIENT-SERVER-022-024-20261018.md)仅供历史追溯，旧材料继续保留。
