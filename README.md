# EndpointAIProxy

EndpointAIProxy is a .NET client and control-plane prototype for routing supported AI agent traffic through a local endpoint proxy. It includes the client core, Windows service, macOS service scripts, control server, installer definitions, and tests.

Production addresses, credentials, certificates, and private deployment bundles are intentionally excluded from this public source tree. Configure the control origin, gateway origin, enrollment material, and signing keys through your private deployment process. Example values use the reserved `example.invalid` domain.

Build with the .NET SDK version selected by `global.json`. Windows MSI and macOS package workflows require their native build environments. Do not commit credentials, private certificates, captured request bodies, generated artifacts, or installer packages containing private configuration.

Client installer version: **0.1.22**. macOS packages include protected stage logs, local service readiness checks, upgrade rollback, and standalone diagnostic/recovery tools. See [macOS deployment](docs/README-MACOS-0.1.22.md) and [verification boundaries](docs/MACOS-ACCEPTANCE-0.1.22.md).

The production Python/MySQL control server source is maintained in [`server/`](server/README.md). Its 0.1.22 console provides policy management, asset management, and terminal analytics. The ASP.NET Core/SQLite control server in `src/` remains a separate prototype; choose the matching deployment workflow. See [Python console analytics](server/docs/CONSOLE_ANALYTICS.md) and [Python upgrade procedure](deployment/README-SERVER-UPGRADE-0.1.22.md). Offline wheels and generated release archives are supplied separately.

For Windows allowlist troubleshooting, run the [one-click diagnostic collector](docs/README-WHITELIST-DIAGNOSTICS.md) with administrator privileges. It combines the client's sanitized diagnostic bundle with read-only cached-policy inspection and live policy-version checks.

The unsigned Apple Silicon package failed an actual IOA root installation: macOS rejected the ad hoc-signed executable, then the postinstall readiness check failed and removed the new service. IOA's reported distribution success did not establish installation success. Developer ID application/package signing, notarization, and native deployment verification remain required before rollout. This repository contains source and placeholders only; supply deployment credentials privately.
