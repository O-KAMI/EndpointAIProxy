# Windows 0.2.5 规模优化候选（尚未放行）

2026-10-29 在构建机生成未签名 x64 MSI r3，未在本机或其他终端安装。受保护输出位于
`private/releases/0.2.5-scale-candidate-20261029-r3`；含生产客户端配置的 MSI 仅可在
授权范围内交付，不应上传或提交 Git。先前 0.2.5 候选和历史 0.2.4-r3 保持不变。
r3 包含公钥验签能力，包内控制配置仍使用现网兼容的旧 HMAC 模式；未经隔离验证不得
直接切换生产签名模式。独立验收整包及说明见 `private/releases/EndpointAIProxy-Go-Windows-0.2.5-acceptance-20261029-r3.zip` 和
[验收步骤](WINDOWS-GO-025-HANDOFF.md)。整包 SHA-256 为
`45c8cf6b4b8ce5667ef343105914969c317981da3214bfb4569f41e3b34cecf3`。

本次 MSI SHA-256：`e9971e1fcbe12fe8fb232a605ea7b0dde7ac736e69c9b8ecc130f9a2a99af229`。
构建清单记录了脏工作树、源码输入摘要和载荷摘要，不能把 Git HEAD 当成完整源码。
构建时 Go 全量测试和 vet 通过，WiX 构建及 MSI 元数据、事务序列、Go 载荷静态检查通过；
Windows Authenticode 状态为 NotSigned，符合本次不签名要求。交付目录中的
`ACCEPTANCE-PENDING.md` 绑定当前包摘要，避免沿用旧版验收说明。
r3 用无安装模式通过了合成数据的 LocalMachine DPAPI 在 .NET 与 Go 间双向互读及
MSI 静态检查；未修改系统服务、未运行 8 小时长稳。

该包仅供受控验收：Windows 10/11 原生安装、旧版本升级、重启、回滚、卸载、
跨用户权限、真实业务与 SSE、IOA 安装及检测均未完成。须对实际交付包再次核对
上述摘要；后续源码变化或重新构建得到的包需要重新记录摘要并重新验收。
控制端 8 小时长稳和 15 万存量、10 万在线容量测试也尚未完成；不据此声明放行。
