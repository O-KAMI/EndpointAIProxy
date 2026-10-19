# Windows Go 0.2.2 源码交付与 IOA 验证

此包包含 Go 客户端和 Windows 安装辅助程序源码、锁定依赖 vendor、一键 MSI 构建与校验材料。
它不包含真实部署凭据、证书或旧 .NET 运行时。解压后保持目录结构，不能单独移动 WiX 项目。
包内 Windows 原生安装结果在实际运行前均为待验；编译或 MSI 静态校验通过不能代表 IOA 已通过。

## 当前验证状态（2026-10-18）

当前交付为 `EndpointAIProxy-Go-Windows-0.2.2-20261018-r3-verified-source.zip`。源码与已冻结 r3 相同，新增完成后的验收证据及项目地图更新；旧 ZIP 保留。

r3 已通过本机五轮 .NET +5 ms 延迟门禁和四小时功能长稳（14,419.34 秒、23,040 请求、3 次重启），Go race/vet、三架构构建及 37 项隔离安装脚本测试通过。具体边界见 [本轮记录](CLIENT-SERVER-022-024-20261018.md) 和 [资源复核](CLIENT-PERFORMANCE-022-R3.md)。RSS 后段增长尚未解释，新增诊断独立预算仍待测；Windows PowerShell 5.1、原生 MSI、SYSTEM、IOA 覆盖升级和恢复仍必须在 Windows 验收。

DSH 默认关闭；先部署兼容 0.1.24 控制端并验证网关接受，再启用。源码 ZIP 不含真实凭据、证书或 .NET 运行时。当前用于构建和隔离安装验证，尚不能认定全面达到正式替换条件。地图中的服务端、旧 .NET、Mac 源码入口可能仅在完整仓库可用。

## 构建

构建机需要 Windows x64、Windows PowerShell 5.1、Go 1.27.x（最低 1.27.0）和 .NET 10 SDK。
`global.json` 从 10.0.100 起允许同一主/次版本的 feature band；不接受 preview SDK。
WiX SDK 与 Util 扩展固定 6.0.2，由首次构建的 NuGet restore 获取；无需单独安装 WiX CLI。
Go 依赖从包内 vendor 使用，不需要 Bash、Python、C 编译器。脚本不会自动下载或安装 SDK。
.NET SDK 只用于构建 MSI，不进入终端载荷。

双击根 `Build-MSI.cmd`，按提示输入外部 `client-credentials.json` 的完整路径；或使用：

```powershell
.\scripts\Build-MSI.ps1 -CredentialsFile C:\Secure\client-credentials.json -OutputDirectory C:\Secure\EndpointAIProxy-Go
```

凭据沿用 `origin/clientToken/policyHmacKey/transportKey/keyId` 五字段，须从受控渠道取得；
不要将真实文件复制进源码目录、聊天或代码库。`origin` 为当前 AES 加密控制协议使用的 HTTP origin，
不能带用户信息、业务路径、查询或片段。输入验证只输出错误类型，不输出字段值。

默认构建 `EndpointAIDLP-Client-0.2.2-go-win-x64.msi`，执行 Go 测试、静态分析、GUI helper、
MSI 身份和事务序列及仅含 Go 载荷的校验。输出包括 MSI、SHA256、manifest、校验报告和日志工具，
保存在仅构建用户、SYSTEM 与管理员可读的目录。临时凭据和含凭据 CAB 在结束时清理。
输出 MSI 不覆盖已有同名候选；再次构建请选择新目录。整个构建过程不安装程序或修改服务。

未提供签名参数时包明确标记为 `unsigned-test-candidate`，是否允许通过 IOA 推送取决于环境策略。
如需签名，使用构建用户证书库 `CurrentUser\My` 中已有代码签名证书：

```powershell
.\scripts\Build-MSI.ps1 -CredentialsFile C:\Secure\client-credentials.json -OutputDirectory C:\Secure\SignedCandidate `
  -SigningCertificateThumbprint YOUR_CERTIFICATE_THUMBPRINT `
  -SignToolPath 'C:\Program Files (x86)\Windows Kits\10\bin\VERSION\x64\signtool.exe' `
  -TimestampUrl https://YOUR_APPROVED_TIMESTAMP_SERVICE
```

三个签名参数须同时提供。服务和 helper 在入 CAB 前签名，MSI 构建后再签名及验证，然后计算 SHA256。
证书不导出、不写进源码包；签名失败会中止构建，不降级输出未签名包。

## Windows 本地检查与 IOA

默认测试仅使用临时合成配置和 DPAPI fixture，不执行安装/卸载：

```powershell
.\scripts\Test-Windows.ps1 -MsiFile C:\Secure\EndpointAIDLP-Client-0.2.2-go-win-x64.msi
```

DPAPI 检查通过 PowerShell 5.1 的 .NET `ProtectedData` 与 Go 实际 protector 双向互读，
沿用 `LocalMachine` 和原 entropy。它不访问已安装客户端数据库。fixture helper 不进入 MSI。
已有客户端占用 18080 时，相关隔离服务测试会跳过，不停止现有客户端。

安装由 IOA 在隔离终端执行；原有 UpgradeCode、服务名 `SfEndpointAIProxy`、18080 和数据目录保留。
Go 客户端向网关发送工号头 `x-sf-userid` 与由客户端生成的 `x-request-id`；HMAC 签名值及字段顺序不变，
其他头保持兼容。网关已有“优先新工号头、回退旧工号头”的源码改动，但尚未部署；
IOA 联调前必须部署该兼容网关，避免工号在联调中丢失。源码 ZIP 不包含整个网关仓库。
先验证 SHA256，再采用：

```text
.\Upgrade-Client.cmd -MsiFile C:\Secure\EndpointAIDLP-Client-0.2.2-go-win-x64.msi
```

退出码 0 为成功；3010 表示成功但需重启。其余退出码视为失败，并收集受保护诊断。
只有明确选择 `-MachineAction Install` 或 `Uninstall`，测试脚本才操作本机 MSI；需要管理员或 IOA 身份。
显式安装及 4 小时健康/资源采样示例：

```powershell
.\scripts\Test-Windows.ps1 -MsiFile C:\Secure\EndpointAIDLP-Client-0.2.2-go-win-x64.msi `
  -MachineAction Install -DurationHours 4
```

测试报告记录实际动作、DPAPI结果、采样时长和重启要求。小于 4 小时不能记为长稳通过。
4 小时期间还应覆盖发现、心跳、原厂/网关切换、并发请求、SSE 取消、捕获及日志清理；
健康采样不能单独证明这些业务项。通过 IOA 取得的业务/部署结果需补入验收记录。

完整验收至少覆盖首装、.NET 0.1.22 升 Go、重复安装、注入失败后的原版恢复、重启自动运行、
卸载解除配置接管；验证设备 ID、route ID、凭据、策略与命令回执保留，普通用户配置 ACL 不变。
控制面离线、配置并发修改、CC Switch 占用及用户后续修改也必须覆盖。并发性能门禁尚未通过时，
候选包只用于隔离验证，不据此替换正式客户端。

## 日志与回退

管理员执行输出目录中的 `Collect-InstallerLogs.ps1` 收集脱敏 MSI 动作、安装阶段和服务状态。
原始 MSI 日志、真实凭据和事务快照不能上传；测试脚本的 `native-msi-private.log` 只留在受保护目录。
报告中的“通过”必须与其列出的已运行检查对应，不能将交叉编译当作真实 SYSTEM 或 IOA 验收。

回退前先停止 Go 服务，保留受保护状态和配置备份，再按已有恢复流程卸载 Go、重新安装保留的
.NET 0.1.22 包；MajorUpgrade 阻止直接降级覆盖。卸载会解除仍属于客户端的配置接管，用户后续修改
应被保留。出现解除失败时先修复/收集证据，不强行删除状态目录。升级失败自动回滚也必须真实验收。

## 材料边界

源码 ZIP 仅按白名单包含 Go 源码/测试、vendor、WiX、PowerShell/CMD、根构建配置和此说明。
不包含生产配置、P12/PFX/私钥/描述文件、状态数据库、机器密钥、日志、捕获、Git 历史或服务端源码。
vendor 中 modernc SQLite 的公开 `embed.db/embed2.db` 测试资源是此规则的明确例外，不含终端状态。
根 `source-manifest.json` 记录除清单自身外所有交付文件的 SHA256，`THIRD-PARTY-LICENSES.txt` 指向 vendor 内许可证。
源码 ZIP 和 MSI 都应作为受控交付物保存；MSI 含部署凭据，不能公开分发。

历史 0.2.1 交付：2026-10-18 更新交付包为 `EndpointAIProxy-Go-Windows-0.2.1-20261018-source.zip`，程序版本仍为 0.2.1；此次仅更新验收文档和附带结果，不改客户端程序。

## 0.2.2 安装入口

新源码包包含 `Upgrade-Client.cmd` 与 `scripts/Upgrade-Client.ps1`；Windows 构建输出也带一键工具及 MigrationHelper.exe/SHA256。默认直接覆盖，显式 Reinstall 才会正常卸载旧产品，要求匹配的旧 MSI 恢复材料；一般错误不转卸载。安装验证读取实际 MSI 版本；同包修复用 /fa，同版异 ProductCode 在 MSI 本体拒绝。完整命令、3010 恢复及状态保护边界见本轮记录。

原 r3 源码交付为 `EndpointAIProxy-Go-Windows-0.2.2-20261018-r3-source.zip`，包含确定性 SSE 截断回归及 full-duplex 修复。首个无 r3 后缀的 0.2.2 包为修复前归档，不用于后续构建。随包 `client-validation-022-20261018-r3.json` 区分源码/隔离通过与原生/性能/长稳待验。

当前优先使用带 `r3-verified` 后缀的包；随包 `client-validation-022-20261018-r3-verified.json` 与性能、四小时结果区分已通过和待验。程序源码相同，此次不修改二进制或重新声明原生验收通过。
