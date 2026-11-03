# 域名白名单、地址分流与用户身份（2026-10-28 工作树扩展）

状态：源码已实现；本机隔离验证结果见文末。未部署生产控制端，未发布新的客户端安装包。
数据库仍为 schema 3；策略正文 schema 2 与数据库 schema 版本是两个独立概念。

## 匹配与转发

使用接管前原始 Base URL 的 hostname，规范化大小写、IDNA 和末尾点号。
`openai.com` 匹配自身与子域名，不匹配 `fakeopenai.com`、`openai.com.evil.com` 或 URL 路径。
域名规则不限制协议、端口、路径；IPv4/IPv6 仅精确匹配 IP。

执行顺序为白名单绕过代理 → 最具体域名路由 → 默认路由。
白名单恢复 Agent 的原始地址；转发至原始目标仍经过本机代理并保留原有审计和捕获。
规则网关失败不自动改为原始目标。新策略只影响新请求，不重新创建既有流式请求。

策略新增：

```json
{
  "allowlistedDomains": ["trusted.example.com"],
  "routingRules": [
    {"domain": "openai.com", "routeMode": "passthroughOriginal", "gatewayOrigin": null},
    {"domain": "anthropic.com", "routeMode": "fixedGateway", "gatewayOrigin": "https://gateway-b.example.com"}
  ]
}
```

`routeMode`、`gatewayOrigin`、`allowInsecureGateway` 继续表示默认路由及 HTTP 网关许可。
规则网关省略、null 或空字符串表示沿用默认网关；原始目标规则不能指定网关。
域名白名单和路由规则分别最多 256 条；路由域名规范化后不得重复。
校验默认配置和每条规则的最终有效网关，包括默认模式为原始目标时的网关规则。
请求目标与网关元数据使用同一策略快照，原始路径、查询参数及请求体保持现有转发约定。

## 协商、版本和迁移

Go 在现有 `/api/v2/devices/{deviceId}/policy` 查询中追加 `policySchemaVersion=2`。
参数在 AES-GCM 信封的 query 内传输，不改变信封结构或原始响应正文验签规则。
无参数仍返回 schema 1，去掉域名规则、分流规则和转换记录，保留原来的精确 URL 白名单及单一路由。
旧 .NET 不修改；旧 Go、.NET 不支持新规则，控制台显示需升级。

首次协商 schema 2 时，在既有全局锁 → 终端锁顺序下分配更高的终端有效版本，保存至
`device_policy_state.effective_policy_json` 并记录能力协商审计。重复请求或多 worker 并发只分配一次。
全局更新、终端覆盖和撤销覆盖均保留单调版本水位。恢复继承不将 schema 2 终端降回 schema 1。

旧 `allowlistedBaseUrls` 按需自动转换为 `allowlistedDomains`，包括全局配置和已有单终端覆盖；
去掉协议、端口和路径后去重。旧精确列表保留供 schema 1 客户端使用。
完整策略通过 `allowlistMigration` 返回原 URL → 域名记录，控制台提供展开查看。
转换是幂等的 JSON 升级：首次读取即可取得转换结果，有效策略和管理员写入沿既有事务持久化，
不新增表、不执行 DDL、不修改凭据或重新注册终端。转换会放宽原路径、端口限制。

心跳新增 `runtime.supportedPolicySchemaVersion` 与 `policy.appliedSchemaVersion`。
未上报默认为 1，旧心跳序列化向量保持原样；应用统计同时检查实际版本与 schema 能力。
分析按各终端合并后的策略匹配域名，并按命中规则汇总白名单覆盖。

## 单终端编辑与工号

既有 `/admin/v1/devices/{deviceId}/policy` GET/PUT/DELETE 扩展新字段，仍以 `expectedVersion` 做 CAS。
覆盖列表整体替换；省略字段继承全局；空数组表示清空此终端的列表。
保留 `allowlistedBaseUrls` 供旧管理接口使用，旧 URL 写入会同步转换域名。

进入详情自动加载策略；覆盖默认路由、白名单和域名规则分别控制编辑状态。
切换终端清空上一终端表单，使用请求修订号丢弃迟到响应；自动刷新只更新应用状态，不覆盖草稿。
409 或保存失败保留草稿。已保存与终端已应用分别显示，校准失败保留错误状态。

资产摘要新增 `employeeIds`，从既有最新心跳的 `users[].accountName` 提取并去重。
保留前导零、去掉 SF 域前缀，排除 SID 回退、空值和系统账户；不假定工号仅能包含数字。
没有可用值显示“未识别”；离线值仅表示最后上报身份，不推断当前登录人或资产所有人。
无需新增客户端身份采集或数据库列。

## 发布与验证

先部署兼容控制端，再升级 Go 客户端并试点；不将旧客户端的版本回执视为已支持域名分流。
新增运行依赖 `idna==3.11` 已锁定。Linux 离线发布前须将该 wheel 连同全部既有锁定依赖准备到
`deployment/wheelhouse/{x86_64,aarch64}`，并通过既有 `offline_wheels()` 完整性检查。
本轮不生成离线发布包、不运行 MSI、不修改现网策略。

策略回退使用更高版本恢复既有配置，不能降低版本、清库或删除终端水位。
新客户端缓存含 schema 2；不得直接覆盖为只识别 schema 1 的旧二进制。
Linux 多 worker、原生服务升级/重启、SYSTEM/root 权限和 Mac 隔离终端仍须在发布前验收。

本轮本机验证（Windows，Go 1.27.3，独立 MySQL 8.0.28，仅监听 loopback）：

- Go `test ./...`、`vet ./...` 通过；新增域名、选路、缓存不可变性、低版本拒绝及隔离配置恢复回归。Mac arm64、amd64 交叉构建通过，不代表 Mac 原生运行验收。
- 最终 Python 控制面回归 135 项通过、14 项跳过、1 项排除；策略专项另行运行 44 项通过。跳过中包含单独执行的 3 项可选浏览器用例，其余平台/环境限制不计通过。运行命令见下。
- 浏览器 3 项通过，覆盖工号列、自动加载、单终端保存/重载/恢复继承、409 草稿保留、全局规则、移动视口及迟到响应跨终端隔离。
- 旧 .NET 心跳/签名向量、真实 MySQL 事务及并发版本分配、AES-GCM schema 协商通过。
- Windows 无法导入 Linux 备份模块 `fcntl`，不将相关测试、Gunicorn 真实多 worker 及离线发布检查计为通过。

```powershell
# 使用已安装依赖的隔离 Python，MySQL 测试库由 fixture 随机创建并清理。
$env:ENDPOINTAI_TEST_MYSQL = "1"
python -m pytest -q --ignore=tests/test_contracts.py --ignore=tests/test_maintenance.py --ignore=tests/test_release.py -k "not test_app_py_real_http_original_client_workflow_and_restart" --basetemp <独立测试临时目录>
# 可选浏览器回归：安装 Playwright，并指定已安装的测试浏览器或准备其 Chromium。
$env:ENDPOINTAI_TEST_BROWSER = "1"
python -m pytest -q tests/test_domain_console_browser.py --basetemp <另一独立测试临时目录>
```

本机 SDK/虚拟环境是测试工具，不替换生产 Python 3.13.15 与正式客户端载荷。
