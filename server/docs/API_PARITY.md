# 0.1.19 服务端迁移对应清单

对照基准为原版 EndpointAIDLPMVP，Git 提交 `2e2679b15859bfc715636c68604b3fa9a237d344`。原版源码保持不变。实现采用 Python/MySQL，外部 HTTPS 由 Nginx 承接。此清单描述实现对应关系，实际验证范围与未完成项见 [验收记录](ACCEPTANCE.md)。

## HTTP 接口

原版入口为 `src/Sf.EndpointAI.ControlServer/Program.cs`。Python 蓝图由 `app.create_app` 注册，管理员蓝图前缀为 `/admin/v1`。UUID 路径参数沿用设备与命令身份边界。

| 方法和路径 | Python 实现 | 对应能力 |
| --- | --- | --- |
| GET `/`、`/console` | `controlserver/console.py`、`templates/console.html` | 跳转及原版管理页面 |
| GET `/health/live`、`/health/ready` | `routes_health.py` | 存活、数据库和备份状态 |
| GET `/api/v1/policy` | `routes_client.py` | 旧版客户端策略与原始响应签名 |
| POST `/api/v1/heartbeat` | 同上 | 旧版设备心跳 |
| POST `/api/v1/events/batch` | 同上 | 旧版事件批量上报 |
| POST `/api/v2/enroll` | 同上 | 注册、设备凭据发放和更新 |
| POST `/api/v2/heartbeat` | 同上 | 设备身份认证、完整快照、命令领取 |
| GET `/api/v2/devices/{deviceId}/policy` | 同上 | 设备范围内策略下发 |
| POST `/api/v2/events/batch` | 同上 | 设备范围内事件去重入库 |
| POST `/api/v2/commands/{commandId}/status` | 同上 | 设备命令状态回报 |
| GET、PUT `/admin/v1/policy` | `routes_admin.py` | 策略读取、验证及版本冲突检测 |
| GET `/admin/v1/devices` | 同上 | 设备列表、过滤与分页 |
| GET `/admin/v1/dashboard` | 同上 | 设备和端点统计 |
| GET `/admin/v1/devices/{deviceId}` | 同上 | 设备、Agent、端点及活动详情 |
| GET、POST `/admin/v1/devices/{deviceId}/commands` | 同上 | 命令历史及启用/停用命令创建 |
| POST `/admin/v1/commands/{commandId}/cancel` | 同上 | 命令取消 |
| GET `/admin/v1/audit` | 同上 | 管理员操作审计 |

另外保留 `/health` 作为存活检查别名。

## 协议、状态和存储

| 原版要求 | 实现位置及行为 | 自动化证据 |
| --- | --- | --- |
| 共享请求、响应及枚举 | `models.py` 对应原版 Contracts；输出 camelCase，接收原版字段及枚举形式 | `test_contracts.py`、`test_dotnet_vectors.py` |
| 策略签名 | `security.py` 对实际响应字节计算 HMAC，保留 v1 签名形式 | 原版 .NET 固定向量、真实 HTTPS 客户端验签 |
| 命令签名 | 独立派生命令密钥、固定字段顺序及时间表示 | .NET 向量及原版通信类接收签名命令 |
| 设备身份 | 存储设备 Token 哈希，校验请求中的设备身份；不依赖额外 X-Device-Id 头 | 跨设备访问拒绝、凭据轮换测试 |
| 策略规则 | `validation.py` 保留默认网关、CCR 精确 Base URL 白名单、去重、长度和版本规则 | .NET URL 规范化向量、并发策略更新测试 |
| 心跳快照 | `database.py` 在同一事务更新设备、Agent、运行状态、端点和活动 | 快照替换、重复资产回滚、断连恢复 |
| 活动时间 | 新启动状态未观察到请求时保留此前实际观察记录，同时更新新启动计数 | 资产与活动测试 |
| 设备统计 | 保留原版 Agent 过滤和端点去重规则 | MySQL 资产与 HTTP 流程测试；真实终端待验收 |
| 事件幂等 | 事件唯一约束、重复事件不重复计入 | v1/v2 事件测试 |
| 远程命令 | 设备行锁协调创建、领取和取消；执行中命令不因过期丢失；终态不可回退 | 并发、租约恢复、取消、过期、终态测试 |
| 管理界面 | 从原版 ControlConsolePage.Html 提取页面 | 页面内容检查及浏览器部分交互，范围见验收记录 |

MySQL 的 11 张表为 `schema_migrations`、`control_policy`、`device_credentials`、`device_heartbeats`、`agent_inventory`、`device_runtime`、`agent_endpoint_assets`、`proxy_activity`、`endpoint_events`、`remote_commands`、`admin_audit_log`。采用 InnoDB、utf8mb4、JSON、DATETIME(6) 和必要索引；建表唯一来源为 `conf/endpoint_ai_proxy.sql`。策略版本和结构校验信息持久化，不依赖单进程内存。

## 部署方式变更

- 原版服务端运行时替换为 Python 3.13.15、Flask、Gunicorn；业务存储替换为 MySQL。
- Nginx 对外提供 HTTPS；PRD 应用监听回环地址，只信任回环反向代理设置的转发信息。生产控制接口拒绝未标明 HTTPS 的访问。
- 建表改为显式维护命令。应用启动只检查结构；空旧表重建前检查所有项目表，无关表保留，发现项目数据拒绝重建。MySQL DDL 并非可整体回滚，因此必须在停止所有服务实例后执行。
- 备份由独立 systemd 作业运行，24 小时一次，保留 7 份成功归档；使用原生 mysqldump、gzip 和 SHA-256 校验。恢复到明确指定的空库。
- 自签名生产证书在目标服务器生成，RSA 3072、IP SAN、默认 365 天。发布包不含私钥或真实凭据。客户端固定公钥和浏览器证书信任分别配置。
- `Set-ProductionClientControl.ps1` 提供 Windows 客户端配置辅助，支持预览和失败回滚。原版客户端代码、模型网关及本地模型代理逻辑不改动；真实服务操作必须在隔离终端执行。

## 验证边界

接口存在和测试通过不能证明所有可能输入的行为完全等价。例如 MySQL/Python 时间精度为微秒，不能据此承诺保留 .NET 所有 100 纳秒时间位。实际生产时间、数据规模、公司 MySQL 版本与权限、Linux 运行权限、浏览器和真实终端仍按验收清单验证。发现影响原版功能的差异后修复并补充有针对性的用例，不以本清单替代环境验收。
# 0.1.20 传输层变更

下文业务对照以 0.1.19 为基线；0.1.20 保留业务契约，但外部客户端必须通过
`POST /api/transport/v1` 进行 AES-256-GCM 双向加密。旧 `/api/v1/`、`/api/v2/`
仅用于解密后的内部路由，外部直接调用返回 403。管理页面/API 按用户选择使用明文 HTTP。
旧 HTTPS、Nginx、证书验收描述不适用于 0.1.20；当前结果见 `ACCEPTANCE.md`。
