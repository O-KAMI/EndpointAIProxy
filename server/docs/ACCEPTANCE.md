# 0.1.20 本地验收记录

完整服务端测试：**96 passed，0 failed，0 skipped，8.06 秒**。
机器为 macOS arm64；Python 3.13.15、隔离 MySQL 8.4.10（127.0.0.1:13306）、.NET SDK 10.0.101。
JUnit 原始结果位于交付目录 `server/artifacts/acceptance-tests.xml`，不包含在源码 ZIP 内。

## 已验证

- 0.1.19 基线业务：策略版本与白名单、注册与 Token 轮换、v1/v2 心跳、设备资产、事件去重、远程命令生命周期与审计。
- MySQL 事务回滚、连接断开恢复、备份保留、完整恢复、备份写入失败清理和进程回收。
- 旧业务处理器测试通过仅测试可设置的 Python 对象标记访问内部边界；HTTP 请求无法伪造该对象。
  新加密测试与真实 HTTP 测试不使用该标记，验证外部直接访问旧客户端接口被拒绝。
- Python/.NET 双向 AES-256-GCM：空值、中文与 emoji、1.5 MB 大正文、响应请求 ID 绑定、原始策略正文 HMAC。
- 密钥错误、密文/标签/元信息篡改、过期报文、明文绕过、防重放记录唯一索引缺失时拒绝启动。
- 8 个并发调用及真实 Gunicorn 多工作进程并发中，相同报文只成功一次，其余拒绝；服务重启后仍拒绝旧报文。
- 发现并修复过期记录清理的 MySQL 间隙锁死锁：防重放事务使用 READ COMMITTED 和有限死锁重试。
  并发防重放专项在修复后另行连续执行 5 次，全部通过。
- .NET 客户端拒绝 7 种非法 HTTP/密文情况，区分未认证的外层 401 与解密认证后的设备 401。
- `python app.py` 实际启动两个 Gunicorn gthread 工作进程，以真实 HTTP 完成 .NET 注册、策略验签、心跳、事件、
  启用/停用命令领取与签名验证、Executing/Succeeded 回执；这些回执是模拟执行，不代表真实终端已启停。
- 实际 HTTP 请求/响应字节检查：客户端外层不带认证头，业务路径和 Token 在密文内，响应业务正文不可直接读出。
  这是 HTTP 报文检查，没有生成网络抓包 pcap 文件。
- 0.1.19 数据库增量升级前后逐表比较业务记录，注册 Token 仍能认证，重复运行幂等；首次初始化拒绝覆盖非空未知业务表。
- 公开源码打包规则排除 MySQL 实际配置、密钥和运行产物，正式密钥文件权限为 600，客户端凭据不含管理员 Token。

## 客户端构建与交付边界

- Windows x64 自包含发布成功，输出 PE32+ x86-64；MSI 构建和配置脚本已更新，需在 Windows 执行。
- macOS arm64、x86_64 自包含发布及两种 PKG 构建成功；脚本语法与 LaunchDaemon plist 检查通过。
- PKG 未签名、未公证；Windows MSI 尚未在本机生成，Windows PowerShell 脚本未在真实 Windows 执行。
- 未在开发机安装客户端、启动真实挂载或修改真实 Agent 用户配置。
- 本机验证的是 Gunicorn 在 macOS 上的 HTTP 行为；不冒充已完成 Linux systemd、timer、logrotate 验收。

## 复现

在 `server/` 使用 Python 3.13.15 安装 `requirements-dev.txt`。准备只监听本机的隔离 MySQL（默认 13306、root 无密码，
仅适用于这套本地测试），每个测试使用随机 `eai_test_*` 数据库并在结束后删除。

```sh
dotnet build tests/dotnet/Interop.csproj -p:OriginalRoot=/absolute/path/to/EndpointAIDLP-0.1.20/client -o artifacts/interop
ENDPOINTAI_TEST_MYSQL=1 \
ENDPOINTAI_TEST_MYSQL_BIN=/absolute/path/to/mysql/bin \
ENDPOINTAI_TEST_DOTNET=/absolute/path/to/dotnet \
ENDPOINTAI_TEST_INTEROP=/absolute/path/to/server/artifacts/interop/Interop.dll \
python -m pytest -q --junitxml=artifacts/acceptance-tests.xml
```

`OriginalRoot` 是保留的测试参数名，在 0.1.20 测试中必须指向本次修改后的 `client/`，不是原型目录。
没有对应外部工具时相关测试会跳过；上述本次完整运行没有跳过。

## 上生产前待验收

1. Linux Python 3.13.15、数据库权限与连通性、TCP 8080 网段访问控制。
2. `app.py` 前台启动、systemd 开机恢复、备份定时器执行与 logrotate。
3. Windows MSI 构建/安装、macOS PKG 原生安装，两平台导入独立凭据后注册与心跳。
4. 覆盖升级保持设备数据及 Agent 配置，真实远程停用、恢复和重启后状态一致。
5. 普通浏览器管理页面登录、策略编辑、命令创建提示框、历史与审计；本次只自动验证 HTTP/API 与原有页面资源。
6. 长稳和业务负载、密钥轮换操作、数据库备份恢复及版本回退演练。

管理页面为用户选择的内网明文 HTTP；客户端 AES 不保护管理员 Token 或页面完整性。
共享密钥不能隔离客户端之间的身份，设备 Token 与策略/命令签名仍保留。
