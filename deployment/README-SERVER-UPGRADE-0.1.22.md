# 生产 Python 服务端升级到 0.1.22

本次更新控制台与分析接口，保持 MySQL、策略、HTTP 8080、管理员 Token、客户端 Token、AES 和 HMAC 密钥。客户端无需更新，没有数据库结构迁移。

## 上传文件

以下四个文件上传到服务器 appdeploy 用户主目录（~），保持名称不变：

- EndpointAIDLP-Server-0.1.22-update.zip：离线升级包，含两种 Linux 架构依赖及逐文件 manifest。
- update-server-0.1.22.py：备份、配置继承、升级和回退脚本。
- SHA256SUMS-SERVER-0.1.22.txt：校验 ZIP、脚本及本说明。
- README-SERVER-UPGRADE-0.1.22.md：本说明。

单独的 .sha256 文件供独立校验；源码 ZIP 供查阅，不代替离线升级包。包内无生产凭证，无须上传旧配置、数据库、客户端安装包或 .NET 服务端程序。

## 执行步骤

以当前运行服务的 appdeploy 账户登录：

```bash
cd ~
sha256sum -c SHA256SUMS-SERVER-0.1.22.txt
```

三个文件全部显示 OK 后继续，校验失败先重新上传。使用已有虚拟环境的 Python：

```bash
upgrade_python=/app/EndpointAIDLP-Server-0.1.21/.venv/bin/python
if [ ! -x "$upgrade_python" ]; then
  upgrade_python=/app/EndpointAIDLP-Server-0.1.20/.venv/bin/python
fi
"$upgrade_python" "$HOME/update-server-0.1.22.py" --action status
```

应显示一个旧版本运行中、0.1.22 未运行。确认 /app 可写且空间足够，先备份：

```bash
command -v mysqldump
"$upgrade_python" "$HOME/update-server-0.1.22.py" --action backup
```

备份成功会输出路径；数据库压缩备份、conf 和 launch-env.json 位于旧目录 upgrade-backups/<UTC时间>/。备份包含敏感配置，仅限管理员保管。缺少 mysqldump 或备份失败先处理原因，不执行下一步。

执行升级：

```bash
"$upgrade_python" "$HOME/update-server-0.1.22.py"
```

脚本自动识别唯一运行的 0.1.20/0.1.21，在 /app/EndpointAIDLP-Server-0.1.22 解压、校验、继承配置、建立虚拟环境并离线安装依赖。准备期间旧服务继续运行，检查通过后正常切换并检查健康、策略、资产、分析和下钻接口。成功应输出“更新成功”。

不能唯一识别来源时，确认真实目录后明确指定，例如：

```bash
"$upgrade_python" "$HOME/update-server-0.1.22.py" --old-dir /app/EndpointAIDLP-Server-0.1.21 --action status
"$upgrade_python" "$HOME/update-server-0.1.22.py" --old-dir /app/EndpointAIDLP-Server-0.1.21 --action backup
"$upgrade_python" "$HOME/update-server-0.1.22.py" --old-dir /app/EndpointAIDLP-Server-0.1.21
```

不要先手动停止旧服务。systemd 托管时脚本拒绝切换且不停止进程；须由管理员确认实际单元，按托管流程升级，不能通过杀进程绕过。默认流程适用于 Python 3.13.15、Linux x86_64/aarch64、8080端口和上述目录。升级不运行 init-db、migrate-db 或 secrets，不配置开机自启动。

## 升级后验收

```bash
/app/EndpointAIDLP-Server-0.1.22/.venv/bin/python "$HOME/update-server-0.1.22.py" --action status
curl --fail --silent --show-error http://127.0.0.1:8080/health/ready
```

应显示旧版未运行、新版运行中且健康成功。打开 http://10.220.22.112:8080/console，强制刷新，用原管理员 Token 登录：

1. 默认进入数据分析，点击数字可下钻且数量和分页一致。
2. 资产列表、详情正常，等待至少两次原有心跳确认持续上报。
3. 策略版本、白名单和网关保持原值，不为验收修改生产网关。
4. 验证策略下发或远程启停时使用专用测试终端，检查回报版本及命令状态。

日志在新版目录 console.log 和 logs/app.log；分享前脱敏。保持原自启动安排，脚本不会新增 systemd 服务。

## 失败及回退

准备失败时旧服务继续运行，新目录保留诊断；目标目录存在时脚本拒绝覆盖，不要盲目重复升级或删除旧目录。切换失败会尝试恢复旧服务，仍须检查 status 与健康接口确认现场结果。

回退命令：

```bash
/app/EndpointAIDLP-Server-0.1.22/.venv/bin/python "$HOME/update-server-0.1.22.py" --action rollback
/app/EndpointAIDLP-Server-0.1.22/.venv/bin/python "$HOME/update-server-0.1.22.py" --action status
curl --fail --silent --show-error http://127.0.0.1:8080/health/ready
```

新版虚拟环境尚未建立时，用上述 "$upgrade_python" 执行 rollback/status。回退保留当前数据库，不恢复旧快照或抹掉升级期间的新数据。不要删除原服务目录或 /app/.EndpointAIDLP-Server-0.1.22-upgrade.json 来源记录。
