# 生产 Python 服务端升级到 0.1.23

0.1.23 修复当前目标服务分类和异常状态长期挂红问题。升级保持现有 MySQL 数据、策略、HTTP 8080、管理员 Token、客户端 Token、AES 和 HMAC 密钥；客户端无需更新，没有数据库结构迁移。

## 上传文件

将以下四个文件上传到生产服务器 `appdeploy` 用户主目录，保持文件名不变：

- `EndpointAIDLP-Server-0.1.23-update.zip`
- `update-server-0.1.23.py`
- `README-SERVER-UPGRADE-0.1.23.md`
- `SHA256SUMS-SERVER-0.1.23.txt`

包内不含生产凭证。无需上传旧配置、数据库文件或客户端安装包。

## 校验和升级

使用当前运行服务的 `appdeploy` 账户执行：

```bash
cd "$HOME"
sha256sum -c SHA256SUMS-SERVER-0.1.23.txt

upgrade_python=/app/EndpointAIDLP-Server-0.1.22/.venv/bin/python
if [ ! -x "$upgrade_python" ]; then
  upgrade_python=/app/EndpointAIDLP-Server-0.1.21/.venv/bin/python
fi

"$upgrade_python" "$HOME/update-server-0.1.23.py" --action status
```

状态应显示旧版本运行中、0.1.23 未运行。数据库备份为可选步骤；本次升级不修改数据库结构或已有数据。服务器已安装 `mysqldump` 且需要额外备份时执行：

```bash
command -v mysqldump
"$upgrade_python" "$HOME/update-server-0.1.23.py" --action backup
```

没有 `mysqldump` 可以跳过备份，直接升级：

```bash
"$upgrade_python" "$HOME/update-server-0.1.23.py"
```

脚本在 `/app/EndpointAIDLP-Server-0.1.23` 准备源码和离线依赖。准备期间旧服务继续运行；准备检查全部通过后才切换，并验证健康、策略、资产、分析和下钻接口。不要提前停止旧服务。

无法唯一识别旧服务时，明确指定实际目录：

```bash
"$upgrade_python" "$HOME/update-server-0.1.23.py" \
  --old-dir /app/EndpointAIDLP-Server-0.1.22 --action status

"$upgrade_python" "$HOME/update-server-0.1.23.py" \
  --old-dir /app/EndpointAIDLP-Server-0.1.22
```

脚本仅支持 Linux x86_64/aarch64、Python 3.13.15、8080 端口和同一 `appdeploy` 账户管理的进程。检测到应用由 systemd 服务单元托管时会在停止进程前退出。

## 升级后验收

```bash
/app/EndpointAIDLP-Server-0.1.23/.venv/bin/python \
  "$HOME/update-server-0.1.23.py" --action status

curl --fail --silent --show-error \
  http://127.0.0.1:8080/health/ready
```

打开 `http://10.220.22.112:8080/console` 并强制刷新，然后检查：

1. 页面版本为 0.1.23，不再出现“已观测代理请求/当前配置”切换。
2. 图表名称为“LLM 当前目标服务分布”。
3. 两个内部白名单域名显示为“白名单目标”。
4. “当前代理请求异常”只显示仍启用、仍走代理且本次运行最近请求失败的终端。
5. 策略版本、白名单、连接网关、资产和远程操作记录保持原值。
6. 等待至少两次原有心跳，确认终端持续上报和恢复后的异常自动清除。

日志位于 `/app/EndpointAIDLP-Server-0.1.23/console.log` 和 `logs/app.log`。

## 失败和回退

准备失败时旧服务继续运行。切换失败时脚本会尝试恢复旧服务。目标目录已经存在时脚本拒绝覆盖，应先检查状态和日志，不要直接删除目录后重试。

回退命令：

```bash
/app/EndpointAIDLP-Server-0.1.23/.venv/bin/python \
  "$HOME/update-server-0.1.23.py" --action rollback

/app/EndpointAIDLP-Server-0.1.23/.venv/bin/python \
  "$HOME/update-server-0.1.23.py" --action status

curl --fail --silent --show-error \
  http://127.0.0.1:8080/health/ready
```

回退只切换运行目录，不恢复数据库快照，也不会删除升级期间收到的终端数据。保留原服务目录和 `/app/.EndpointAIDLP-Server-0.1.23-upgrade.json`，用于识别回退来源。
