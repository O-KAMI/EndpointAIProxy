# 生产 Python 服务端升级到 0.1.24

0.1.24 增加 Go 客户端 DSH 心跳、资产和控制台兼容，并修复相同命令完成回执重试被拒绝的问题。升级保持现有 MySQL 数据、策略、HTTP 8080、管理员 Token、客户端 Token、AES 和 HMAC 密钥；旧 .NET/Go 客户端继续兼容，没有数据库结构迁移；DSH 客户端应在本次升级及网关兼容验收后再开启接管。

## 上传文件

将交付包解压目录内的全部文件上传到生产服务器 `appdeploy` 用户主目录，保持文件名不变；校验清单也包含构建清单、验收记录与测试脚本，不能只复制升级 ZIP。主要入口为：

- `EndpointAIDLP-Server-0.1.24-update.zip`
- `update-server-0.1.24.py`
- `README-SERVER-UPGRADE-0.1.24.md`
- `SHA256SUMS-SERVER-0.1.24.txt`

包内不含生产凭证。无需上传旧配置、数据库文件或客户端安装包。

## 校验和升级

使用当前运行服务的 `appdeploy` 账户执行：

```bash
cd "$HOME"
sha256sum -c SHA256SUMS-SERVER-0.1.24.txt

upgrade_python=/app/EndpointAIDLP-Server-0.1.23/.venv/bin/python
if [ ! -x "$upgrade_python" ]; then
  upgrade_python=/app/EndpointAIDLP-Server-0.1.22/.venv/bin/python
fi
if [ ! -x "$upgrade_python" ]; then
  upgrade_python=/app/EndpointAIDLP-Server-0.1.21/.venv/bin/python
fi

"$upgrade_python" "$HOME/update-server-0.1.24.py" --action status
```

状态应显示 0.1.23/0.1.22/0.1.21 中唯一旧版本运行中、0.1.24 未运行。数据库备份为可选步骤；本次升级不修改数据库结构或已有数据。服务器已安装 `mysqldump` 且需要额外备份时执行：

```bash
command -v mysqldump
"$upgrade_python" "$HOME/update-server-0.1.24.py" --action backup
```

没有 `mysqldump` 可以跳过备份，直接升级：

```bash
"$upgrade_python" "$HOME/update-server-0.1.24.py"
```

脚本在 `/app/EndpointAIDLP-Server-0.1.24` 准备源码和离线依赖。准备期间旧服务继续运行；准备检查全部通过后才切换，并验证健康、策略、资产、分析和下钻接口。不要提前停止旧服务。

无法唯一识别旧服务时，明确指定实际目录：

```bash
"$upgrade_python" "$HOME/update-server-0.1.24.py" \
  --old-dir /app/EndpointAIDLP-Server-0.1.22 --action status

"$upgrade_python" "$HOME/update-server-0.1.24.py" \
  --old-dir /app/EndpointAIDLP-Server-0.1.22
```

脚本仅支持 Linux x86_64/aarch64、Python 3.13.15、8080 端口和同一 `appdeploy` 账户管理的进程。检测到应用由 systemd 服务单元托管时会在停止进程前退出。

## 升级后验收

```bash
/app/EndpointAIDLP-Server-0.1.24/.venv/bin/python \
  "$HOME/update-server-0.1.24.py" --action status

curl --fail --silent --show-error \
  http://127.0.0.1:8080/health/ready
```

打开 `http://10.220.22.112:8080/console` 并强制刷新，然后检查：

1. 页面版本为 0.1.24，原有 Claude/Codex 资产、策略与远程操作正常；开启 DSH 后，DSH 独立显示，三种 wire API 不被误判为 Codex。
2. 图表名称为“LLM 当前目标服务分布”。
3. 两个内部白名单域名显示为“白名单目标”。
4. “当前代理请求异常”只显示仍启用、仍走代理且本次运行最近请求失败的终端。
5. 策略版本、白名单、连接网关、资产和远程操作记录保持原值。
6. 等待至少两次原有心跳，确认终端持续上报和恢复后的异常自动清除。完成回执响应丢失后的相同重试仍应被接受，冲突结果保持 409。

日志位于 `/app/EndpointAIDLP-Server-0.1.24/console.log` 和 `logs/app.log`。

## 失败和回退

准备失败时旧服务继续运行。切换失败时脚本会尝试恢复旧服务。目标目录已经存在时脚本拒绝覆盖，应先检查状态和日志，不要直接删除目录后重试。

回退命令：

```bash
/app/EndpointAIDLP-Server-0.1.24/.venv/bin/python \
  "$HOME/update-server-0.1.24.py" --action rollback

/app/EndpointAIDLP-Server-0.1.24/.venv/bin/python \
  "$HOME/update-server-0.1.24.py" --action status

curl --fail --silent --show-error \
  http://127.0.0.1:8080/health/ready
```

回退只切换运行目录，不恢复数据库快照，也不会删除升级期间收到的终端数据。保留原服务目录和 `/app/.EndpointAIDLP-Server-0.1.24-upgrade.json`，用于识别回退来源。

## DSH 与回退边界

先升级控制端，再验证外部模型网关接受 `DeepSeekHarness` 及 Files 查询参数，最后在安装成功的 Go 0.2.1 客户端受控服务配置中开启 DSH。控制台目前不远程设置 `SF_PROXY_ENABLE_DSH`。

回退到不识别 DSH 的控制端之前，先在客户端停用 DSH 上报/接管并验证心跳；回退旧 .NET 客户端前必须由新 Go 成功解除 DSH 配置。不要重新注册设备或生成新凭据来规避兼容问题。

本交付包含 `BUILD-MANIFEST.json`、锁定双架构运行依赖和 `ACCEPTANCE-0.1.24.md`。可选的 `test_update_024.py` 为部署逻辑隔离回归；执行它需要 pytest，不会启动或切换真实服务。发布工具位于完整仓库 `server/tools/package_delivery.py`，每次输出至新目录。
