# EndpointAIDLP Server 0.1.22

生产 Python 3.13.15 + MySQL 控制服务，保持 HTTP 8080 和 AES-256-GCM 客户端通信。控制台拆成默认数据分析、策略管理、资产管理；新增管理员只读分析和分页下钻接口。保留策略版本冲突检查、网关编辑、终端详情、远程操作及审计。

本版不修改数据库结构、客户端协议或凭证，不新增请求采集、逐请求日志和历史趋势。现有加密客户端继续使用，无须重新安装。

使用同级交付目录的 EndpointAIDLP-Server-0.1.22-update.zip、update-server-0.1.22.py 和 SHA256SUMS-SERVER-0.1.22.txt。具体命令见同级 README-SERVER-UPGRADE-0.1.22.md。

脚本适用于 appdeploy 账户以 start.py 启动、未由 systemd 托管的现有 /app/EndpointAIDLP-Server-0.1.20 或 0.1.21，新版安装到 /app/EndpointAIDLP-Server-0.1.22。支持 Linux x86_64 / aarch64 离线依赖。准备失败不停止旧服务；切换失败尝试恢复旧服务；保留原目录，持久化回退来源，不配置开机自启动。

app.py 是 Gunicorn 入口；start.py 加载私有 launch-env.json。start.py --check 只检查配置和现有数据库。本次不要执行 init-db、migrate-db 或生成新凭证。

统计口径见 [CONSOLE_ANALYTICS.md](docs/CONSOLE_ANALYTICS.md)，本版验证记录见 [ACCEPTANCE-0.1.22.md](docs/ACCEPTANCE-0.1.22.md)。Linux 真实服务器的切换仍须按现场结果验收。
