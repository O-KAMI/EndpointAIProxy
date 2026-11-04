# 服务端日志轮转

`logrotate.conf` 对应可选 `endpointai` systemd 部署的 `/var/log/endpointai/app.log`。
`logrotate-appdeploy.conf` 对应升级脚本的 `/app/EndpointAIDLP-Server-*/logs/app.log`、`console.log` 和 `appdeploy` 账户，两者不可替代或重复覆盖。模板不会自动安装；当前灰度实际安装情况见本文末尾。

部署前核对实际 `LOG_DIR`、版本目录、运行用户与主组；调整模板路径和 `su`/`create`，然后由管理员通过 `logrotate --debug <模板>` 检查配置与权限后接入既有调度。`maxsize` 仅在调度运行时检查，不是实时硬限制；应按磁盘预算选择调度频率。

`app.log` 使用 `WatchedFileHandler`，可以更名并创建新文件，不需停服。直接启动时的 `console.log` 是继承的文件描述符，模板采用 `copytruncate`，复制到截断之间有小量日志丢失窗口；不得把 console 当作唯一业务审计证据。若要求无此窗口，需要改为进程监管/journald 输出并完成部署验收；当前灰度已切换，旧版本仍保留此历史轮转规则。

模板覆盖保留版本目录，因此目录删除/归档策略也应单独管理；不删除回退版本或私有部署配置。

2026-11-04 授权灰度现场已改用普通账号的用户级服务：
`endpointai-gray.user.service.example`、`endpointai-gray-logrotate.user.service.example`、
`endpointai-gray-logrotate.user.timer.example` 和 `logrotate-gray-user.conf.example`。
这套配置使用现场核实的 `appdeploy:mwopr`，与旧模板的同名主组假设不同；已检查配置并
实际运行轮转任务成功。每小时检查 20 MiB 阈值，app 日志保留 14 份，历史 console 保留
7 份；阈值仍不是实时硬上限。新版服务 stdout/stderr 进入既有用户 journald，未更改
主机全局 journal 配额。`Linger=yes`、服务启用和受控重启已核实，实际主机重启未执行。
完整范围见[灰度验证](../docs/GRAY-LINUX-VALIDATION-20261104.md)。其他现场不要直接套用账号、组或路径。
