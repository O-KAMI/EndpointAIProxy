# 服务端日志轮转

`logrotate.conf` 对应可选 `endpointai` systemd 部署的 `/var/log/endpointai/app.log`。
`logrotate-appdeploy.conf` 对应升级脚本的 `/app/EndpointAIDLP-Server-*/logs/app.log`、`console.log` 和 `appdeploy` 账户，两者不可替代或重复覆盖。模板不会自动安装，本次未改变现场配置。

部署前核对实际 `LOG_DIR`、版本目录、运行用户与主组；调整模板路径和 `su`/`create`，然后由管理员通过 `logrotate --debug <模板>` 检查配置与权限后接入既有调度。`maxsize` 仅在调度运行时检查，不是实时硬限制；应按磁盘预算选择调度频率。

`app.log` 使用 `WatchedFileHandler`，可以更名并创建新文件，不需停服。`console.log` 是启动时继承的文件描述符，模板采用 `copytruncate`，复制到截断之间有小量日志丢失窗口；不得把 console 当作唯一业务审计证据。若要求无此窗口，需要单独改为进程监管/journald 输出并完成部署验收，本次没有切换生产生命周期。

模板覆盖保留版本目录，因此目录删除/归档策略也应单独管理；不删除回退版本或私有部署配置。
