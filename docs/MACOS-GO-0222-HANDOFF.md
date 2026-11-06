# macOS Go 0.2.22 构建与验收

源码包含 vendored 依赖，不含真实凭据、Apple 私钥或签名 PKG。Windows 交叉编译不等于
Mac 原生验收。两种架构分别构建、签名、公证及验收，保留 0.2.21 历史材料。

构建机要求 Go 1.27.x、Python 3.9+、Xcode 命令行工具及 Developer ID Application/Installer。
使用外部凭据模式，避免将生产客户端凭据上传 Apple 公证。以下身份及路径由操作者填写：

```zsh
export CLIENT_IMPLEMENTATION=go VERSION=0.2.22
unset CLIENT_CREDENTIALS_FILE
export EXTERNAL_CLIENT_CREDENTIALS=true
export APP_SIGN_IDENTITY='<Developer ID Application 身份>'
export INSTALLER_SIGN_IDENTITY='<Developer ID Installer 身份>'
export ARTIFACT_SUFFIX='-0222-unique' # 每轮改为此前未用的编号
export ARCH=arm64 # 另一轮改为 x86_64，并使用新的编号
./installer/macos/Build-Pkg.sh
./installer/macos/Notarize-Pkg.sh '<本轮 PKG>' '<notarytool Keychain profile>'
python3 installer/macos/tests/validate_go_pkg.py --package '<公证后的 PKG>' --architecture "$ARCH" --version "$VERSION" --private-scratch '<现有 0700 私有目录>'
```

最终 SHA-256 必须在公证及 stapling 后计算。安装前通过受控渠道把客户端凭据放入
`/private/etc/sf-endpointai-client-credentials.json`，root 所有、0600，不能是链接；不回传凭据。
默认网关为 `http://network-dlp-aigw.sf-express.com:80`，显式允许 HTTP，有效策略缓存优先。
不修改现有 HTTP 控制地址/身份，也不启用可选 schema 6 或传输迁移。

Apple Silicon/Intel 均执行首装、旧版升级、重启、卸载、配置恢复、多用户权限、真实对话、SSE、
断网缓存与恢复同步。控制流程及 DSH 已知阻断按
[0.2.22 复测清单](CLIENT-0222-ADDITIONAL-ACCEPTANCE.md)执行，未执行项记 BLOCKED。

原生业务八小时期间，另开受限终端采集完整目录增长（此工具只读，不判定业务通过）：

```zsh
sudo python3 go-client/scripts/observe_resources.py --data-root '/Library/Application Support/SF/EndpointAIProxy' --output '<数据根外的新 resources.jsonl>' --package-sha256 '<最终公证 PKG SHA-256>' --hours 8
```

每分钟最多两秒元数据扫描，继续未完成的扫描，不读正文、不跟随链接；不完整数值为 null。
记录进程 RSS/CPU/线程、服务 PID、控制同步、事件队列、业务轮次与错误的独立时间线；目录工具
不能替代这些观测。包摘要字段由测试人员提供，须与最终 PKG 自行核对。

独立合成长稳在没有真实服务占用 18080 的授权环境执行，绑定最终包内服务：

```zsh
cd go-client
go build -mod=vendor -o '<私有输出目录>/soak-control' ./cmd/soak-control
python3 scripts/soak.py --go '<最终包内服务>' --control-helper '<私有输出目录>/soak-control' --hours 8 --sample-seconds 10 --restarts 3 --output '<新 soak-report.json>'
```

先用独立路径短测，再执行八小时。回传格式、附件清单与脱敏要求见复测清单；签名、公证、
两架构原生业务和八小时观察须全部绑定各自最终包，不能使用历史包结论替代。
