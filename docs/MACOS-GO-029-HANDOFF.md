# macOS Go 0.2.9 构建与独立终端验收

本源码包不含客户端凭据、Apple 私钥或签名 PKG。需要在受控 Mac 构建机上使用
Go 1.27.x、Python 3、Xcode 命令行工具、受信任的 Developer ID Application 与
Installer 签名身份，以及已配置的 notarytool Keychain profile。构建及公证必须
对 arm64 和 x86_64 分别完成；交叉编译通过不能替代原生安装。

客户端凭据从受控渠道单独提供，不能写入源码包、PKG、聊天、公开目录或验收报告。
Apple 公证会上传整个 PKG；必须使用外部凭据模式构建不含真实凭据的包。
目前现网为旧 HMAC 协议；除非隔离服务已先完成公钥签名配置与兼容验证，不要擅自
把客户端输入切换到 `policyPublicKey`。新旧回退均应保留对应受保护的凭据和备份。

在解压后的源码根目录，先由构建用户准备仅自己可读写的临时目录、签名身份和真实
部署配置。以下变量均由操作者填写；`ARTIFACT_SUFFIX` 必须是此前未使用的值，
因为构建脚本会清理同名构建目录。不要复制执行占位值：

```zsh
export CLIENT_IMPLEMENTATION=go VERSION=0.2.9
unset CLIENT_CREDENTIALS_FILE
export EXTERNAL_CLIENT_CREDENTIALS=true
export APP_SIGN_IDENTITY='<Developer ID Application 身份>'
export INSTALLER_SIGN_IDENTITY='<Developer ID Installer 身份>'
export ARTIFACT_SUFFIX='-candidate-unique' # 换成此前未使用的英文编号
export ARCH=arm64   # 在另一轮改为 x86_64；候选编号也应不同
./installer/macos/Build-Pkg.sh
./installer/macos/Notarize-Pkg.sh '<本轮生成的 PKG 路径>' '<notarytool Keychain profile>'
```

候选编号只允许英文字母、数字和连字符。公证及 stapling 会改变 PKG；最终摘要须在
公证完成后计算，不能沿用公证前的摘要。接着用构建机上的受保护临时目录检查**最终包**：

```zsh
python3 installer/macos/tests/validate_go_pkg.py \
  --package '<公证后的 PKG 路径>' \
  --architecture "$ARCH" --version "$VERSION" --private-scratch '<现有的 0700 私有目录>'
```

该脚本检查签名、公证票据、Gatekeeper、包身份、架构、脚本、不含凭据、载荷和
所有权，不安装软件。它在当前工作区尚未进行 macOS 原生执行，需记录命令结果与
最终包 SHA-256；失败时保留现场，不能据源码或交叉编译标记通过。构建包时，
`python3 installer/macos/tests/test_installer.py` 还可在符合脚本要求的隔离临时目录中
运行安装脚本模拟测试；它不会替代真实安装。

将已签名、公证且摘要核对一致的包通过授权受控渠道交给独立验收终端管理员，在
Apple Silicon 与 Intel 各自执行：干净首装、旧版覆盖升级、重启、卸载和原配置恢复，
并检查多用户权限、真实对话、代理路径、SSE、断网缓存与恢复后的同步。确认目标
终端与测试数据均获准后，再使用系统 Installer 或 IOA 安装；保留安装退出码、
服务状态及控制端回执。用户已有配置和旧安装不得为伪造干净首装而删除。

安装之前，终端管理员在该终端通过受控渠道取得客户端凭据，校验格式，并将其放在
`/private/etc/sf-endpointai-client-credentials.json`，所有者为 root、权限 0600、
不能是符号链接或硬链接；安装脚本会在受保护的安装会话中制作快照。该本地文件
不进入 PKG 或公证上传。安装成功后按组织规定处理临时凭据；后续修复或重装前需
重新提供，禁止为了重试而清理客户端身份或覆盖用户更新的配置。

回传包 SHA-256、macOS 版本与架构、签名和公证检查结果、各阶段结果、脱敏请求关联
和失败码；不要回传 PKG、凭据、API Key、原始请求正文或未经审查的安装日志。
未获得两架构原生证据、实际签名及公证前，Mac 推广门禁保持未通过。
当前长稳门禁为 8 小时；历史版本的 4 小时结果不代表本候选通过。

本候选支持在固定服务器证书公钥的 HTTPS 上承载既有加密协议；现有 HTTP 凭据仍可用。HTTPS 尚未在现网启用或验证。切换地址或证书固定值会改变设备身份绑定，必须先在隔离环境验证受控凭据恢复和回退，不能删除状态或批量重新注册来掩盖问题。不要在未完成入口、证书与恢复验证时修改生产地址。
