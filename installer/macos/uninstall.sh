#!/bin/zsh
set -euo pipefail

if [[ "$EUID" -ne 0 ]]; then
  echo "Run with sudo: sudo /usr/local/share/sf-endpointai-proxy/uninstall.sh" >&2
  exit 5
fi

SERVICE="/Library/Application Support/SF/EndpointAIProxy/bin/Sf.EndpointAI.Client.Service"
if [[ -x "$SERVICE" ]]; then
  "$SERVICE" --maintenance=detach-all --auto-attach=false || true
fi

/bin/launchctl bootout system/com.sf.endpointai.proxy >/dev/null 2>&1 || true
/bin/rm -f "/Library/LaunchDaemons/com.sf.endpointai.proxy.plist"
/bin/rm -f "/usr/local/sbin/sf-endpointai-diagnostics"
/bin/rm -f "/usr/local/sbin/sf-endpointai-installer-logs" "/usr/local/sbin/sf-endpointai-installer-recover"
/bin/rm -rf "/usr/local/share/sf-endpointai-proxy"

echo "Service files removed. Data and /etc/sf-endpointai-proxy.conf were retained."
echo "After review, remove data manually if required: /Library/Application Support/SF/EndpointAIProxy"
