#!/bin/zsh
set -euo pipefail

CONFIG_FILE="/etc/sf-endpointai-proxy.conf"
if [[ -r "$CONFIG_FILE" ]]; then
  set -a
  source "$CONFIG_FILE"
  set +a
fi

export SF_PROXY_DATA_ROOT="${SF_PROXY_DATA_ROOT:-/Library/Application Support/SF/EndpointAIProxy}"
export DOTNET_BUNDLE_EXTRACT_BASE_DIR="${DOTNET_BUNDLE_EXTRACT_BASE_DIR:-$SF_PROXY_DATA_ROOT/.net}"

exec "/Library/Application Support/SF/EndpointAIProxy/bin/Sf.EndpointAI.Client.Service" \
  --auto-attach=true \
  --route-mode=FixedGateway \
  --gateway-origin=http://gateway.example.invalid \
  --allow-insecure-gateway=true
