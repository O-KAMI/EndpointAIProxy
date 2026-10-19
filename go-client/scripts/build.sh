#!/bin/sh
set -eu
SCRIPT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULE_ROOT=$(CDPATH= cd -- "$SCRIPT_ROOT/.." && pwd)
REPO_ROOT=$(CDPATH= cd -- "$MODULE_ROOT/.." && pwd)
VERSION=${VERSION:-0.2.2}
GO=${GO:-go}
TARGETS=${TARGETS:-"windows-amd64 darwin-amd64 darwin-arm64"}
OUTPUT_ROOT=${OUTPUT_ROOT:-"$REPO_ROOT/artifacts/go-client/$VERSION"}
cd "$MODULE_ROOT"
for target in $TARGETS; do
  case "$target" in
    windows-amd64) target_os=windows; target_arch=amd64; ext=.exe ;;
    darwin-amd64) target_os=darwin; target_arch=amd64; ext= ;;
    darwin-arm64) target_os=darwin; target_arch=arm64; ext= ;;
    *) echo "Unsupported target: $target" >&2; exit 2 ;;
  esac
  out="$OUTPUT_ROOT/$target"
  mkdir -p "$out/service" "$out/installer-actions"
  CGO_ENABLED=0 GOOS=$target_os GOARCH=$target_arch "$GO" build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o "$out/service/Sf.EndpointAI.Client.Service$ext" ./cmd/endpointai
  if [ "$target_os" = windows ]; then
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 "$GO" build -trimpath -ldflags="-s -w -H=windowsgui -X main.version=$VERSION" -o "$out/installer-actions/Sf.EndpointAI.InstallerActions.exe" ./cmd/installer-actions
    cp "$REPO_ROOT/installer/Sf.EndpointAI.Setup/Collect-Diagnostics.cmd" "$out/service/Collect-Diagnostics.cmd"
    cp "$REPO_ROOT/installer/Sf.EndpointAI.Setup/Uninstall-EndpointAI.cmd" "$out/service/Uninstall-EndpointAI.cmd"
  fi
  echo "Candidate payload: $out"
done
