#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VERSION="${VERSION:-0.1.19}"
ARCH="${ARCH:-$(uname -m)}"

case "$ARCH" in
  arm64) RID="osx-arm64" ;;
  x86_64) RID="osx-x64" ;;
  *) echo "Unsupported macOS architecture: $ARCH" >&2; exit 2 ;;
esac

ARTIFACT_ROOT="$REPO_ROOT/artifacts/macos/$RID"
PUBLISH_DIR="$ARTIFACT_ROOT/publish"
PACKAGE_ROOT="$ARTIFACT_ROOT/package-root"
PACKAGE_SCRIPTS="$ARTIFACT_ROOT/package-scripts"
OUTPUT_PKG="$ARTIFACT_ROOT/Sf.EndpointAI.Proxy.macOS.$VERSION.$RID.pkg"
APP_ROOT="$PACKAGE_ROOT/Library/Application Support/SF/EndpointAIProxy"
SHARE_ROOT="$PACKAGE_ROOT/usr/local/share/sf-endpointai-proxy"

case "$ARTIFACT_ROOT" in
  "$REPO_ROOT"/artifacts/macos/*) ;;
  *) echo "Refusing to clean unexpected artifact path: $ARTIFACT_ROOT" >&2; exit 3 ;;
esac

rm -rf "$ARTIFACT_ROOT"
mkdir -p "$PUBLISH_DIR" "$APP_ROOT/bin" "$SHARE_ROOT" \
  "$PACKAGE_ROOT/Library/LaunchDaemons" "$PACKAGE_ROOT/usr/local/sbin" "$PACKAGE_SCRIPTS"

dotnet restore "$REPO_ROOT/src/Sf.EndpointAI.Client.Service/Sf.EndpointAI.Client.Service.csproj" \
  --runtime "$RID" --force-evaluate
dotnet publish "$REPO_ROOT/src/Sf.EndpointAI.Client.Service/Sf.EndpointAI.Client.Service.csproj" \
  --configuration Release --runtime "$RID" --self-contained true --no-restore \
  --output "$PUBLISH_DIR" -p:Version="$VERSION" -p:PublishSingleFile=false \
  -p:DebugType=None -p:DebugSymbols=false

/bin/cp -R "$PUBLISH_DIR/." "$APP_ROOT/bin/"
/bin/chmod 0755 "$APP_ROOT/bin/Sf.EndpointAI.Client.Service"
install -m 0755 "$SCRIPT_DIR/run-service.sh" "$APP_ROOT/bin/run-service.sh"
install -m 0644 "$SCRIPT_DIR/com.sf.endpointai.proxy.plist" \
  "$PACKAGE_ROOT/Library/LaunchDaemons/com.sf.endpointai.proxy.plist"
install -m 0755 "$SCRIPT_DIR/sf-endpointai-diagnostics" \
  "$PACKAGE_ROOT/usr/local/sbin/sf-endpointai-diagnostics"
install -m 0755 "$SCRIPT_DIR/uninstall.sh" "$SHARE_ROOT/uninstall.sh"
install -m 0600 "$SCRIPT_DIR/sf-endpointai-proxy.conf.example" "$SHARE_ROOT/sf-endpointai-proxy.conf.example"
install -m 0755 "$SCRIPT_DIR/preinstall" "$PACKAGE_SCRIPTS/preinstall"
install -m 0755 "$SCRIPT_DIR/postinstall" "$PACKAGE_SCRIPTS/postinstall"

if [[ -n "${APP_SIGN_IDENTITY:-}" ]]; then
  while IFS= read -r -d '' FILE; do
    if [[ "$FILE" != "$APP_ROOT/bin/Sf.EndpointAI.Client.Service" ]] \
      && /usr/bin/file "$FILE" | /usr/bin/grep -q 'Mach-O'; then
      /usr/bin/codesign --force --timestamp --sign "$APP_SIGN_IDENTITY" "$FILE"
    fi
  done < <(/usr/bin/find "$APP_ROOT/bin" -type f -print0)
  /usr/bin/codesign --force --timestamp --options runtime \
    --sign "$APP_SIGN_IDENTITY" "$APP_ROOT/bin/Sf.EndpointAI.Client.Service"
  /usr/bin/codesign --verify --strict --verbose=2 "$APP_ROOT/bin/Sf.EndpointAI.Client.Service"
fi

PKGBUILD_ARGS=(
  --root "$PACKAGE_ROOT"
  --scripts "$PACKAGE_SCRIPTS"
  --identifier "com.sf.endpointai.proxy"
  --version "$VERSION"
  --install-location "/"
)
if [[ -n "${INSTALLER_SIGN_IDENTITY:-}" ]]; then
  PKGBUILD_ARGS+=(--sign "$INSTALLER_SIGN_IDENTITY")
fi

/usr/bin/pkgbuild "${PKGBUILD_ARGS[@]}" "$OUTPUT_PKG"
/usr/sbin/pkgutil --check-signature "$OUTPUT_PKG" || true
/usr/bin/shasum -a 256 "$OUTPUT_PKG" | tee "$OUTPUT_PKG.sha256"
echo "PKG created: $OUTPUT_PKG"
