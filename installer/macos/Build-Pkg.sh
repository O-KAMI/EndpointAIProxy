#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CLIENT_IMPLEMENTATION="${CLIENT_IMPLEMENTATION:-dotnet}"
case "$CLIENT_IMPLEMENTATION" in
  dotnet) VERSION="${VERSION:-0.1.22}"; [[ "$VERSION" == 0.1.22 ]] || { echo 'The .NET installer supports version 0.1.22 only.' >&2; exit 2; } ;;
  go) VERSION="${VERSION:-0.2.2}" ;;
  *) echo 'CLIENT_IMPLEMENTATION must be dotnet or go.' >&2; exit 2 ;;
esac
[[ "$VERSION" =~ '^[0-9]+\.[0-9]+\.[0-9]+$' ]] || { echo 'Invalid package version.' >&2; exit 2; }
export COPYFILE_DISABLE=1
umask 077
[[ -n "${CLIENT_CREDENTIALS_FILE:-}" && -f "$CLIENT_CREDENTIALS_FILE" ]] || { echo "Set CLIENT_CREDENTIALS_FILE to private client credentials." >&2; exit 2; }
if [[ "$CLIENT_IMPLEMENTATION" == go ]]; then
  python3 "$REPO_ROOT/go-client/scripts/validate_credentials.py" "$CLIENT_CREDENTIALS_FILE"
else
  python3 "$SCRIPT_DIR/Validate-ClientCredentials.py" "$CLIENT_CREDENTIALS_FILE"
fi
ARCH="${ARCH:-$(uname -m)}"
DOTNET="${DOTNET:-dotnet}"

case "$ARCH" in
  arm64) RID="osx-arm64" ;;
  x86_64) RID="osx-x64" ;;
  *) echo "Unsupported macOS architecture: $ARCH" >&2; exit 2 ;;
esac

ARTIFACT_SUFFIX="${ARTIFACT_SUFFIX:-}"
[[ "$ARTIFACT_SUFFIX" =~ '^[a-zA-Z0-9-]*$' ]] || { echo "Invalid artifact suffix." >&2; exit 2; }
ARTIFACT_ROOT="$REPO_ROOT/artifacts/macos/$RID"
if [[ "$CLIENT_IMPLEMENTATION" == go ]]; then
  ARTIFACT_ROOT="$REPO_ROOT/artifacts/macos/go-$VERSION$ARTIFACT_SUFFIX/$RID"
fi
PUBLISH_DIR="$ARTIFACT_ROOT/publish"
PACKAGE_ROOT="$ARTIFACT_ROOT/package-root"
PACKAGE_SCRIPTS="$ARTIFACT_ROOT/package-scripts"
OUTPUT_PKG="$ARTIFACT_ROOT/EndpointAIDLP-Client-$VERSION-$RID.pkg"
APP_ROOT="$PACKAGE_ROOT/Library/Application Support/SF/EndpointAIProxy"
SHARE_ROOT="$PACKAGE_ROOT/usr/local/share/sf-endpointai-proxy"
if [[ -n "${DEVELOPMENT_APP_BUNDLE:-}" ]]; then
  [[ "$CLIENT_IMPLEMENTATION" == go && -d "$DEVELOPMENT_APP_BUNDLE/Contents" && -f "$DEVELOPMENT_APP_BUNDLE/Contents/embedded.provisionprofile" ]] || { echo 'A Go development app with an embedded profile is required.' >&2; exit 2; }
  [[ -z "${APP_SIGN_IDENTITY:-}" ]] || { echo 'The development app is already signed; do not re-sign it as a standalone payload.' >&2; exit 2; }
  /usr/bin/codesign --verify --deep --strict "$DEVELOPMENT_APP_BUNDLE"
  [[ "$(/usr/bin/plutil -extract CFBundleIdentifier raw -o - "$DEVELOPMENT_APP_BUNDLE/Contents/Info.plist")" == com.sf.endpointai.proxy ]] || exit 2
  [[ "$(/usr/bin/plutil -extract CFBundleShortVersionString raw -o - "$DEVELOPMENT_APP_BUNDLE/Contents/Info.plist")" == "$VERSION" ]] || exit 2
  /usr/bin/file "$DEVELOPMENT_APP_BUNDLE/Contents/MacOS/Sf.EndpointAI.Client.Service" | /usr/bin/grep -q "$ARCH" || { echo 'Development app architecture mismatch.' >&2; exit 2; }
  ARTIFACT_ROOT="$REPO_ROOT/artifacts/macos/go-development-$VERSION$ARTIFACT_SUFFIX/$RID"
  PUBLISH_DIR="$ARTIFACT_ROOT/publish"
  PACKAGE_ROOT="$ARTIFACT_ROOT/package-root"
  PACKAGE_SCRIPTS="$ARTIFACT_ROOT/package-scripts"
  OUTPUT_PKG="$ARTIFACT_ROOT/EndpointAIDLP-Client-$VERSION-development-$RID.pkg"
  APP_ROOT="$PACKAGE_ROOT/Library/Application Support/SF/EndpointAIProxy"
  SHARE_ROOT="$PACKAGE_ROOT/usr/local/share/sf-endpointai-proxy"
fi

case "$ARTIFACT_ROOT" in
  "$REPO_ROOT"/artifacts/macos/*) ;;
  *) echo "Refusing to clean unexpected artifact path: $ARTIFACT_ROOT" >&2; exit 3 ;;
esac

rm -rf "$ARTIFACT_ROOT"
mkdir -p "$PUBLISH_DIR" "$APP_ROOT/bin" "$SHARE_ROOT" \
  "$PACKAGE_ROOT/Library/LaunchDaemons" "$PACKAGE_ROOT/usr/local/sbin" "$PACKAGE_SCRIPTS"

if [[ -n "${DEVELOPMENT_APP_BUNDLE:-}" ]]; then
  /bin/cp -R "$DEVELOPMENT_APP_BUNDLE" "$PUBLISH_DIR/EndpointAIProxy.app"
  /usr/bin/printf '%s\n' '#!/bin/zsh' 'exec "/Library/Application Support/SF/EndpointAIProxy/bin/EndpointAIProxy.app/Contents/MacOS/Sf.EndpointAI.Client.Service" "$@"' > "$PUBLISH_DIR/Sf.EndpointAI.Client.Service"
elif [[ "$CLIENT_IMPLEMENTATION" == go ]]; then
  GO_ARCH=amd64
  [[ "$ARCH" == arm64 ]] && GO_ARCH=arm64
  VERSION="$VERSION" TARGETS="darwin-$GO_ARCH" /bin/sh "$REPO_ROOT/go-client/scripts/build.sh"
  /bin/cp "$REPO_ROOT/artifacts/go-client/$VERSION/darwin-$GO_ARCH/service/Sf.EndpointAI.Client.Service" "$PUBLISH_DIR/"
else
"$DOTNET" restore "$REPO_ROOT/src/Sf.EndpointAI.Client.Service/Sf.EndpointAI.Client.Service.csproj" \
  --runtime "$RID" --force-evaluate -p:NuGetAudit=false
"$DOTNET" publish "$REPO_ROOT/src/Sf.EndpointAI.Client.Service/Sf.EndpointAI.Client.Service.csproj" \
  --configuration Release --runtime "$RID" --self-contained true --no-restore \
  --output "$PUBLISH_DIR" -p:Version="$VERSION" -p:PublishSingleFile=false \
  -p:DebugType=None -p:DebugSymbols=false
fi

/bin/cp -R "$PUBLISH_DIR/." "$APP_ROOT/bin/"
/bin/chmod 0755 "$APP_ROOT/bin/Sf.EndpointAI.Client.Service"
SUPPORT_FILE="$SCRIPT_DIR/InstallerSupport.sh"
if [[ "$CLIENT_IMPLEMENTATION" == go ]]; then
  SUPPORT_FILE="$ARTIFACT_ROOT/InstallerSupport.sh"
  /usr/bin/sed -e "s/^SF_VERSION=0.1.22$/SF_VERSION=$VERSION/" \
    -e 's/^SF_IMPLEMENTATION=dotnet$/SF_IMPLEMENTATION=go/' \
    "$SCRIPT_DIR/InstallerSupport.sh" > "$SUPPORT_FILE"
fi
install -m 0755 "$SCRIPT_DIR/run-service.sh" "$APP_ROOT/bin/run-service.sh"
install -m 0644 "$SCRIPT_DIR/com.sf.endpointai.proxy.plist" \
  "$PACKAGE_ROOT/Library/LaunchDaemons/com.sf.endpointai.proxy.plist"
install -m 0755 "$SCRIPT_DIR/sf-endpointai-diagnostics" \
  "$PACKAGE_ROOT/usr/local/sbin/sf-endpointai-diagnostics"
install -m 0755 "$SCRIPT_DIR/uninstall.sh" "$SHARE_ROOT/uninstall.sh"
install -m 0755 "$SCRIPT_DIR/Set-ProductionClientControl.sh" "$SHARE_ROOT/Set-ProductionClientControl.sh"
install -m 0755 "$SUPPORT_FILE" "$SHARE_ROOT/InstallerSupport.sh"
install -m 0755 "$SCRIPT_DIR/Collect-MacInstallerLogs.sh" "$PACKAGE_ROOT/usr/local/sbin/sf-endpointai-installer-logs"
install -m 0755 "$SCRIPT_DIR/Recover-MacInstallation.sh" "$PACKAGE_ROOT/usr/local/sbin/sf-endpointai-installer-recover"
install -m 0600 "$SCRIPT_DIR/sf-endpointai-proxy.conf.example" "$SHARE_ROOT/sf-endpointai-proxy.conf.example"
install -m 0755 "$SCRIPT_DIR/preinstall" "$PACKAGE_SCRIPTS/preinstall"
install -m 0755 "$SCRIPT_DIR/postinstall" "$PACKAGE_SCRIPTS/postinstall"
install -m 0755 "$SUPPORT_FILE" "$PACKAGE_SCRIPTS/InstallerSupport.sh"
print -r -- "$ARCH" > "$PACKAGE_SCRIPTS/package-arch"
print -r -- "$VERSION" > "$PACKAGE_SCRIPTS/package-version"
install -m 0600 "$CLIENT_CREDENTIALS_FILE" "$PACKAGE_SCRIPTS/client-credentials.json"

if [[ -n "${APP_SIGN_IDENTITY:-}" ]]; then
  while IFS= read -r -d '' FILE; do
    if [[ "$FILE" != "$APP_ROOT/bin/Sf.EndpointAI.Client.Service" ]] \
      && /usr/bin/file "$FILE" | /usr/bin/grep -q 'Mach-O'; then
      /usr/bin/codesign --force --timestamp --options runtime --sign "$APP_SIGN_IDENTITY" "$FILE"
      /usr/bin/codesign --verify --strict "$FILE"
    fi
  done < <(/usr/bin/find "$APP_ROOT/bin" -type f -print0)
  if [[ "$CLIENT_IMPLEMENTATION" == go ]]; then
    /usr/bin/codesign --force --timestamp --options runtime \
      --sign "$APP_SIGN_IDENTITY" "$APP_ROOT/bin/Sf.EndpointAI.Client.Service"
  else
    /usr/bin/codesign --force --timestamp --options runtime \
      --entitlements "$SCRIPT_DIR/service.entitlements.plist" \
      --sign "$APP_SIGN_IDENTITY" "$APP_ROOT/bin/Sf.EndpointAI.Client.Service"
  fi
  /usr/bin/codesign --verify --strict --verbose=2 "$APP_ROOT/bin/Sf.EndpointAI.Client.Service"
fi

PKGBUILD_ARGS=(
  --root "$PACKAGE_ROOT"
  --scripts "$PACKAGE_SCRIPTS"
  --identifier "com.sf.endpointai.proxy"
  --version "$VERSION"
  --install-location "/"
  --ownership recommended
)
if [[ -n "${DEVELOPMENT_APP_BUNDLE:-}" ]]; then
  COMPONENTS="$ARTIFACT_ROOT/components.plist"
  /usr/bin/pkgbuild --analyze --root "$PACKAGE_ROOT" "$COMPONENTS"
  python3 - "$COMPONENTS" <<'PY'
import plistlib,sys
from pathlib import Path
p=Path(sys.argv[1]);items=plistlib.loads(p.read_bytes())
for item in items:
    item['BundleIsRelocatable']=False
    item['BundleHasStrictIdentifier']=True
    item['BundleOverwriteAction']='upgrade'
p.write_bytes(plistlib.dumps(items))
PY
  PKGBUILD_ARGS+=(--component-plist "$COMPONENTS")
fi
if [[ -n "${INSTALLER_SIGN_IDENTITY:-}" ]]; then
  PKGBUILD_ARGS+=(--sign "$INSTALLER_SIGN_IDENTITY")
fi

/usr/bin/pkgbuild "${PKGBUILD_ARGS[@]}" "$OUTPUT_PKG"
if [[ -n "${INSTALLER_SIGN_IDENTITY:-}" ]]; then
  /usr/sbin/pkgutil --check-signature "$OUTPUT_PKG"
else
  echo 'Unsigned PKG: isolated IOA validation required before rollout.'
fi
(cd "$ARTIFACT_ROOT" && /usr/bin/shasum -a 256 "${OUTPUT_PKG:t}") | tee "$OUTPUT_PKG.sha256"
echo "PKG created: $OUTPUT_PKG"
