#!/bin/zsh
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <pkg-path> <notarytool-keychain-profile>" >&2
  exit 2
fi

PKG_PATH="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
PROFILE="$2"

# Notarization uploads the complete package. Never upload embedded credentials.
umask 077
INSPECT_DIR=$(/usr/bin/mktemp -d "${TMPDIR:-/private/tmp}/endpointai-notary-check.XXXXXXXX")
trap '/bin/rm -rf "$INSPECT_DIR"' EXIT
/usr/sbin/pkgutil --expand-full "$PKG_PATH" "$INSPECT_DIR/expanded"
[[ -f "$INSPECT_DIR/expanded/Scripts/external-credentials" && ! -L "$INSPECT_DIR/expanded/Scripts/external-credentials" && \
   "$(<"$INSPECT_DIR/expanded/Scripts/external-credentials")" == v1 ]] || { echo 'Refusing notarization: external credential mode required.' >&2; exit 2; }
[[ -z "$(/usr/bin/find "$INSPECT_DIR/expanded" -iname '*credentials*.json' -print -quit)" ]] || { echo 'Refusing notarization: embedded credential file detected.' >&2; exit 2; }

/usr/bin/xcrun notarytool submit "$PKG_PATH" --keychain-profile "$PROFILE" --wait
/usr/bin/xcrun stapler staple "$PKG_PATH"
/usr/sbin/spctl --assess --type install --verbose=2 "$PKG_PATH"
/usr/bin/shasum -a 256 "$PKG_PATH" | tee "$PKG_PATH.sha256"
