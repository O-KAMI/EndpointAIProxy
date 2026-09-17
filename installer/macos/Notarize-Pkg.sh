#!/bin/zsh
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <pkg-path> <notarytool-keychain-profile>" >&2
  exit 2
fi

PKG_PATH="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
PROFILE="$2"

/usr/bin/xcrun notarytool submit "$PKG_PATH" --keychain-profile "$PROFILE" --wait
/usr/bin/xcrun stapler staple "$PKG_PATH"
/usr/sbin/spctl --assess --type install --verbose=2 "$PKG_PATH"
/usr/bin/shasum -a 256 "$PKG_PATH" | tee "$PKG_PATH.sha256"
