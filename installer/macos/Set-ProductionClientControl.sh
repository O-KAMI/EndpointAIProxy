#!/bin/zsh
set -euo pipefail
SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/InstallerSupport.sh"
[[ $# -eq 1 ]] || { print -u2 'Expected one credentials file; PKG installation needs no such argument.'; exit 2; }
trap 'sf_failed_exit $?' EXIT
trap 'exit 1' HUP INT TERM
main() {
  sf_step sf_open_log || return 1
  SF_STAGE=preflight
  sf_step sf_validate_credentials "$1" || return 1
  [[ -f "$SF_PLIST" && -d "$SF_BIN" ]] || return 1
  local item
  for item in "$SF_CONFIG" "$SF_PLIST" "$SF_BIN" "$SF_SHARE"; do sf_step sf_safe_path "$item" || return 1; done
  sf_step sf_acquire || return 1
  sf_step sf_snapshot || return 1
  SF_STOP_ATTEMPTED=1
  sf_step sf_stop || return 1
  sf_step sf_write_config || return 1
  sf_step sf_start || return 1
  sf_step sf_ready || return 1
  SF_STAGE=complete
  sf_log success || return 1
  sf_clear_session || return 1
}
if ! main "$@"; then
  trap - EXIT
  sf_failed_exit 1
  exit 1
fi
print 'Client control configuration installed.'
