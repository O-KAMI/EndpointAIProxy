#!/bin/zsh
set -euo pipefail
SCRIPT_DIR="${0:A:h}"
if [[ -f "$SCRIPT_DIR/InstallerSupport.sh" ]]; then
  source "$SCRIPT_DIR/InstallerSupport.sh"
else
  source /usr/local/share/sf-endpointai-proxy/InstallerSupport.sh
fi
[[ $EUID -eq 0 ]] || { print -u2 'Root execution required.'; exit 1; }
if ! sf_load_session; then
  print -u2 'No valid pending installation snapshot found. Collect logs before further changes.'
  exit 1
fi
pid="$(<"$SF_LOCK/script-pid")"
[[ "$pid" =~ '^[0-9]+$' ]] || exit 1
if /bin/kill -0 "$pid" 2>/dev/null; then
  print -u2 'Installation script is still running; recovery refused.'
  exit 1
fi
/bin/mkdir -m 0700 "$SF_LOCK/recovery" 2>/dev/null || { print -u2 'Recovery is already running.'; exit 1; }
trap '/bin/rmdir "$SF_LOCK/recovery" 2>/dev/null || true' EXIT
# IOA must first confirm its installation task has ended. A dead script PID
# cannot prove Installer has finished copying the payload.
print -r -- "$$" > "$SF_LOCK/script-pid"
SF_STAGE=manual_recovery
sf_log begin
if [[ ! -f "$SF_SESSION/backup-ready" ]]; then
  sf_log incomplete_snapshot_discarded
  sf_clear_session
  exit 0
fi
if sf_restore; then
  SF_STAGE=manual_recovery; sf_log success; sf_clear_session
  print 'Previous files and service state restored. Receipt may show the attempted version.'
else
  SF_STAGE=manual_recovery; sf_log failed 1; exit 1
fi
