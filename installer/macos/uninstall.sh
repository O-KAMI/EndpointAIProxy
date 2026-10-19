#!/bin/zsh
# Stop, detach, then remove registration. Failed detach retains recovery material.
set -euo pipefail
SCRIPT_DIR="${0:A:h}"
if [[ -f "$SCRIPT_DIR/InstallerSupport.sh" ]]; then
  source "$SCRIPT_DIR/InstallerSupport.sh"
else
  source /usr/local/share/sf-endpointai-proxy/InstallerSupport.sh
fi
[[ $EUID -eq 0 ]] || { print -u2 'Root execution required.'; exit 5; }
sf_open_log
was_loaded=0
stopped=0
retain_session=0
removing=0
uninstall_exit() {
  local code=$?
  trap - EXIT
  if (( code != 0 )); then
    sf_log failed "$code" || true
    # Restore only this operation's protected registration/tools snapshot if a
    # later removal fails. Configuration backups and bin are never deleted.
    if (( SF_OWN_LOCK && removing )); then
      sf_restore_one plist "$SF_PLIST" || retain_session=1
      sf_restore_one share "$SF_SHARE" || retain_session=1
      sf_restore_one diagnostics /usr/local/sbin/sf-endpointai-diagnostics || retain_session=1
      sf_restore_one collector /usr/local/sbin/sf-endpointai-installer-logs || retain_session=1
      sf_restore_one recovery /usr/local/sbin/sf-endpointai-installer-recover || retain_session=1
    fi
    # Only restart after confirmed exit; never bootstrap beside a process that
    # is still draining or failed to stop.
    if (( was_loaded && stopped )); then
      SF_STAGE=uninstall_recover
      if /bin/launchctl print "$SF_JOB" >/dev/null 2>&1 || { sf_start && sf_ready; }; then
        sf_log old_service_ready || true
      else
        sf_log old_service_not_ready 1 || true
        retain_session=1
        print -u2 'UNINSTALL_SERVICE_RESTORE_FAILED: registration and recovery data retained.'
      fi
    fi
    print -u2 'UNINSTALL_FAILED: configuration, registration and recovery data retained.'
  fi
  # This uninstall session has no payload snapshot. State/config-backups and
  # installation evidence remain in the data root, including on failure.
  if (( SF_OWN_LOCK && ! retain_session )); then
    /bin/rm -rf "$SF_SESSION" "$SF_LOCK" || true
  fi
  exit "$code"
}
trap uninstall_exit EXIT
sf_acquire
if /bin/launchctl print "$SF_JOB" >/dev/null 2>&1; then was_loaded=1; fi
# Version is evidence only; retain the support-file default if no marker exists.
if [[ -f "$SF_BIN/version" && ! -L "$SF_BIN/version" ]]; then
  v="$(<"$SF_BIN/version")"
  [[ "$v" =~ '^[0-9]+\.[0-9]+\.[0-9]+$' ]] && SF_VERSION="$v"
fi
sf_snapshot_one plist "$SF_PLIST"
sf_snapshot_one share "$SF_SHARE"
sf_snapshot_one diagnostics /usr/local/sbin/sf-endpointai-diagnostics
sf_snapshot_one collector /usr/local/sbin/sf-endpointai-installer-logs
sf_snapshot_one recovery /usr/local/sbin/sf-endpointai-installer-recover
# Fail closed if the service cannot be proven stopped; never swallow bootout.
SF_STOP_ATTEMPTED=1
sf_stop
stopped=1
SERVICE="$(sf_client_executable)"
sf_safe_path "$SERVICE"
[[ -x "$SERVICE" && -f "$SERVICE" ]] || { SF_STAGE=uninstall_detach; exit 1; }
SF_STAGE=uninstall_detach
# Maintenance operates on the retained default data root. Do not source agent
# configuration, print credentials, or discard its exit status.
SF_PROXY_DATA_ROOT="$SF_DATA" SF_PROXY_E2E_PROFILE_ROOT='' "$SERVICE" --maintenance=detach-all --auto-attach=false
sf_log detached
SF_STAGE=uninstall_remove
removing=1
/bin/rm -f "$SF_PLIST"
/bin/rm -f /usr/local/sbin/sf-endpointai-diagnostics
/bin/rm -f /usr/local/sbin/sf-endpointai-installer-logs /usr/local/sbin/sf-endpointai-installer-recover
/bin/rm -rf "$SF_SHARE"
sf_log success
print 'Service registration removed. Data, configuration backups and /etc/sf-endpointai-proxy.conf retained.'
