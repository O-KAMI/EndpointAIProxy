#!/bin/zsh
# Shared by PKG scripts and independent tools. Never enable xtrace.
set -euo pipefail
umask 077
SF_VERSION=0.1.22
SF_DATA='/Library/Application Support/SF/EndpointAIProxy'
SF_CONFIG=/private/etc/sf-endpointai-proxy.conf
SF_PLIST=/Library/LaunchDaemons/com.sf.endpointai.proxy.plist
SF_SHARE=/usr/local/share/sf-endpointai-proxy
SF_BIN="$SF_DATA/bin"
SF_LOGS="$SF_DATA/InstallerLogs"
SF_BACKUPS="$SF_DATA/InstallerRollback"
SF_SESSION="$SF_BACKUPS/current"
SF_LOCK=/private/var/run/sf-endpointai-installer.lock
SF_JOB=system/com.sf.endpointai.proxy
SF_STAGE=begin
SF_LOG=''
SF_ID=''
SF_STOP_ATTEMPTED=0
SF_BACKUP_READY=0
SF_OWN_LOCK=0
SF_ERROR_LINE=0
SF_ERROR_MEMBER=none
TRAPZERR() {
  local location="${funcfiletrace[1]:-unknown:0}"
  SF_ERROR_LINE="${location##*:}"
  [[ "$SF_ERROR_LINE" == <-> ]] || SF_ERROR_LINE=0
}
sf_step() {
  if "$@"; then return 0; fi
  local location="${funcfiletrace[1]:-unknown:0}"
  SF_ERROR_LINE="${location##*:}"
  [[ "$SF_ERROR_LINE" == <-> ]] || SF_ERROR_LINE=0
  SF_ERROR_MEMBER="${1:t}"
  return 1
}

sf_safe_path() {
  local item="$1"
  while [[ "$item" != / && -n "$item" ]]; do
    [[ ! -L "$item" ]] || return 1
    item="${item:h}"
  done
}
sf_secure_dir() {
  sf_safe_path "$1" || return 1
  /bin/mkdir -p "$1" || return 1
  /usr/sbin/chown root:wheel "$1" || return 1
  /bin/chmod 0700 "$1" || return 1
}
sf_log() {
  # Internal stage/outcome enums only; no raw command output or credentials.
  [[ -n "$SF_LOG" ]] || return 0
  local error_type=none
  (( ${2:-0} == 0 )) || error_type=command_failure
  /usr/bin/printf '{"timeUtc":"%s","installationId":"%s","version":"%s","stage":"%s","outcome":"%s","exitCode":%d,"errorType":"%s","lineNumber":%d,"member":"%s"}\n' \
    "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ)" "$SF_ID" "$SF_VERSION" "$SF_STAGE" "$1" "${2:-0}" "$error_type" "$SF_ERROR_LINE" "$SF_ERROR_MEMBER" >> "$SF_LOG"
}
sf_open_log() {
  [[ $EUID -eq 0 ]] || { print -u2 'Root execution required; no interactive elevation.'; return 1; }
  sf_safe_path "$SF_DATA" || return 1
  /bin/mkdir -p "$SF_DATA" || return 1
  /usr/sbin/chown root:wheel "$SF_DATA" || return 1
  /bin/chmod 0750 "$SF_DATA" || return 1
  sf_secure_dir "$SF_LOGS" || return 1
  SF_ID="$(/bin/date -u +%Y%m%dT%H%M%SZ)-$(/usr/bin/uuidgen)"
  SF_LOG="$SF_LOGS/install-$SF_ID.jsonl"
  : > "$SF_LOG" || return 1
  /bin/chmod 0600 "$SF_LOG" || return 1
  sf_log begin || return 1
  local files=("$SF_LOGS"/install-*.jsonl(NOn)) old active='' kept=0 quota=20
  if [[ -f "$SF_SESSION/id" ]] && sf_safe_path "$SF_SESSION/id"; then
    active="install-$(<"$SF_SESSION/id").jsonl"
    [[ -f "$SF_LOGS/$active" ]] && quota=19 || active=''
  fi
  for old in "${files[@]}"; do
    [[ "${old:t}" == "$active" ]] && continue
    (( kept += 1 ))
    if (( kept > quota )); then sf_safe_path "$old" && /bin/rm -f "$old" || return 1; fi
  done
}
sf_load_session() {
  sf_safe_path "$SF_SESSION" && sf_safe_path "$SF_LOCK" || return 1
  sf_safe_path "$SF_SESSION/id" && sf_safe_path "$SF_LOCK/id" && sf_safe_path "$SF_LOCK/script-pid" || return 1
  [[ -f "$SF_SESSION/id" && -f "$SF_LOCK/id" ]] || return 1
  SF_ID="$(<"$SF_SESSION/id")"
  [[ "$SF_ID" =~ '^[0-9]{8}T[0-9]{6}Z-[A-Fa-f0-9-]{36}$' ]] || return 1
  [[ "$(<"$SF_LOCK/id")" == "$SF_ID" ]] || return 1
  SF_LOG="$SF_LOGS/install-$SF_ID.jsonl"
  sf_safe_path "$SF_LOG" || return 1
  [[ -f "$SF_LOG" && $(/usr/bin/stat -f %u "$SF_SESSION") -eq 0 && \
     $(/usr/bin/stat -f %u "$SF_LOG") -eq 0 && $(/usr/bin/stat -f %u "$SF_LOCK") -eq 0 && \
     $(/usr/bin/stat -f %Lp "$SF_SESSION") == 700 && $(/usr/bin/stat -f %Lp "$SF_LOCK") == 700 && \
     $(/usr/bin/stat -f %Lp "$SF_LOG") == 600 && $(/usr/bin/stat -f %l "$SF_LOG") -eq 1 ]] || return 1
}
sf_acquire() {
  sf_safe_path "$SF_LOCK" || return 1
  [[ ! -e "$SF_SESSION" ]] || { sf_log recovery_required 1; return 1; }
  # Never automatically remove stale locks: Installer may still copy payload.
  /bin/mkdir -m 0700 "$SF_LOCK" 2>/dev/null || { sf_log install_locked 1; return 1; }
  SF_OWN_LOCK=1
  print -r -- "$SF_ID" > "$SF_LOCK/id" || return 1
  print -r -- "$$" > "$SF_LOCK/script-pid" || return 1
  sf_secure_dir "$SF_BACKUPS" && sf_secure_dir "$SF_SESSION" || return 1
  print -r -- "$SF_ID" > "$SF_SESSION/id" || return 1
}
sf_validate_credentials() {
  local credentials="$1" length
  [[ -f "$credentials" && ! -L "$credentials" ]] || return 1
  SF_ORIGIN=$(/usr/bin/plutil -extract origin raw -o - "$credentials" 2>/dev/null) || return 1
  [[ "$SF_ORIGIN" == http://control.example.invalid:8080 ]] || return 1
  SF_TOKEN=$(/usr/bin/plutil -extract clientToken raw -o - "$credentials" 2>/dev/null) || return 1
  SF_HMAC=$(/usr/bin/plutil -extract policyHmacKey raw -o - "$credentials" 2>/dev/null) || return 1
  SF_AES=$(/usr/bin/plutil -extract transportKey raw -o - "$credentials" 2>/dev/null) || return 1
  SF_KEYID=$(/usr/bin/plutil -extract keyId raw -o - "$credentials" 2>/dev/null) || return 1
  [[ "$SF_TOKEN" =~ '^[A-Za-z0-9_-]{16,}$' && "$SF_KEYID" =~ '^[A-Za-z0-9_-]{1,64}$' ]] || return 1
  [[ "$SF_HMAC" =~ '^[A-Za-z0-9+/]+={0,2}$' && "$SF_AES" =~ '^[A-Za-z0-9+/]+={0,2}$' ]] || return 1
  length=$(print -rn -- "$SF_AES" | /usr/bin/base64 -D 2>/dev/null | /usr/bin/wc -c) || return 1
  [[ $length -eq 32 ]] || return 1
  length=$(print -rn -- "$SF_HMAC" | /usr/bin/base64 -D 2>/dev/null | /usr/bin/wc -c) || return 1
  [[ $length -ge 32 ]] || return 1
}
sf_preflight() {
  local script_dir="$1" target="$2" arch major item
  SF_STAGE=preflight
  [[ "$target" == / ]] || { sf_log unsupported_target 1; return 1; }
  arch=$(/usr/sbin/sysctl -n hw.optional.arm64 2>/dev/null || print 0)
  [[ "$arch" == 1 ]] && arch=arm64 || arch=x86_64
  major=$(/usr/bin/sw_vers -productVersion) || return 1
  major="${major%%.*}"
  [[ $major -ge 14 ]] || { sf_log unsupported_os 1; return 1; }
  [[ -f "$script_dir/package-arch" && "$(<"$script_dir/package-arch")" == "$arch" ]] || { sf_log wrong_architecture 1; return 1; }
  [[ -f "$script_dir/package-version" && "$(<"$script_dir/package-version")" == "$SF_VERSION" ]] || return 1
  sf_validate_credentials "$script_dir/client-credentials.json" || { sf_log invalid_credentials 1; return 1; }
  for item in "$SF_CONFIG" "$SF_PLIST" "$SF_BIN" "$SF_SHARE" \
    /usr/local/sbin/sf-endpointai-diagnostics /usr/local/sbin/sf-endpointai-installer-logs \
    /usr/local/sbin/sf-endpointai-installer-recover; do
    sf_safe_path "$item" || { sf_log unsafe_path 1; return 1; }
  done
  /usr/bin/printf '{"stage":"environment","identity":"root","architecture":"%s","macOSMajor":%d}\n' "$arch" "$major" >> "$SF_LOG" || return 1
  sf_log validated
}
sf_snapshot_one() {
  local key="$1" target_path="$2"
  [[ -e "$target_path" ]] || return 0
  /bin/cp -pR "$target_path" "$SF_SESSION/$key" || return 1
  : > "$SF_SESSION/$key.present" || return 1
}
sf_snapshot() {
  SF_STAGE=backup
  sf_snapshot_one bin "$SF_BIN" || return 1
  sf_snapshot_one share "$SF_SHARE" || return 1
  sf_snapshot_one config "$SF_CONFIG" || return 1
  sf_snapshot_one plist "$SF_PLIST" || return 1
  sf_snapshot_one diagnostics /usr/local/sbin/sf-endpointai-diagnostics || return 1
  sf_snapshot_one collector /usr/local/sbin/sf-endpointai-installer-logs || return 1
  sf_snapshot_one recovery /usr/local/sbin/sf-endpointai-installer-recover || return 1
  if /bin/launchctl print "$SF_JOB" >/dev/null 2>&1; then : > "$SF_SESSION/was-loaded" || return 1; fi
  : > "$SF_SESSION/backup-ready" || return 1
  SF_BACKUP_READY=1
  sf_log saved
}
sf_pid() {
  /bin/launchctl print "$SF_JOB" 2>/dev/null | /usr/bin/awk '/^[[:space:]]*pid = [0-9]+$/ {print $3; exit}'
}
sf_stop() {
  SF_STAGE=stop_service
  local pid='' started='' program='' n
  if /bin/launchctl print "$SF_JOB" >/dev/null 2>&1; then
    program=$(/bin/launchctl print "$SF_JOB" 2>/dev/null | /usr/bin/awk '/^[[:space:]]*program = / {sub(/^[[:space:]]*program = /, ""); print; exit}') || return 1
    [[ "$program" == "$SF_BIN/run-service.sh" ]] || { sf_log unexpected_service_path 1; return 1; }
    pid=$(sf_pid) || return 1
    if [[ -n "$pid" ]]; then
      [[ "$pid" =~ '^[0-9]+$' ]] || return 1
      started=$(/bin/ps -p "$pid" -o lstart= 2>/dev/null || true)
      print -r -- "$pid" > "$SF_SESSION/stopping-pid" || return 1
      print -r -- "$started" > "$SF_SESSION/stopping-started" || return 1
    fi
    if ! /bin/launchctl bootout "$SF_JOB" >/dev/null 2>&1; then
      if /bin/launchctl print "$SF_JOB" >/dev/null 2>&1; then sf_log bootout_failed 1; return 1; fi
    fi
  fi
  if [[ -z "$pid" && -f "$SF_SESSION/stopping-pid" && -f "$SF_SESSION/stopping-started" ]]; then
    pid="$(<"$SF_SESSION/stopping-pid")"
    started="$(<"$SF_SESSION/stopping-started")"
    [[ "$pid" =~ '^[0-9]+$' ]] || return 1
  fi
  for n in {1..10}; do
    if [[ -z "$pid" || -z "$started" || "$(/bin/ps -p "$pid" -o lstart= 2>/dev/null || true)" != "$started" ]]; then
      /bin/rm -f "$SF_SESSION/stopping-pid" "$SF_SESSION/stopping-started" || return 1
      sf_log stopped; return 0
    fi
    /bin/sleep 1
  done
  sf_log stop_timeout 1
  return 1
}
sf_write_config() {
  SF_STAGE=write_config
  sf_safe_path "$SF_CONFIG" || return 1
  local temp
  temp=$(/usr/bin/mktemp /private/etc/sf-endpointai-proxy.XXXXXX) || return 1
  print -r -- "$temp" > "$SF_SESSION/config-temp" || { /bin/rm -f "$temp"; return 1; }
  if [[ -f "$SF_CONFIG" ]]; then
    /usr/bin/awk '!/^[[:space:]]*(export[[:space:]]+)?SF_PROXY_(CONTROL_(ORIGIN|TOKEN|HMAC_KEY|TRANSPORT_KEY|TRANSPORT_KEY_ID|SERVER_CERTIFICATE_SPKI_SHA256)|ALLOW_INSECURE_CONTROL_SERVER)=/' "$SF_CONFIG" > "$temp" || return 1
  fi
  {
    print -r -- "SF_PROXY_CONTROL_ORIGIN='$SF_ORIGIN'"
    print -r -- "SF_PROXY_CONTROL_TOKEN='$SF_TOKEN'"
    print -r -- "SF_PROXY_CONTROL_HMAC_KEY='$SF_HMAC'"
    print -r -- "SF_PROXY_CONTROL_TRANSPORT_KEY='$SF_AES'"
    print -r -- "SF_PROXY_CONTROL_TRANSPORT_KEY_ID='$SF_KEYID'"
  } >> "$temp" || return 1
  /usr/sbin/chown root:wheel "$temp" && /bin/chmod 0600 "$temp" || return 1
  /bin/mv -f "$temp" "$SF_CONFIG" || return 1
  unset SF_TOKEN SF_HMAC SF_AES
  sf_log protected_config_written
}
sf_start() {
  SF_STAGE=start_service
  /usr/bin/plutil -lint "$SF_PLIST" >/dev/null 2>&1 || return 1
  /bin/launchctl enable "$SF_JOB" >/dev/null 2>&1 || return 1
  /bin/launchctl bootstrap system "$SF_PLIST" >/dev/null 2>&1 || return 1
  /bin/launchctl kickstart "$SF_JOB" >/dev/null 2>&1 || return 1
  sf_log registered
}
sf_service_evidence() {
  local info exit_value signal_value
  info=$(/bin/launchctl print "$SF_JOB" 2>/dev/null || true)
  exit_value=$(print -r -- "$info" | /usr/bin/awk '/^[[:space:]]*last exit code = / {print $5; exit}')
  signal_value=$(print -r -- "$info" | /usr/bin/awk '/^[[:space:]]*last terminating signal = / {print $NF; exit}')
  [[ "$exit_value" =~ '^(0|[1-9][0-9]{0,2})$' ]] || exit_value=null
  [[ "$signal_value" =~ '^(0|[1-9][0-9]{0,2})$' ]] || signal_value=null
  /usr/bin/printf '{"stage":"service_exit","outcome":"service_exit_status","lastExitCode":%s,"lastSignal":%s}\n' "$exit_value" "$signal_value" >> "$SF_LOG"
}
sf_ready() {
  SF_STAGE=health_check
  local deadline=$((SECONDS + 60)) pid='' executable='' health='' version='' code='' synced='' previous=''
  while (( SECONDS < deadline )); do
    pid=$(sf_pid 2>/dev/null || true)
    if [[ "$pid" =~ '^[0-9]+$' ]]; then
      executable=$(/bin/ps -ww -p "$pid" -o comm= 2>/dev/null || true)
      if [[ "$executable" == "$SF_BIN/Sf.EndpointAI.Client.Service" ]]; then
        health=$(/usr/bin/curl --silent --fail --max-time 2 --noproxy '*' http://127.0.0.1:18080/healthz 2>/dev/null || true)
        version=$(print -rn -- "$health" | /usr/bin/plutil -extract clientVersion raw -o - - 2>/dev/null || true)
        if [[ "$version" == "$SF_VERSION" && "$previous" == "$pid" ]]; then
          sf_log local_ready
          synced=$(print -rn -- "$health" | /usr/bin/plutil -extract lastControlSyncAtUtc raw -o - - 2>/dev/null || true)
          code=$(print -rn -- "$health" | /usr/bin/plutil -extract lastControlErrorCode raw -o - - 2>/dev/null || true)
          SF_STAGE=control_plane
          if [[ -n "$synced" && "$synced" != null && ( -z "$code" || "$code" == null ) ]]; then sf_log sync_observed
          else sf_log sync_pending; fi
          return 0
        fi
        [[ "$version" == "$SF_VERSION" ]] && previous="$pid" || previous=''
      else previous=''; fi
    else previous=''; fi
    /bin/sleep 1
  done
  sf_service_evidence || return 1
  sf_log not_ready 1
  return 1
}
sf_restore_one() {
  local key="$1" target_path="$2"
  sf_safe_path "$target_path" && sf_safe_path "$SF_SESSION/$key" || return 1
  /bin/rm -rf "$target_path" || return 1
  if [[ -f "$SF_SESSION/$key.present" ]]; then
    [[ -e "$SF_SESSION/$key" ]] || return 1
    /bin/mkdir -p "${target_path:h}" || return 1
    /bin/cp -pR "$SF_SESSION/$key" "$target_path" || return 1
  fi
}
sf_restore() {
  [[ -f "$SF_SESSION/backup-ready" ]] || return 1
  sf_stop || return 1
  SF_STAGE=restore_files
  sf_restore_one bin "$SF_BIN" || return 1
  sf_restore_one share "$SF_SHARE" || return 1
  sf_restore_one config "$SF_CONFIG" || return 1
  if [[ -f "$SF_CONFIG" ]]; then
    /usr/sbin/chown root:wheel "$SF_CONFIG" && /bin/chmod 0600 "$SF_CONFIG" || return 1
  fi
  sf_restore_one plist "$SF_PLIST" || return 1
  sf_restore_one diagnostics /usr/local/sbin/sf-endpointai-diagnostics || return 1
  sf_restore_one collector /usr/local/sbin/sf-endpointai-installer-logs || return 1
  sf_restore_one recovery /usr/local/sbin/sf-endpointai-installer-recover || return 1
  sf_log files_restored
  if [[ -f "$SF_SESSION/was-loaded" ]]; then
    sf_start || return 1
    local n pid='' executable=''
    for n in {1..30}; do
      pid=$(sf_pid 2>/dev/null || true)
      executable=''
      [[ "$pid" =~ '^[0-9]+$' ]] && executable=$(/bin/ps -ww -p "$pid" -o comm= 2>/dev/null || true)
      if [[ "$executable" == "$SF_BIN/Sf.EndpointAI.Client.Service" ]] && \
        /usr/bin/curl --silent --fail --max-time 2 --noproxy '*' http://127.0.0.1:18080/healthz >/dev/null 2>&1; then
        SF_STAGE=rollback; sf_log old_service_ready; return 0
      fi
      /bin/sleep 1
    done
    SF_STAGE=rollback; sf_log old_service_not_ready 1; return 1
  fi
  SF_STAGE=rollback; sf_log previous_service_state_restored
}
sf_cleanup_temp() {
  if [[ -f "$SF_SESSION/config-temp" ]]; then
    local temp="$(<"$SF_SESSION/config-temp")"
    if [[ "$temp" == /private/etc/sf-endpointai-proxy.* && "$temp" != "$SF_CONFIG" ]]; then
      sf_safe_path "$temp" && /bin/rm -f "$temp" || return 1
    fi
  fi
}
sf_clear_session() {
  sf_cleanup_temp || return 1
  sf_safe_path "$SF_SESSION" && sf_safe_path "$SF_LOCK" || return 1
  /bin/rm -rf "$SF_SESSION" "$SF_LOCK" || return 1
  SF_OWN_LOCK=0
}
sf_failed_exit() {
  local code="$1"
  (( code != 0 )) || return 0
  set +e
  sf_log failed "$code"
  if (( SF_BACKUP_READY && SF_STOP_ATTEMPTED )); then
    if sf_restore; then sf_clear_session; else SF_STAGE=rollback; sf_log recovery_required 1; fi
  elif (( SF_OWN_LOCK )); then
    if [[ -f "$SF_SESSION/id" && "$(<"$SF_SESSION/id")" == "$SF_ID" ]]; then sf_clear_session
    else /bin/rm -rf "$SF_LOCK"; fi
  fi
  print -u2 'EndpointAIDLP installation failed. Collect InstallerLogs; recovery may be required.'
}
