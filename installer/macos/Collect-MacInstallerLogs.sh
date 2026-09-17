#!/bin/zsh
set -euo pipefail
SCRIPT_DIR="${0:A:h}"
if [[ -f "$SCRIPT_DIR/InstallerSupport.sh" ]]; then
  source "$SCRIPT_DIR/InstallerSupport.sh"
else
  source /usr/local/share/sf-endpointai-proxy/InstallerSupport.sh
fi
[[ $EUID -eq 0 ]] || { print -u2 'Root execution required.'; exit 1; }
sf_secure_dir "$SF_LOGS"
id="$(/bin/date -u +%Y%m%dT%H%M%SZ)-$(/usr/bin/uuidgen)"
stage="$SF_LOGS/collect-$id"
sf_secure_dir "$stage"
trap '/bin/rm -rf "$stage"' EXIT

# Rebuild logs from allowlisted fields, rather than export arbitrary text.
files=("$SF_LOGS"/install-*.jsonl(NOn))
for file in "${files[@]:0:20}"; do
  sf_safe_path "$file"
  [[ $(/usr/bin/stat -f %u "$file") -eq 0 && $(/usr/bin/stat -f %l "$file") -eq 1 ]] || exit 1
  output="$stage/${file:t}"
  : > "$output"
  while IFS= read -r line; do
    stage_value=$(print -rn -- "$line" | /usr/bin/plutil -extract stage raw -o - - 2>/dev/null || true)
    outcome=$(print -rn -- "$line" | /usr/bin/plutil -extract outcome raw -o - - 2>/dev/null || true)
    case "$stage_value" in
      service_exit)
        exit_value=$(print -rn -- "$line" | /usr/bin/plutil -extract lastExitCode raw -o - - 2>/dev/null || true)
        signal_value=$(print -rn -- "$line" | /usr/bin/plutil -extract lastSignal raw -o - - 2>/dev/null || true)
        [[ "$exit_value" =~ '^(0|[1-9][0-9]{0,2})$' ]] || exit_value=null
        [[ "$signal_value" =~ '^(0|[1-9][0-9]{0,2})$' ]] || signal_value=null
        /usr/bin/printf '{"stage":"service_exit","outcome":"service_exit_status","lastExitCode":%s,"lastSignal":%s}\n' "$exit_value" "$signal_value" >> "$output"
        continue ;;
      environment)
        architecture=$(print -rn -- "$line" | /usr/bin/plutil -extract architecture raw -o - - 2>/dev/null || true)
        [[ "$architecture" == arm64 || "$architecture" == x86_64 ]] || architecture=unknown
        major=$(print -rn -- "$line" | /usr/bin/plutil -extract macOSMajor raw -o - - 2>/dev/null || true)
        [[ "$major" =~ '^[0-9]{1,3}$' ]] || major=0
        /usr/bin/printf '{"stage":"environment","identity":"root","architecture":"%s","macOSMajor":%d}\n' "$architecture" "$major" >> "$output"
        continue ;;
      begin|preflight|backup|stop_service|payload|postinstall|write_config|start_service|health_check|control_plane|complete|restore_files|rollback|manual_recovery) ;;
      *) print '{"outcome":"unreadable_log_entry"}' >> "$output"; continue ;;
    esac
    case "$outcome" in
      begin|validated|install_locked|recovery_required|unsupported_target|unsupported_os|wrong_architecture|invalid_credentials|unsafe_path|saved|unexpected_service_path|bootout_failed|stopped|stop_timeout|protected_config_written|registered|local_ready|sync_observed|sync_pending|not_ready|files_restored|old_service_ready|old_service_not_ready|previous_service_state_restored|failed|prepared|success|incomplete_snapshot_discarded) ;;
      *) outcome=unreadable_log_entry ;;
    esac
    stamp=$(print -rn -- "$line" | /usr/bin/plutil -extract timeUtc raw -o - - 2>/dev/null || true)
    [[ "$stamp" =~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' ]] || stamp=unknown
    code=$(print -rn -- "$line" | /usr/bin/plutil -extract exitCode raw -o - - 2>/dev/null || true)
    [[ "$code" =~ '^[0-9]{1,3}$' ]] || code=1
    error_type=none
    (( code == 0 )) || error_type=command_failure
    line_number=$(print -rn -- "$line" | /usr/bin/plutil -extract lineNumber raw -o - - 2>/dev/null || true)
    [[ "$line_number" =~ '^[0-9]{1,6}$' ]] || line_number=0
    member=$(print -rn -- "$line" | /usr/bin/plutil -extract member raw -o - - 2>/dev/null || true)
    case "$member" in
      none|sf_open_log|sf_preflight|sf_acquire|sf_snapshot|sf_stop|sf_load_session|sf_validate_credentials|sf_safe_path|sf_write_config|sf_start|sf_ready|mkdir|chown|chmod) ;;
      *) member=unknown ;;
    esac
    /usr/bin/printf '{"timeUtc":"%s","stage":"%s","outcome":"%s","exitCode":%d,"errorType":"%s","lineNumber":%d,"member":"%s"}\n' "$stamp" "$stage_value" "$outcome" "$code" "$error_type" "$line_number" "$member" >> "$output"
  done < "$file"
done

# System installation log is shared by all products. Only map matching lines
# to fixed event categories; never copy raw script output, arguments or paths.
system_log=/private/var/log/install.log
if [[ -f "$system_log" ]] && sf_safe_path "$system_log"; then
  cutoff=$(/bin/date -v-24H '+%Y-%m-%d %H:%M:%S')
  if (( ${#files} > 0 )); then
    stamp="${files[1]:t}"
    stamp="${stamp#install-}"
    stamp="${stamp%%Z-*}Z"
    epoch=$(/bin/date -j -u -f '%Y%m%dT%H%M%SZ' "$stamp" +%s 2>/dev/null || true)
    [[ "$epoch" == <-> ]] && cutoff=$(/bin/date -r "$epoch" '+%Y-%m-%d %H:%M:%S')
  fi
  /usr/bin/tail -n 20000 "$system_log" | /usr/bin/awk -v cutoff="$cutoff" '
    substr($0,1,19) >= cutoff && /com\.sf\.endpointai\.proxy|EndpointAIDLP-Client-0\.1\.22-osx-(arm64|x64)\.pkg/ {
      event="package_event"
      if ($0 ~ /[Ff]ail|[Ee]rror/) event="package_failure"
      else if ($0 ~ /[Ss]uccess|[Ff]inish/) event="package_finished"
      else if ($0 ~ /preinstall|postinstall|[Ss]cript/) event="package_script"
      stamp=$1
      if (stamp !~ /^[0-9-]+$/) stamp="unknown"
      printf "{\"date\":\"%s\",\"event\":\"%s\"}\n",stamp,event
    }' | /usr/bin/tail -n 200 > "$stage/system-install-events.jsonl"
fi
receipt=$(/usr/sbin/pkgutil --pkg-info-plist com.sf.endpointai.proxy 2>/dev/null || true)
version=$(print -rn -- "$receipt" | /usr/bin/plutil -extract pkg-version raw -o - - 2>/dev/null || true)
[[ "$version" =~ '^[0-9]+\.[0-9]+\.[0-9]+$' ]] || version=unknown
pid=$(sf_pid 2>/dev/null || true)
loaded=not_running
executable=''
[[ "$pid" =~ '^[0-9]+$' ]] && executable=$(/bin/ps -ww -p "$pid" -o comm= 2>/dev/null || true)
health=''
if [[ "$executable" == "$SF_BIN/Sf.EndpointAI.Client.Service" ]]; then
  loaded=running
  health=$(/usr/bin/curl --silent --fail --max-time 2 --noproxy '*' http://127.0.0.1:18080/healthz 2>/dev/null || true)
fi
runtime=$(print -rn -- "$health" | /usr/bin/plutil -extract clientVersion raw -o - - 2>/dev/null || true)
[[ "$runtime" =~ '^[0-9]+\.[0-9]+\.[0-9]+$' ]] || runtime=unknown
status_value=$(print -rn -- "$health" | /usr/bin/plutil -extract status raw -o - - 2>/dev/null || true)
[[ "$status_value" == ok ]] && healthy=true || healthy=false
/usr/bin/printf '{"receiptVersion":"%s","runtimeVersion":"%s","service":"%s","localHealthy":%s}\n' \
  "$version" "$runtime" "$loaded" "$healthy" > "$stage/status.json"
zip="$SF_LOGS/EndpointAIDLP-install-diagnostics-$id.zip"
/usr/bin/ditto -c -k --norsrc --noextattr --keepParent "$stage" "$zip"
/usr/sbin/chown root:wheel "$zip"
/bin/chmod 0600 "$zip"
archives=("$SF_LOGS"/EndpointAIDLP-install-diagnostics-*.zip(NOn))
for archive in "${archives[@]:20}"; do sf_safe_path "$archive"; /bin/rm -f "$archive"; done
print -r -- "$zip"
