#!/usr/bin/env bash
# Long-running DFIR capture for app launch, TCC, PCAP, process, log, and recursive evidence.
set -Eeuo pipefail
IFS=$'\n\t'

PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin:$PATH"
export PATH LC_ALL=C LANG=C

DURATION_SECONDS=12600
START_DELAY_SECONDS=120
SAMPLE_INTERVAL=300
OUT_BASE="/Volumes/Evidence"
SOURCE_ROOT="/Volumes/Storage"
PCAP_INTERFACE="any"
RUN_RECURSIVE=1
RECURSIVE_LIMIT_FILES=0
RECURSIVE_HASH_MODE="all"
RUN_PROVENANCE=1
PROVENANCE_RAW_EVENT_LIMIT=100000
PROVENANCE_MAX_DB_MIB=2048
LAUNCH_APPS=()

usage() {
  cat <<'USAGE'
Usage: scripts/overnight_app_capture.sh [options]

Options:
  --duration-seconds N      Live capture duration (default: 12600, 3.5 hours)
  --start-delay-seconds N   Delay before starting capture/launch (default: 120)
  --sample-interval N       Process/network sample interval (default: 300)
  --out-base DIR            Output parent directory (default: /Volumes/Evidence)
  --source-root DIR         Source volume for app discovery/recursive scan (default: /Volumes/Storage)
  --pcap-interface IFACE    tshark/tcpdump interface (default: any)
  --launch-app PATH         App bundle path to launch; repeatable
  --no-recursive            Skip recursive verifier after live capture
  --recursive-limit-files N Limit recursive verifier file count (default: 0/unlimited)
  --recursive-hash-mode M   Recursive verifier hash mode: code|all|none (default: all)
  --no-provenance           Skip targeted provenance watcher
  --provenance-raw-limit N  Raw provenance ring-buffer row cap (default: 100000)
  --provenance-max-db-mib N Max provenance SQLite+WAL size before watcher stops (default: 2048)
  -h, --help                Show help

This script is read-only against source apps except for intentionally launching selected app bundles.
It writes all evidence under --out-base and never prints secrets to stdout.
USAGE
}

while (($#)); do
  case "$1" in
    --duration-seconds) DURATION_SECONDS="${2:?missing duration}"; shift 2 ;;
    --start-delay-seconds) START_DELAY_SECONDS="${2:?missing delay}"; shift 2 ;;
    --sample-interval) SAMPLE_INTERVAL="${2:?missing interval}"; shift 2 ;;
    --out-base) OUT_BASE="${2:?missing output base}"; shift 2 ;;
    --source-root) SOURCE_ROOT="${2:?missing source root}"; shift 2 ;;
    --pcap-interface) PCAP_INTERFACE="${2:?missing interface}"; shift 2 ;;
    --launch-app) LAUNCH_APPS+=("${2:?missing app path}"); shift 2 ;;
    --no-recursive) RUN_RECURSIVE=0; shift ;;
    --recursive-limit-files) RECURSIVE_LIMIT_FILES="${2:?missing limit}"; shift 2 ;;
    --recursive-hash-mode) RECURSIVE_HASH_MODE="${2:?missing hash mode}"; shift 2 ;;
    --no-provenance) RUN_PROVENANCE=0; shift ;;
    --provenance-raw-limit) PROVENANCE_RAW_EVENT_LIMIT="${2:?missing raw limit}"; shift 2 ;;
    --provenance-max-db-mib) PROVENANCE_MAX_DB_MIB="${2:?missing db MiB limit}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[FATAL] unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "$DURATION_SECONDS" =~ ^[0-9]+$ ]] || { echo "[FATAL] duration must be numeric" >&2; exit 2; }
[[ "$START_DELAY_SECONDS" =~ ^[0-9]+$ ]] || { echo "[FATAL] delay must be numeric" >&2; exit 2; }
[[ "$SAMPLE_INTERVAL" =~ ^[0-9]+$ ]] || { echo "[FATAL] interval must be numeric" >&2; exit 2; }
[[ "$RECURSIVE_LIMIT_FILES" =~ ^[0-9]+$ ]] || { echo "[FATAL] recursive limit must be numeric" >&2; exit 2; }
[[ "$RECURSIVE_HASH_MODE" =~ ^(code|all|none)$ ]] || { echo "[FATAL] recursive hash mode must be code, all, or none" >&2; exit 2; }
[[ "$PROVENANCE_RAW_EVENT_LIMIT" =~ ^[0-9]+$ ]] || { echo "[FATAL] provenance raw limit must be numeric" >&2; exit 2; }
[[ "$PROVENANCE_MAX_DB_MIB" =~ ^[0-9]+$ ]] || { echo "[FATAL] provenance max db MiB must be numeric" >&2; exit 2; }
[[ -d "$OUT_BASE" ]] || mkdir -p "$OUT_BASE"
OUT_BASE="$(cd "$OUT_BASE" && pwd -P)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"

if ((${#LAUNCH_APPS[@]} == 0)); then
  matcher=(grep -Ei 'Google Chrome\.app$|ChatGPT Atlas.*\.app$|Codex Computer Use\.app$')
  if command -v rg >/dev/null 2>&1; then
    matcher=(rg -i 'Google Chrome\.app$|ChatGPT Atlas.*\.app$|Codex Computer Use\.app$')
  fi
  while IFS= read -r app; do LAUNCH_APPS+=("$app"); done < <(
    find "$SOURCE_ROOT" -maxdepth 7 -type d -name '*.app' 2>/dev/null |
      "${matcher[@]}" |
      sort
  )
fi

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$OUT_BASE/overnight_app_capture_$RUN_TS"
mkdir -p "$RUN_DIR"/{apps,tcc,pcap,process,logs,recursive,provenance,hashes,triage}
LOG="$RUN_DIR/run.log"

log_msg() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG"; }
run_capture() { local out="$1"; shift; { "$@"; } >"$out" 2>&1 || true; }
safe() { printf '%s' "$1" | tr -cs 'A-Za-z0-9._-' '_' | cut -c1-120; }
sha256() { shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'; }

write_manifest() {
  {
    echo "run_dir=$RUN_DIR"
    echo "started_setup_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "duration_seconds=$DURATION_SECONDS"
    echo "start_delay_seconds=$START_DELAY_SECONDS"
    echo "sample_interval=$SAMPLE_INTERVAL"
    echo "source_root=$SOURCE_ROOT"
    echo "pcap_interface=$PCAP_INTERFACE"
    echo "recursive=$RUN_RECURSIVE"
    echo "recursive_hash_mode=$RECURSIVE_HASH_MODE"
    echo "recursive_limit_files=$RECURSIVE_LIMIT_FILES"
    echo "provenance=$RUN_PROVENANCE"
    echo "provenance_raw_event_limit=$PROVENANCE_RAW_EVENT_LIMIT"
    echo "provenance_max_db_mib=$PROVENANCE_MAX_DB_MIB"
    echo "sudo_cached=$(sudo -n true >/dev/null 2>&1 && echo yes || echo no)"
    if ((${#LAUNCH_APPS[@]})); then
      printf 'launch_app=%s\n' "${LAUNCH_APPS[@]}"
    fi
  } > "$RUN_DIR/SESSION_MANIFEST.txt"
  {
    sw_vers 2>/dev/null || true
    echo
    command -v tshark || true
    command -v dumpcap || true
    command -v tcpdump || true
    command -v sqlite3 || true
    tshark --version 2>&1 | head -n 4 || true
  } > "$RUN_DIR/tool_versions.txt"
}

start_provenance() {
  if (( ! RUN_PROVENANCE )); then
    log_msg "Provenance watcher disabled"
    echo ""
    return 0
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    log_msg "python3 unavailable; provenance watcher skipped"
    printf 'python3 unavailable\n' > "$RUN_DIR/provenance/not_started.txt"
    echo ""
    return 0
  fi
  local duration=$((DURATION_SECONDS + (${#LAUNCH_APPS[@]} * 25) + 120))
  log_msg "Starting provenance watcher for ${duration}s"
  python3 "$REPO_ROOT/scripts/provenance_watcher.py" \
    --out-dir "$RUN_DIR/provenance" \
    --duration-seconds "$duration" \
    --sample-interval "$SAMPLE_INTERVAL" \
    --raw-event-limit "$PROVENANCE_RAW_EVENT_LIMIT" \
    --max-db-mib "$PROVENANCE_MAX_DB_MIB" \
    --target "$SOURCE_ROOT" \
    --target "$SOURCE_ROOT/Ellis_Archive" \
    --target "$SOURCE_ROOT/Applications-Staged-From-Sentinel_OS" \
    --target "/private/var/folders" \
    --target "$HOME/Library/Application Support/com.openai.atlas" \
    --target "$HOME/Library/Application Support/Google/Chrome" \
    > "$RUN_DIR/provenance/provenance_watcher.stdout" \
    2> "$RUN_DIR/provenance/provenance_watcher.stderr" &
  echo $!
}

capture_app_static() {
  local app="$1"
  local idx="$2"
  local out="$RUN_DIR/apps/$(printf '%02d_%s' "$idx" "$(safe "$(basename "$app")")")"
  mkdir -p "$out"
  printf '%s\n' "$app" > "$out/app_path.txt"
  if [[ ! -d "$app" ]]; then
    printf 'missing\n' > "$out/status.txt"
    return 0
  fi
  run_capture "$out/ls.txt" ls -laOe@ "$app"
  run_capture "$out/stat.txt" stat "$app"
  run_capture "$out/xattr.txt" xattr -lr "$app"
  run_capture "$out/info_plist.txt" plutil -p "$app/Contents/Info.plist"
  run_capture "$out/codesign_verify_deep.txt" codesign --verify --deep --strict --verbose=4 "$app"
  run_capture "$out/codesign_details.txt" codesign -dvvv --entitlements :- "$app"
  run_capture "$out/spctl_execute.txt" spctl --assess --type execute -vv "$app"
  find "$app" -maxdepth 4 -type f -print0 2>/dev/null | xargs -0 shasum -a 256 > "$out/bundle_hashes_depth4.sha256" 2>/dev/null || true
}

capture_tcc_snapshot() {
  local label="$1"
  local out="$RUN_DIR/tcc/$label"
  mkdir -p "$out"
  local dbs=(
    "$HOME/Library/Application Support/com.apple.TCC/TCC.db"
    "/Library/Application Support/com.apple.TCC/TCC.db"
  )
  local db base copy
  for db in "${dbs[@]}"; do
    base="$(safe "$db")"
    if [[ -r "$db" ]]; then
      copy="$out/${base}.snapshot.db"
      stat "$db" > "$out/${base}.stat.txt" 2>&1 || true
      shasum -a 256 "$db" > "$out/${base}.source.sha256" 2>&1 || true
      cp -p "$db" "$copy" 2>"$out/${base}.copy_error.txt" || true
      chmod 444 "$copy" 2>/dev/null || true
      if [[ -f "$copy" ]]; then
        shasum -a 256 "$copy" > "$out/${base}.snapshot.sha256" 2>&1 || true
        sqlite3 "$copy" ".schema" > "$out/${base}.schema.sql" 2>&1 || true
        sqlite3 -header -csv "$copy" "SELECT * FROM access;" > "$out/${base}.access.csv" 2>&1 || true
        sqlite3 -header -csv "$copy" "SELECT * FROM access WHERE lower(client) LIKE '%atlas%' OR lower(client) LIKE '%openai%' OR lower(client) LIKE '%chrome%' OR lower(client) LIKE '%google%' OR lower(client) LIKE '%codex%';" > "$out/${base}.target_rows.csv" 2>&1 || true
      fi
    else
      printf 'not readable: %s\n' "$db" > "$out/${base}.not_readable.txt"
      if [[ "$db" == /Library/* ]] && sudo -n true >/dev/null 2>&1; then
        sudo stat "$db" > "$out/${base}.sudo_stat.txt" 2>&1 || true
      fi
    fi
  done
}

start_pcap() {
  local duration="$1"
  if command -v tshark >/dev/null 2>&1; then
    log_msg "Starting tshark for ${duration}s on interface ${PCAP_INTERFACE}"
    tshark -i "$PCAP_INTERFACE" -f "not port 22 and not port 3389" -b filesize:100000 -a duration:"$duration" -w "$RUN_DIR/pcap/live_capture.pcapng" -q >"$RUN_DIR/pcap/tshark.stdout" 2>"$RUN_DIR/pcap/tshark.stderr" &
    echo $!
  elif command -v tcpdump >/dev/null 2>&1; then
    log_msg "Starting tcpdump for ${duration}s on interface ${PCAP_INTERFACE}"
    tcpdump -i "$PCAP_INTERFACE" -s 0 -G "$duration" -W 1 -w "$RUN_DIR/pcap/live_capture.pcap" >"$RUN_DIR/pcap/tcpdump.stdout" 2>"$RUN_DIR/pcap/tcpdump.stderr" &
    echo $!
  else
    log_msg "No packet capture tool available"
    echo ""
  fi
}

summarize_pcap() {
  find "$RUN_DIR/pcap" -type f \( -name '*.pcap' -o -name '*.pcapng' \) -print0 2>/dev/null | xargs -0 shasum -a 256 > "$RUN_DIR/pcap/pcap_hashes.sha256" 2>/dev/null || true
  local pcap
  while IFS= read -r pcap; do
    [[ -f "$pcap" ]] || continue
    local stem="$RUN_DIR/pcap/$(safe "$(basename "$pcap")")"
    if command -v tshark >/dev/null 2>&1; then
      tshark -r "$pcap" -q -z endpoints,ip > "${stem}.endpoints_ip.txt" 2>&1 || true
      tshark -r "$pcap" -q -z conv,tcp > "${stem}.tcp_conversations.txt" 2>&1 || true
      tshark -r "$pcap" -Y "dns" -T fields -e frame.time -e ip.src -e ip.dst -e dns.qry.name -E header=y -E separator=$'\t' > "${stem}.dns.tsv" 2>&1 || true
      tshark -r "$pcap" -Y "tls.handshake.extensions_server_name" -T fields -e frame.time -e ip.src -e ip.dst -e tls.handshake.extensions_server_name -E header=y -E separator=$'\t' > "${stem}.tls_sni.tsv" 2>&1 || true
      tshark -r "$pcap" -Y "http.host || http.request.uri" -T fields -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.uri -E header=y -E separator=$'\t' > "${stem}.http.tsv" 2>&1 || true
    fi
  done < <(find "$RUN_DIR/pcap" -type f \( -name '*.pcap' -o -name '*.pcapng' \) -print)
}

launch_apps() {
  printf 'index\tpath\tsha256_depth4\tlaunch_status\n' > "$RUN_DIR/apps/launch_plan.tsv"
  local i=0 app status
  for app in "${LAUNCH_APPS[@]}"; do
    i=$((i+1))
    capture_app_static "$app" "$i"
    status="missing"
    if [[ -d "$app" ]]; then
      log_msg "Launching app: $app"
      if open -n "$app" >"$RUN_DIR/apps/$(printf '%02d' "$i")_open.stdout" 2>"$RUN_DIR/apps/$(printf '%02d' "$i")_open.stderr"; then
        status="launched"
      else
        status="launch_failed"
      fi
    fi
    printf '%s\t%s\t%s\t%s\n' "$i" "$app" "" "$status" >> "$RUN_DIR/apps/launch_plan.tsv"
    sleep 20
  done
}

sample_state() {
  local label="$1"
  local out="$RUN_DIR/process/$label"
  mkdir -p "$out"
  ps auxww > "$out/ps_auxww.txt" 2>&1 || true
  pgrep -afil 'Atlas|ChatGPT|OpenAI|Chrome|Google Chrome|Codex' > "$out/pgrep_targets.txt" 2>&1 || true
  lsof -nP -iTCP -iUDP > "$out/lsof_network.txt" 2>&1 || true
  netstat -anv > "$out/netstat_anv.txt" 2>&1 || true
}

collect_logs() {
  local last_arg="${DURATION_SECONDS}s"
  log show --style syslog --last "$last_arg" --predicate 'process == "tccd" OR eventMessage CONTAINS[c] "TCC" OR eventMessage CONTAINS[c] "atlas" OR eventMessage CONTAINS[c] "openai" OR eventMessage CONTAINS[c] "chrome" OR eventMessage CONTAINS[c] "codex" OR eventMessage CONTAINS[c] "camera" OR eventMessage CONTAINS[c] "microphone" OR eventMessage CONTAINS[c] "screen"' > "$RUN_DIR/logs/correlated_unified_log.log" 2>&1 || true
}

write_reviewer_readme() {
  cat > "$RUN_DIR/REVIEWER_README.md" <<EOF
# Overnight App Capture

Started: $RUN_TS
Duration seconds: $DURATION_SECONDS
Source root: $SOURCE_ROOT

## Review Order

1. \`SESSION_MANIFEST.txt\`
2. \`apps/launch_plan.tsv\` and each app's signing/spctl output
3. \`tcc/pre\`, \`tcc/post_launch\`, and \`tcc/final\`
4. \`pcap/pcap_hashes.sha256\`, endpoint summaries, DNS TSV, TLS SNI TSV, and HTTP TSV
5. \`process/*/pgrep_targets.txt\`, \`lsof_network.txt\`, and \`netstat_anv.txt\`
6. \`logs/correlated_unified_log.log\`
7. \`provenance/provenance.sqlite3\`, \`EVENT_AGGREGATES.csv\`, \`PATH_SUMMARY.csv\`, and \`PROCESS_SUMMARY.csv\`
8. \`recursive/\` if recursive verifier was enabled
9. \`hashes/GLOBAL_MANIFEST.sha256\`

## Notes

- This run intentionally launched selected app bundles so TCC, process, log, and network behavior could be correlated in one window.
- The provenance watcher uses a capped raw-event ring buffer and aggregate SQLite tables to avoid unbounded duplicate logs.
- System TCC requires root. If unavailable, the run logs not-readable markers and still captures user TCC.
- PCAP capture depends on local dumpcap/tshark/tcpdump permissions. Review stderr files under \`pcap/\` for capture limitations.
EOF
}

main() {
  write_manifest
  cp "$0" "$RUN_DIR/overnight_app_capture.sh"
  log_msg "Prepared run directory: $RUN_DIR"
  log_msg "Start delay: ${START_DELAY_SECONDS}s"
  sleep "$START_DELAY_SECONDS"

  log_msg "Capture window starting"
  capture_tcc_snapshot pre
  sample_state pre
  local provenance_pid=""
  provenance_pid="$(start_provenance | tail -n 1)"
  local pcap_pid=""
  pcap_pid="$(start_pcap "$DURATION_SECONDS" | tail -n 1)"
  launch_apps
  capture_tcc_snapshot post_launch
  sample_state post_launch

  local end=$((SECONDS + DURATION_SECONDS))
  local sample=0
  while (( SECONDS < end )); do
    sleep "$SAMPLE_INTERVAL" || true
    sample=$((sample+1))
    sample_state "sample_$(printf '%03d' "$sample")"
    capture_tcc_snapshot "sample_$(printf '%03d' "$sample")"
  done

  if [[ -n "$pcap_pid" ]]; then
    wait "$pcap_pid" 2>/dev/null || true
  fi
  if [[ -n "$provenance_pid" ]]; then
    wait "$provenance_pid" 2>/dev/null || true
  fi
  capture_tcc_snapshot final
  sample_state final
  collect_logs
  summarize_pcap

  if (( RUN_RECURSIVE )); then
    log_msg "Starting recursive verifier on $SOURCE_ROOT"
    "$REPO_ROOT/recursive_macos_volume_verify.sh" \
      --allow-writable \
      --out-base "$RUN_DIR/recursive" \
      --case overnight_recursive \
      --hash-mode "$RECURSIVE_HASH_MODE" \
      --limit-files "$RECURSIVE_LIMIT_FILES" \
      "$SOURCE_ROOT" > "$RUN_DIR/recursive/recursive.stdout" 2> "$RUN_DIR/recursive/recursive.stderr" || true
  fi

  write_reviewer_readme
  find "$RUN_DIR" -type f ! -path "$RUN_DIR/hashes/GLOBAL_MANIFEST.sha256" -print0 | sort -z | xargs -0 shasum -a 256 > "$RUN_DIR/hashes/GLOBAL_MANIFEST.sha256"
  log_msg "Capture complete: $RUN_DIR"
  echo "$RUN_DIR"
}

main "$@"
