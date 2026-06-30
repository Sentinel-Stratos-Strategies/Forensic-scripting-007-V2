#!/usr/bin/env bash
# Sequential 007 go-plan launcher with macOS notifications and resumable status.
set -Eeuo pipefail
IFS=$'\n\t'

PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin:$PATH"
export PATH LC_ALL=C LANG=C

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CASE_NAME="007_go_plan"
OUT_BASE="/Volumes/Evidence"
SOURCE_ROOT="/Volumes/Storage"
MOBILE_BACKUP_ROOT="$HOME/Library/Application Support/MobileSync/Backup"
PCAP_INTERFACE="any"
DURATION_SECONDS=12600
SAMPLE_INTERVAL=300
RECURSIVE_HASH_MODE="all"
RECURSIVE_LIMIT_FILES=0
RUN_RECURSIVE=1
APP_WATCH_CYCLES=2
APP_WATCH_INTERVAL=15
RECENT_MAX_DEPTH=6
RECENT_HASH_LIMIT=$((8 * 1024 * 1024))
MIN_FREE_GB=10
CUTOFF="$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"
SMOKE=0
LAUNCH_APPS=()
HYDRATE_REPORTS=()

usage() {
  cat <<'USAGE'
Usage: scripts/run_007_go_plan.sh [options]

Options:
  --case NAME                 Case/run name prefix (default: 007_go_plan)
  --out-base DIR              Output parent directory (default: /Volumes/Evidence)
  --source-root DIR           Evidence/source root (default: /Volumes/Storage)
  --mobile-backup-root DIR    MobileSync backup root
  --duration-seconds N        Live capture duration (default: 12600)
  --sample-interval N         Live sample interval (default: 300)
  --pcap-interface IFACE      PCAP interface (default: any)
  --launch-app PATH           App bundle to launch and inventory; repeatable
  --hydrate-report PATH       Hydrate JSON/CSV report to copy into the run; repeatable
  --cutoff ISO_TIME           Recent artifact cutoff (default: UTC now minus 7 days on macOS)
  --recent-max-depth N        Recent artifact scan depth (default: 6)
  --recent-hash-limit N       Recent artifact hash size limit (default: 8 MiB)
  --min-free-gb N             Required free GiB on output volume (default: 10)
  --recursive-hash-mode MODE  code|all|none (default: all)
  --recursive-limit-files N   Recursive verifier file limit (default: 0)
  --no-recursive              Skip recursive verifier inside live capture
  --smoke                     Short smoke run: 60s live capture, no recursive verifier
  -h, --help                  Show help

Run sudo -v before launching if you want root-readable TCC/packet-capture evidence.
USAGE
}

while (($#)); do
  case "$1" in
    --case) CASE_NAME="${2:?missing case name}"; shift 2 ;;
    --out-base) OUT_BASE="${2:?missing output base}"; shift 2 ;;
    --source-root) SOURCE_ROOT="${2:?missing source root}"; shift 2 ;;
    --mobile-backup-root) MOBILE_BACKUP_ROOT="${2:?missing MobileSync root}"; shift 2 ;;
    --duration-seconds) DURATION_SECONDS="${2:?missing duration}"; shift 2 ;;
    --sample-interval) SAMPLE_INTERVAL="${2:?missing interval}"; shift 2 ;;
    --pcap-interface) PCAP_INTERFACE="${2:?missing interface}"; shift 2 ;;
    --launch-app) LAUNCH_APPS+=("${2:?missing app path}"); shift 2 ;;
    --hydrate-report) HYDRATE_REPORTS+=("${2:?missing report path}"); shift 2 ;;
    --cutoff) CUTOFF="${2:?missing cutoff}"; shift 2 ;;
    --recent-max-depth) RECENT_MAX_DEPTH="${2:?missing depth}"; shift 2 ;;
    --recent-hash-limit) RECENT_HASH_LIMIT="${2:?missing hash limit}"; shift 2 ;;
    --min-free-gb) MIN_FREE_GB="${2:?missing free GiB}"; shift 2 ;;
    --recursive-hash-mode) RECURSIVE_HASH_MODE="${2:?missing mode}"; shift 2 ;;
    --recursive-limit-files) RECURSIVE_LIMIT_FILES="${2:?missing limit}"; shift 2 ;;
    --no-recursive) RUN_RECURSIVE=0; shift ;;
    --smoke) SMOKE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[FATAL] unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if (( SMOKE )); then
  DURATION_SECONDS=60
  SAMPLE_INTERVAL=20
  RUN_RECURSIVE=0
  APP_WATCH_CYCLES=1
  APP_WATCH_INTERVAL=1
  RECENT_MAX_DEPTH=2
  RECURSIVE_HASH_MODE="none"
  RECURSIVE_LIMIT_FILES=100
fi

[[ "$DURATION_SECONDS" =~ ^[0-9]+$ ]] || { echo "[FATAL] bad duration" >&2; exit 2; }
[[ "$SAMPLE_INTERVAL" =~ ^[0-9]+$ ]] || { echo "[FATAL] bad sample interval" >&2; exit 2; }
[[ "$RECENT_MAX_DEPTH" =~ ^[0-9]+$ ]] || { echo "[FATAL] bad recent max depth" >&2; exit 2; }
[[ "$RECENT_HASH_LIMIT" =~ ^[0-9]+$ ]] || { echo "[FATAL] bad recent hash limit" >&2; exit 2; }
[[ "$MIN_FREE_GB" =~ ^[0-9]+$ ]] || { echo "[FATAL] bad min free GiB" >&2; exit 2; }
[[ "$RECURSIVE_LIMIT_FILES" =~ ^[0-9]+$ ]] || { echo "[FATAL] bad recursive limit" >&2; exit 2; }
[[ "$RECURSIVE_HASH_MODE" =~ ^(code|all|none)$ ]] || { echo "[FATAL] recursive hash mode must be code, all, or none" >&2; exit 2; }

mkdir -p "$OUT_BASE"
OUT_BASE="$(cd "$OUT_BASE" && pwd -P)"
RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$OUT_BASE/${CASE_NAME}_${RUN_TS}"
mkdir -p "$RUN_DIR"/{logs,database,iphone_host_snapshot,ios_backup_app_verify,prelaunch,app_watch_pre,live_capture,bundle_inventory,cache_scan,recent_artifacts,hydrate_import,hashes}

LOG="$RUN_DIR/logs/go_plan.log"
STATUS_FILE="$RUN_DIR/GO_PLAN_STATUS.txt"
LOCK_DIR="$OUT_BASE/.${CASE_NAME}.lock"

notify() {
  local message="$1"
  if command -v osascript >/dev/null 2>&1; then
    /usr/bin/osascript -e "display notification \"${message//\"/\\\"}\" with title \"007 Go Plan\"" >/dev/null 2>&1 || true
  fi
}

log_msg() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG"
}

write_status() {
  local tmp="$STATUS_FILE.tmp.$$"
  {
    echo "run_dir=$RUN_DIR"
    echo "case=$CASE_NAME"
    echo "status=$1"
    echo "phase=${2:-}"
    echo "updated_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "log=$LOG"
  } > "$tmp"
  mv -f "$tmp" "$STATUS_FILE"
}

preflight_validate() {
  [[ "$(uname -s)" == "Darwin" ]] || { echo "[FATAL] macOS required for TCC/log/LaunchServices collectors"; return 2; }
  [[ -d "$SOURCE_ROOT" ]] || { echo "[FATAL] source root missing: $SOURCE_ROOT"; return 2; }
  [[ -d "$OUT_BASE" ]] || { echo "[FATAL] output root missing: $OUT_BASE"; return 2; }
  [[ -w "$OUT_BASE" ]] || { echo "[FATAL] output root not writable: $OUT_BASE"; return 2; }
  local free_kib min_kib
  free_kib="$(df -k "$OUT_BASE" | awk 'NR==2 {print $4}')"
  min_kib=$((MIN_FREE_GB * 1024 * 1024))
  if [[ -n "$free_kib" && "$free_kib" -lt "$min_kib" ]]; then
    echo "[FATAL] output root has less than ${MIN_FREE_GB}GiB free: $OUT_BASE"
    return 2
  fi
  for tool in python3 find sort shasum; do
    command -v "$tool" >/dev/null 2>&1 || { echo "[FATAL] required tool missing: $tool"; return 2; }
  done
  {
    echo "preflight_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "uname=$(uname -a)"
    echo "out_base=$OUT_BASE"
    echo "source_root=$SOURCE_ROOT"
    echo "mobile_backup_root=$MOBILE_BACKUP_ROOT"
    echo "min_free_gb=$MIN_FREE_GB"
    df -h "$OUT_BASE" "$SOURCE_ROOT" 2>/dev/null || true
    echo
    for tool in python3 sqlite3 osascript log system_profiler tshark tcpdump rg grep; do
      printf '%s=' "$tool"
      command -v "$tool" || true
    done
  } > "$RUN_DIR/PREFLIGHT.txt"
}

phase() {
  local name="$1"
  shift
  write_status "running" "$name"
  notify "Starting: $name"
  log_msg "START $name"
  local start end rc
  start=$(date +%s)
  set +e
  "$@" >>"$LOG" 2>&1
  rc=$?
  set -e
  end=$(date +%s)
  if (( rc == 0 )); then
    log_msg "END $name rc=0 elapsed=$((end - start))s"
    notify "Finished: $name"
  else
    log_msg "FAIL $name rc=$rc elapsed=$((end - start))s"
    write_status "failed" "$name"
    notify "FAILED: $name"
    exit "$rc"
  fi
}

cleanup() {
  if [[ -f "$LOCK_DIR/pid" ]] && [[ "$(cat "$LOCK_DIR/pid" 2>/dev/null)" == "$$" ]]; then
    rm -rf "$LOCK_DIR"
  fi
}
trap cleanup EXIT

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  if [[ -f "$LOCK_DIR/pid" ]] && ! kill -0 "$(cat "$LOCK_DIR/pid" 2>/dev/null)" 2>/dev/null; then
    rm -rf "$LOCK_DIR"
    mkdir "$LOCK_DIR" 2>/dev/null || {
      echo "[FATAL] stale go-plan lock could not be replaced: $LOCK_DIR" >&2
      exit 3
    }
  else
    echo "[FATAL] another go-plan run appears active: $LOCK_DIR" >&2
    exit 3
  fi
fi
printf '%s\n' "$$" > "$LOCK_DIR/pid"

discover_apps() {
  if ((${#LAUNCH_APPS[@]} > 0)); then
    return
  fi
  local matcher=(grep -Ei 'Google Chrome\.app$|ChatGPT Atlas.*\.app$|Codex\.app$|Codex Computer Use\.app$')
  if command -v rg >/dev/null 2>&1; then
    matcher=(rg -i 'Google Chrome\.app$|ChatGPT Atlas.*\.app$|Codex\.app$|Codex Computer Use\.app$')
  fi
  while IFS= read -r app; do
    LAUNCH_APPS+=("$app")
  done < <(
    find "$SOURCE_ROOT" /Applications "$HOME/.codex" -maxdepth 8 -type d -name '*.app' 2>/dev/null |
      "${matcher[@]}" |
      sort -u
  )
}

write_case_manifest() {
  discover_apps
  {
    echo "case=$CASE_NAME"
    echo "run_dir=$RUN_DIR"
    echo "repo_root=$REPO_ROOT"
    echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "source_root=$SOURCE_ROOT"
    echo "mobile_backup_root=$MOBILE_BACKUP_ROOT"
    echo "out_base=$OUT_BASE"
    echo "duration_seconds=$DURATION_SECONDS"
    echo "sample_interval=$SAMPLE_INTERVAL"
    echo "pcap_interface=$PCAP_INTERFACE"
    echo "recursive=$RUN_RECURSIVE"
    echo "recursive_hash_mode=$RECURSIVE_HASH_MODE"
    echo "recursive_limit_files=$RECURSIVE_LIMIT_FILES"
    echo "cutoff=$CUTOFF"
    echo "smoke=$SMOKE"
    echo "sudo_cached=$(sudo -n true >/dev/null 2>&1 && echo yes || echo no)"
    if ((${#LAUNCH_APPS[@]})); then
      printf 'launch_app=%s\n' "${LAUNCH_APPS[@]}"
    fi
    printf 'hydrate_report=%s\n' "${HYDRATE_REPORTS[@]:-}"
  } > "$RUN_DIR/CASE_CONTEXT.env"
}

init_databases() {
  "$REPO_ROOT/scripts/init_007_databases.py" --out-dir "$RUN_DIR/database"
}

prelaunch_apps() {
  discover_apps
  local app rc
  : > "$RUN_DIR/prelaunch/targets.txt"
  : > "$RUN_DIR/prelaunch/open_results.tsv"
  printf 'timestamp_utc\treturn_code\tapp\n' > "$RUN_DIR/prelaunch/open_results.tsv"

  for app in "${LAUNCH_APPS[@]+"${LAUNCH_APPS[@]}"}"; do
    [[ -d "$app" ]] || continue
    printf '%s\n' "$app" >> "$RUN_DIR/prelaunch/targets.txt"
    notify "Prelaunching: $(basename "$app")"
    set +e
    /usr/bin/open "$app" >/dev/null 2>&1
    rc=$?
    set -e
    printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$rc" "$app" >> "$RUN_DIR/prelaunch/open_results.tsv"
    sleep 3
  done

  sleep 15
  ps axww -o pid,ppid,user,stat,lstart,command > "$RUN_DIR/prelaunch/ps_after_prelaunch.txt" || true
  pgrep -af 'ChatGPT Atlas|Google Chrome|Codex|Codex Computer Use|CUAService|SkyComputerUse|OpenAI|Chrome' \
    > "$RUN_DIR/prelaunch/pgrep_after_prelaunch.txt" 2>/dev/null || true
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP -iUDP > "$RUN_DIR/prelaunch/lsof_network_after_prelaunch.txt" 2>/dev/null || true
  fi
}

iphone_snapshot() {
  "$REPO_ROOT/scripts/hydrate/iphone_host_snapshot.py" \
    --out-dir "$RUN_DIR/iphone_host_snapshot" \
    --log-minutes 120 \
    --backup-root "$MOBILE_BACKUP_ROOT"
}

ios_backup_app_verify() {
  "$REPO_ROOT/scripts/hydrate/ios_backup_app_verify.py" \
    --backup-root "$MOBILE_BACKUP_ROOT" \
    --out-dir "$RUN_DIR/ios_backup_app_verify" \
    --pattern openai \
    --pattern chatgpt \
    --pattern atlas \
    --pattern chrome \
    --pattern google \
    --pattern codex \
    --pattern perplexity \
    --pattern comet
}

app_watch_pre() {
  "$REPO_ROOT/scripts/hydrate/app_watch.py" \
    --apps atlas chrome codex \
    --out-dir "$RUN_DIR/app_watch_pre" \
    --cycles "$APP_WATCH_CYCLES" \
    --interval "$APP_WATCH_INTERVAL" \
    --recent-seconds 1800 \
    --file-limit 200
}

live_capture() {
  local cmd=(
    "$REPO_ROOT/scripts/overnight_app_capture.sh"
    --start-delay-seconds 0
    --duration-seconds "$DURATION_SECONDS"
    --sample-interval "$SAMPLE_INTERVAL"
    --out-base "$RUN_DIR/live_capture"
    --source-root "$SOURCE_ROOT"
    --pcap-interface "$PCAP_INTERFACE"
    --recursive-hash-mode "$RECURSIVE_HASH_MODE"
    --recursive-limit-files "$RECURSIVE_LIMIT_FILES"
  )
  (( RUN_RECURSIVE )) || cmd+=(--no-recursive)
  local app
  for app in "${LAUNCH_APPS[@]+"${LAUNCH_APPS[@]}"}"; do
    [[ -d "$app" ]] && cmd+=(--launch-app "$app")
  done
  "${cmd[@]}" | tee "$RUN_DIR/live_capture/overnight_app_capture.stdout"
}

bundle_inventory() {
  local targets=()
  local app
  for app in "${LAUNCH_APPS[@]+"${LAUNCH_APPS[@]}"}"; do
    [[ -d "$app" ]] && targets+=("$app")
  done
  if ((${#targets[@]} == 0)); then
    echo "No app bundle targets found; skipping bundle inventory"
    return 0
  fi
  "$REPO_ROOT/scripts/hydrate/bundle_binary_inventory.py" \
    --out-dir "$RUN_DIR/bundle_inventory" \
    "${targets[@]}"
}

cache_scan() {
  local roots=(
    "$HOME/Library/Application Support/Google/Chrome"
    "$HOME/.codex"
    "$HOME/Library/Application Support/ChatGPT Atlas"
    "$HOME/Library/Application Support/com.openai.atlas"
  )
  local root safe
  for root in "${roots[@]}"; do
    [[ -e "$root" ]] || continue
    safe="$(printf '%s' "$root" | tr -cs 'A-Za-z0-9._-' '_' | cut -c1-80)"
    "$REPO_ROOT/scripts/hydrate/cache_forensic_scan.py" \
      --scope "$root" \
      --outdir "$RUN_DIR/cache_scan/$safe" \
      --recent-hours 168 \
      --indicator "ChatGPT Atlas" \
      --indicator "com.openai.codex" \
      --indicator "kTCCServiceSystemPolicyAllFiles" \
      --indicator "MobileSync" \
      --indicator "ConfigurationProfiles"
  done
}

recent_artifacts() {
  local roots=()
  [[ -e "$SOURCE_ROOT" ]] && roots+=("$SOURCE_ROOT")
  [[ -e "$MOBILE_BACKUP_ROOT" ]] && roots+=("$MOBILE_BACKUP_ROOT")
  if ((${#roots[@]} == 0)); then
    echo "No recent artifact roots found; skipping"
    return 0
  fi
  "$REPO_ROOT/scripts/hydrate/recent_artifact_window.py" \
    --out-dir "$RUN_DIR/recent_artifacts" \
    --cutoff "$CUTOFF" \
    --max-depth "$RECENT_MAX_DEPTH" \
    --hash-limit "$RECENT_HASH_LIMIT" \
    "${roots[@]}"
}

hydrate_import() {
  local report
  for report in "${HYDRATE_REPORTS[@]}"; do
    if [[ -f "$report" ]]; then
      cp -p "$report" "$RUN_DIR/hydrate_import/"
    else
      echo "Hydrate report missing: $report"
    fi
  done
}

final_manifest() {
  find "$RUN_DIR" -type f ! -path "$RUN_DIR/hashes/HASH_MANIFEST.sha256" -print0 |
    sort -z |
    xargs -0 shasum -a 256 > "$RUN_DIR/hashes/HASH_MANIFEST.sha256"
  {
    echo "# 007 Go Plan Reviewer README"
    echo
    echo "- Run dir: \`$RUN_DIR\`"
    echo "- Status: complete"
    echo "- Main log: \`$LOG\`"
    echo "- Status file: \`$STATUS_FILE\`"
    echo "- Databases: \`database/\`"
    echo "- Live capture: \`live_capture/\`"
    echo "- Hydrate/iPhone lane: \`iphone_host_snapshot/\`, \`hydrate_import/\`"
    echo "- iOS backup app verification: \`ios_backup_app_verify/\`"
    echo "- App evidence: \`app_watch_pre/\`, \`bundle_inventory/\`, \`cache_scan/\`"
    echo "- Recent artifact window: \`recent_artifacts/\`"
    echo "- Hash manifest: \`hashes/HASH_MANIFEST.sha256\`"
  } > "$RUN_DIR/REVIEWER_README.md"
}

write_status "starting" "preflight"
notify "Starting 007 go-plan launcher"
preflight_validate
phase "preflight and case manifest" write_case_manifest
phase "initialize 007 databases" init_databases
phase "iPhone host and MobileSync snapshot" iphone_snapshot
phase "iOS backup app verification" ios_backup_app_verify
phase "prelaunch target apps" prelaunch_apps
phase "pre-live app watch snapshot" app_watch_pre
phase "live TCC PCAP app-launch recursive capture" live_capture
phase "bundle and Mach-O inventory" bundle_inventory
phase "cache forensic scan" cache_scan
phase "recent artifact window scan" recent_artifacts
phase "Hydrate report import" hydrate_import
phase "final hash manifest and README" final_manifest
write_status "complete" "done"
notify "007 go-plan complete"
log_msg "COMPLETE $RUN_DIR"
echo "$RUN_DIR"
