#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
OUT_BASE="${1:-/Volumes/Evidence}"
SOURCE_ROOT="${2:-/Volumes/Storage}"
MOBILE_BACKUP_ROOT="${3:-$HOME/Library/Application Support/MobileSync/Backup}"
PCAP_INTERFACE="${PCAP_INTERFACE:-$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}')}"
PCAP_INTERFACE="${PCAP_INTERFACE:-en0}"
RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$OUT_BASE/007_go_plan_detached_$RUN_TS.log"

mkdir -p "$OUT_BASE"
cd "$REPO_ROOT"

nohup bash -c '
  set -euo pipefail
  log="$1"; out_base="$2"; source_root="$3"; mobile_backup_root="$4"; repo_root="$5"; pcap_interface="$6"
  exec </dev/null
  exec >>"$log" 2>&1
  echo "supervisor_started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "out_base=$out_base"
  echo "source_root=$source_root"
  echo "mobile_backup_root=$mobile_backup_root"
  echo "pcap_interface=$pcap_interface"
  exec bash "$repo_root/scripts/run_007_go_plan.sh" \
    --case 007_go_plan \
    --out-base "$out_base" \
    --source-root "$source_root" \
    --mobile-backup-root "$mobile_backup_root" \
    --pcap-interface "$pcap_interface" \
    --duration-seconds 10800 \
    --sample-interval 300 \
    --recursive-hash-mode all \
    --recursive-limit-files 0
' _ "$LOG" "$OUT_BASE" "$SOURCE_ROOT" "$MOBILE_BACKUP_ROOT" "$REPO_ROOT" "$PCAP_INTERFACE" >/dev/null 2>&1 &

PID=$!
echo "$PID" > "$OUT_BASE/007_go_plan_detached_$RUN_TS.pid"
printf 'pid=%s\nlog=%s\n' "$PID" "$LOG"
