#!/usr/bin/env bash
# Lightweight status probe for 007 go-plan runs.
set -uo pipefail
IFS=$'\n\t'

OUT_BASE="${1:-/Volumes/Evidence}"
CASE_GLOB="${2:-*007_go_plan_*}"

printf '007 status check UTC: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'out_base=%s\n' "$OUT_BASE"

if [[ ! -d "$OUT_BASE" ]]; then
  echo "out_base_missing=yes"
  exit 0
fi

RUN_DIR="$(
  find "$OUT_BASE" -maxdepth 1 -type d -name "$CASE_GLOB" -print0 2>/dev/null |
    xargs -0 ls -td 2>/dev/null |
    head -n 1
)"

if [[ -z "$RUN_DIR" ]]; then
  echo "run_dir_missing=yes"
else
  printf 'run_dir=%s\n' "$RUN_DIR"
  if [[ -f "$RUN_DIR/GO_PLAN_STATUS.txt" ]]; then
    echo
    echo "== GO_PLAN_STATUS.txt =="
    sed -n '1,80p' "$RUN_DIR/GO_PLAN_STATUS.txt"
  fi
  if [[ -f "$RUN_DIR/logs/go_plan.log" ]]; then
    echo
    echo "== go_plan.log tail =="
    tail -n 40 "$RUN_DIR/logs/go_plan.log"
  fi
  echo
  echo "== run folder sizes =="
  du -sh "$RUN_DIR" "$RUN_DIR"/* 2>/dev/null | sort -h | tail -n 20
  echo
  echo "== newest files =="
  find "$RUN_DIR" -type f -print0 2>/dev/null |
    xargs -0 ls -lt 2>/dev/null |
    head -n 20
fi

echo
echo "== app/process watch =="
pgrep -af 'ChatGPT Atlas|Google Chrome|Codex|Codex Computer Use|CUAService|SkyComputerUse|OpenAI|Chrome' 2>/dev/null || true

echo
echo "== mounted volumes =="
df -h "$OUT_BASE" /Volumes/Storage 2>/dev/null || true
