#!/usr/bin/env bash
# Run the LLM/AI forensic detector suite and optional recursive volume verification.
set -Eeuo pipefail
IFS=$'\n\t'

PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin:$PATH"
export PATH LC_ALL=C LANG=C

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
INPUT_ROOT="/Volumes/Storage"
OUTPUT_BASE="/Volumes/Evidence"
CASE_NAME="forensic_suite"
RUN_RECURSIVE=1
HASH_MODE="code"
LIMIT_FILES=0
PYTHON_BIN="${PYTHON:-python3}"
MAX_TEXT_MB=16
ALLOW_WRITABLE_SOURCE=0
INSPECT_DMG_CONTENTS=0

usage() {
  cat <<'USAGE'
Usage: scripts/master_detector.sh [options]

Options:
  --input DIR          Directory or mounted volume to recursively inspect (default: /Volumes/Storage)
  --output DIR         Parent directory for report output (default: /Volumes/Evidence)
  --case NAME          Case name prefix (default: forensic_suite)
  --hash-mode MODE     Recursive verifier hash mode: code|all|none (default: code)
  --limit-files N      Stop recursive verifier after N regular files per source (default: 0/unlimited)
  --max-text-mb N      Maximum text-file size searched by recursive verifier (default: 16)
  --allow-writable     Permit recursive verifier to scan a writable source volume
  --inspect-dmg-contents
                       Mount DMGs read-only and inventory their contents
  --python PATH        Python interpreter to run detectors (default: python3 or $PYTHON)
  --no-recursive       Skip recursive volume verification
  -h, --help           Show help

The script is read-only against the input path. It writes a timestamped report directory under --output.
USAGE
}

while (($#)); do
  case "$1" in
    --input) INPUT_ROOT="${2:?missing input directory}"; shift 2 ;;
    --output) OUTPUT_BASE="${2:?missing output directory}"; shift 2 ;;
    --case) CASE_NAME="${2:?missing case name}"; shift 2 ;;
    --hash-mode) HASH_MODE="${2:?missing hash mode}"; shift 2 ;;
    --limit-files) LIMIT_FILES="${2:?missing file limit}"; shift 2 ;;
    --max-text-mb) MAX_TEXT_MB="${2:?missing max text size}"; shift 2 ;;
    --allow-writable) ALLOW_WRITABLE_SOURCE=1; shift ;;
    --inspect-dmg-contents) INSPECT_DMG_CONTENTS=1; shift ;;
    --python) PYTHON_BIN="${2:?missing python path}"; shift 2 ;;
    --no-recursive) RUN_RECURSIVE=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[FATAL] Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -d "$INPUT_ROOT" || -e "$INPUT_ROOT" ]] || { echo "[FATAL] input not found: $INPUT_ROOT" >&2; exit 2; }
[[ "$HASH_MODE" =~ ^(code|all|none)$ ]] || { echo "[FATAL] bad --hash-mode: $HASH_MODE" >&2; exit 2; }
[[ "$LIMIT_FILES" =~ ^[0-9]+$ ]] || { echo "[FATAL] --limit-files must be numeric" >&2; exit 2; }
[[ "$MAX_TEXT_MB" =~ ^[0-9]+$ ]] || { echo "[FATAL] --max-text-mb must be numeric" >&2; exit 2; }
mkdir -p "$OUTPUT_BASE"
OUTPUT_BASE="$(cd "$OUTPUT_BASE" && pwd -P)"

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUTPUT_DIR="$OUTPUT_BASE/${CASE_NAME}_${RUN_TS}"
mkdir -p "$OUTPUT_DIR"/detectors
LOG="$OUTPUT_DIR/run.log"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG"
}

run_detector() {
  local name="$1"
  local script="$2"
  shift 2

  log "Running $name"
  if [[ ! -f "$script" ]]; then
    printf '[WARN] missing detector: %s\n' "$script" | tee -a "$LOG"
    return 0
  fi

  (
    cd "$OUTPUT_DIR/detectors"
    "$PYTHON_BIN" "$script" "$@"
  ) >"$OUTPUT_DIR/detectors/${name}_output.txt" 2>&1 || {
    printf '[WARN] detector exited non-zero: %s\n' "$name" | tee -a "$LOG"
  }
}

{
  echo "case=$CASE_NAME"
  echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "repo_root=$REPO_ROOT"
  echo "input_root=$INPUT_ROOT"
  echo "output_dir=$OUTPUT_DIR"
  echo "python=$("$PYTHON_BIN" --version 2>&1 || true)"
  echo "hash_mode=$HASH_MODE"
  echo "limit_files=$LIMIT_FILES"
  echo "max_text_mb=$MAX_TEXT_MB"
  echo "allow_writable_source=$ALLOW_WRITABLE_SOURCE"
  echo "inspect_dmg_contents=$INSPECT_DMG_CONTENTS"
} > "$OUTPUT_DIR/CASE_MANIFEST.txt"

log "Output directory: $OUTPUT_DIR"
run_detector "Anomaly_Detection" "$REPO_ROOT/scripts/anomaly_detector.py"
run_detector "Signature_Detection" "$REPO_ROOT/scripts/signature_detector.py"
run_detector "Behavioral_Analysis" "$REPO_ROOT/scripts/behavioral_analyzer.py" "-d" "5"
run_detector "Persistence_Detection" "$REPO_ROOT/scripts/persistence_detector.py"
run_detector "Log_Analysis" "$REPO_ROOT/scripts/log_analyzer.py"

if (( RUN_RECURSIVE )); then
  log "Running recursive macOS volume verifier against $INPUT_ROOT"
  recursive_cmd=("$REPO_ROOT/recursive_macos_volume_verify.sh" \
    --out-base "$OUTPUT_DIR" \
    --case "${CASE_NAME}_recursive" \
    --hash-mode "$HASH_MODE" \
    --limit-files "$LIMIT_FILES" \
    --max-text-mb "$MAX_TEXT_MB" \
  )
  (( ALLOW_WRITABLE_SOURCE )) && recursive_cmd+=(--allow-writable)
  (( INSPECT_DMG_CONTENTS )) && recursive_cmd+=(--inspect-dmg-contents)
  recursive_cmd+=("$INPUT_ROOT")
  "${recursive_cmd[@]}" >"$OUTPUT_DIR/recursive_verify.stdout" 2>"$OUTPUT_DIR/recursive_verify.stderr" || {
      printf '[WARN] recursive verifier exited non-zero\n' | tee -a "$LOG"
    }
fi

SUMMARY_FILE="$OUTPUT_DIR/SUMMARY_REPORT.txt"
{
  echo "LLM/AI Forensic Detection Suite"
  echo "================================"
  echo
  echo "Scan Date UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Input: $INPUT_ROOT"
  echo "Output: $OUTPUT_DIR"
  echo
  echo "Detector Reports"
  echo "----------------"
  for report in "$OUTPUT_DIR"/detectors/*_report.json; do
    [[ -f "$report" ]] || continue
    printf '%s\tfindings=%s\n' "$(basename "$report")" "$(grep -o '\"type\"' "$report" | wc -l | tr -d ' ')"
  done
  echo
  echo "Recursive Evidence"
  echo "------------------"
  if (( RUN_RECURSIVE )); then
    sed -n '1,3p' "$OUTPUT_DIR/recursive_verify.stdout" 2>/dev/null || true
  else
    echo "Skipped by --no-recursive"
  fi
  echo
  echo "Next Reviewer Paths"
  echo "-------------------"
  echo "CASE_MANIFEST.txt"
  echo "detectors/"
  echo "recursive verifier output directory listed in recursive_verify.stdout"
  echo "run.log"
} > "$SUMMARY_FILE"

find "$OUTPUT_DIR" -type f ! -name output_hashes.sha256 -print0 | sort -z | xargs -0 shasum -a 256 > "$OUTPUT_DIR/output_hashes.sha256"
log "Complete: $OUTPUT_DIR"
echo "$OUTPUT_DIR"
