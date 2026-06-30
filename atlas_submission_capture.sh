#!/usr/bin/env bash
# Build a read-only, reviewer-friendly macOS app evidence packet for bug bounty submissions.
# Captures recursive bundle inventories, signing/notarization evidence, TCC state, recent logs,
# optional packet capture, terminal transcript, login history, and tamper-evident hashes.
set -Eeuo pipefail
IFS=$'\n\t'

PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin:$PATH"
export PATH LC_ALL=C LANG=C

usage() {
  cat <<'USAGE'
Usage:
  atlas_submission_capture.sh <manifest.csv> [output_base] [options]

Manifest header:
  name,suspect_app,baseline_app,process_match,pcap_glob,extra_glob

Options:
  --pcap-duration SEC       Run tcpdump for SEC seconds when available (default: 0/off)
  --pcap-interface IFACE    tcpdump interface (default: any)
  --log-lookback DUR        macOS log lookback for tccd/process evidence (default: 2h)
  --no-zip                  Do not create final zip archive
  -h, --help                Show help

Safety:
  Read-only against target apps. Does not sudo, strip quarantine, mutate bundles, or execute suspect code.
USAGE
}

MANIFEST="${1:-}"
OUT_BASE="$PWD"
[[ $# -ge 1 ]] && shift
if [[ $# -ge 1 && "${1}" != -* ]]; then
  OUT_BASE="$1"
  shift
fi
PCAP_DURATION=0
PCAP_INTERFACE=""
LOG_LOOKBACK="2h"
MAKE_ZIP=1

while (($#)); do
  case "$1" in
    --pcap-duration) PCAP_DURATION="${2:?missing seconds}"; shift 2 ;;
    --pcap-interface) PCAP_INTERFACE="${2:?missing interface}"; shift 2 ;;
    --log-lookback) LOG_LOOKBACK="${2:?missing duration}"; shift 2 ;;
    --no-zip) MAKE_ZIP=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[FATAL] Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "$MANIFEST" && -f "$MANIFEST" ]] || { usage >&2; echo "[FATAL] manifest not found: $MANIFEST" >&2; exit 2; }
[[ "$PCAP_DURATION" =~ ^[0-9]+$ ]] || { echo "[FATAL] --pcap-duration must be an integer" >&2; exit 2; }
mkdir -p "$OUT_BASE"
OUT_BASE="$(cd "$OUT_BASE" && pwd -P)"
RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$OUT_BASE/bug_bounty_evidence_$RUN_TS"
mkdir -p "$RUN_DIR"
LOG="$RUN_DIR/run.log"
SUMMARY="$RUN_DIR/summary.tsv"
ARTIFACTS="$RUN_DIR/artifact_summary.tsv"
printf 'case\trole\tpath\tsha256\tsize\tbirth_utc\tmtime_utc\tbundle_id\tteam_id\tcodesign\tspctl\tnotes\n' > "$SUMMARY"
printf 'case\trole\ttype\tpath\tsha256\tsize\tbirth_utc\tmtime_utc\tbundle_id\tteam_id\tnotes\n' > "$ARTIFACTS"

log(){ printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG"; }
safe(){ printf '%s' "$1" | tr -cs 'A-Za-z0-9._-' '_'; }
sha256(){ shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'; }
stat_field(){ stat -f "$1" "$2" 2>/dev/null || true; }
iso_epoch(){ [[ "${1:-}" =~ ^[0-9]+$ && "$1" -gt 0 ]] && date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true; }
plist_get(){ /usr/libexec/PlistBuddy -c "Print :$2" "$1" 2>/dev/null || plutil -extract "$2" raw -o - "$1" 2>/dev/null || true; }

csv_to_tsv() {
  python3 - "$1" <<'PY'
import csv, sys
with open(sys.argv[1], newline='') as f:
    for row in csv.DictReader(f):
        print('\t'.join(row.get(k,'') for k in ['name','suspect_app','baseline_app','process_match','pcap_glob','extra_glob']))
PY
}

run_capture(){ local out="$1"; shift; { "$@"; } >"$out" 2>&1 || true; }
copy_if_present(){ local pat="$1" dest="$2"; [[ -n "$pat" ]] || return 0; mkdir -p "$dest"; compgen -G "$pat" >/dev/null || return 0; while IFS= read -r f; do cp -pR "$f" "$dest/" 2>>"$LOG" || true; done < <(compgen -G "$pat"); }

bundle_id_for(){ local app="$1"; if [[ -f "$app/Contents/Info.plist" ]]; then plist_get "$app/Contents/Info.plist" CFBundleIdentifier; fi; return 0; }
team_id_for(){ codesign -dv "$1" 2>/dev/null | awk -F= '/TeamIdentifier=/{print $2; exit}' || true; }
artifact_type(){ case "$1" in *.app) echo app;; *.xpc) echo xpc;; *.framework) echo framework;; *.dylib) echo dylib;; *.plist) echo plist;; *.mobileprovision|*.provisionprofile) echo provisioning;; *) [[ -x "$1" && -f "$1" ]] && echo executable || file -b "$1" 2>/dev/null | cut -c1-80;; esac; }

summarize_bundle(){
  local case_name="$1" role="$2" app="$3" dir="$4"
  mkdir -p "$dir"
  if [[ ! -e "$app" ]]; then printf '%s\t%s\t%s\t\t\t\t\t\t\tmissing\tmissing\n' "$case_name" "$role" "$app" >> "$SUMMARY"; return; fi
  run_capture "$dir/codesign_bundle.txt" codesign --verify --deep --strict --verbose=4 "$app"
  run_capture "$dir/codesign_details.txt" codesign -dvvv --entitlements :- "$app"
  run_capture "$dir/spctl_bundle.txt" spctl --assess --type execute --verbose=4 "$app"
  run_capture "$dir/quarantine_xattr.txt" xattr -lr "$app"
  run_capture "$dir/info_plist.txt" plutil -p "$app/Contents/Info.plist"
  local bid team size birth mt sha cs sp
  bid="$(bundle_id_for "$app")"; team="$(team_id_for "$app")"; size="$(du -sk "$app" 2>/dev/null | awk '{print $1"K"}')"
  birth="$(iso_epoch "$(stat_field %B "$app")")"; mt="$(iso_epoch "$(stat_field %m "$app")")"; sha="$(find "$app" -type f -maxdepth 3 -print0 2>/dev/null | xargs -0 shasum -a 256 2>/dev/null | shasum -a 256 | awk '{print $1}')"
  cs="$(head -1 "$dir/codesign_bundle.txt" 2>/dev/null || true)"; sp="$(head -1 "$dir/spctl_bundle.txt" 2>/dev/null || true)"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$case_name" "$role" "$app" "$sha" "$size" "$birth" "$mt" "$bid" "$team" "$cs" "$sp" "outer bundle" >> "$SUMMARY"

  printf 'type\tpath\tsha256\tsize\tbirth_utc\tmtime_utc\tbundle_id\tteam_id\tnotes\n' > "$dir/recursive_inventory.tsv"
  while IFS= read -r -d '' p; do
    local typ psha psz pb pm pbid pteam notes
    typ="$(artifact_type "$p")"; psha=""; [[ -f "$p" ]] && psha="$(sha256 "$p")"
    psz="$(stat_field %z "$p")"; pb="$(iso_epoch "$(stat_field %B "$p")")"; pm="$(iso_epoch "$(stat_field %m "$p")")"
    pbid=""; [[ -d "$p" && "$p" == *.app && -f "$p/Contents/Info.plist" ]] && pbid="$(bundle_id_for "$p")"
    pteam=""; [[ -d "$p" && ( "$p" == *.app || "$p" == *.xpc || "$p" == *.framework ) ]] && pteam="$(team_id_for "$p")"
    notes="recursive-read-only"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$typ" "$p" "$psha" "$psz" "$pb" "$pm" "$pbid" "$pteam" "$notes" >> "$dir/recursive_inventory.tsv"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$case_name" "$role" "$typ" "$p" "$psha" "$psz" "$pb" "$pm" "$pbid" "$pteam" "$notes" >> "$ARTIFACTS"
  done < <(find "$app" \( -name '*.app' -o -name '*.xpc' -o -name '*.framework' -o -name '*.dylib' -o -name '*.plist' -o -name '*.mobileprovision' -o -perm -111 \) -print0 2>>"$LOG")
}

collect_global_context(){
  mkdir -p "$RUN_DIR/context"
  run_capture "$RUN_DIR/context/system_profiler.txt" system_profiler SPSoftwareDataType SPHardwareDataType
  run_capture "$RUN_DIR/context/logins_last.txt" last
  run_capture "$RUN_DIR/context/current_users_who.txt" who
  run_capture "$RUN_DIR/context/deleted_codex_history_hits.txt" sh -c 'for f in "$HOME"/.{bash,zsh,fish}_history "$HOME"/.local/share/fish/fish_history; do [ -f "$f" ] && printf -- "--- %s ---\n" "$f" && rg -n -i "codex|deleted|rm |trash|unlink" "$f"; done'
}

collect_tcc(){
  local case_dir="$1" ids_file="$2"; mkdir -p "$case_dir/tcc"
  local db="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
  if [[ -r "$db" ]]; then
    cp -p "$db" "$case_dir/tcc/tcc_snapshot.db" 2>>"$LOG" || true
    chmod 444 "$case_dir/tcc/tcc_snapshot.db" 2>>"$LOG" || true
    shasum -a 256 "$db" > "$case_dir/tcc/tcc_original_hashes.sha256" 2>>"$LOG" || true
    [[ -f "$case_dir/tcc/tcc_snapshot.db" ]] && shasum -a 256 "$case_dir/tcc/tcc_snapshot.db" > "$case_dir/tcc/tcc_snapshot_hashes.sha256" 2>>"$LOG" || true
    sqlite3 -header -csv "$db" 'select service,client,client_type,auth_value,auth_reason,auth_version,indirect_object_identifier,last_modified from access order by last_modified desc;' > "$case_dir/tcc/user_tcc_access.csv" 2>"$case_dir/tcc/sqlite_error.txt" || true
    if [[ -f "$case_dir/tcc/tcc_snapshot.db" && -x "./scripts/credential_artifact_scanner.py" ]]; then
      python3 ./scripts/credential_artifact_scanner.py --target "$case_dir/tcc/tcc_snapshot.db" --output "$case_dir/tcc/credential_triage_hits.tsv" >>"$LOG" 2>&1 || true
    fi
  fi
  : > "$case_dir/tcc/target_rows.csv"
  while IFS= read -r bid; do [[ -n "$bid" && -f "$case_dir/tcc/user_tcc_access.csv" ]] && rg -i --fixed-strings "$bid" "$case_dir/tcc/user_tcc_access.csv" >> "$case_dir/tcc/target_rows.csv" || true; done < "$ids_file"
  run_capture "$case_dir/tcc/tccd_recent.log" log show --style syslog --last "$LOG_LOOKBACK" --predicate 'process == "tccd" OR eventMessage CONTAINS[c] "TCC"'
}

collect_process(){ local case_dir="$1" match="$2"; mkdir -p "$case_dir/process"; [[ -n "$match" ]] || return 0; run_capture "$case_dir/process/pgrep.txt" pgrep -afil "$match"; run_capture "$case_dir/process/ps.txt" ps auxww; }

collect_login_truth_scanner_audit(){
  local case_dir="$1" proc_match="${2:-}" audit_dir="$case_dir/login_and_truth_scanner_audit"
  mkdir -p "$audit_dir"
  local history_files=(
    "$HOME/.bash_history"
    "$HOME/.zsh_history"
    "$HOME/.fish_history"
    "$HOME/.local/share/fish/fish_history"
  )
  : > "$audit_dir/codex_history_hits.txt"
  local f base
  for f in "${history_files[@]}"; do
    [[ -f "$f" ]] || continue
    base="$(basename "$f")"
    {
      printf -- "--- %s ---\n" "$f"
      rg -n -i 'codex|truth[ _-]?scanner|truth scanner|atlas|openai|pcap|deleted|trash|unlink|rm ' "$f" || true
    } >> "$audit_dir/codex_history_hits.txt"
    {
      printf -- "--- %s ---\n" "$f"
      rg -n -i 'codex|/Applications/Codex\.app|rm[[:space:]]+-rf|trash|unlink|deleted' "$f" || true
    } > "$audit_dir/${base}.deleted_codex.filtered.txt"
  done
  [[ -n "$proc_match" ]] && run_capture "$audit_dir/process_match_history_hits.txt" sh -c 'for f in "$HOME"/.{bash,zsh,fish}_history "$HOME"/.local/share/fish/fish_history; do [ -f "$f" ] && printf -- "--- %s ---\n" "$f" && rg -n -i -- "$1" "$f"; done' sh "$proc_match"
  find "$HOME/.Trash" "$HOME/.Trash/"* "$HOME"/.Trash-*/ 2>/dev/null | rg -i 'codex|truth[ _-]?scanner|truth scanner|atlas|openai' > "$audit_dir/trash_codex_paths.txt" 2>/dev/null || true
  find "$audit_dir" -type f -empty -delete 2>/dev/null || true
}

collect_pcap(){
  local case_dir="$1" glob="$2"; mkdir -p "$case_dir/pcap"
  copy_if_present "$glob" "$case_dir/pcap/provided"
  if (( PCAP_DURATION > 0 )) && command -v tcpdump >/dev/null; then
    log "Starting tcpdump for ${PCAP_DURATION}s${PCAP_INTERFACE:+ on $PCAP_INTERFACE}"
    local tcpdump_cmd=(tcpdump)
    [[ -n "$PCAP_INTERFACE" ]] && tcpdump_cmd+=(-i "$PCAP_INTERFACE")
    tcpdump_cmd+=(-s 0 -w "$case_dir/pcap/live_capture.pcap")
    "${tcpdump_cmd[@]}" >"$case_dir/pcap/tcpdump.stdout" 2>"$case_dir/pcap/tcpdump.stderr" &
    local pid=$!; sleep "$PCAP_DURATION"; kill -INT "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
  fi
  find "$case_dir/pcap" -type f -print0 2>/dev/null | xargs -0 shasum -a 256 > "$case_dir/pcap/pcap_hashes.sha256" 2>/dev/null || true
}

collect_global_context
csv_to_tsv "$MANIFEST" | while IFS=$'\t' read -r name suspect baseline proc pcap_glob extra_glob; do
  [[ -n "$name" ]] || continue
  case_dir="$RUN_DIR/$(safe "$name")"; mkdir -p "$case_dir"
  log "Collecting case: $name"
  summarize_bundle "$name" suspect "$suspect" "$case_dir/suspect"
  summarize_bundle "$name" baseline "$baseline" "$case_dir/baseline"
  if [[ -x "./scripts/modification_timeline_scanner.py" ]]; then
    timeline_targets=()
    [[ -e "$suspect" ]] && timeline_targets+=(--target "$suspect")
    [[ -e "$baseline" ]] && timeline_targets+=(--target "$baseline")
    if ((${#timeline_targets[@]})); then
      python3 ./scripts/modification_timeline_scanner.py "${timeline_targets[@]}" --output "$case_dir/modification_timeline.tsv" >>"$LOG" 2>&1 || true
    fi
  fi
  { bundle_id_for "$suspect"; bundle_id_for "$baseline"; awk -F'\t' 'NR>1 && $7 {print $7}' "$case_dir"/*/recursive_inventory.tsv 2>/dev/null || true; } | sort -u > "$case_dir/bundle_ids.txt"
  collect_process "$case_dir" "$proc"
  collect_login_truth_scanner_audit "$case_dir" "$proc"
  collect_tcc "$case_dir" "$case_dir/bundle_ids.txt"
  collect_pcap "$case_dir" "$pcap_glob"
  copy_if_present "$extra_glob" "$case_dir/extra_artifacts"
  cat > "$case_dir/REVIEWER_README.md" <<CASE
# $name evidence packet

1. Start with \`suspect/codesign_bundle.txt\`, \`suspect/spctl_bundle.txt\`, and \`baseline/\` equivalents.
2. Review \`suspect/recursive_inventory.tsv\` and \`baseline/recursive_inventory.tsv\` for nested apps, XPC services, frameworks, dylibs, plists, and executables.
3. Inspect \`tcc/target_rows.csv\`, \`tcc/tccd_recent.log\`, \`process/\`, and \`pcap/pcap_hashes.sha256\`.
4. Use top-level \`artifact_summary.tsv\` and \`case_hashes.sha256\` for tamper-evident review.
CASE
done

find "$RUN_DIR" -type f ! -name case_hashes.sha256 -print0 | sort -z | xargs -0 shasum -a 256 > "$RUN_DIR/case_hashes.sha256"
if (( MAKE_ZIP )); then (cd "$OUT_BASE" && ditto -c -k --sequesterRsrc --keepParent "$(basename "$RUN_DIR")" "$(basename "$RUN_DIR").zip" 2>>"$LOG" || zip -qry "$(basename "$RUN_DIR").zip" "$(basename "$RUN_DIR")"); fi
log "Done: $RUN_DIR"
echo "$RUN_DIR"
