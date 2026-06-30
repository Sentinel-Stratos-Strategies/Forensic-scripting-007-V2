#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

home="$tmp/home"
mkdir -p "$home/.Trash"
printf 'rm -rf /Applications/Codex.app\ntruth scanner pcap\n' > "$home/.bash_history"
touch "$home/.Trash/deleted-codex.txt"

manifest="$tmp/manifest.csv"
cat > "$manifest" <<'CSV'
name,suspect_app,baseline_app,process_match,pcap_glob,extra_glob
case,/nope,/nope,TruthScanner,,
CSV

stdout="$tmp/stdout"
stderr="$tmp/stderr"
HOME="$home" "$repo_root/atlas_submission_capture.sh" "$manifest" "$tmp/out" --no-zip >"$stdout" 2>"$stderr"
run_dir="$(tail -1 "$stdout")"
audit_dir="$run_dir/case/login_and_truth_scanner_audit"

test -s "$audit_dir/.bash_history.deleted_codex.filtered.txt"
rg -q 'rm -rf /Applications/Codex.app' "$audit_dir/.bash_history.deleted_codex.filtered.txt"
test -s "$audit_dir/trash_codex_paths.txt"
rg -q 'deleted-codex.txt' "$audit_dir/trash_codex_paths.txt"
test -s "$audit_dir/codex_history_hits.txt"
rg -q 'truth scanner pcap' "$audit_dir/codex_history_hits.txt"
