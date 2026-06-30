#!/bin/bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

RUN="$TMP/007_go_plan_20260630T000000Z"
LIVE="$RUN/live_capture/overnight_app_capture_20260630T000001Z"
REC="$LIVE/recursive/overnight_recursive_20260630T000002Z"
DIR="$REC/Storage_fake/directories/Applications_test"

mkdir -p "$RUN/logs" "$LIVE/pcap" "$LIVE/tcc" "$RUN/analysis" "$RUN/database" "$DIR"

cat > "$RUN/GO_PLAN_STATUS.txt" <<EOF
run_dir=$RUN
case=007_go_plan
status=stopped_by_user
phase=test phase
updated_utc=2026-06-30T00:00:00Z
log=$RUN/logs/go_plan.log
EOF

cat > "$RUN/logs/go_plan.log" <<EOF
[2026-06-30T00:00:01Z] Capture window starting
[2026-06-30T00:00:02Z] Launching app: /Applications/Test.app
EOF

printf 'pcap' > "$LIVE/pcap/live_capture_00001_20260630000001.pcapng"
shasum -a 256 "$LIVE/pcap/live_capture_00001_20260630000001.pcapng" > "$LIVE/pcap/pcap_hashes.sha256"

cat > "$DIR/objects.tsv" <<EOF
relative_path	kind	mode	uid	gid	size	mtime_epoch	birth_epoch	flags	sha256	class	file_description	link_target
Applications/Test.app	file	-rw-r--r--	501	20	4	1	1	none	abc	mach-o	Mach-O
EOF

cat > "$DIR/code_verification.tsv" <<EOF
relative_path	class	sha256	static_parse	codesign	gatekeeper	identifier	team_identifier	authorities	xattr_names	quarantine	detail_file
Applications/Test.app	mach-o	abc	not_applicable	valid	not_applicable	com.example.test	TEAMID	Authority	none		details/test.txt
EOF

printf '130\n' > "$REC/INTERRUPTED.txt"

OUT="$TMP/packet"
python3 "$ROOT/scripts/build_narrative_claim_packet.py" --run-dir "$RUN" --out-dir "$OUT" >/tmp/narrative_packet_path.txt

test -s "$OUT/FORENSIC_NARRATIVE.md"
test -s "$OUT/CLAIM_MATRIX.tsv"
test -s "$OUT/EVIDENCE_BASE.tsv"
test -s "$OUT/CHRONOLOGY.tsv"
test -s "$OUT/GENESIS_HANDOFF.json"
test -s "$OUT/HASH_MANIFEST.sha256"

grep -q 'stopped_by_user' "$OUT/FORENSIC_NARRATIVE.md"
grep -q 'C070' "$OUT/CLAIM_MATRIX.tsv"
grep -q 'Genesis' "$OUT/README.md"
