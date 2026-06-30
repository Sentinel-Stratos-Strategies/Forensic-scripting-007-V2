#!/bin/bash
set -u
set -o pipefail

REPO="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/parent-child-trust.XXXXXX")

cleanup() {
  rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

GROUP="$TMP_ROOT/group"
OUT="$TMP_ROOT/out"
mkdir -p "$GROUP"

cat > "$GROUP/code_verification.tsv" <<'EOF'
relative_path	class	sha256	static_parse	codesign	gatekeeper	identifier	team_identifier	authorities	xattr_names	quarantine	detail_file
BadParent/usr/bin/good	mach-o	abc	not_applicable	valid	not_applicable	com.apple.good	not set	Software Signing;Apple Root CA			details/good.txt
BadParent/usr/bin/bad	mach-o	def	not_applicable	invalid	not_applicable	com.apple.bad	not set	Software Signing;Apple Root CA			details/bad.txt
EOF

cat > "$GROUP/objects.tsv" <<'EOF'
relative_path	kind	mode	uid	gid	size	mtime_epoch	birth_epoch	flags	sha256	class	file_description	link_target
BadParent	directory	drwxr-xr-x	501	20	1	1	1	-		not_applicable	directory	
BadParent/usr/bin/good	file	-rwxr-xr-x	501	20	1	1	1	-	abc	mach-o	Mach-O	
EOF

cat > "$TMP_ROOT/parent.json" <<'EOF'
{
  "target_path": "/tmp/BadParent",
  "parent_trust_status": "untrusted_expected_sealed_parent_not_verifiable_from_copied_directory"
}
EOF

"$REPO/scripts/child_parent_trust_contrast.py" \
  --recursive-dir "$GROUP" \
  --parent-report "$TMP_ROOT/parent.json" \
  --out-dir "$OUT" >/dev/null

rg -q 'valid_inner_signature_inside_untrusted_or_unverified_parent' "$OUT/trust_boundary_contrast.md" || {
  echo 'FAIL: boundary classification missing'
  exit 1
}
rg -q 'do not validate the disk image, recovery mount, APFS seal, or acquisition route' "$OUT/trust_boundary_contrast.md" || {
  echo 'FAIL: reviewer-safe parent/child warning missing'
  exit 1
}

echo 'PASS: parent/child trust contrast fixture checks passed'
