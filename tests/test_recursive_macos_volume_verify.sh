#!/bin/bash
set -u
set -o pipefail

SCRIPT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)/recursive_macos_volume_verify.sh"
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/os-boot-verify-v2.XXXXXX")
FIXTURE="$TMP_ROOT/FIXTURE_VOLUME"
OUT_BASE="$TMP_ROOT/results"

cleanup() {
  rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

mkdir -p "$FIXTURE/Applications/Test.app/Contents/MacOS"
mkdir -p "$FIXTURE/AgentWork/one" "$FIXTURE/AgentWork/two"
mkdir -p "$FIXTURE/Library/LaunchAgents"
cp /bin/echo "$FIXTURE/Applications/Test.app/Contents/MacOS/testbin"

cat > "$FIXTURE/AgentWork/one/run.sh" <<'EOF'
#!/bin/bash
echo one
EOF
cat > "$FIXTURE/AgentWork/two/run.sh" <<'EOF'
#!/bin/bash
echo two
EOF
chmod +x "$FIXTURE/AgentWork/one/run.sh" "$FIXTURE/AgentWork/two/run.sh"

cat > "$FIXTURE/Library/LaunchAgents/example.test.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>example.test</string></dict></plist>
EOF
printf 'API_KEY=supersecret-test-value\n' > "$FIXTURE/AgentWork/.env"
printf 'this is not a disk image\n' > "$FIXTURE/AgentWork/not-valid.dmg"

"$SCRIPT" --allow-writable --out-base "$OUT_BASE" --case USB_verify_v2 "$FIXTURE"
rc=$?
[ "$rc" -eq 0 ] || { echo "FAIL: verifier exited $rc"; exit 1; }

CASE_DIR=$(find "$OUT_BASE" -mindepth 1 -maxdepth 1 -type d -name 'USB_verify_v2_*' | head -n 1)
[ -n "$CASE_DIR" ] || { echo 'FAIL: case directory missing'; exit 1; }
[ -e "$CASE_DIR/COMPLETE" ] || { echo 'FAIL: completion marker missing'; exit 1; }
[ ! -e "$CASE_DIR/INCOMPLETE" ] || { echo 'FAIL: incomplete marker remained'; exit 1; }

VERIFY_FILES=$(find "$CASE_DIR" -name code_verification.tsv -type f)
RUN_ROWS=$(printf '%s\n' "$VERIFY_FILES" | xargs grep -h 'AgentWork/.*/run.sh' | wc -l | tr -d ' ')
[ "$RUN_ROWS" -eq 2 ] || { echo "FAIL: expected two distinct run.sh rows, got $RUN_ROWS"; exit 1; }

rg -q 'Applications/Test.app/Contents/MacOS/testbin' "$CASE_DIR" || { echo 'FAIL: nested app executable not verified'; exit 1; }
rg -q 'Library/LaunchAgents/example.test.plist' "$CASE_DIR" || { echo 'FAIL: launch plist not verified'; exit 1; }
if find "$CASE_DIR" -name objects.tsv -type f -exec awk -F '\t' 'FNR>1 && ($3=="" || $4=="" || $5=="" || $6==""){bad=1} END{exit bad}' {} +; then
  :
else
  echo 'FAIL: stat metadata columns are empty or collapsed'
  exit 1
fi
if rg -q 'supersecret-test-value' "$CASE_DIR"; then
  echo 'FAIL: secret value was copied into results'
  exit 1
fi
rg -q 'API_KEY' "$CASE_DIR" || { echo 'FAIL: redacted sensitive keyword hit missing'; exit 1; }
CONTAINER_REPORT=$(find "$CASE_DIR" -name container_verification.tsv -type f | head -n 1)
[ -n "$CONTAINER_REPORT" ] || { echo 'FAIL: container verification report missing'; exit 1; }
awk -F '\t' 'NR==1 && $4=="structure" && $6=="signature" && $8=="trust"{ok=1} END{exit !ok}' "$CONTAINER_REPORT" || {
  echo 'FAIL: container trust matrix columns missing'
  exit 1
}
awk -F '\t' '$1=="AgentWork/not-valid.dmg" && $4=="invalid" && $8=="untrusted_invalid_structure"{ok=1} END{exit !ok}' "$CONTAINER_REPORT" || {
  echo 'FAIL: invalid DMG was not classified as untrusted_invalid_structure'
  exit 1
}
if awk -F '\t' '$1=="AgentWork/not-valid.dmg" && $8=="trusted"{found=1} END{exit !found}' "$CONTAINER_REPORT"; then
  echo 'FAIL: invalid DMG was classified as trusted'
  exit 1
fi
if rg -q 'Is a directory' "$CASE_DIR"; then
  echo 'FAIL: a directory was passed to a file hashing/signature command'
  exit 1
fi
find "$CASE_DIR" -name output_hashes.sha256 -type f | grep -q . || { echo 'FAIL: output hash manifest missing'; exit 1; }
while IFS= read -r manifest; do
  shasum -c "$manifest" >/dev/null || { echo "FAIL: stale output manifest: $manifest"; exit 1; }
done < <(find "$CASE_DIR" -name output_hashes.sha256 -type f)
shasum -c "$CASE_DIR/case_output_hashes.sha256" >/dev/null || { echo 'FAIL: stale case output manifest'; exit 1; }

echo 'PASS: os_boot_verify_v2 fixture checks passed'
