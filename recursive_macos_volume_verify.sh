#!/bin/bash
# Read-only, per-object verification for mounted macOS evidence volumes.
#
# Default:
#   ./recursive_macos_volume_verify.sh /Volumes/OS_BOOT /Volumes/RESCUE_OS
#
# This script never executes code from the evidence volume. It inventories every
# object, hashes and statically checks code-like files individually, validates
# app/package/disk-image containers, and writes all results outside the source.

set -u
set -o pipefail

PATH="/usr/bin:/bin:/usr/sbin:/sbin:$HOME/.homebrew/bin:$PATH"
export PATH LC_ALL=C LANG=C

SCRIPT_HOME="$(cd -- "$(dirname -- "$0")" && pwd -P)"
OUT_BASE="$SCRIPT_HOME/results"
ALLOW_WRITABLE=0
HASH_MODE="code"
MAX_TEXT_MB=16
LIMIT_FILES=0
CASE_PREFIX="USB_verify_v2"
INSPECT_DMG_CONTENTS=0
DMG_MAX_FILES=100000
CONTAINER_ONLY=""
VOLUMES=()
ATTACHED_DEVICES=()

usage() {
  cat <<'EOF'
Usage: recursive_macos_volume_verify.sh [options] [VOLUME ...]

Options:
  --out-base DIR       Result parent directory (default: script/results)
  --case NAME          Case directory prefix (default: USB_verify_v2)
  --hash-mode MODE     code|all|none (default: code)
  --hash-all           SHA-256 every regular file, including non-code data
  --no-hash            Do not hash regular files
  --max-text-mb N      Maximum text-file size searched by ripgrep (default: 16)
  --limit-files N      Stop after N regular files per volume; marks run partial
  --inspect-dmg-contents
                       Mount DMGs read-only, inventory internal objects, and
                       verify nested apps/containers without executing content
  --dmg-max-files N    Maximum internal objects inventoried per DMG (default: 100000)
  --container-only FILE
                       Verify one package/archive/DMG without walking its volume
  --allow-writable     Permit a writable source (intended only for test fixtures)
  -h, --help           Show this help

With no VOLUME arguments, mounted /Volumes/OS_BOOT and /Volumes/RESCUE_OS are used.
EOF
}

fatal() {
  echo "[FATAL] $*" >&2
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --out-base)
      [ "$#" -ge 2 ] || fatal "--out-base requires a directory"
      OUT_BASE="$2"
      shift 2
      ;;
    --case)
      [ "$#" -ge 2 ] || fatal "--case requires a name"
      CASE_PREFIX="$2"
      shift 2
      ;;
    --hash-mode)
      [ "$#" -ge 2 ] || fatal "--hash-mode requires code, all, or none"
      HASH_MODE="$2"
      shift 2
      ;;
    --hash-all)
      HASH_MODE="all"
      shift
      ;;
    --no-hash)
      HASH_MODE="none"
      shift
      ;;
    --max-text-mb)
      [ "$#" -ge 2 ] || fatal "--max-text-mb requires a number"
      MAX_TEXT_MB="$2"
      shift 2
      ;;
    --limit-files)
      [ "$#" -ge 2 ] || fatal "--limit-files requires a number"
      LIMIT_FILES="$2"
      shift 2
      ;;
    --inspect-dmg-contents)
      INSPECT_DMG_CONTENTS=1
      shift
      ;;
    --dmg-max-files)
      [ "$#" -ge 2 ] || fatal "--dmg-max-files requires a number"
      DMG_MAX_FILES="$2"
      shift 2
      ;;
    --container-only)
      [ "$#" -ge 2 ] || fatal "--container-only requires a file"
      CONTAINER_ONLY="$2"
      shift 2
      ;;
    --allow-writable)
      ALLOW_WRITABLE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      while [ "$#" -gt 0 ]; do
        VOLUMES[${#VOLUMES[@]}]="$1"
        shift
      done
      ;;
    -*)
      fatal "unknown option: $1"
      ;;
    *)
      VOLUMES[${#VOLUMES[@]}]="$1"
      shift
      ;;
  esac
done

case "$MAX_TEXT_MB" in *[!0-9]*|'') fatal "--max-text-mb must be an integer";; esac
case "$LIMIT_FILES" in *[!0-9]*|'') fatal "--limit-files must be an integer";; esac
case "$DMG_MAX_FILES" in *[!0-9]*|'') fatal "--dmg-max-files must be an integer";; esac
case "$HASH_MODE" in code|all|none) ;; *) fatal "--hash-mode must be code, all, or none";; esac

if [ "${#VOLUMES[@]}" -eq 0 ] && [ -z "$CONTAINER_ONLY" ]; then
  [ -d /Volumes/OS_BOOT ] && VOLUMES[${#VOLUMES[@]}]="/Volumes/OS_BOOT"
  [ -d /Volumes/RESCUE_OS ] && VOLUMES[${#VOLUMES[@]}]="/Volumes/RESCUE_OS"
fi
if [ -z "$CONTAINER_ONLY" ]; then
  [ "${#VOLUMES[@]}" -gt 0 ] || fatal "no source volumes were supplied or mounted"
else
  [ -f "$CONTAINER_ONLY" ] || fatal "container is not a regular file: $CONTAINER_ONLY"
  CONTAINER_ONLY="$(cd -- "$(dirname -- "$CONTAINER_ONLY")" && pwd -P)/$(basename -- "$CONTAINER_ONLY")"
fi

mkdir -p "$OUT_BASE" || fatal "cannot create output base: $OUT_BASE"
OUT_BASE="$(cd "$OUT_BASE" && pwd -P)"
UTC_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
CASE="${CASE_PREFIX}_${UTC_STAMP}"
OUT="$OUT_BASE/$CASE"
mkdir -p "$OUT"
touch "$OUT/INCOMPLETE"

RUN_COMPLETE=0
on_exit() {
  rc=$?
  for attached_device in "${ATTACHED_DEVICES[@]-}"; do
    [ -n "$attached_device" ] || continue
    hdiutil detach "$attached_device" >/dev/null 2>&1 || true
  done
  if [ "$RUN_COMPLETE" -eq 1 ]; then
    rm -f "$OUT/INCOMPLETE"
    touch "$OUT/COMPLETE"
  else
    date -u +%Y-%m-%dT%H:%M:%SZ > "$OUT/00_utc_end.txt" 2>/dev/null || true
    printf 'exit_code=%s\n' "$rc" > "$OUT/INTERRUPTED.txt" 2>/dev/null || true
  fi
  trap - EXIT
  exit "$rc"
}

mark_detached() {
  detached_device=$1
  for attached_index in "${!ATTACHED_DEVICES[@]}"; do
    if [ "${ATTACHED_DEVICES[$attached_index]}" = "$detached_device" ]; then
      unset 'ATTACHED_DEVICES[attached_index]'
    fi
  done
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

LOG="$OUT/command_log.md"
ERRORS="$OUT/errors.tsv"
printf 'stage\tpath\texit_code\tmessage\n' > "$ERRORS"

log() {
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '[%s] %s\n' "$now" "$*" | tee -a "$LOG"
}

escape_tsv() {
  value=$1
  value=${value//\\/\\\\}
  value=${value//$'\t'/\\t}
  value=${value//$'\r'/\\r}
  value=${value//$'\n'/\\n}
  printf '%s' "$value"
}

record_error() {
  stage=$(escape_tsv "$1")
  path=$(escape_tsv "$2")
  code=$(escape_tsv "$3")
  message=$(escape_tsv "$4")
  printf '%s\t%s\t%s\t%s\n' "$stage" "$path" "$code" "$message" >> "$ERRORS"
}

safe_component() {
  printf '%s' "$1" | tr -cs 'A-Za-z0-9._-' '_' | cut -c1-80
}

path_id() {
  printf '%s' "$1" | shasum -a 256 | awk '{print substr($1,1,16)}'
}

relative_path() {
  path=$1
  root=$2
  if [ "$path" = "$root" ]; then
    printf '.'
  else
    printf '%s' "${path#"$root"/}"
  fi
}

top_name() {
  rel=$1
  case "$rel" in
    */*) printf '%s' "${rel%%/*}" ;;
    .) printf '_ROOT_' ;;
    *) printf '_ROOT_FILES' ;;
  esac
}

top_output_dir() {
  top=$1
  slug="$(safe_component "$top")_$(path_id "$top")"
  dir="$CURRENT_VOUT/directories/$slug"
  mkdir -p "$dir/details"
  if [ ! -e "$dir/objects.tsv" ]; then
    printf 'relative_path\tkind\tmode\tuid\tgid\tsize\tmtime_epoch\tbirth_epoch\tflags\tsha256\tclass\tfile_description\tlink_target\n' > "$dir/objects.tsv"
  fi
  if [ ! -e "$dir/code_verification.tsv" ]; then
    printf 'relative_path\tclass\tsha256\tstatic_parse\tcodesign\tgatekeeper\tidentifier\tteam_identifier\tauthorities\txattr_names\tquarantine\tdetail_file\n' > "$dir/code_verification.tsv"
  fi
  printf '%s' "$dir"
}

write_object_row() {
  out_file=$1
  rel=$2
  kind=$3
  mode=$4
  uid=$5
  gid=$6
  size=$7
  mtime=$8
  birth=$9
  flags=${10}
  sha=${11}
  class=${12}
  description=${13}
  link_target=${14}
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(escape_tsv "$rel")" "$(escape_tsv "$kind")" "$(escape_tsv "$mode")" \
    "$(escape_tsv "$uid")" "$(escape_tsv "$gid")" "$(escape_tsv "$size")" \
    "$(escape_tsv "$mtime")" "$(escape_tsv "$birth")" "$(escape_tsv "$flags")" \
    "$(escape_tsv "$sha")" "$(escape_tsv "$class")" "$(escape_tsv "$description")" \
    "$(escape_tsv "$link_target")" >> "$out_file"
}

classify_file() {
  path=$1
  description=$2
  lower=$(printf '%s' "$path" | tr '[:upper:]' '[:lower:]')
  case "$description" in
    *Mach-O*) printf 'mach-o'; return ;;
  esac
  case "$lower" in
    *.dylib|*.so|*.bundle) printf 'native-library'; return ;;
    *.sh|*.bash|*.zsh|*.command) printf 'shell'; return ;;
    *.py|*.pyw) printf 'python'; return ;;
    *.js|*.mjs|*.cjs) printf 'javascript'; return ;;
    *.ts|*.tsx) printf 'typescript'; return ;;
    *.json) printf 'json'; return ;;
    *.plist) printf 'plist'; return ;;
    *.pkg) printf 'package'; return ;;
    *.dmg) printf 'disk-image'; return ;;
    *.zip|*.tar|*.tgz|*.tar.gz|*.tbz|*.tbz2|*.tar.bz2|*.tar.xz) printf 'archive'; return ;;
    *.pem|*.key|*.p12|*.pfx) printf 'key-material'; return ;;
  esac
  if [ -x "$path" ]; then
    if [ "$(head -c 2 "$path" 2>/dev/null)" = '#!' ]; then
      first_line=$(head -n 1 "$path" 2>/dev/null || true)
      case "$first_line" in
        *python*) printf 'python'; return ;;
        *node*) printf 'javascript'; return ;;
        *bash*|*zsh*|*'/sh'*) printf 'shell'; return ;;
      esac
    fi
    printf 'executable-other'
    return
  fi
  printf 'data'
}

should_hash() {
  class=$1
  case "$HASH_MODE" in
    all) return 0 ;;
    none) return 1 ;;
  esac
  case "$class" in
    mach-o|native-library|shell|python|javascript|typescript|json|plist|package|disk-image|archive|key-material|executable-other) return 0 ;;
  esac
  return 1
}

static_parse() {
  class=$1
  path=$2
  detail=$3
  case "$class" in
    shell)
      if /bin/bash -n "$path" > "$detail" 2>&1; then printf 'pass'; else printf 'fail'; fi
      ;;
    python)
      if python3 - "$path" > "$detail" 2>&1 <<'PY'
import ast
import sys
import tokenize

path = sys.argv[1]
with tokenize.open(path) as handle:
    ast.parse(handle.read(), filename=path)
PY
      then printf 'pass'; else printf 'fail'; fi
      ;;
    javascript)
      if command -v node >/dev/null 2>&1; then
        if node --check "$path" > "$detail" 2>&1; then printf 'pass'; else printf 'fail'; fi
      else
        printf 'not_checked_node_missing'
      fi
      ;;
    json)
      if command -v jq >/dev/null 2>&1; then
        if jq empty "$path" > "$detail" 2>&1; then printf 'pass'; else printf 'fail'; fi
      elif plutil -lint "$path" > "$detail" 2>&1; then printf 'pass'; else printf 'fail'; fi
      ;;
    plist)
      if plutil -lint "$path" > "$detail" 2>&1; then printf 'pass'; else printf 'fail'; fi
      ;;
    typescript)
      printf 'not_checked_project_compiler_required'
      ;;
    *)
      printf 'not_applicable'
      ;;
  esac
}

verify_code_file() {
  path=$1
  rel=$2
  class=$3
  sha=$4
  top_dir=$5
  item_id="$(path_id "$rel")_$(safe_component "$(basename "$rel")")"
  detail_rel="details/${item_id}.txt"
  detail="$top_dir/$detail_rel"
  : > "$detail"

  parse_status="$(static_parse "$class" "$path" "$detail")"
  codesign_status="not_applicable"
  gatekeeper_status="not_applicable"
  identifier=""
  team_identifier=""
  authorities=""

  case "$class" in
    mach-o|native-library)
      {
        echo '[codesign verify]'
        codesign --verify --strict --verbose=4 "$path"
      } >> "$detail" 2>&1
      rc=$?
      if [ "$rc" -eq 0 ]; then
        codesign_status="valid"
      elif rg -q 'not signed at all|code object is not signed' "$detail" 2>/dev/null; then
        codesign_status="unsigned"
      else
        codesign_status="invalid"
      fi
      {
        echo
        echo '[codesign metadata]'
        codesign -dvvv "$path"
        echo
        echo '[entitlements]'
        codesign -d --entitlements :- "$path"
      } >> "$detail" 2>&1 || true
      identifier=$(awk -F= '/^Identifier=/{print $2; exit}' "$detail")
      team_identifier=$(awk -F= '/^TeamIdentifier=/{print $2; exit}' "$detail")
      authorities=$(awk -F= '/^Authority=/{if (n++) printf ";"; printf "%s",$2}' "$detail")
      ;;
  esac

  xattr_names=$(xattr "$path" 2>/dev/null | paste -sd, -)
  quarantine=$(xattr -p com.apple.quarantine "$path" 2>/dev/null | tr '\t\r\n' '   ' || true)
  [ -s "$detail" ] || rm -f "$detail"
  [ -e "$detail" ] || detail_rel=""

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(escape_tsv "$rel")" "$(escape_tsv "$class")" "$(escape_tsv "$sha")" \
    "$(escape_tsv "$parse_status")" "$(escape_tsv "$codesign_status")" \
    "$(escape_tsv "$gatekeeper_status")" "$(escape_tsv "$identifier")" \
    "$(escape_tsv "$team_identifier")" "$(escape_tsv "$authorities")" \
    "$(escape_tsv "$xattr_names")" "$(escape_tsv "$quarantine")" \
    "$(escape_tsv "$detail_rel")" >> "$top_dir/code_verification.tsv"
}

verify_app_bundles() {
  volume=$1
  volume_out=$2
  app_report="$volume_out/app_bundles.tsv"
  printf 'relative_path\tcodesign\tgatekeeper\tidentifier\tteam_identifier\tauthorities\tdetail_file\n' > "$app_report"
  while IFS= read -r -d '' app; do
    rel=$(relative_path "$app" "$volume")
    item_id="$(path_id "$rel")_$(safe_component "$(basename "$rel")")"
    detail_rel="bundle_details/${item_id}.txt"
    detail="$volume_out/$detail_rel"
    mkdir -p "$(dirname "$detail")"
    {
      echo '[bundle codesign verify]'
      codesign --verify --deep --strict --verbose=4 "$app"
    } > "$detail" 2>&1
    rc=$?
    if [ "$rc" -eq 0 ]; then sign_status="valid"; else sign_status="invalid"; fi
    {
      echo
      echo '[bundle codesign metadata]'
      codesign -dvvv "$app"
      echo
      echo '[bundle entitlements]'
      codesign -d --entitlements :- "$app"
      echo
      echo '[gatekeeper]'
      spctl --assess --type execute -vv "$app"
    } >> "$detail" 2>&1
    spctl --assess --type execute -vv "$app" >/dev/null 2>&1
    if [ "$?" -eq 0 ]; then gatekeeper="accepted"; else gatekeeper="rejected_or_unavailable"; fi
    identifier=$(awk -F= '/^Identifier=/{print $2; exit}' "$detail")
    team_identifier=$(awk -F= '/^TeamIdentifier=/{print $2; exit}' "$detail")
    authorities=$(awk -F= '/^Authority=/{if (n++) printf ";"; printf "%s",$2}' "$detail")
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$(escape_tsv "$rel")" "$sign_status" "$gatekeeper" \
      "$(escape_tsv "$identifier")" "$(escape_tsv "$team_identifier")" \
      "$(escape_tsv "$authorities")" "$(escape_tsv "$detail_rel")" >> "$app_report"
  done < <(find "$volume" -xdev -type d -name '*.app' -prune -print0 2>> "$volume_out/find_errors.log")
}

inspect_dmg_contents() {
  path=$1
  outer_rel=$2
  volume_out=$3
  item_id=$4

  content_out="$volume_out/container_details/${item_id}_contents"
  mkdir -p "$content_out"
  attach_log="$content_out/attach.txt"
  if ! hdiutil attach -readonly -nobrowse -noautoopen -owners off "$path" > "$attach_log" 2>&1; then
    printf 'attach_failed'
    return
  fi

  backing_device=$(awk '/^\/dev\/disk[0-9]+[[:space:]]/{print $1; exit}' "$attach_log")
  mount_point=$(awk -F '\t' 'index($NF,"/Volumes/")==1{print $NF; exit}' "$attach_log")
  if [ -n "$backing_device" ]; then
    ATTACHED_DEVICES+=("$backing_device")
  fi
  if [ -z "$backing_device" ] || [ -z "$mount_point" ] || [ ! -d "$mount_point" ]; then
    if [ -n "$backing_device" ]; then
      hdiutil detach "$backing_device" >> "$attach_log" 2>&1 || true
      mark_detached "$backing_device"
    fi
    printf 'attach_missing_mount'
    return
  fi

  mount_line=$(mount | grep -F " on $mount_point " | head -n 1 || true)
  printf '\n[mount]\n%s\n' "$mount_line" >> "$attach_log"
  case "$mount_line" in
    *read-only*) ;;
    *)
      hdiutil detach "$backing_device" >> "$attach_log" 2>&1 || true
      mark_detached "$backing_device"
      printf 'rejected_not_read_only'
      return
      ;;
  esac

  objects="$content_out/objects.tsv"
  printf 'internal_path\tkind\tmode\tsize\tsha256\tclass\tstatic_parse\tfile_description\n' > "$objects"
  object_count=0
  partial=0
  while IFS= read -r -d '' internal_path; do
    object_count=$((object_count + 1))
    if [ "$DMG_MAX_FILES" -gt 0 ] && [ "$object_count" -gt "$DMG_MAX_FILES" ]; then
      partial=1
      break
    fi
    internal_rel=$(relative_path "$internal_path" "$mount_point")
    kind="other"
    mode=$(stat -f '%Sp' "$internal_path" 2>/dev/null || true)
    size=$(stat -f '%z' "$internal_path" 2>/dev/null || true)
    sha=""
    class="not_applicable"
    parse_status="not_applicable"
    description=""
    if [ -L "$internal_path" ]; then
      kind="symlink"
      description=$(file -b -h "$internal_path" 2>/dev/null || true)
    elif [ -d "$internal_path" ]; then
      kind="directory"
      description="directory"
    elif [ -f "$internal_path" ]; then
      kind="file"
      description=$(file -b "$internal_path" 2>/dev/null || true)
      class=$(classify_file "$internal_path" "$description")
      if should_hash "$class"; then
        sha=$(shasum -a 256 "$internal_path" 2>/dev/null | awk '{print $1}')
      fi
      case "$class" in
        shell|python|javascript|typescript|json|plist)
          parse_detail="$content_out/parse_$(path_id "$internal_rel").txt"
          parse_status=$(static_parse "$class" "$internal_path" "$parse_detail")
          [ -s "$parse_detail" ] || rm -f "$parse_detail"
          ;;
      esac
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$(escape_tsv "$internal_rel")" "$kind" "$(escape_tsv "$mode")" \
      "$(escape_tsv "$size")" "$sha" "$class" "$parse_status" \
      "$(escape_tsv "$description")" >> "$objects"
  done < <(find "$mount_point" -xdev -print0 2>> "$content_out/find_errors.log")

  printf 'outer_path=%s\nmount_point=%s\nobjects_seen=%s\npartial=%s\n' \
    "$outer_rel" "$mount_point" "$object_count" "$partial" > "$content_out/scope.txt"
  verify_app_bundles "$mount_point" "$content_out"
  verify_containers "$mount_point" "$content_out" 0
  find "$content_out" -type f ! -name output_hashes.sha256 -exec shasum -a 256 {} \; > "$content_out/output_hashes.sha256"

  if hdiutil detach "$backing_device" >> "$attach_log" 2>&1; then
    mark_detached "$backing_device"
    if [ "$partial" -eq 1 ]; then printf 'partial'; else printf 'inventoried'; fi
  else
    printf 'inventoried_detach_failed'
  fi
}

verify_containers() {
  volume=$1
  volume_out=$2
  allow_content_inspection=${3:-1}
  report="$volume_out/container_verification.tsv"
  printf 'relative_path\tclass\tsha256\tstructure\tchecksum\tsignature\tgatekeeper\ttrust\tcontent_inspection\tdetail_file\n' > "$report"
  while IFS= read -r -d '' path; do
    rel=$(relative_path "$path" "$volume")
    lower=$(printf '%s' "$path" | tr '[:upper:]' '[:lower:]')
    sha=$(shasum -a 256 "$path" 2>/dev/null | awk '{print $1}')
    item_id="$(path_id "$rel")_$(safe_component "$(basename "$rel")")"
    detail_rel="container_details/${item_id}.txt"
    detail="$volume_out/$detail_rel"
    mkdir -p "$(dirname "$detail")"
    structure="not_checked"
    checksum="not_applicable"
    signature="not_applicable"
    gatekeeper="not_applicable"
    trust="not_assessed"
    content_inspection="not_requested"
    class="archive"
    case "$lower" in
      *.pkg)
        class="package"
        {
          echo '[pkg signature]'
          pkgutil --check-signature "$path"
          echo
          echo '[gatekeeper]'
          spctl --assess --type install -vv "$path"
          echo
          echo '[xar listing: first 5000 entries]'
          xar -tf "$path" | awk 'NR<=5000'
        } > "$detail" 2>&1
        if pkgutil --check-signature "$path" >/dev/null 2>&1; then signature="valid"; else signature="invalid_or_unsigned"; fi
        if spctl --assess --type install -vv "$path" >/dev/null 2>&1; then gatekeeper="accepted"; else gatekeeper="rejected"; fi
        if xar -tf "$path" >/dev/null 2>&1; then structure="listable"; else structure="invalid"; fi
        if [ "$signature" = "valid" ] && [ "$gatekeeper" = "accepted" ]; then trust="trusted"; else trust="untrusted"; fi
        ;;
      *.dmg)
        class="disk-image"
        {
          echo '[image info]'
          hdiutil imageinfo "$path"
          echo
          echo '[image verify]'
          hdiutil verify "$path"
          echo
          echo '[codesign verify]'
          codesign --verify --strict --verbose=4 "$path"
          echo
          echo '[codesign metadata]'
          codesign -dvvv "$path"
          echo
          echo '[gatekeeper primary signature]'
          spctl --assess --type open --context context:primary-signature -vv "$path"
        } > "$detail" 2>&1
        if hdiutil imageinfo "$path" >/dev/null 2>&1; then structure="valid"; else structure="invalid"; fi
        if hdiutil verify "$path" >/dev/null 2>&1; then checksum="valid"; else checksum="invalid"; fi
        if codesign --verify --strict --verbose=4 "$path" >/dev/null 2>&1; then
          signature="valid"
        else
          codesign_description=$(codesign -dvvv "$path" 2>&1 || true)
          if printf '%s\n' "$codesign_description" | rg -q 'not signed at all|code object is not signed'; then
            signature="unsigned"
          else
            signature="invalid"
          fi
        fi
        if spctl --assess --type open --context context:primary-signature -vv "$path" >/dev/null 2>&1; then gatekeeper="accepted"; else gatekeeper="rejected"; fi
        if [ "$structure" != "valid" ]; then
          trust="untrusted_invalid_structure"
        elif [ "$checksum" != "valid" ]; then
          trust="untrusted_checksum_failed"
        elif [ "$signature" = "unsigned" ]; then
          trust="untrusted_unsigned"
        elif [ "$signature" != "valid" ]; then
          trust="untrusted_invalid_signature"
        elif [ "$gatekeeper" != "accepted" ]; then
          trust="untrusted_gatekeeper_rejected"
        else
          trust="trusted"
        fi
        if [ "$INSPECT_DMG_CONTENTS" -eq 1 ] && [ "$allow_content_inspection" -eq 1 ] && [ "$structure" = "valid" ]; then
          content_inspection=$(inspect_dmg_contents "$path" "$rel" "$volume_out" "$item_id")
        fi
        ;;
      *.zip)
        unzip -Z1 "$path" 2>&1 | awk 'NR<=5000' > "$detail"
        [ "${PIPESTATUS[0]}" -eq 0 ] && structure="listable" || structure="invalid"
        trust="untrusted_unsigned_archive"
        ;;
      *)
        tar -tf "$path" 2>&1 | awk 'NR<=5000' > "$detail"
        [ "${PIPESTATUS[0]}" -eq 0 ] && structure="listable" || structure="invalid"
        trust="untrusted_unsigned_archive"
        ;;
    esac
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$(escape_tsv "$rel")" "$class" "$sha" "$structure" "$checksum" \
      "$signature" "$gatekeeper" "$trust" "$content_inspection" \
      "$(escape_tsv "$detail_rel")" >> "$report"
  done < <(
    if [ -n "$CONTAINER_ONLY" ] && [ "$allow_content_inspection" -eq 1 ]; then
      printf '%s\0' "$CONTAINER_ONLY"
    else
      find "$volume" -xdev -type f \( -iname '*.pkg' -o -iname '*.dmg' -o -iname '*.zip' -o -iname '*.tar' -o -iname '*.tgz' -o -iname '*.tar.gz' -o -iname '*.tbz' -o -iname '*.tbz2' -o -iname '*.tar.bz2' -o -iname '*.tar.xz' \) -print0 2>> "$volume_out/find_errors.log"
    fi
  )
}

verify_container_only() {
  path=$1
  source_dir=$(dirname "$path")
  source_mount=$(df "$path" 2>/dev/null | awk 'NR==2{print $NF}')
  source_mount_line=$(mount | grep -F " on $source_mount " | head -n 1 || true)
  if [ "$ALLOW_WRITABLE" -ne 1 ]; then
    case "$source_mount_line" in
      *read-only*) ;;
      *) fatal "refusing container on writable or unverified source: $path" ;;
    esac
  fi

  slug="container_only_$(path_id "$path")"
  volume_out="$OUT/$slug"
  mkdir -p "$volume_out"
  printf '%s\n' "$source_mount_line" > "$volume_out/00_mount.txt"
  ls -laOe@ "$path" > "$volume_out/00_source_listing.txt" 2>&1 || true
  verify_containers "$source_dir" "$volume_out" 1
  find "$volume_out" -type f ! -name output_hashes.sha256 -exec shasum -a 256 {} \; > "$volume_out/output_hashes.sha256"
}

collect_high_signal_paths() {
  volume=$1
  volume_out=$2
  find "$volume" -xdev \( \
    -path '*/LaunchAgents/*' -o -path '*/LaunchDaemons/*' -o \
    -path '*/ConfigurationProfiles/*' -o -path '*/Managed Preferences/*' -o \
    -name 'mdmclient.plist' -o -name 'CloudConfigurationDetails.plist' -o \
    -name 'PayloadManifest.plist' -o -name 'TCC.db' -o -name 'TCCAccessory.db' -o \
    -name 'appsscript.json' -o -name '.clasprc.json' -o -name 'workspace_admin_audit.json' \
  \) -print 2>> "$volume_out/find_errors.log" > "$volume_out/high_signal_paths.txt"

  if command -v rg >/dev/null 2>&1; then
    rg --hidden --no-follow --no-messages --with-filename -i -n -o \
      --max-filesize "${MAX_TEXT_MB}M" \
      -g '!**/.git/objects/**' -g '!**/node_modules/**' -g '!**/.venv/**' \
      -g '!**/venv/**' -g '!**/Library/Caches/**' -g '!**/homebrew/Cellar/**' \
      -g '!*.jmod' -g '!*.jar' -g '!*.zip' -g '!*.tar*' -g '!*.dmg' -g '!*.pkg' \
      -e 'token|secret|api[_-]?key|password|passphrase|private[ _-]?key|BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY' \
      "$volume" > "$volume_out/sensitive_keyword_hits_redacted.txt" 2>> "$volume_out/rg_errors.log" || true

    rg --hidden --no-follow --no-messages --with-filename -i -n -o \
      --max-filesize "${MAX_TEXT_MB}M" \
      -g '!**/.git/objects/**' -g '!**/node_modules/**' -g '!**/.venv/**' \
      -g '!**/venv/**' -g '!**/Library/Caches/**' -g '!**/homebrew/Cellar/**' \
      -g '!*.jmod' -g '!*.jar' -g '!*.zip' -g '!*.tar*' -g '!*.dmg' -g '!*.pkg' \
      -e 'mdmBaseURL|axm-servicediscovery|com\.apple\.remotemanagement|ConfigurationProfiles|RunAtLoad|KeepAlive|ProgramArguments|osascript|curl[[:space:]]|base64|cloudflare|warp|codex-local|unsloth|gemma' \
      "$volume" > "$volume_out/forensic_keyword_hits.txt" 2>> "$volume_out/rg_errors.log" || true
  else
    printf 'ripgrep unavailable; text search not run\n' > "$volume_out/rg_errors.log"
  fi
}

summarize_directories() {
  volume_out=$1
  report="$volume_out/directory_summary.tsv"
  printf 'directory_group\tobjects\tcode_candidates\tparse_failures\tinvalid_or_unsigned_native_code\n' > "$report"
  for dir in "$volume_out"/directories/*; do
    [ -d "$dir" ] || continue
    objects=$(awk 'NR>1{n++} END{print n+0}' "$dir/objects.tsv")
    candidates=$(awk 'NR>1{n++} END{print n+0}' "$dir/code_verification.tsv")
    parse_failures=$(awk -F '\t' 'NR>1 && $4=="fail"{n++} END{print n+0}' "$dir/code_verification.tsv")
    native_failures=$(awk -F '\t' 'NR>1 && ($5=="invalid" || $5=="unsigned"){n++} END{print n+0}' "$dir/code_verification.tsv")
    printf '%s\t%s\t%s\t%s\t%s\n' "$(basename "$dir")" "$objects" "$candidates" "$parse_failures" "$native_failures" >> "$report"
  done
}

inventory_volume() {
  volume=$1
  [ -d "$volume" ] || fatal "source volume is not a directory: $volume"
  volume="$(cd "$volume" && pwd -P)"
  case "$OUT/" in "$volume/"*) fatal "output directory cannot be inside source volume: $volume";; esac

  vname="$(basename "$volume")"
  vslug="$(safe_component "$vname")_$(path_id "$volume")"
  CURRENT_VOUT="$OUT/$vslug"
  export CURRENT_VOUT
  mkdir -p "$CURRENT_VOUT/directories"

  source_mount=$(df "$volume" 2>/dev/null | awk 'NR==2{print $NF}')
  mount_line=$(mount | grep -F " on $source_mount " | head -n 1 || true)
  disk_read_only=$(diskutil info "$source_mount" 2>/dev/null | awk -F: '/Volume Read-Only/{gsub(/^[ \t]+/,"",$2); print $2; exit}')
  if [ "$ALLOW_WRITABLE" -ne 1 ]; then
    case "$mount_line $disk_read_only" in
      *read-only*|*'Yes (read-only mount flag set)'*) ;;
      *) fatal "refusing writable or unverified source: $volume" ;;
    esac
  fi

  log "Starting volume: $volume"
  date -u +%Y-%m-%dT%H:%M:%SZ > "$CURRENT_VOUT/00_utc_start.txt"
  printf '%s\n' "$mount_line" > "$CURRENT_VOUT/00_mount.txt"
  diskutil info "$source_mount" > "$CURRENT_VOUT/00_diskutil_info.txt" 2>&1 || true
  ls -laOe@ "$volume" > "$CURRENT_VOUT/00_root_listing.txt" 2>&1 || true

  file_count=0
  partial=0
  while IFS= read -r -d '' path; do
    rel=$(relative_path "$path" "$volume")
    top=$(top_name "$rel")
    top_dir=$(top_output_dir "$top")
    kind="other"
    description=""
    link_target=""
    sha=""
    class="not_applicable"

    if [ -L "$path" ]; then
      kind="symlink"
      link_target=$(readlink "$path" 2>/dev/null || true)
      description=$(file -b -h "$path" 2>/dev/null || true)
    elif [ -d "$path" ]; then
      kind="directory"
      description="directory"
    elif [ -f "$path" ]; then
      kind="file"
      file_count=$((file_count + 1))
      if [ "$LIMIT_FILES" -gt 0 ] && [ "$file_count" -gt "$LIMIT_FILES" ]; then
        partial=1
        break
      fi
      description=$(file -b "$path" 2>/dev/null || true)
      class=$(classify_file "$path" "$description")
      if should_hash "$class"; then
        sha=$(shasum -a 256 "$path" 2>/dev/null | awk '{print $1}')
        [ -n "$sha" ] || record_error "sha256" "$rel" "1" "hash failed"
      fi
    fi

    stat_fields=$(stat -f '%Sp|%u|%g|%z|%m|%B|%Sf' "$path" 2>/dev/null || true)
    mode=$(printf '%s' "$stat_fields" | awk -F '|' '{print $1}')
    uid=$(printf '%s' "$stat_fields" | awk -F '|' '{print $2}')
    gid=$(printf '%s' "$stat_fields" | awk -F '|' '{print $3}')
    size=$(printf '%s' "$stat_fields" | awk -F '|' '{print $4}')
    mtime=$(printf '%s' "$stat_fields" | awk -F '|' '{print $5}')
    birth=$(printf '%s' "$stat_fields" | awk -F '|' '{print $6}')
    flags=$(printf '%s' "$stat_fields" | awk -F '|' '{print $7}')
    write_object_row "$top_dir/objects.tsv" "$rel" "$kind" "$mode" "$uid" "$gid" "$size" "$mtime" "$birth" "$flags" "$sha" "$class" "$description" "$link_target"

    case "$class" in
      mach-o|native-library|shell|python|javascript|typescript|json|plist|executable-other)
        verify_code_file "$path" "$rel" "$class" "$sha" "$top_dir"
        ;;
    esac
  done < <(find "$volume" -xdev -print0 2>> "$CURRENT_VOUT/find_errors.log")

  printf 'file_limit=%s\nfiles_seen=%s\npartial=%s\n' "$LIMIT_FILES" "$file_count" "$partial" > "$CURRENT_VOUT/run_scope.txt"
  verify_app_bundles "$volume" "$CURRENT_VOUT"
  verify_containers "$volume" "$CURRENT_VOUT"
  collect_high_signal_paths "$volume" "$CURRENT_VOUT"
  summarize_directories "$CURRENT_VOUT"

  date -u +%Y-%m-%dT%H:%M:%SZ > "$CURRENT_VOUT/00_utc_end.txt"
  log "Finished volume: $volume (files seen: $file_count, partial: $partial)"
  find "$CURRENT_VOUT" -type f ! -name output_hashes.sha256 -exec shasum -a 256 {} \; > "$CURRENT_VOUT/output_hashes.sha256"
}

{
  echo "case=$CASE"
  echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "script=$0"
  echo "script_sha256=$(shasum -a 256 "$0" | awk '{print $1}')"
  echo "hash_mode=$HASH_MODE"
  echo "max_text_mb=$MAX_TEXT_MB"
  echo "limit_files=$LIMIT_FILES"
  echo "inspect_dmg_contents=$INSPECT_DMG_CONTENTS"
  echo "dmg_max_files=$DMG_MAX_FILES"
  echo "container_only=$CONTAINER_ONLY"
  echo "allow_writable=$ALLOW_WRITABLE"
  for source_volume in "${VOLUMES[@]-}"; do
    [ -n "$source_volume" ] && printf 'source=%s\n' "$source_volume"
  done
} > "$OUT/00_case_manifest.txt"

{
  bash --version | head -n 1
  shasum -a 256 "$0"
  file --version 2>&1 | head -n 1
  codesign --version 2>&1 || true
  spctl --version 2>&1 || true
  plutil -help 2>&1 | head -n 1
  rg --version 2>&1 | head -n 1 || true
  jq --version 2>&1 || true
  python3 --version 2>&1 || true
  node --version 2>&1 || true
} > "$OUT/00_tool_versions.txt"

log "Case output: $OUT"
if [ -n "$CONTAINER_ONLY" ]; then
  verify_container_only "$CONTAINER_ONLY"
else
  for volume in "${VOLUMES[@]}"; do
    inventory_volume "$volume"
  done
fi

RUN_COMPLETE=1
rm -f "$OUT/INCOMPLETE"
touch "$OUT/COMPLETE"
date -u +%Y-%m-%dT%H:%M:%SZ > "$OUT/00_utc_end.txt"
log "Collection complete: $OUT"
find "$OUT" -type f ! -name case_output_hashes.sha256 -exec shasum -a 256 {} \; > "$OUT/case_output_hashes.sha256"
echo "$OUT"
