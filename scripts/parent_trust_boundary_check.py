#!/usr/bin/env python3
"""
Read-only parent-layer trust check for disk images, mounted volumes, and copied
directory trees.

This intentionally does not replace recursive child-code verification. It asks
the higher-level question first: is the parent container, mounted volume, or
copied tree itself able to prove its own trust boundary?
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


IMAGE_SUFFIXES = {
    ".dmg",
    ".sparseimage",
    ".sparsebundle",
    ".iso",
}
APPLE_FIRMWARE_SUFFIXES = {
    ".img4",
    ".ipsw",
    ".aea",
    ".apfs",
    ".img",
}
SUSPECT_PARENT_MARKERS = re.compile(
    r"(broken|ssv|recovery|preboot|cryptex|basesystem|full_image|snapshot|msuprepareupdate)",
    re.IGNORECASE,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def path_id(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_cmd(cmd: list[str], out_dir: Path, label: str, timeout: int = 120) -> dict[str, Any]:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", label).strip("_") or "command"
    out_path = out_dir / f"{safe}.txt"
    started = utc_now()
    try:
        proc = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        result = {
            "label": label,
            "command": cmd,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "started_utc": started,
            "ended_utc": utc_now(),
            "output_file": str(out_path.name),
        }
    except FileNotFoundError as exc:
        result = {
            "label": label,
            "command": cmd,
            "returncode": 127,
            "stdout": "",
            "stderr": str(exc),
            "started_utc": started,
            "ended_utc": utc_now(),
            "output_file": str(out_path.name),
        }
    except subprocess.TimeoutExpired as exc:
        result = {
            "label": label,
            "command": cmd,
            "returncode": 124,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or f"timeout after {timeout}s",
            "started_utc": started,
            "ended_utc": utc_now(),
            "output_file": str(out_path.name),
        }

    with out_path.open("w", encoding="utf-8") as handle:
        handle.write(f"$ {' '.join(cmd)}\n")
        handle.write(f"started_utc={result['started_utc']}\n")
        handle.write(f"ended_utc={result['ended_utc']}\n")
        handle.write(f"returncode={result['returncode']}\n\n")
        handle.write("[stdout]\n")
        handle.write(result["stdout"])
        if result["stdout"] and not result["stdout"].endswith("\n"):
            handle.write("\n")
        handle.write("\n[stderr]\n")
        handle.write(result["stderr"])
        if result["stderr"] and not result["stderr"].endswith("\n"):
            handle.write("\n")
    return result


def parse_key_values(text: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def tab(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("\\", "\\\\").replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n")


def infer_target_kind(path: Path) -> str:
    lower = path.name.lower()
    suffix = "".join(Path(lower).suffixes[-2:]) if lower.endswith((".tar.gz", ".tar.xz", ".tar.bz2")) else path.suffix.lower()
    if path.is_dir():
        if lower.endswith(".app"):
            return "app_bundle"
        return "directory_or_mounted_volume"
    if suffix in IMAGE_SUFFIXES:
        return "disk_image"
    if suffix in APPLE_FIRMWARE_SUFFIXES:
        return "apple_firmware_or_apfs_artifact"
    if suffix == ".pkg":
        return "package"
    return "file"


def status_for_disk_image(results: dict[str, dict[str, Any]]) -> str:
    imageinfo = results.get("hdiutil_imageinfo", {})
    verify = results.get("hdiutil_verify", {})
    codesign = results.get("codesign_verify", {})
    spctl = results.get("spctl_primary_signature", {})
    metadata = results.get("codesign_metadata", {})

    if imageinfo.get("returncode") != 0:
        return "untrusted_invalid_image_structure"
    if verify.get("returncode") != 0:
        return "untrusted_image_checksum_or_signature_failed"
    if codesign.get("returncode") == 0 and spctl.get("returncode") == 0:
        return "trusted_parent_image"
    combined = f"{metadata.get('stdout','')}\n{metadata.get('stderr','')}\n{codesign.get('stderr','')}"
    if re.search(r"not signed at all|code object is not signed", combined, re.IGNORECASE):
        return "untrusted_unsigned_parent_image"
    if codesign.get("returncode") not in (0, None):
        return "untrusted_invalid_parent_signature"
    if spctl.get("returncode") not in (0, None):
        return "untrusted_parent_gatekeeper_rejected"
    return "review_required_parent_image"


def reviewer_sentence(status: str, kind: str, expected_sealed: bool) -> str:
    if status.startswith("trusted_parent"):
        return (
            "The parent artifact passed the available parent-layer trust checks. "
            "Child-code verification should still be reviewed separately."
        )
    if "not_self_authenticating_directory_tree" in status:
        return (
            "This target is a copied directory tree, so valid inner code signatures "
            "cannot prove the original disk image, recovery mount, APFS seal, or "
            "acquisition route."
        )
    if "expected_sealed" in status:
        return (
            "This target was expected to represent sealed system or recovery content, "
            "but the parent layer did not establish a valid sealed parent boundary."
        )
    if "untrusted" in status:
        return (
            "The parent artifact did not pass parent-layer trust checks. Valid child "
            "code signatures must be treated as inner-file facts only."
        )
    if kind == "apple_firmware_or_apfs_artifact":
        return (
            "This Apple firmware/APFS-style artifact needs a specialized parent-layer "
            "validator; ordinary Mach-O child-code verification is not enough."
        )
    return (
        "The parent layer needs human review before child-code verification can be "
        "used as a safety conclusion."
    )


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    target = Path(args.target).expanduser()
    if not target.exists():
        raise SystemExit(f"target does not exist: {target}")
    target_abs = target.resolve()
    out_dir = Path(args.out_dir).expanduser().resolve()
    command_dir = out_dir / "command_outputs"
    command_dir.mkdir(parents=True, exist_ok=True)

    kind = infer_target_kind(target_abs)
    record: dict[str, Any] = {
        "generated_utc": utc_now(),
        "target_path": str(target_abs),
        "target_kind": kind,
        "expected_sealed": bool(args.expected_sealed),
        "source_note": args.source_note or "",
        "sha256": "not_requested",
        "size_bytes": "",
        "source_mount": "",
        "mount_line": "",
        "diskutil": {},
        "name_markers": [],
        "command_outputs": {},
        "parent_trust_status": "review_required",
        "reviewer_safe_sentence": "",
    }

    try:
        record["size_bytes"] = target_abs.stat().st_size if target_abs.is_file() else ""
    except OSError:
        record["size_bytes"] = ""

    if args.hash and target_abs.is_file():
        record["sha256"] = sha256_file(target_abs)

    marker_text = str(target_abs)
    record["name_markers"] = sorted(set(m.group(0) for m in SUSPECT_PARENT_MARKERS.finditer(marker_text)))

    df_result = run_cmd(["df", str(target_abs)], command_dir, "df_target", 30)
    record["command_outputs"]["df_target"] = df_result["output_file"]
    df_lines = df_result["stdout"].splitlines()
    source_mount = df_lines[1].split()[-1] if len(df_lines) > 1 and df_lines[1].split() else ""
    record["source_mount"] = source_mount

    mount_result = run_cmd(["mount"], command_dir, "mount_all", 30)
    record["command_outputs"]["mount_all"] = mount_result["output_file"]
    mount_line = ""
    if source_mount:
        needle = f" on {source_mount} "
        for line in mount_result["stdout"].splitlines():
            if needle in line:
                mount_line = line
                break
    record["mount_line"] = mount_line

    if source_mount:
        diskutil_result = run_cmd(["diskutil", "info", source_mount], command_dir, "diskutil_info_source_mount", 60)
        record["command_outputs"]["diskutil_info_source_mount"] = diskutil_result["output_file"]
        record["diskutil"] = parse_key_values(diskutil_result["stdout"])
        snapshots = run_cmd(["diskutil", "apfs", "listSnapshots", source_mount], command_dir, "diskutil_apfs_listSnapshots", 60)
        record["command_outputs"]["diskutil_apfs_listSnapshots"] = snapshots["output_file"]

    if kind == "disk_image":
        commands = {
            "hdiutil_imageinfo": ["hdiutil", "imageinfo", str(target_abs)],
            "hdiutil_verify": ["hdiutil", "verify", str(target_abs)],
            "codesign_verify": ["codesign", "--verify", "--strict", "--verbose=4", str(target_abs)],
            "codesign_metadata": ["codesign", "-dvvv", str(target_abs)],
            "spctl_primary_signature": [
                "spctl",
                "--assess",
                "--type",
                "open",
                "--context",
                "context:primary-signature",
                "-vv",
                str(target_abs),
            ],
        }
        command_results = {}
        for label, cmd in commands.items():
            result = run_cmd(cmd, command_dir, label, 180)
            command_results[label] = result
            record["command_outputs"][label] = result["output_file"]
        record["parent_trust_status"] = status_for_disk_image(command_results)
    elif kind == "package":
        pkg = run_cmd(["pkgutil", "--check-signature", str(target_abs)], command_dir, "pkgutil_check_signature", 90)
        spctl = run_cmd(["spctl", "--assess", "--type", "install", "-vv", str(target_abs)], command_dir, "spctl_install", 90)
        record["command_outputs"]["pkgutil_check_signature"] = pkg["output_file"]
        record["command_outputs"]["spctl_install"] = spctl["output_file"]
        if pkg["returncode"] == 0 and spctl["returncode"] == 0:
            record["parent_trust_status"] = "trusted_parent_package"
        else:
            record["parent_trust_status"] = "untrusted_parent_package_signature_or_gatekeeper_failed"
    elif kind == "directory_or_mounted_volume":
        sealed = record["diskutil"].get("Sealed", "")
        volume_read_only = record["diskutil"].get("Volume Read-Only", "")
        is_mount_root = bool(source_mount and os.path.realpath(str(target_abs)) == os.path.realpath(source_mount))
        record["target_kind"] = "mounted_volume" if is_mount_root else "copied_directory_tree"
        if args.expected_sealed and is_mount_root and sealed == "Yes":
            record["parent_trust_status"] = "expected_sealed_mount_reports_sealed"
        elif args.expected_sealed and is_mount_root and sealed and sealed != "Yes":
            record["parent_trust_status"] = "untrusted_expected_sealed_volume_not_sealed"
        elif args.expected_sealed:
            record["parent_trust_status"] = "untrusted_expected_sealed_parent_not_verifiable_from_copied_directory"
        elif not is_mount_root:
            record["parent_trust_status"] = "not_self_authenticating_directory_tree"
        elif sealed == "No":
            record["parent_trust_status"] = "mounted_volume_unsealed"
        elif volume_read_only == "No":
            record["parent_trust_status"] = "mounted_volume_writable_review_required"
        else:
            record["parent_trust_status"] = "mounted_volume_review_required"
    elif kind == "apple_firmware_or_apfs_artifact":
        record["parent_trust_status"] = "specialized_apple_image_validation_required"
    else:
        record["parent_trust_status"] = "parent_file_review_required"

    record["reviewer_safe_sentence"] = reviewer_sentence(
        record["parent_trust_status"], record["target_kind"], bool(args.expected_sealed)
    )
    return record


def write_outputs(record: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "parent_trust_boundary.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    headers = [
        "target_path",
        "target_kind",
        "expected_sealed",
        "sha256",
        "size_bytes",
        "source_mount",
        "volume_read_only",
        "sealed",
        "parent_trust_status",
        "reviewer_safe_sentence",
    ]
    values = {
        "target_path": record.get("target_path", ""),
        "target_kind": record.get("target_kind", ""),
        "expected_sealed": record.get("expected_sealed", ""),
        "sha256": record.get("sha256", ""),
        "size_bytes": record.get("size_bytes", ""),
        "source_mount": record.get("source_mount", ""),
        "volume_read_only": record.get("diskutil", {}).get("Volume Read-Only", ""),
        "sealed": record.get("diskutil", {}).get("Sealed", ""),
        "parent_trust_status": record.get("parent_trust_status", ""),
        "reviewer_safe_sentence": record.get("reviewer_safe_sentence", ""),
    }
    with (out_dir / "parent_trust_boundary.tsv").open("w", encoding="utf-8") as handle:
        handle.write("\t".join(headers) + "\n")
        handle.write("\t".join(tab(values[h]) for h in headers) + "\n")

    md = [
        "# Parent Trust Boundary Check",
        "",
        f"- Generated UTC: `{record.get('generated_utc')}`",
        f"- Target: `{record.get('target_path')}`",
        f"- Kind: `{record.get('target_kind')}`",
        f"- Expected sealed: `{record.get('expected_sealed')}`",
        f"- Parent trust status: `{record.get('parent_trust_status')}`",
        f"- Source mount: `{record.get('source_mount')}`",
        f"- Diskutil sealed: `{record.get('diskutil', {}).get('Sealed', '')}`",
        f"- Volume read-only: `{record.get('diskutil', {}).get('Volume Read-Only', '')}`",
        "",
        "## Reviewer-Safe Reading",
        "",
        record.get("reviewer_safe_sentence", ""),
        "",
        "## Boundary Rule",
        "",
        (
            "Valid inner code signatures do not upgrade an untrusted, unverified, "
            "unsealed, or copied parent container. Parent trust and child-code "
            "trust are separate evidence layers."
        ),
        "",
    ]
    if record.get("source_note"):
        md.extend(["## Source Note", "", record["source_note"], ""])
    (out_dir / "parent_trust_boundary.md").write_text("\n".join(md), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check parent image/mount/seal trust without executing evidence.")
    parser.add_argument("target", help="Disk image, package, mounted volume, or copied directory tree")
    parser.add_argument("--out-dir", required=True, help="Directory for derived parent trust outputs")
    parser.add_argument("--expected-sealed", action="store_true", help="Treat target as expected sealed system/recovery content")
    parser.add_argument("--source-note", default="", help="Short evidence note, such as copied from read-only recovery volume")
    parser.add_argument("--hash", action="store_true", help="Hash a regular-file parent artifact")
    args = parser.parse_args()

    out_dir = Path(args.out_dir).expanduser().resolve()
    record = build_report(args)
    write_outputs(record, out_dir)
    print(out_dir)
    print(record["parent_trust_status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
