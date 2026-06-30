#!/usr/bin/env python3
"""Compare two metadata manifests from Storage/local and Drive/downloaded copies."""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path


COMPARE_FIELDS = [
    "type",
    "size",
    "mode_octal",
    "uid",
    "gid",
    "flags",
    "created_time",
    "modified_time",
    "changed_time",
    "accessed_time",
    "sha256",
    "xattr_names",
    "xattr_value_sha256",
]

OUT_FIELDS = [
    "relative_path",
    "status",
    "hash_state",
    "metadata_diff_fields",
    "local_path",
    "drive_path",
    "local_sha256",
    "drive_sha256",
    "local_created_time",
    "drive_created_time",
    "local_modified_time",
    "drive_modified_time",
    "local_changed_time",
    "drive_changed_time",
    "notes",
]


def read_manifest(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        rows = {}
        for row in csv.DictReader(f):
            key = row.get("relative_path") or row.get("path")
            rows[key] = row
        return rows


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_diff(local_rows, drive_rows):
    out = []
    all_keys = sorted(set(local_rows) | set(drive_rows))
    for key in all_keys:
        local = local_rows.get(key)
        drive = drive_rows.get(key)
        if local and not drive:
            out.append(
                {
                    "relative_path": key,
                    "status": "local_only",
                    "hash_state": "not_comparable",
                    "local_path": local.get("path", ""),
                    "local_sha256": local.get("sha256", ""),
                    "local_created_time": local.get("created_time", ""),
                    "local_modified_time": local.get("modified_time", ""),
                    "local_changed_time": local.get("changed_time", ""),
                    "notes": "Present in local manifest only.",
                }
            )
            continue
        if drive and not local:
            out.append(
                {
                    "relative_path": key,
                    "status": "drive_only",
                    "hash_state": "not_comparable",
                    "drive_path": drive.get("path", ""),
                    "drive_sha256": drive.get("sha256", ""),
                    "drive_created_time": drive.get("created_time", ""),
                    "drive_modified_time": drive.get("modified_time", ""),
                    "drive_changed_time": drive.get("changed_time", ""),
                    "notes": "Present in Drive/downloaded manifest only.",
                }
            )
            continue

        assert local and drive
        diff_fields = [field for field in COMPARE_FIELDS if local.get(field, "") != drive.get(field, "")]
        local_hash = local.get("sha256", "")
        drive_hash = drive.get("sha256", "")
        if local_hash and drive_hash and local_hash == drive_hash:
            hash_state = "same_hash"
        elif local_hash and drive_hash and local_hash != drive_hash:
            hash_state = "different_hash"
        else:
            hash_state = "hash_missing"

        if diff_fields:
            if hash_state == "same_hash":
                status = "same_hash_metadata_diff"
                notes = "Byte hash matches but filesystem metadata differs; useful preservation/copy/staging signal if examiner effects are controlled."
            elif hash_state == "different_hash":
                status = "content_and_metadata_diff"
                notes = "Both bytes and metadata differ."
            else:
                status = "metadata_diff_hash_unknown"
                notes = "Metadata differs but at least one side lacks a file hash."
        else:
            status = "match"
            notes = "Compared fields match."

        out.append(
            {
                "relative_path": key,
                "status": status,
                "hash_state": hash_state,
                "metadata_diff_fields": ";".join(diff_fields),
                "local_path": local.get("path", ""),
                "drive_path": drive.get("path", ""),
                "local_sha256": local_hash,
                "drive_sha256": drive_hash,
                "local_created_time": local.get("created_time", ""),
                "drive_created_time": drive.get("created_time", ""),
                "local_modified_time": local.get("modified_time", ""),
                "drive_modified_time": drive.get("modified_time", ""),
                "local_changed_time": local.get("changed_time", ""),
                "drive_changed_time": drive.get("changed_time", ""),
                "notes": notes,
            }
        )
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-manifest", required=True)
    parser.add_argument("--drive-manifest", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    local_rows = read_manifest(Path(args.local_manifest))
    drive_rows = read_manifest(Path(args.drive_manifest))
    rows = build_diff(local_rows, drive_rows)

    diff_csv = out_dir / "LOCAL_VS_DRIVE_METADATA_DIFF.csv"
    with diff_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=OUT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    counts = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    summary_lines = ["# Local vs Drive Metadata Diff\n\n"]
    for key in sorted(counts):
        summary_lines.append(f"- {key}: {counts[key]}\n")
    summary_lines.append("\nReviewer priority: start with `same_hash_metadata_diff`, then `content_and_metadata_diff`.\n")
    (out_dir / "DIFF_SUMMARY.md").write_text("".join(summary_lines), encoding="utf-8")

    hash_lines = []
    for path in [diff_csv, out_dir / "DIFF_SUMMARY.md"]:
        hash_lines.append(f"{sha256_path(path)}  {path.name}\n")
    (out_dir / "HASH_MANIFEST.sha256").write_text("".join(hash_lines), encoding="utf-8")
    print(out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
