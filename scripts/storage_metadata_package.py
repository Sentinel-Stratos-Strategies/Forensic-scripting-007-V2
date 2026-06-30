#!/usr/bin/env python3
"""Build a metadata-first evidence package for a staged Storage volume."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import os
import subprocess
import sys
from pathlib import Path


FIELDS = [
    "path",
    "relative_path",
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
    "read_error",
]


def iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")


def sha256_file(path: Path) -> tuple[str, str]:
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest(), ""
    except Exception as exc:
        return "", str(exc)


def file_type(path: Path) -> str:
    try:
        if path.is_symlink():
            return "symlink"
        if path.is_dir():
            return "directory"
        if path.is_file():
            return "file"
        return "other"
    except OSError:
        return "unknown"


def xattr_summary(path: Path) -> tuple[str, str]:
    try:
        names = sorted(os.listxattr(path, follow_symlinks=False))
    except Exception:
        return "", ""
    hashes = []
    for name in names:
        try:
            value = os.getxattr(path, name, follow_symlinks=False)
            hashes.append(f"{name}:{hashlib.sha256(value).hexdigest()}")
        except Exception:
            hashes.append(f"{name}:unreadable")
    return ";".join(names), ";".join(hashes)


def row_for(root: Path, path: Path, hash_files: bool) -> dict[str, str]:
    row = {field: "" for field in FIELDS}
    row["path"] = str(path)
    try:
        row["relative_path"] = str(path.relative_to(root))
    except ValueError:
        row["relative_path"] = str(path)
    try:
        st = path.lstat()
        row["type"] = file_type(path)
        row["size"] = str(st.st_size)
        row["mode_octal"] = oct(st.st_mode & 0o7777)
        row["uid"] = str(st.st_uid)
        row["gid"] = str(st.st_gid)
        row["flags"] = str(getattr(st, "st_flags", ""))
        row["created_time"] = iso(getattr(st, "st_birthtime", st.st_ctime))
        row["modified_time"] = iso(st.st_mtime)
        row["changed_time"] = iso(st.st_ctime)
        row["accessed_time"] = iso(st.st_atime)
        xnames, xhashes = xattr_summary(path)
        row["xattr_names"] = xnames
        row["xattr_value_sha256"] = xhashes
        if hash_files and row["type"] == "file":
            digest, err = sha256_file(path)
            row["sha256"] = digest
            row["read_error"] = err
    except Exception as exc:
        row["read_error"] = str(exc)
    return row


def iter_paths(root: Path, limit_files: int) -> tuple[int, list[Path]]:
    paths = []
    seen = 0
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        paths.append(current_path)
        for name in dirs:
            dir_path = current_path / name
            if dir_path.is_symlink():
                paths.append(dir_path)
        for name in files:
            paths.append(current_path / name)
            seen += 1
            if limit_files and seen >= limit_files:
                return seen, paths
    return seen, paths


def write_manifest(root: Path, out_csv: Path, hash_files: bool, limit_files: int) -> tuple[int, bool]:
    file_count, paths = iter_paths(root, limit_files)
    partial = bool(limit_files and file_count >= limit_files)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        for path in paths:
            writer.writerow(row_for(root, path, hash_files))
    return file_count, partial


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_archive(source: Path, archive_path: Path) -> int:
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "ditto",
        "-c",
        "-k",
        "--keepParent",
        "--sequesterRsrc",
        "--preserveHFSCompression",
        str(source),
        str(archive_path),
    ]
    with (archive_path.with_suffix(archive_path.suffix + ".stdout")).open("w", encoding="utf-8") as stdout, (
        archive_path.with_suffix(archive_path.suffix + ".stderr")
    ).open("w", encoding="utf-8") as stderr:
        proc = subprocess.run(cmd, stdout=stdout, stderr=stderr)
    return proc.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="/Volumes/Storage")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--case", default="storage_metadata_package")
    parser.add_argument("--hash-files", action="store_true", help="Hash each regular file; can take a long time.")
    parser.add_argument("--limit-files", type=int, default=0)
    parser.add_argument("--archive", action="store_true", help="Create a metadata-preserving zip with ditto.")
    args = parser.parse_args()

    source = Path(args.source).resolve()
    if not source.exists():
        print(f"source not found: {source}", file=sys.stderr)
        return 2
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(args.out_dir) / f"{args.case}_{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest = out_dir / "STORAGE_LOCAL_MANIFEST.csv"
    file_count, partial = write_manifest(source, manifest, args.hash_files, args.limit_files)
    archive_path = out_dir / "STORAGE_ARCHIVE.zip"
    archive_status = "not_requested"
    if args.archive:
        rc = run_archive(source, archive_path)
        archive_status = f"exit_code={rc}"
        if archive_path.exists():
            (out_dir / "STORAGE_ARCHIVE.sha256").write_text(
                f"{sha256_path(archive_path)}  {archive_path.name}\n", encoding="utf-8"
            )

    (out_dir / "PACKAGE_SUMMARY.md").write_text(
        "# Storage Metadata Package\n\n"
        f"- source: `{source}`\n"
        f"- manifest: `{manifest}`\n"
        f"- hash_files: `{args.hash_files}`\n"
        f"- limit_files: `{args.limit_files}`\n"
        f"- files_seen: `{file_count}`\n"
        f"- partial: `{partial}`\n"
        f"- archive_status: `{archive_status}`\n"
        f"- archive: `{archive_path if archive_path.exists() else 'not_created'}`\n\n"
        "Xattr values are not written in plaintext; only xattr names and value SHA-256 hashes are recorded.\n",
        encoding="utf-8",
    )
    hash_lines = []
    for path in sorted(out_dir.iterdir()):
        if path.is_file() and path.name != "HASH_MANIFEST.sha256":
            hash_lines.append(f"{sha256_path(path)}  {path.name}\n")
    (out_dir / "HASH_MANIFEST.sha256").write_text("".join(hash_lines), encoding="utf-8")
    print(out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
