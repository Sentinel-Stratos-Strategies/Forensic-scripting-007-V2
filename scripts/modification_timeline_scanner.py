#!/usr/bin/env python3
"""
Modification Timeline Scanner

Builds a TSV timeline for files under one or more evidence paths without
executing target binaries. Useful for quickly comparing bundle and artifact
modification chronology in reviewer packets.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import stat
from datetime import datetime, timezone
from pathlib import Path


def iso_utc(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_paths(roots: list[Path]):
    for root in roots:
        if root.is_file() or root.is_symlink():
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in {".git", "__pycache__"}]
            for name in filenames:
                yield Path(dirpath) / name


def scan_timeline(targets: list[str], output_path: str, hash_files: bool) -> int:
    roots = [Path(t) for t in targets]
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = []

    for path in iter_paths(roots):
        try:
            st = path.lstat()
        except OSError:
            continue
        mode = stat.filemode(st.st_mode)
        digest = ""
        if hash_files and path.is_file() and not path.is_symlink():
            try:
                digest = sha256_file(path)
            except OSError:
                digest = ""
        rows.append((iso_utc(st.st_mtime), iso_utc(st.st_ctime), st.st_size, mode, digest, str(path)))

    rows.sort(key=lambda row: (row[0], row[-1]))
    with output.open("w", newline="") as tsvfile:
        writer = csv.writer(tsvfile, delimiter="\t")
        writer.writerow(["mtime_utc", "ctime_utc", "size_bytes", "mode", "sha256", "path"])
        writer.writerows(rows)
    print(f"[+] Timeline: Wrote {len(rows)} file record(s) to {output}")
    return len(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a modification timeline TSV for evidence paths.")
    parser.add_argument("--target", action="append", required=True, help="File or directory to scan; may be repeated")
    parser.add_argument("--output", required=True, help="Path to output TSV file")
    parser.add_argument("--hash", action="store_true", help="Include SHA-256 hashes for regular files")
    args = parser.parse_args()
    scan_timeline(args.target, args.output, args.hash)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
