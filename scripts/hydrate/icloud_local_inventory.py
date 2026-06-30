#!/usr/bin/env python3
import argparse
import csv
import hashlib
import os
import subprocess
from datetime import datetime
from pathlib import Path


def iso(ts):
    try:
        return datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")
    except Exception:
        return ""


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(args, timeout=10):
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout, check=False)
    except Exception as exc:
        return f"ERROR: {exc}"
    out = (p.stdout or "").strip()
    err = (p.stderr or "").strip()
    if p.returncode != 0 and err:
        return f"ERROR({p.returncode}): {err[:300]}"
    return out[:800]


def xattrs(path):
    out = run(["/usr/bin/xattr", "-l", path])
    if out.startswith("ERROR"):
        return ""
    return out.replace("\n", " | ")[:1000]


def file_kind(path):
    return run(["/usr/bin/file", "-b", path])


def should_include(st, cutoff_ts):
    birth = getattr(st, "st_birthtime", 0)
    return birth >= cutoff_ts or st.st_mtime >= cutoff_ts or st.st_ctime >= cutoff_ts


def inventory(root, cutoff_ts, hash_limit, max_rows):
    rows = []
    root = Path(root).expanduser()
    if not root.exists():
        return [{
            "root": str(root),
            "path": str(root),
            "error": "missing",
        }]
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        filenames.sort()
        paths = [Path(dirpath)] + [Path(dirpath) / name for name in filenames]
        for p in paths:
            try:
                st = os.lstat(p)
            except OSError as exc:
                rows.append({"root": str(root), "path": str(p), "error": str(exc)})
                continue
            if not should_include(st, cutoff_ts):
                continue
            is_file = p.is_file() and not p.is_symlink()
            digest = ""
            note = ""
            kind = ""
            if is_file:
                kind = file_kind(str(p))
                if st.st_size <= hash_limit:
                    try:
                        digest = sha256_file(p)
                    except Exception as exc:
                        note = f"hash_error:{exc}"
                else:
                    note = f"hash_skipped_over_{hash_limit}_bytes"
            rows.append({
                "root": str(root),
                "path": str(p),
                "relative_path": str(p.relative_to(root)) if p != root else ".",
                "type": "symlink" if p.is_symlink() else "directory" if p.is_dir() else "file" if p.is_file() else "other",
                "birth_time": iso(getattr(st, "st_birthtime", 0)),
                "modified_time": iso(st.st_mtime),
                "changed_time": iso(st.st_ctime),
                "accessed_time": iso(st.st_atime),
                "size": st.st_size,
                "mode": oct(st.st_mode & 0o7777),
                "uid": st.st_uid,
                "gid": st.st_gid,
                "file_kind": kind,
                "sha256": digest,
                "notes": note,
                "xattrs": xattrs(str(p)),
                "error": "",
            })
            if len(rows) >= max_rows:
                return rows
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--cutoff", required=True)
    ap.add_argument("--hash-limit", type=int, default=16 * 1024 * 1024)
    ap.add_argument("--max-rows", type=int, default=10000)
    ap.add_argument("roots", nargs="+")
    args = ap.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    cutoff = datetime.fromisoformat(args.cutoff)
    if cutoff.tzinfo is None:
        cutoff = cutoff.astimezone()
    cutoff_ts = cutoff.timestamp()

    rows = []
    for root in args.roots:
        rows.extend(inventory(root, cutoff_ts, args.hash_limit, args.max_rows))

    fields = [
        "root", "path", "relative_path", "type", "birth_time", "modified_time",
        "changed_time", "accessed_time", "size", "mode", "uid", "gid",
        "file_kind", "sha256", "notes", "xattrs", "error",
    ]
    csv_path = out / "icloud_local_recent_inventory.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, "") for k in fields})

    md_path = out / "icloud_local_recent_summary.md"
    with md_path.open("w", encoding="utf-8") as fh:
        fh.write("# Local iCloud Drive Recent Inventory\n\n")
        fh.write(f"Generated: {datetime.now().astimezone().isoformat(timespec='seconds')}\n\n")
        fh.write(f"Cutoff: {cutoff.isoformat(timespec='seconds')}\n\n")
        fh.write(f"Rows: {len(rows)}\n\n")
        fh.write("| Path | Type | Birth | Modified | Size | SHA-256 / Note |\n")
        fh.write("| --- | --- | --- | --- | ---: | --- |\n")
        for row in rows[:200]:
            digest = row.get("sha256") or row.get("notes") or row.get("error", "")
            fh.write(f"| `{row.get('path','')}` | {row.get('type','')} | {row.get('birth_time','')} | {row.get('modified_time','')} | {row.get('size','')} | `{digest}` |\n")
        if len(rows) > 200:
            fh.write(f"\nOnly first 200 rows shown. See `{csv_path}`.\n")

    print(csv_path)
    print(md_path)


if __name__ == "__main__":
    main()
