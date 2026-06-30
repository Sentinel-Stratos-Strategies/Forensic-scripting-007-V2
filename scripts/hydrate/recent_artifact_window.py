#!/usr/bin/env python3
import argparse
import csv
import hashlib
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def iso(ts):
    if not ts:
        return ""
    return datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_tool(args):
    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
            check=False,
        )
    except Exception as exc:
        return f"ERROR: {exc}"
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    if proc.returncode != 0 and err:
        return f"ERROR({proc.returncode}): {err[:500]}"
    return out[:1000]


def file_kind(path):
    return run_tool(["/usr/bin/file", "-b", path])


def xattrs(path):
    out = run_tool(["/usr/bin/xattr", "-l", path])
    if out.startswith("ERROR"):
        return ""
    return out.replace("\n", " | ")[:1000]


def scan_path(path, cutoff_ts, rows, max_depth, hash_limit, depth=0):
    try:
        st = os.lstat(path)
    except OSError as exc:
        rows.append({
            "path": path,
            "error": str(exc),
        })
        return

    birth = getattr(st, "st_birthtime", 0)
    recent = birth >= cutoff_ts or st.st_mtime >= cutoff_ts or st.st_ctime >= cutoff_ts

    if recent:
        mode = st.st_mode
        is_file = os.path.isfile(path) and not os.path.islink(path)
        digest = ""
        hash_note = ""
        if is_file:
            if st.st_size <= hash_limit:
                try:
                    digest = sha256_file(path)
                except Exception as exc:
                    hash_note = f"hash_error:{exc}"
            else:
                hash_note = f"skipped_over_{hash_limit}_bytes"
        rows.append({
            "path": path,
            "volume": Path(path).parts[2] if len(Path(path).parts) > 2 else "",
            "type": "symlink" if os.path.islink(path) else ("directory" if os.path.isdir(path) else "file" if os.path.isfile(path) else "other"),
            "birth_time": iso(birth),
            "modified_time": iso(st.st_mtime),
            "changed_time": iso(st.st_ctime),
            "accessed_time": iso(st.st_atime),
            "size": st.st_size,
            "mode": oct(st.st_mode & 0o7777),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "file_kind": file_kind(path) if is_file or path.endswith(".dmg") else "",
            "sha256": digest,
            "hash_note": hash_note,
            "xattrs": xattrs(path),
            "error": "",
        })

    if depth >= max_depth:
        return
    if os.path.isdir(path) and not os.path.islink(path):
        try:
            with os.scandir(path) as it:
                names = sorted(entry.path for entry in it)
        except OSError as exc:
            if recent:
                rows[-1]["error"] = str(exc)
            return
        for child in names:
            scan_path(child, cutoff_ts, rows, max_depth, hash_limit, depth + 1)


def dmg_info(path):
    info = {
        "path": path,
        "imageinfo": run_tool(["/usr/bin/hdiutil", "imageinfo", path]),
        "verify": run_tool(["/usr/bin/hdiutil", "verify", path]),
    }
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--cutoff", required=True, help="ISO timestamp, local time accepted")
    ap.add_argument("--max-depth", type=int, default=6)
    ap.add_argument("--hash-limit", type=int, default=8 * 1024 * 1024)
    ap.add_argument("--dmg", action="append", default=[], help="Optional DMG path to verify; repeatable")
    ap.add_argument("roots", nargs="+")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cutoff = datetime.fromisoformat(args.cutoff)
    if cutoff.tzinfo is None:
        cutoff = cutoff.astimezone()
    cutoff_ts = cutoff.timestamp()

    rows = []
    for root in args.roots:
        if os.path.exists(root):
            scan_path(root, cutoff_ts, rows, args.max_depth, args.hash_limit)
        else:
            rows.append({"path": root, "error": "missing"})

    fieldnames = [
        "path", "volume", "type", "birth_time", "modified_time", "changed_time",
        "accessed_time", "size", "mode", "uid", "gid", "file_kind", "sha256",
        "hash_note", "xattrs", "error",
    ]
    csv_path = out_dir / "recent_artifact_window_inventory.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})

    md_path = out_dir / "recent_artifact_window_summary.md"
    by_volume = {}
    for row in rows:
        by_volume.setdefault(row.get("volume", "unknown"), []).append(row)

    dmg_records = [dmg_info(path) for path in args.dmg if os.path.exists(path)]

    with md_path.open("w", encoding="utf-8") as fh:
        fh.write("# Recent Artifact Window Summary\n\n")
        fh.write(f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n\n")
        fh.write(f"Cutoff: {cutoff.isoformat(timespec='seconds')}\n\n")
        fh.write(f"Max depth scanned: {args.max_depth}\n\n")
        fh.write(f"Rows written: {len(rows)}\n\n")
        for volume, volume_rows in sorted(by_volume.items()):
            fh.write(f"## {volume}\n\n")
            fh.write(f"Recent rows: {len(volume_rows)}\n\n")
            top = [r for r in volume_rows if r.get("path", "").count(os.sep) <= 3]
            if top:
                fh.write("| Path | Type | Birth | Modified | Size | Hash Note |\n")
                fh.write("| --- | --- | --- | --- | ---: | --- |\n")
                for r in top:
                    fh.write(
                        f"| `{r.get('path','')}` | {r.get('type','')} | {r.get('birth_time','')} | "
                        f"{r.get('modified_time','')} | {r.get('size','')} | {r.get('hash_note','')} |\n"
                    )
                fh.write("\n")
        for dmg in dmg_records:
            fh.write("## DMG Verification\n\n")
            fh.write(f"Path: `{dmg['path']}`\n\n")
            fh.write("### hdiutil imageinfo\n\n")
            fh.write("```text\n")
            fh.write(dmg["imageinfo"] + "\n")
            fh.write("```\n\n")
            fh.write("### hdiutil verify\n\n")
            fh.write("```text\n")
            fh.write(dmg["verify"] + "\n")
            fh.write("```\n")

    print(csv_path)
    print(md_path)


if __name__ == "__main__":
    main()
