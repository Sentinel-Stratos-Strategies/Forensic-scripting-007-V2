#!/usr/bin/env python3
"""
Host-side snapshot for a plugged-in iPhone or iPad.

This stays on the Mac side and records what macOS can currently see:
- USB inventory
- Apple Mobile Device related services
- Recent host logs for pairing, sync, sharing, and trust
- Recent MobileDevice / lockdownd style plist and log changes
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path


def now_slug() -> str:
    return datetime.now().strftime("%Y%m%dT%H%M%S")


def run_capture(path: Path, cmd: list[str]) -> None:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=45, check=False)
        text = (proc.stdout or "") + (proc.stderr or "")
    except Exception as exc:  # pragma: no cover - collector best effort
        text = f"[collector_error] {' '.join(cmd)} :: {exc}\n"
    path.write_text(text, encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest(out_dir: Path) -> None:
    rows = []
    for path in sorted(p for p in out_dir.rglob("*") if p.is_file() and p.name != "SHA256SUMS"):
        rows.append(f"{sha256_file(path)}  {path.relative_to(out_dir)}")
    (out_dir / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect host-side evidence for an attached iPhone/iPad")
    parser.add_argument("--out-dir", default=None, help="Output directory")
    parser.add_argument("--log-minutes", type=int, default=20, help="Recent unified-log window")
    parser.add_argument(
        "--backup-root",
        default=str(Path.home() / "Library/Application Support/MobileSync/Backup"),
        help="MobileSync backup root to inventory at depth 2",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir) if args.out_dir else Path.cwd() / f"iphone_host_snapshot_{now_slug()}"
    out_dir.mkdir(parents=True, exist_ok=True)

    commands = {
        "spusb.json": ["/usr/sbin/system_profiler", "SPUSBDataType", "-json"],
        "spnetwork.json": ["/usr/sbin/system_profiler", "SPNetworkDataType", "-json"],
        "ioreg_usb.txt": ["/usr/sbin/ioreg", "-p", "IOUSB", "-l", "-w", "0"],
        "ioreg_ioservice.txt": ["/usr/sbin/ioreg", "-rc", "AppleUSBDevice", "-l", "-w", "0"],
        "ps_mobile_services.txt": ["/bin/ps", "-axo", "pid,ppid,lstart,command"],
        "lockdown_dir.txt": ["/bin/ls", "-laO", "/var/db/lockdown"],
        "amds_dir.txt": ["/bin/ls", "-laO", "/Library/Apple/System/Library/PrivateFrameworks/MobileDevice.framework"],
        "mobilesync_backup_root.txt": ["/usr/bin/find", args.backup_root, "-maxdepth", "2", "-mindepth", "1", "-print"],
    }

    for name, cmd in commands.items():
        run_capture(out_dir / name, cmd)

    log_predicate = (
        '(process == "usbd" OR process == "mobileassetd" OR process == "sharingd" OR process == "rapportd" '
        'OR process == "lockdownd" OR process == "trustd" OR process == "imagent" OR process == "apsd" '
        'OR eventMessage CONTAINS[c] "iPhone" OR eventMessage CONTAINS[c] "iPad" '
        'OR eventMessage CONTAINS[c] "pair" OR eventMessage CONTAINS[c] "lockdown" '
        'OR eventMessage CONTAINS[c] "MobileDevice" OR eventMessage CONTAINS[c] "trust")'
    )
    run_capture(
        out_dir / "unified_log_recent.txt",
        [
            "/usr/bin/log",
            "show",
            "--last",
            f"{args.log_minutes}m",
            "--style",
            "compact",
            "--predicate",
            log_predicate,
        ],
    )

    find_script = r"""
import os, time, json
home = os.path.expanduser("~")
roots = ["/var/db/lockdown", os.path.join(home, "Library/Logs"), os.path.join(home, "Library/Application Support")]
cutoff = time.time() - __LOG_MINUTES__ * 60
rows = []
for root in roots:
    if not os.path.exists(root):
        continue
    for dp, dns, fns in os.walk(root):
        for n in fns:
            if not any(x in n.lower() for x in ("mobile", "lockdown", "pair", "trust", "iphone", "ipad", "usbmux")):
                continue
            p = os.path.join(dp, n)
            try:
                st = os.stat(p)
            except OSError:
                continue
            if st.st_mtime >= cutoff:
                rows.append({
                    "mtime_local": time.strftime("%Y-%m-%d %H:%M:%S %z", time.localtime(st.st_mtime)),
                    "size": st.st_size,
                    "path": p,
                })
rows.sort(key=lambda r: r["mtime_local"], reverse=True)
print(json.dumps(rows[:250], indent=2))
""".replace("__LOG_MINUTES__", str(args.log_minutes))
    run_capture(out_dir / "recent_ios_host_files.json", ["/usr/bin/python3", "-c", find_script])

    manifest = {
        "created_local": datetime.now().isoformat(),
        "notes": "Host-side only snapshot. This does not unlock or extract the phone.",
        "backup_root": args.backup_root,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    write_manifest(out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
