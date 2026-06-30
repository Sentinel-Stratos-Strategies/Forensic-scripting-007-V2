#!/usr/bin/env python3
"""
Read-only rolling watcher for app-focused forensic collection.

Targets:
- Atlas
- Google Chrome
- Codex / Codex Computer Use
- Warp / developer tools when present

Outputs:
- SQLite database with timestamped process/socket/file/log samples
- Raw text snapshots per cycle

This collector does not modify target app state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

UTC = timezone.utc
TEXT_SUFFIXES = {".log", ".json", ".plist", ".toml", ".db", ".sqlite", ".txt"}
HOME = Path.home()


@dataclass(frozen=True)
class AppConfig:
    key: str
    display_name: str
    process_markers: tuple[str, ...]
    watch_roots: tuple[str, ...]
    log_files: tuple[str, ...]


APP_CONFIGS = {
    "atlas": AppConfig(
        key="atlas",
        display_name="ChatGPT Atlas",
        process_markers=(
            "/Applications/ChatGPT Atlas.app/",
            "ChatGPT Atlas",
            "com.openai.atlas",
            "Atlas",
        ),
        watch_roots=(
            str(HOME / "Library/Application Support/ChatGPT Atlas"),
            str(HOME / "Library/Logs/ChatGPT Atlas"),
            "/Volumes/Storage/Ellis_Archive/Investigations/ATLAS_EVIDENCE_20260620T043223Z",
        ),
        log_files=(),
    ),
    "codex": AppConfig(
        key="codex",
        display_name="Codex",
        process_markers=(
            "/Applications/Codex.app/",
            "com.openai.codex",
            "Codex Computer Use.app",
            "SkyComputerUse",
            "com.openai.sky.CUAService",
        ),
        watch_roots=(
            str(HOME / ".codex"),
            str(HOME / "Library/Application Support/Codex"),
            str(HOME / "Library/Logs/Codex"),
        ),
        log_files=(),
    ),
    "chrome": AppConfig(
        key="chrome",
        display_name="Google Chrome",
        process_markers=(
            "/Applications/Google Chrome.app/",
            "Google Chrome Helper",
            "chrome-devtools-mcp",
        ),
        watch_roots=(
            str(HOME / "Library/Application Support/Google/Chrome"),
            str(HOME / "chrome-devtools-mcp"),
            str(HOME / ".config/chrome-devtools-mcp"),
        ),
        log_files=(),
    ),
    "warp": AppConfig(
        key="warp",
        display_name="Warp",
        process_markers=(
            "/Applications/Warp.app/",
            "/Volumes/OS_BOOT/Applications/Warp.app/",
            "dev.warp.Warp-Stable",
            " terminal-server",
        ),
        watch_roots=(
            str(HOME / "Library/Application Support/dev.warp.Warp-Stable"),
            str(HOME / "Library/Group Containers/2BBY89MBSN.dev.warp"),
            str(HOME / ".warp"),
        ),
        log_files=(str(HOME / "Library/Logs/warp.log"),),
    ),
    "granola": AppConfig(
        key="granola",
        display_name="Granola",
        process_markers=("/Applications/Granola.app/", "Granola Helper"),
        watch_roots=(str(HOME / "Library/Application Support/Granola"),),
        log_files=(),
    ),
    "antigravity": AppConfig(
        key="antigravity",
        display_name="Antigravity",
        process_markers=("/Applications/Antigravity.app/", "google.antigravity", "daily-cloudcode-pa.googleapis.com"),
        watch_roots=(
            str(HOME / "Library/Application Support/Antigravity"),
            str(HOME / "Library/Application Support/Antigravity IDE"),
            str(HOME / ".gemini"),
            str(HOME / "antigravity"),
            str(HOME / "Antigravity"),
        ),
        log_files=(
            str(HOME / "Library/Logs/Antigravity/language_server.log"),
        ),
    ),
}


def utc_now() -> str:
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def local_now_slug() -> str:
    return datetime.now().strftime("%Y%m%dT%H%M%S")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def ensure_db(db_path: Path) -> None:
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.executescript(
        """
        create table if not exists process_samples (
            sample_time_utc text,
            app_key text,
            pid integer,
            ppid integer,
            create_time_utc text,
            exe text,
            cmdline text
        );
        create table if not exists socket_samples (
            sample_time_utc text,
            app_key text,
            pid integer,
            proto text,
            local_addr text,
            remote_addr text,
            status text
        );
        create table if not exists file_samples (
            sample_time_utc text,
            app_key text,
            path text,
            size integer,
            mtime_utc text,
            sha256 text
        );
        create table if not exists log_samples (
            sample_time_utc text,
            app_key text,
            path text,
            mtime_utc text,
            sha256 text,
            tail_text text
        );
        create table if not exists notes (
            sample_time_utc text,
            source text,
            note text
        );
        """
    )
    con.commit()
    con.close()


def iso_from_ts(ts: float | None) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_text(cmd: list[str]) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=25, check=False)
    except Exception as exc:  # pragma: no cover - best effort collector
        return f"[collector_error] {' '.join(cmd)} :: {exc}\n"
    out = proc.stdout or ""
    err = proc.stderr or ""
    return out + err


def parse_ps_rows() -> list[dict[str, str]]:
    raw = run_text(["/bin/ps", "-axo", "pid=,ppid=,lstart=,command="])
    rows: list[dict[str, str]] = []
    for line in raw.splitlines():
        line = line.rstrip()
        if not line:
            continue
        parts = line.split(None, 7)
        if len(parts) < 8:
            continue
        pid, ppid = parts[0], parts[1]
        lstart = " ".join(parts[2:7])
        command = parts[7]
        rows.append({"pid": pid, "ppid": ppid, "lstart": lstart, "command": command})
    return rows


def process_matches(config: AppConfig, row: dict[str, str]) -> bool:
    hay = row["command"].lower()
    return any(marker.lower() in hay for marker in config.process_markers)


def tail_text(path: Path, lines: int) -> str:
    data = run_text(["/usr/bin/tail", "-n", str(lines), str(path)])
    return data[-24000:]


def watch_files(root: Path, since_ts: float, limit: int) -> list[tuple[Path, os.stat_result]]:
    found: list[tuple[Path, os.stat_result]] = []
    if not root.exists():
        return found
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            st = path.stat()
        except OSError:
            continue
        if st.st_mtime >= since_ts:
            found.append((path, st))
    found.sort(key=lambda item: item[1].st_mtime, reverse=True)
    return found[:limit]


def write_cycle_snapshot(path: Path, title: str, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        handle.write(f"\n## {title}\n")
        handle.write(text)
        if not text.endswith("\n"):
            handle.write("\n")


def collect_once(
    config: AppConfig,
    out_root: Path,
    db_path: Path,
    cycle_index: int,
    recent_seconds: int,
    tail_lines: int,
    file_limit: int,
) -> None:
    sample_time = utc_now()
    cycle_dir = out_root / config.key / f"cycle_{cycle_index:04d}"
    cycle_dir.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
    cur = con.cursor()

    procs = [row for row in parse_ps_rows() if process_matches(config, row)]
    process_rows: list[str] = []
    for proc in procs:
        pid = int(proc["pid"])
        ppid = int(proc["ppid"])
        cmdline = proc["command"]
        exe = cmdline.split(" ")[0] if cmdline else ""
        create_time = proc["lstart"]
        cur.execute(
            "insert into process_samples values (?, ?, ?, ?, ?, ?, ?)",
            (sample_time, config.key, pid, ppid, create_time, exe, cmdline),
        )
        process_rows.append(f"{pid}\t{ppid}\t{create_time}\t{exe}\t{cmdline}")

        lsof_text = run_text(["/usr/sbin/lsof", "-nP", "-i", "-a", "-p", str(pid)])
        for line in lsof_text.splitlines():
            if "TCP" not in line and "UDP" not in line:
                continue
            local_addr = ""
            remote_addr = ""
            status = ""
            proto = "TCP" if "TCP" in line else "UDP"
            if "->" in line:
                try:
                    tail = line.split(proto, 1)[1].strip()
                    left, right = tail.split("->", 1)
                    local_addr = left.strip().split(" ")[0]
                    remote_addr = right.strip().split(" ")[0]
                    if "(" in line and line.rstrip().endswith(")"):
                        status = line.rsplit("(", 1)[1].rstrip(")")
                except Exception:
                    pass
            else:
                try:
                    tail = line.split(proto, 1)[1].strip()
                    local_addr = tail.split(" ")[0]
                    if "(" in line and line.rstrip().endswith(")"):
                        status = line.rsplit("(", 1)[1].rstrip(")")
                except Exception:
                    pass
            cur.execute(
                "insert into socket_samples values (?, ?, ?, ?, ?, ?, ?)",
                (sample_time, config.key, pid, proto, local_addr, remote_addr, status),
            )

    (cycle_dir / "processes.tsv").write_text(
        "pid\tppid\tcreate_time_utc\texe\tcmdline\n" + "\n".join(process_rows) + ("\n" if process_rows else ""),
        encoding="utf-8",
    )

    since_ts = time.time() - recent_seconds
    file_rows: list[str] = []
    for root_str in config.watch_roots:
        root = Path(root_str).expanduser()
        for path, st in watch_files(root, since_ts=since_ts, limit=file_limit):
            digest = ""
            try:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            except Exception:
                digest = ""
            cur.execute(
                "insert into file_samples values (?, ?, ?, ?, ?, ?)",
                (
                    sample_time,
                    config.key,
                    str(path),
                    int(st.st_size),
                    iso_from_ts(st.st_mtime),
                    digest,
                ),
            )
            file_rows.append(f"{iso_from_ts(st.st_mtime)}\t{st.st_size}\t{digest}\t{path}")

    (cycle_dir / "recent_files.tsv").write_text(
        "mtime_utc\tsize\tsha256\tpath\n" + "\n".join(file_rows) + ("\n" if file_rows else ""),
        encoding="utf-8",
    )

    log_rows: list[str] = []
    for log_path_str in config.log_files:
        log_path = Path(log_path_str).expanduser()
        if not log_path.exists():
            continue
        try:
            st = log_path.stat()
        except OSError:
            continue
        text = tail_text(log_path, tail_lines)
        digest = sha256_text(text)
        cur.execute(
            "insert into log_samples values (?, ?, ?, ?, ?, ?)",
            (sample_time, config.key, str(log_path), iso_from_ts(st.st_mtime), digest, text),
        )
        safe_name = log_path.name.replace("/", "_")
        (cycle_dir / f"logtail_{safe_name}.txt").write_text(text, encoding="utf-8")
        log_rows.append(f"{iso_from_ts(st.st_mtime)}\t{digest}\t{log_path}")

    (cycle_dir / "log_samples.tsv").write_text(
        "mtime_utc\tsha256\tpath\n" + "\n".join(log_rows) + ("\n" if log_rows else ""),
        encoding="utf-8",
    )

    raw_ps = run_text(
        [
            "/bin/ps",
            "-axo",
            "pid,ppid,lstart,command",
        ]
    )
    matched_lines = [
        line for line in raw_ps.splitlines() if any(marker.lower() in line.lower() for marker in config.process_markers)
    ]
    (cycle_dir / "ps_snapshot.txt").write_text("\n".join(matched_lines) + ("\n" if matched_lines else ""), encoding="utf-8")

    if procs:
        lsof_lines: list[str] = []
        for proc in procs[:20]:
            lsof_lines.append(f"## pid {proc['pid']}")
            lsof_lines.append(run_text(["/usr/sbin/lsof", "-nP", "-i", "-a", "-p", str(proc["pid"])]))
        (cycle_dir / "lsof_snapshot.txt").write_text("\n".join(lsof_lines), encoding="utf-8")

    cur.execute("insert into notes values (?, ?, ?)", (sample_time, config.key, f"cycle {cycle_index} complete"))
    con.commit()
    con.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Rolling app-focused forensic watcher")
    parser.add_argument(
        "--apps",
        nargs="+",
        default=["atlas", "chrome", "codex"],
        choices=sorted(APP_CONFIGS.keys()),
        help="Apps to watch",
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help="Output root for session artifacts; default creates app_watch_<timestamp> in repo cwd",
    )
    parser.add_argument("--interval", type=int, default=60, help="Seconds between cycles")
    parser.add_argument("--cycles", type=int, default=0, help="Number of cycles, 0 means run until interrupted")
    parser.add_argument("--recent-seconds", type=int, default=600, help="Recent file window per cycle")
    parser.add_argument("--tail-lines", type=int, default=120, help="Lines to tail from configured app logs")
    parser.add_argument("--file-limit", type=int, default=150, help="Max recent files per root per cycle")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out_dir = Path(args.out_dir) if args.out_dir else Path.cwd() / f"app_watch_{local_now_slug()}"
    out_dir.mkdir(parents=True, exist_ok=True)
    db_path = out_dir / "watch.db"
    ensure_db(db_path)

    manifest = {
        "session_started_utc": utc_now(),
        "apps": args.apps,
        "interval_seconds": args.interval,
        "cycles": args.cycles,
        "recent_seconds": args.recent_seconds,
        "tail_lines": args.tail_lines,
        "file_limit": args.file_limit,
        "host": run_text(["/usr/bin/sw_vers"]) + run_text(["/usr/sbin/system_profiler", "SPHardwareDataType"]),
    }
    (out_dir / "session_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    cycle = 1
    while True:
        cycle_started = utc_now()
        for app_key in args.apps:
            collect_once(
                APP_CONFIGS[app_key],
                out_root=out_dir,
                db_path=db_path,
                cycle_index=cycle,
                recent_seconds=args.recent_seconds,
                tail_lines=args.tail_lines,
                file_limit=args.file_limit,
            )
        write_cycle_snapshot(out_dir / "session.log", f"cycle {cycle} @ {cycle_started}", f"apps={','.join(args.apps)}")
        if args.cycles and cycle >= args.cycles:
            break
        cycle += 1
        time.sleep(args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
