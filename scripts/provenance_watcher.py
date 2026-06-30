#!/usr/bin/env python3
"""Targeted live provenance watcher with bounded SQLite storage.

The goal is not to keep enormous raw fs_usage/log files. Raw lines are capped in
ring-buffer tables, while repeated events are folded into aggregate rows keyed by
source, operation, process, path, and normalized detail hash.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import queue
import re
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path


DEFAULT_TARGETS = [
    "/Volumes/Storage",
    "/Volumes/Storage/Ellis_Archive",
    "/Volumes/Storage/Applications-Staged-From-Sentinel_OS",
    "/private/var/folders",
    str(Path.home() / "Library/Application Support/com.openai.atlas"),
    str(Path.home() / "Library/Application Support/Google/Chrome"),
]

LOG_PREDICATE = (
    'process == "diskarbitrationd" OR process == "diskimages-helper" OR '
    'process == "hdiutil" OR process == "mount" OR process == "fseventsd" OR '
    'process == "launchservicesd" OR process == "syspolicyd" OR process == "tccd" OR '
    'eventMessage CONTAINS[c] "mount" OR eventMessage CONTAINS[c] "disk image" OR '
    'eventMessage CONTAINS[c] "code_sign_clone" OR eventMessage CONTAINS[c] "ChatGPT Atlas" OR '
    'eventMessage CONTAINS[c] "Google Chrome" OR eventMessage CONTAINS[c] "com.openai.atlas" OR '
    'eventMessage CONTAINS[c] "com.google.Chrome"'
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha16(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


class Store:
    def __init__(self, db_path: Path, raw_limit: int, max_db_bytes: int):
        self.db_path = db_path
        self.raw_limit = max(1, raw_limit)
        self.max_db_bytes = max(1024 * 1024, max_db_bytes)
        self.raw_seq = 0
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.init_schema()

    def init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS processes (
              process_id INTEGER PRIMARY KEY,
              process_name TEXT NOT NULL,
              pid INTEGER,
              first_seen_utc TEXT NOT NULL,
              last_seen_utc TEXT NOT NULL,
              seen_count INTEGER NOT NULL DEFAULT 1,
              UNIQUE(process_name, pid)
            );
            CREATE TABLE IF NOT EXISTS paths (
              path_id INTEGER PRIMARY KEY,
              path TEXT NOT NULL UNIQUE,
              target_group TEXT,
              first_seen_utc TEXT NOT NULL,
              last_seen_utc TEXT NOT NULL,
              seen_count INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS event_types (
              event_type_id INTEGER PRIMARY KEY,
              source TEXT NOT NULL,
              operation TEXT NOT NULL,
              UNIQUE(source, operation)
            );
            CREATE TABLE IF NOT EXISTS event_aggregates (
              aggregate_id INTEGER PRIMARY KEY,
              event_type_id INTEGER NOT NULL REFERENCES event_types(event_type_id),
              process_id INTEGER REFERENCES processes(process_id),
              path_id INTEGER REFERENCES paths(path_id),
              detail_hash TEXT NOT NULL,
              first_seen_utc TEXT NOT NULL,
              last_seen_utc TEXT NOT NULL,
              seen_count INTEGER NOT NULL DEFAULT 1,
              example TEXT,
              UNIQUE(event_type_id, process_id, path_id, detail_hash)
            );
            CREATE TABLE IF NOT EXISTS raw_event_ring (
              slot INTEGER PRIMARY KEY,
              sequence INTEGER NOT NULL,
              seen_utc TEXT NOT NULL,
              source TEXT NOT NULL,
              raw_line TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS samples (
              sample_id INTEGER PRIMARY KEY,
              sample_utc TEXT NOT NULL,
              sample_type TEXT NOT NULL,
              path TEXT NOT NULL,
              exit_code INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_event_aggregates_last_seen ON event_aggregates(last_seen_utc);
            CREATE INDEX IF NOT EXISTS idx_paths_path ON paths(path);
            """
        )
        self.conn.commit()

    def put_meta(self, key: str, value: str) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
            self.conn.commit()

    def _get_process_id(self, name: str, pid: int | None, now: str) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO processes(process_name,pid,first_seen_utc,last_seen_utc,seen_count)
            VALUES(?,?,?,?,1)
            ON CONFLICT(process_name,pid) DO UPDATE SET
              last_seen_utc=excluded.last_seen_utc,
              seen_count=processes.seen_count+1
            RETURNING process_id
            """,
            (name or "unknown", pid, now, now),
        )
        return int(cur.fetchone()[0])

    def _get_path_id(self, path: str, targets: list[str], now: str) -> int | None:
        if not path:
            return None
        group = next((t for t in targets if path.startswith(t)), "")
        cur = self.conn.execute(
            """
            INSERT INTO paths(path,target_group,first_seen_utc,last_seen_utc,seen_count)
            VALUES(?,?,?,?,1)
            ON CONFLICT(path) DO UPDATE SET
              last_seen_utc=excluded.last_seen_utc,
              seen_count=paths.seen_count+1
            RETURNING path_id
            """,
            (path, group, now, now),
        )
        return int(cur.fetchone()[0])

    def _get_event_type_id(self, source: str, operation: str) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO event_types(source,operation) VALUES(?,?)
            ON CONFLICT(source,operation) DO UPDATE SET operation=excluded.operation
            RETURNING event_type_id
            """,
            (source, operation or "observed"),
        )
        return int(cur.fetchone()[0])

    def add_raw(self, source: str, raw_line: str, now: str) -> None:
        slot = self.raw_seq % self.raw_limit
        self.conn.execute(
            """
            INSERT INTO raw_event_ring(slot,sequence,seen_utc,source,raw_line)
            VALUES(?,?,?,?,?)
            ON CONFLICT(slot) DO UPDATE SET
              sequence=excluded.sequence,
              seen_utc=excluded.seen_utc,
              source=excluded.source,
              raw_line=excluded.raw_line
            """,
            (slot, self.raw_seq, now, source, raw_line[:4000]),
        )
        self.raw_seq += 1

    def add_event(
        self,
        *,
        source: str,
        operation: str,
        process_name: str,
        pid: int | None,
        path: str,
        detail: str,
        raw_line: str,
        targets: list[str],
    ) -> None:
        if self.storage_limit_reached():
            raise RuntimeError(f"provenance storage limit reached: {self.max_db_bytes} bytes")
        now = utc_now()
        with self.lock:
            self.add_raw(source, raw_line, now)
            process_id = self._get_process_id(process_name or "unknown", pid, now)
            path_id = self._get_path_id(path, targets, now)
            event_type_id = self._get_event_type_id(source, operation)
            self.conn.execute(
                """
                INSERT INTO event_aggregates(
                  event_type_id,process_id,path_id,detail_hash,first_seen_utc,last_seen_utc,seen_count,example
                )
                VALUES(?,?,?,?,?,?,1,?)
                ON CONFLICT(event_type_id,process_id,path_id,detail_hash) DO UPDATE SET
                  last_seen_utc=excluded.last_seen_utc,
                  seen_count=event_aggregates.seen_count+1
                """,
                (event_type_id, process_id, path_id, sha16(detail), now, now, raw_line[:1000]),
            )
            self.conn.commit()

    def storage_limit_reached(self) -> bool:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(self.db_path) + suffix)
            if path.exists():
                total += path.stat().st_size
        return total >= self.max_db_bytes

    def add_sample(self, sample_type: str, path: Path, exit_code: int) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT INTO samples(sample_utc,sample_type,path,exit_code) VALUES(?,?,?,?)",
                (utc_now(), sample_type, str(path), exit_code),
            )
            self.conn.commit()

    def close(self) -> None:
        with self.lock:
            self.conn.commit()
            self.conn.close()


FS_PID_RX = re.compile(r"\s(?P<proc>[A-Za-z0-9_.() -]{1,80})\.(?P<pid>\d+)\s")
PATH_RX = re.compile(r"(/(?:Volumes|private|Users|System|Library)/[^\s]+)")
LOG_PROC_RX = re.compile(r'"processImagePath":"(?P<path>[^"]+)"|"process":"(?P<proc>[^"]+)"')


def classify_operation(line: str) -> str:
    low = line.lower()
    for name in ["rename", "clone", "write", "create", "open", "unlink", "mkdir", "rmdir", "mount", "attach", "exec", "stat"]:
        if name in low:
            return name
    if "wrdata" in low or "write" in low:
        return "write"
    if "fsgetpath" in low or "getattr" in low:
        return "stat"
    return "observed"


def target_path_from_line(line: str, targets: list[str]) -> str:
    candidates = [m.group(1).rstrip(",;") for m in PATH_RX.finditer(line)]
    for path in candidates:
        if any(path.startswith(target) for target in targets):
            return path
    return candidates[0] if candidates else ""


def parse_fs_usage(line: str) -> tuple[str, int | None, str, str]:
    m = FS_PID_RX.search(line)
    proc = m.group("proc").strip() if m else "unknown"
    pid = int(m.group("pid")) if m else None
    return proc, pid, classify_operation(line), line


def parse_log_line(line: str) -> tuple[str, int | None, str, str]:
    proc = "unknown"
    msg = line[:4000]
    try:
        record = json.loads(line)
        proc = Path(str(record.get("processImagePath") or record.get("process") or "unknown")).name
        msg = str(record.get("eventMessage") or msg)[:4000]
    except json.JSONDecodeError:
        m = LOG_PROC_RX.search(line[:4000])
        if m:
            proc = Path(m.group("path") or m.group("proc") or "unknown").name
    return proc, None, classify_operation(msg), msg


def reader_thread(
    proc: subprocess.Popen,
    source: str,
    store: Store,
    targets: list[str],
    stop: threading.Event,
    parsers,
) -> None:
    assert proc.stdout is not None
    while not stop.is_set():
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                break
            time.sleep(0.1)
            continue
        line = line.rstrip("\n")
        if not line:
            continue
        if not any(target in line for target in targets) and source == "fs_usage":
            continue
        process_name, pid, operation, detail = parsers(line)
        path = target_path_from_line(line, targets)
        try:
            store.add_event(
                source=source,
                operation=operation,
                process_name=process_name,
                pid=pid,
                path=path,
                detail=detail,
                raw_line=line,
                targets=targets,
            )
        except RuntimeError as exc:
            store.put_meta("stop_reason", str(exc))
            stop.set()
            break


def start_process(args: list[str], stderr_path: Path) -> subprocess.Popen | None:
    try:
        err = stderr_path.open("w", encoding="utf-8")
        return subprocess.Popen(args, stdout=subprocess.PIPE, stderr=err, text=True, bufsize=1)
    except Exception as exc:
        stderr_path.write_text(f"start_failed={exc}\n", encoding="utf-8")
        return None


def sudo_available() -> bool:
    return subprocess.run(["sudo", "-n", "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def sample_command(out_dir: Path, store: Store, sample_type: str, args: list[str]) -> None:
    out = out_dir / f"{int(time.time())}_{sample_type}.txt"
    try:
        completed = subprocess.run(args, text=True, capture_output=True, timeout=30)
        out.write_text(completed.stdout + completed.stderr, encoding="utf-8", errors="replace")
        store.add_sample(sample_type, out, completed.returncode)
    except Exception as exc:
        out.write_text(f"sample_failed={exc}\n", encoding="utf-8")
        store.add_sample(sample_type, out, 1)


def export_views(db_path: Path, out_dir: Path) -> None:
    conn = sqlite3.connect(str(db_path))
    queries = {
        "EVENT_AGGREGATES.csv": """
            SELECT ea.first_seen_utc, ea.last_seen_utc, ea.seen_count,
                   et.source, et.operation, p.process_name, p.pid, paths.path, paths.target_group,
                   ea.detail_hash, ea.example
            FROM event_aggregates ea
            JOIN event_types et USING(event_type_id)
            LEFT JOIN processes p USING(process_id)
            LEFT JOIN paths ON paths.path_id = ea.path_id
            ORDER BY ea.seen_count DESC, ea.last_seen_utc DESC
        """,
        "PATH_SUMMARY.csv": """
            SELECT path, target_group, first_seen_utc, last_seen_utc, seen_count
            FROM paths
            ORDER BY seen_count DESC, last_seen_utc DESC
        """,
        "PROCESS_SUMMARY.csv": """
            SELECT process_name, pid, first_seen_utc, last_seen_utc, seen_count
            FROM processes
            ORDER BY seen_count DESC, last_seen_utc DESC
        """,
        "SAMPLES.csv": """
            SELECT sample_utc, sample_type, path, exit_code
            FROM samples
            ORDER BY sample_utc
        """,
    }
    for name, query in queries.items():
        rows = conn.execute(query)
        with (out_dir / name).open("w", encoding="utf-8", newline="") as f:
            import csv

            writer = csv.writer(f)
            writer.writerow([d[0] for d in rows.description])
            writer.writerows(rows)
    conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--duration-seconds", type=int, default=3600)
    parser.add_argument("--sample-interval", type=int, default=300)
    parser.add_argument("--raw-event-limit", type=int, default=100000)
    parser.add_argument("--max-db-mib", type=int, default=2048)
    parser.add_argument("--target", action="append", default=[])
    parser.add_argument("--no-fs-usage", action="store_true")
    parser.add_argument("--no-log-stream", action="store_true")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    sample_dir = out_dir / "samples"
    sample_dir.mkdir(exist_ok=True)
    targets = [str(Path(t).expanduser()) for t in (args.target or DEFAULT_TARGETS)]
    db_path = out_dir / "provenance.sqlite3"
    if args.duration_seconds < 1 or args.sample_interval < 1 or args.raw_event_limit < 1 or args.max_db_mib < 1:
        print("[FATAL] duration, interval, raw-event-limit, and max-db-mib must be positive", file=sys.stderr)
        return 2

    store = Store(db_path, args.raw_event_limit, args.max_db_mib * 1024 * 1024)
    store.put_meta("started_utc", utc_now())
    store.put_meta("duration_seconds", str(args.duration_seconds))
    store.put_meta("raw_event_limit", str(args.raw_event_limit))
    store.put_meta("max_db_mib", str(args.max_db_mib))
    store.put_meta("targets", "\n".join(targets))
    store.put_meta("pid", str(os.getpid()))

    stop = threading.Event()
    procs: list[subprocess.Popen] = []
    threads: list[threading.Thread] = []

    def request_stop(signum, _frame):
        store.put_meta("stop_signal", str(signum))
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    if not args.no_fs_usage:
        fs_cmd = ["fs_usage", "-w", "-f", "filesystem"]
        if sudo_available():
            fs_cmd = ["sudo", "-n"] + fs_cmd
            store.put_meta("fs_usage_sudo", "yes")
        else:
            store.put_meta("fs_usage_sudo", "no")
        fs = start_process(fs_cmd, out_dir / "fs_usage.stderr")
        if fs:
            procs.append(fs)
            t = threading.Thread(target=reader_thread, args=(fs, "fs_usage", store, targets, stop, parse_fs_usage), daemon=True)
            t.start()
            threads.append(t)

    if not args.no_log_stream:
        logp = start_process(
            ["log", "stream", "--style", "ndjson", "--info", "--predicate", LOG_PREDICATE],
            out_dir / "log_stream.stderr",
        )
        if logp:
            procs.append(logp)
            t = threading.Thread(target=reader_thread, args=(logp, "log_stream", store, targets, stop, parse_log_line), daemon=True)
            t.start()
            threads.append(t)

    deadline = time.monotonic() + max(1, args.duration_seconds)
    next_sample = time.monotonic()
    while not stop.is_set() and time.monotonic() < deadline:
        if store.storage_limit_reached():
            store.put_meta("stop_reason", "max_db_mib reached")
            break
        if time.monotonic() >= next_sample:
            sample_command(sample_dir, store, "mount", ["mount"])
            sample_command(sample_dir, store, "diskutil_list", ["diskutil", "list"])
            sample_command(sample_dir, store, "ps_targets", ["pgrep", "-afil", "Atlas|ChatGPT|Chrome|Google Chrome|Codex|hdiutil|diskimages|fseventsd"])
            sample_command(
                sample_dir,
                store,
                "lsof_targets",
                [
                    "sh",
                    "-c",
                    "lsof -nP 2>/dev/null | /usr/bin/grep -Ei 'Volumes/Storage|ChatGPT Atlas|Google Chrome|Codex|diskimages|hdiutil' || true",
                ],
            )
            next_sample = time.monotonic() + max(30, args.sample_interval)
        time.sleep(1)

    stop.set()
    for proc in procs:
        if proc.poll() is None:
            proc.terminate()
    time.sleep(1)
    for proc in procs:
        if proc.poll() is None:
            proc.kill()
    for thread in threads:
        thread.join(timeout=2)

    store.put_meta("ended_utc", utc_now())
    store.put_meta("db_bytes_final", str(sum((Path(str(db_path) + suffix).stat().st_size if Path(str(db_path) + suffix).exists() else 0) for suffix in ("", "-wal", "-shm"))))
    store.close()
    export_views(db_path, out_dir)
    (out_dir / "README.md").write_text(
        "# Provenance Watcher\n\n"
        "This directory contains a bounded SQLite provenance capture. Raw event lines are stored in "
        "`raw_event_ring` up to the configured cap; repeated events are folded into `event_aggregates` "
        "with first/last timestamps and counts.\n\n"
        "Start with `EVENT_AGGREGATES.csv`, then review `PATH_SUMMARY.csv`, `PROCESS_SUMMARY.csv`, "
        "and raw samples under `samples/`.\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
