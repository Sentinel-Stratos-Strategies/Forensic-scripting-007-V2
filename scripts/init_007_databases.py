#!/usr/bin/env python3
"""Initialize the three 007 SQLite database layers."""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = {
    "007_core.sqlite": ROOT / "database" / "007_core_schema.sql",
    "007_graph.sqlite": ROOT / "database" / "007_graph_schema.sql",
    "007_outputs.sqlite": ROOT / "database" / "007_outputs_schema.sql",
}


def validate_out_dir(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    if not out_dir.is_dir():
        raise RuntimeError(f"output path is not a directory: {out_dir}")
    if not os.access(out_dir, os.W_OK | os.X_OK):
        raise RuntimeError(f"output directory is not writable/searchable: {out_dir}")
    probe = out_dir / ".007_db_write_probe"
    probe.write_text("ok\n", encoding="utf-8")
    probe.unlink()


def apply_schema(db_path: Path, schema_path: Path) -> None:
    if not schema_path.is_file():
        raise FileNotFoundError(f"schema file missing: {schema_path}")
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(schema_path.read_text(encoding="utf-8"))
        result = conn.execute("PRAGMA integrity_check").fetchone()
        if not result or result[0] != "ok":
            raise RuntimeError(f"sqlite integrity_check failed for {db_path}: {result}")
        conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()
        conn.commit()
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialize 007 core/graph/output SQLite databases")
    parser.add_argument("--out-dir", required=True, help="Directory where database files should be written")
    args = parser.parse_args()

    out_dir = Path(args.out_dir).expanduser()
    validate_out_dir(out_dir)
    for db_name, schema_path in SCHEMAS.items():
        db_path = out_dir / db_name
        apply_schema(db_path, schema_path)
        print(db_path)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FATAL] {exc}", file=sys.stderr)
        raise SystemExit(1)
