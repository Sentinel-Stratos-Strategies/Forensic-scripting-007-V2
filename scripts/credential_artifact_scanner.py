#!/usr/bin/env python3
"""
Credential Artifact Scanner

Scans a copied/snapshotted macOS TCC SQLite database for high-risk privacy
permissions associated with Atlas/OpenAI/OwlBridge-style bundle identifiers.
The scanner opens databases read-only and writes reviewer-friendly TSV output.
"""

from __future__ import annotations

import argparse
import csv
import sqlite3
import sys
from pathlib import Path

HIGH_RISK_SERVICES = (
    "kTCCServiceSystemPolicyAllFiles",
    "kTCCServiceScreenCapture",
    "kTCCServiceMicrophone",
    "kTCCServiceKeychain",
    "kTCCServiceAppleEvents",
)
DEFAULT_CLIENT_PATTERNS = ("atlas", "openai", "owlbridge")


def _column_names(cursor: sqlite3.Cursor, table: str) -> set[str]:
    cursor.execute(f"PRAGMA table_info({table})")
    return {row[1] for row in cursor.fetchall()}


def _status_expression(columns: set[str]) -> str:
    if "auth_value" in columns:
        return "auth_value"
    if "allowed" in columns:
        return "allowed"
    return "NULL"


def scan_tcc_snapshot(db_path: str, output_path: str, patterns: tuple[str, ...]) -> int:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    try:
        conn = sqlite3.connect(f"file:{Path(db_path).resolve()}?mode=ro", uri=True)
        cursor = conn.cursor()
        columns = _column_names(cursor, "access")
        if not columns:
            raise sqlite3.Error("TCC access table not found")

        status_expr = _status_expression(columns)
        last_modified_expr = "last_modified" if "last_modified" in columns else "NULL"
        client_type_expr = "client_type" if "client_type" in columns else "NULL"
        where_patterns = " OR ".join("LOWER(client) LIKE ?" for _ in patterns)
        placeholders = ",".join("?" for _ in HIGH_RISK_SERVICES)
        query = f"""
            SELECT service, client, {client_type_expr} AS client_type,
                   {status_expr} AS permission_status,
                   {last_modified_expr} AS last_modified
            FROM access
            WHERE service IN ({placeholders})
              AND ({where_patterns})
            ORDER BY service, client;
        """
        params = [*HIGH_RISK_SERVICES, *(f"%{p.lower()}%" for p in patterns)]
        cursor.execute(query, params)
        rows = cursor.fetchall()

        with output.open("w", newline="") as tsvfile:
            writer = csv.writer(tsvfile, delimiter="\t")
            writer.writerow(["Service", "Client", "Client_Type", "Permission_Status", "Last_Modified"])
            writer.writerows(rows)

        if rows:
            print(f"[+] Scanner: Found {len(rows)} high-risk TCC hit(s). Exported to {output}")
        else:
            print("[i] Scanner: No high-risk TCC overrides found in this snapshot.")
        return len(rows)
    except sqlite3.Error as exc:
        print(f"[-] SQLite Error: {exc}", file=sys.stderr)
        return 0
    finally:
        if "conn" in locals():
            conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan copied TCC DB artifacts for credential/privacy triage hits.")
    parser.add_argument("--target", required=True, help="Path to the preserved SQLite DB")
    parser.add_argument("--output", required=True, help="Path to output TSV file")
    parser.add_argument("--pattern", action="append", dest="patterns", help="Case-insensitive client substring to match; may be repeated")
    args = parser.parse_args()
    scan_tcc_snapshot(args.target, args.output, tuple(args.patterns or DEFAULT_CLIENT_PATTERNS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
