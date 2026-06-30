#!/usr/bin/env python3
"""Verify target app presence and available code-ish metadata in iOS MobileSync backups."""

from __future__ import annotations

import argparse
import csv
import getpass
import hashlib
import json
import plistlib
import sqlite3
from pathlib import Path
from typing import Any


DEFAULT_PATTERNS = [
    "openai",
    "chatgpt",
    "atlas",
    "chrome",
    "google",
    "codex",
    "perplexity",
    "comet",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_plist(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as f:
            data = plistlib.load(f)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def write_csv(path: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def backup_file_path(backup_dir: Path, file_id: str) -> Path:
    return backup_dir / file_id[:2] / file_id


def app_rows_from_plist(backup_dir: Path, plist_name: str, patterns: list[str]) -> list[dict[str, Any]]:
    plist_path = backup_dir / plist_name
    data = read_plist(plist_path)
    apps = data.get("Applications") if isinstance(data.get("Applications"), dict) else {}
    rows: list[dict[str, Any]] = []
    for key, value in sorted(apps.items()):
        meta = value if isinstance(value, dict) else {}
        bundle_id = str(meta.get("CFBundleIdentifier") or key)
        blob = json.dumps(meta, default=str, sort_keys=True).lower() + " " + bundle_id.lower()
        if not any(pattern in blob for pattern in patterns):
            continue
        rows.append(
            {
                "backup_dir": str(backup_dir),
                "plist": plist_name,
                "bundle_id": bundle_id,
                "plist_key": key,
                "bundle_version": meta.get("CFBundleVersion", ""),
                "short_version": meta.get("CFBundleShortVersionString", ""),
                "container_class": meta.get("ContainerContentClass", ""),
                "path": meta.get("Path", ""),
                "matched_patterns": ",".join(pattern for pattern in patterns if pattern in blob),
            }
        )
    return rows


def manifest_db_rows(backup_dir: Path, patterns: list[str], hash_limit: int) -> tuple[list[dict[str, Any]], str]:
    db_path = backup_dir / "Manifest.db"
    if not db_path.exists():
        return [], "Manifest.db missing"
    rows: list[dict[str, Any]] = []
    query = """
        SELECT fileID, domain, relativePath, flags
        FROM Files
        WHERE lower(domain) LIKE ?
           OR lower(relativePath) LIKE ?
    """
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            conn.execute("SELECT fileID, domain, relativePath, flags FROM Files LIMIT 1").fetchone()
            for pattern in patterns:
                like = f"%{pattern.lower()}%"
                for file_id, domain, rel_path, flags in conn.execute(query, (like, like)):
                    payload = backup_file_path(backup_dir, str(file_id))
                    size = payload.stat().st_size if payload.exists() else ""
                    sha256 = ""
                    hash_status = "missing_payload"
                    if payload.exists() and payload.is_file():
                        if payload.stat().st_size <= hash_limit:
                            sha256 = sha256_file(payload)
                            hash_status = "hashed"
                        else:
                            hash_status = f"skipped_gt_{hash_limit}"
                    rows.append(
                        {
                            "backup_dir": str(backup_dir),
                            "file_id": file_id,
                            "domain": domain,
                            "relative_path": rel_path,
                            "flags": flags,
                            "payload_path": str(payload),
                            "payload_size": size,
                            "sha256": sha256,
                            "hash_status": hash_status,
                            "matched_pattern": pattern,
                        }
                    )
        finally:
            conn.close()
    except sqlite3.DatabaseError as exc:
        return [], f"Manifest.db unreadable as sqlite: {exc}"
    return rows, "Manifest.db readable"


def encrypted_manifest_rows(
    backup_dir: Path,
    patterns: list[str],
    hash_limit: int,
    passphrase: str,
    decrypt_out_dir: Path,
) -> tuple[list[dict[str, Any]], str]:
    try:
        from iphone_backup_decrypt import EncryptedBackup  # type: ignore
    except Exception as exc:
        return [], f"iphone_backup_decrypt unavailable: {exc}"

    rows: list[dict[str, Any]] = []
    try:
        backup = EncryptedBackup(backup_directory=str(backup_dir), passphrase=passphrase)
        backup.test_decryption()
        with backup.manifest_db_cursor() as cur:
            for pattern in patterns:
                like = f"%{pattern.lower()}%"
                cur.execute(
                    """
                    SELECT fileID, domain, relativePath, flags
                    FROM Files
                    WHERE lower(domain) LIKE ?
                       OR lower(relativePath) LIKE ?
                    ORDER BY domain, relativePath
                    """,
                    (like, like),
                )
                for file_id, domain, rel_path, flags in cur.fetchall():
                    encrypted_payload = backup_file_path(backup_dir, str(file_id))
                    encrypted_size = encrypted_payload.stat().st_size if encrypted_payload.exists() else ""
                    sha256 = ""
                    decrypted_size: int | str = ""
                    output_path = ""
                    status = "not_file"
                    if flags == 1 and encrypted_payload.exists() and encrypted_payload.is_file():
                        if encrypted_payload.stat().st_size <= hash_limit:
                            safe_name = hashlib.sha256(f"{domain}/{rel_path}".encode()).hexdigest()
                            output_path_obj = decrypt_out_dir / safe_name[:2] / safe_name
                            output_path_obj.parent.mkdir(parents=True, exist_ok=True)
                            try:
                                backup.extract_file(
                                    relative_path=str(rel_path),
                                    domain_like=str(domain),
                                    output_filename=str(output_path_obj),
                                )
                                sha256 = sha256_file(output_path_obj)
                                decrypted_size = output_path_obj.stat().st_size
                                output_path = str(output_path_obj)
                                status = "decrypted_hashed"
                            except Exception as exc:
                                status = f"decrypt_failed: {exc}"
                        else:
                            status = f"skipped_gt_{hash_limit}"
                    rows.append(
                        {
                            "backup_dir": str(backup_dir),
                            "file_id": file_id,
                            "domain": domain,
                            "relative_path": rel_path,
                            "flags": flags,
                            "payload_path": str(encrypted_payload),
                            "payload_size": encrypted_size,
                            "sha256": sha256,
                            "hash_status": status,
                            "matched_pattern": pattern,
                            "decrypted_output_path": output_path,
                            "decrypted_size": decrypted_size,
                        }
                    )
    except Exception as exc:
        return rows, f"encrypted backup decrypt failed: {exc}"
    return rows, "encrypted Manifest.db decrypted"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-root", default=str(Path.home() / "Library/Application Support/MobileSync/Backup"))
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--pattern", action="append", default=[])
    parser.add_argument("--hash-limit", type=int, default=32 * 1024 * 1024)
    parser.add_argument("--ask-password", action="store_true", help="Prompt locally for the encrypted backup password")
    parser.add_argument(
        "--decrypted-out-dir",
        default=None,
        help="Directory for decrypted matching files; defaults to OUT_DIR/decrypted_payloads",
    )
    args = parser.parse_args()

    backup_root = Path(args.backup_root).expanduser()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    patterns = [p.lower() for p in (args.pattern or DEFAULT_PATTERNS)]
    passphrase = getpass.getpass("iOS backup password: ") if args.ask_password else ""
    decrypt_out_dir = Path(args.decrypted_out_dir) if args.decrypted_out_dir else out_dir / "decrypted_payloads"

    backup_dirs = sorted(p for p in backup_root.iterdir() if p.is_dir()) if backup_root.exists() else []
    plist_rows: list[dict[str, Any]] = []
    db_rows: list[dict[str, Any]] = []
    summary_rows: list[dict[str, Any]] = []

    for backup_dir in backup_dirs:
        info = read_plist(backup_dir / "Info.plist")
        manifest_plist = read_plist(backup_dir / "Manifest.plist")
        for plist_name in ("Info.plist", "Manifest.plist"):
            plist_rows.extend(app_rows_from_plist(backup_dir, plist_name, patterns))
        rows, manifest_status = manifest_db_rows(backup_dir, patterns, args.hash_limit)
        if args.ask_password and rows == [] and "unreadable" in manifest_status:
            rows, manifest_status = encrypted_manifest_rows(backup_dir, patterns, args.hash_limit, passphrase, decrypt_out_dir)
        db_rows.extend(rows)
        summary_rows.append(
            {
                "backup_dir": str(backup_dir),
                "device_name": info.get("Device Name", ""),
                "product_type": info.get("Product Type", ""),
                "product_version": info.get("Product Version", ""),
                "last_backup_date": info.get("Last Backup Date", ""),
                "manifest_encrypted": manifest_plist.get("IsEncrypted", ""),
                "manifest_db_status": manifest_status,
                "plist_app_matches": sum(1 for row in plist_rows if row.get("backup_dir") == str(backup_dir)),
                "manifest_db_matches": len(rows),
                "hash_limit": args.hash_limit,
            }
        )

    write_csv(
        out_dir / "IOS_BACKUP_APP_METADATA_MATCHES.csv",
        ["backup_dir", "plist", "bundle_id", "plist_key", "bundle_version", "short_version", "container_class", "path", "matched_patterns"],
        plist_rows,
    )
    write_csv(
        out_dir / "IOS_BACKUP_MANIFEST_FILE_MATCHES.csv",
        [
            "backup_dir",
            "file_id",
            "domain",
            "relative_path",
            "flags",
            "payload_path",
            "payload_size",
            "sha256",
            "hash_status",
            "matched_pattern",
            "decrypted_output_path",
            "decrypted_size",
        ],
        db_rows,
    )
    write_csv(
        out_dir / "IOS_BACKUP_APP_VERIFY_SUMMARY.csv",
        ["backup_dir", "device_name", "product_type", "product_version", "last_backup_date", "manifest_encrypted", "manifest_db_status", "plist_app_matches", "manifest_db_matches", "hash_limit"],
        summary_rows,
    )
    (out_dir / "README.md").write_text(
        "# iOS Backup App Verification\n\n"
        "This verifier matches MobileSync backup application metadata against target app families. "
        "If `Manifest.db` is readable, matching payload files are hashed up to the configured size limit. "
        "If the backup is encrypted and `Manifest.db` cannot be opened as SQLite, plist-derived app metadata "
        "is still preserved and the database blocker is recorded in `IOS_BACKUP_APP_VERIFY_SUMMARY.csv`.\n",
        encoding="utf-8",
    )
    manifest = {
        "backup_root": str(backup_root),
        "out_dir": str(out_dir),
        "patterns": patterns,
        "hash_limit": args.hash_limit,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
