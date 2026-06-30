#!/usr/bin/env python3
import csv
import hashlib
import os
import plistlib
import shutil
from datetime import datetime
from pathlib import Path


REPO = Path("/Users/fresh/Forensic_007")
OUT = REPO / "reports" / "ios_backup_bridge_20260628"
PRIOR = REPO / "reports" / "one_pass_big_swing_20260627"
LOCKDOWN = Path("/Volumes/Storage/Ellis_Archive/Investigations/root_directories/db/lockdown")
PAIRING = LOCKDOWN / "00008110-000E24281430201E.plist"
SYSCONFIG = LOCKDOWN / "SystemConfiguration.plist"
MOBILESYNC = Path.home() / "Library/Application Support/MobileSync/Backup"


def write_csv(path, fieldnames, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def stat_times(path):
    try:
        st = path.stat()
    except OSError:
        return "", "", ""
    created = datetime.fromtimestamp(st.st_birthtime).astimezone().isoformat(timespec="seconds")
    modified = datetime.fromtimestamp(st.st_mtime).astimezone().isoformat(timespec="seconds")
    return created, modified, str(st.st_size)


def sha256_file(path):
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def plist_safe_values(path):
    secret_terms = ("cert", "key", "escrow", "wifi", "bluetooth", "data", "private", "public", "irk")
    try:
        with path.open("rb") as f:
            data = plistlib.load(f)
    except Exception:
        return []
    out = []
    if isinstance(data, dict):
        for key, value in data.items():
            if any(term in key.lower() for term in secret_terms):
                continue
            if isinstance(value, (str, int, float, bool)):
                out.append((key, str(value)))
    return out


def append_if_exists(src, dst):
    if src.exists():
        shutil.copy2(src, dst)
    else:
        dst.write_text("", encoding="utf-8")


def build():
    OUT.mkdir(parents=True, exist_ok=True)

    ios_synced_fields = [
        "screenshot_source",
        "display_name",
        "model_value",
        "serial_value",
        "syncing_started_raw",
        "syncing_started_normalized",
        "user_statement_same_physical_mac",
        "notes",
        "confidence",
    ]
    ios_synced_rows = [
        {
            "screenshot_source": "user-provided iPhone synced-computers screenshot/statement",
            "display_name": "Home's MacBook Pro",
            "model_value": "",
            "serial_value": "",
            "syncing_started_raw": "2026-06-08 22:39",
            "syncing_started_normalized": "2026-06-08T22:39:00-05:00",
            "user_statement_same_physical_mac": "yes",
            "notes": "Recorded as IOS_SYNCED_COMPUTER_IDENTITY_DRIFT; no spoofing conclusion.",
            "confidence": "screenshot-derived/user-stated",
        },
        {
            "screenshot_source": "user-provided iPhone synced-computers screenshot/statement",
            "display_name": "macdaddy.local",
            "model_value": "Apple device",
            "serial_value": "AAAAAAAAAAAA",
            "syncing_started_raw": "2026-06-10 00:52",
            "syncing_started_normalized": "2026-06-10T00:52:00-05:00",
            "user_statement_same_physical_mac": "yes",
            "notes": "Recorded as IOS_SYNCED_COMPUTER_IDENTITY_DRIFT; needs backup/lockdown corroboration.",
            "confidence": "screenshot-derived/user-stated",
        },
        {
            "screenshot_source": "user-provided iPhone synced-computers screenshot/statement",
            "display_name": "home's MacBook Pro",
            "model_value": "MacBook Pro",
            "serial_value": "KFLXHW07KY",
            "syncing_started_raw": "2026-06-17 11:36",
            "syncing_started_normalized": "2026-06-17T11:36:00-05:00",
            "user_statement_same_physical_mac": "yes",
            "notes": "Current Mac serial matches this serial; preserved lockdown pairing plist birth time is 2026-06-17T11:36:05-05:00.",
            "confidence": "strongly supported",
        },
    ]
    write_csv(OUT / "IOS_SYNCED_COMPUTERS.csv", ios_synced_fields, ios_synced_rows)

    backup_fields = [
        "backup_path",
        "backup_hash_root",
        "encrypted_flag",
        "backup_date",
        "device_name",
        "product_type",
        "iOS_version",
        "manifest_db_present",
        "info_plist_present",
        "manifest_plist_present",
        "status_plist_present",
        "matched_app_family",
        "profile_or_mdm_hits",
        "synced_computer_hits",
        "notes",
    ]
    backup_rows = [
        {
            "backup_path": str(MOBILESYNC),
            "encrypted_flag": "pending",
            "manifest_db_present": "no",
            "info_plist_present": "no",
            "manifest_plist_present": "no",
            "status_plist_present": "no",
            "matched_app_family": "not evaluated",
            "profile_or_mdm_hits": "not evaluated",
            "synced_computer_hits": "not evaluated",
            "notes": "No MobileSync backup metadata existed before the user-created backup; rerun after backup completes.",
        }
    ]
    write_csv(OUT / "IOS_BACKUP_BRIDGE.csv", backup_fields, backup_rows)

    lockdown_fields = [
        "record_path",
        "filename",
        "plist_key",
        "plist_value",
        "related_name_match",
        "related_serial_match",
        "created_time",
        "modified_time",
        "notes",
    ]
    lockdown_rows = []
    for path in [SYSCONFIG, PAIRING]:
        created, modified, _ = stat_times(path)
        values = plist_safe_values(path)
        if not values:
            lockdown_rows.append(
                {
                    "record_path": str(path),
                    "filename": path.name,
                    "created_time": created,
                    "modified_time": modified,
                    "notes": "No non-secret plist scalar values extracted or file unreadable.",
                }
            )
        for key, value in values:
            lockdown_rows.append(
                {
                    "record_path": str(path),
                    "filename": path.name,
                    "plist_key": key,
                    "plist_value": value,
                    "related_name_match": "not_observed",
                    "related_serial_match": "KFLXHW07KY time-aligned" if path == PAIRING else "not_observed",
                    "created_time": created,
                    "modified_time": modified,
                    "notes": "Preserved Mac-side lockdown artifact; secret-bearing plist fields intentionally excluded.",
                }
            )
    lockdown_rows.append(
        {
            "record_path": "/var/db/lockdown",
            "filename": "",
            "notes": "Current live path exists but is not readable from this shell; sudo -n reported password required.",
        }
    )
    write_csv(OUT / "LOCKDOWN_PAIRING_RECORDS.csv", lockdown_fields, lockdown_rows)

    mobile_fields = [
        "backup_root",
        "file_path",
        "file_type",
        "created_time",
        "modified_time",
        "hash_if_available",
        "device_match",
        "timeline_relevance",
        "notes",
    ]
    mobile_rows = [
        {
            "backup_root": str(MOBILESYNC),
            "file_path": str(MOBILESYNC),
            "file_type": "directory",
            "device_match": "pending",
            "timeline_relevance": "pending new backup",
            "notes": "Directory not present during baseline scan; expected to appear after user starts backup.",
        }
    ]
    write_csv(OUT / "MOBILESYNC_BACKUP_INDEX.csv", mobile_fields, mobile_rows)

    app_domain_fields = ["domain_or_bundle_id", "source", "matched_lane", "matched_app_family", "notes"]
    app_domain_rows = [
        {
            "domain_or_bundle_id": "not_observed",
            "source": "baseline before backup",
            "matched_lane": "encrypted iOS backup bridge",
            "matched_app_family": "not evaluated",
            "notes": "No backup Manifest.db or iLEAPP output available yet.",
        }
    ]
    write_csv(OUT / "IOS_APP_DOMAIN_MATCHES.csv", app_domain_fields, app_domain_rows)

    log_fields = [
        "timestamp",
        "process",
        "subsystem",
        "category",
        "event_message",
        "matched_name_or_serial",
        "matched_lane",
        "notes",
    ]
    log_rows = [
        {
            "timestamp": "2026-06-28T03:38:37-05:00",
            "process": "runningboardd",
            "subsystem": "com.apple.runningboard",
            "category": "process",
            "event_message": "Resolved pid to xpcservice com.apple.AppleDeviceQueryService and osservice com.apple.mobilerepaird in current retained logs.",
            "matched_lane": "iOS device services baseline",
            "notes": "Current retained logs did not return June 8/10/17 pairing-specific hits; broad trust/security noise excluded.",
        }
    ]
    write_csv(OUT / "UNIFIED_LOG_IOS_PAIRING_EVENTS.csv", log_fields, log_rows)

    claim_fields = ["claim", "lane", "evidence", "control", "status", "payout_relevance", "next_minimal_test"]
    claim_rows = [
        {
            "claim": "iOS shows multiple synced-computer identities that the user identifies as one physical Mac.",
            "lane": "IOS_SYNCED_COMPUTER_IDENTITY_DRIFT",
            "evidence": "Three user-provided synced-computer entries dated 2026-06-08, 2026-06-10, and 2026-06-17.",
            "control": "Do not label spoofing; host name changes, pairing regeneration, reinstall/restore, or profile state remain controls.",
            "status": "Proven as screenshot/user-stated identity drift; mechanism unknown.",
            "payout_relevance": "Potential bridge only if backup/lockdown metadata ties to app-provenance timeline.",
            "next_minimal_test": "Create encrypted backup, then parse Info.plist/Manifest.plist/Status.plist/Manifest.db metadata only.",
        },
        {
            "claim": "The 2026-06-17 iOS synced-computer entry aligns with preserved Mac-side lockdown pairing state.",
            "lane": "lockdown pairing bridge",
            "evidence": "Preserved pairing plist 00008110-000E24281430201E.plist created 2026-06-17T11:36:05-05:00; current Mac serial is KFLXHW07KY.",
            "control": "Preserved copy path may include copy/examiner effects; plist contents do not expose display name in safe fields.",
            "status": "Strongly supported; not fully closed.",
            "payout_relevance": "This is the strongest current iOS-to-Mac bridge candidate.",
            "next_minimal_test": "Compare new backup metadata and any readable live lockdown record timestamps to the preserved pairing plist.",
        },
        {
            "claim": "Encrypted iOS backup metadata bridges to app-family or management-state timeline.",
            "lane": "encrypted iOS backup bridge",
            "evidence": "No backup metadata existed at baseline.",
            "control": "Do not infer from absence; user is about to create the backup.",
            "status": "Pending.",
            "payout_relevance": "High if metadata contains synced-computer/profile/app-domain overlap.",
            "next_minimal_test": "Run the metadata-only parser after backup completion.",
        },
    ]
    write_csv(OUT / "CLAIM_MATRIX_IOS_BRIDGE.csv", claim_fields, claim_rows)

    append_if_exists(PRIOR / "MASTER_INVENTORY.csv", OUT / "updated_MASTER_INVENTORY.csv")
    with (OUT / "updated_MASTER_INVENTORY.csv").open("a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["iOS bridge", "IOS_SYNCED_COMPUTERS.csv", str(OUT / "IOS_SYNCED_COMPUTERS.csv"), "created", "", "user screenshot-derived identity drift baseline"])
        writer.writerow(["iOS bridge", "LOCKDOWN_PAIRING_RECORDS.csv", str(OUT / "LOCKDOWN_PAIRING_RECORDS.csv"), "created", "", "preserved lockdown pairing baseline"])
        writer.writerow(["iOS bridge", "IOS_BACKUP_BRIDGE.csv", str(OUT / "IOS_BACKUP_BRIDGE.csv"), "pending", "", "backup metadata pending user-created backup"])

    append_if_exists(PRIOR / "MERGED_TIMELINE.csv", OUT / "updated_MERGED_TIMELINE.csv")
    with (OUT / "updated_MERGED_TIMELINE.csv").open("a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["2026-06-08T22:39:00-05:00", "iOS bridge", "iPhone", "IOS_SYNCED_COMPUTER_IDENTITY_DRIFT", "Home's MacBook Pro", "user-provided synced-computers screenshot/statement", "", "", "", "First listed synced-computer identity; mechanism unknown.", "no"])
        writer.writerow(["2026-06-10T00:52:00-05:00", "iOS bridge", "iPhone", "IOS_SYNCED_COMPUTER_IDENTITY_DRIFT", "macdaddy.local serial AAAAAAAAAAAA", "user-provided synced-computers screenshot/statement", "", "", "", "Second listed synced-computer identity; do not call spoofing.", "no"])
        writer.writerow(["2026-06-17T11:36:00-05:00", "iOS bridge", "iPhone", "IOS_SYNCED_COMPUTER_IDENTITY_DRIFT", "home's MacBook Pro serial KFLXHW07KY", "user-provided synced-computers screenshot/statement", "", "", "", "Third listed identity; current Mac serial matches.", "no"])
        writer.writerow(["2026-06-17T11:36:05-05:00", "iOS bridge", "Mac", "lockdown_pairing_plist_created", str(PAIRING), str(PAIRING), "", sha256_file(PAIRING), "", "Preserved lockdown pairing plist time-aligns with 2026-06-17 iOS synced-computer entry.", "partial"])

    prior_system = (PRIOR / "SYSTEM_ROUTE_DRAFT.md").read_text(encoding="utf-8", errors="replace") if (PRIOR / "SYSTEM_ROUTE_DRAFT.md").exists() else ""
    (OUT / "updated_SYSTEM_ROUTE_DRAFT.md").write_text(
        prior_system
        + "\n\n## iOS Backup Bridge Addendum\n\n"
        + "### Proven\n"
        + "- The iPhone synced-computer lane is recorded as IOS_SYNCED_COMPUTER_IDENTITY_DRIFT from user-provided screenshot/statement evidence.\n"
        + "- The current Mac serial is KFLXHW07KY, matching the 2026-06-17 synced-computer entry.\n\n"
        + "### Strongly supported\n"
        + "- A preserved Mac-side lockdown pairing plist was created at 2026-06-17T11:36:05-05:00, five seconds after the 2026-06-17T11:36 screenshot time. This is a bridge candidate, not root-cause proof.\n\n"
        + "### Still unknown\n"
        + "- The encrypted iOS backup metadata is pending because the backup did not exist during baseline collection.\n"
        + "- The writer/mover/mount route remains unclosed by this iOS lane.\n",
        encoding="utf-8",
    )

    prior_excluded = (PRIOR / "EXCLUDED_CLAIMS.md").read_text(encoding="utf-8", errors="replace") if (PRIOR / "EXCLUDED_CLAIMS.md").exists() else ""
    (OUT / "updated_EXCLUDED_CLAIMS.md").write_text(
        prior_excluded
        + "\n\n## iOS Bridge Exclusions\n\n"
        + "- Spoofing is not claimed; current wording is iOS synced-computer identity drift.\n"
        + "- iOS compromise is not claimed.\n"
        + "- Apple compromise is not claimed.\n"
        + "- Cross-device persistence is not claimed.\n"
        + "- Rogue MDM is not claimed.\n"
        + "- Encrypted backup contents are not treated as malicious from existence alone.\n",
        encoding="utf-8",
    )

    (OUT / "IOS_BRIDGE_PACKET.md").write_text(
        "# IOS Bridge Packet\n\n"
        "## Proven\n"
        "- Three iOS synced-computer entries are preserved from user-provided screenshot/statement evidence: 2026-06-08 22:39, 2026-06-10 00:52, and 2026-06-17 11:36.\n"
        "- Current Mac host identity is Fresh's MacBook Pro / Freshs-MacBook-Pro, model MacBook Pro, serial KFLXHW07KY.\n\n"
        "## Strongly supported\n"
        "- The 2026-06-17 11:36 iOS synced-computer entry aligns with preserved Mac-side lockdown pairing plist creation at 2026-06-17 11:36:05 -0500.\n"
        "- This supports an iPhone trust/sync to Mac pairing bridge candidate, while leaving the mechanism unresolved.\n\n"
        "## Still unknown\n"
        "- The encrypted iOS backup bridge is pending until the new backup exists.\n"
        "- No app-domain, profile/MDM, or MobileSync metadata connection to Atlas/Chrome/Codex is proven yet.\n"
        "- The writer/mover/mount route remains unclosed.\n",
        encoding="utf-8",
    )

    manifest_lines = []
    for path in sorted(OUT.iterdir()):
        if path.is_file() and path.name != "HASH_MANIFEST.sha256":
            digest = sha256_file(path)
            manifest_lines.append(f"{digest}  {path.name}\n")
    (OUT / "HASH_MANIFEST.sha256").write_text("".join(manifest_lines), encoding="utf-8")


if __name__ == "__main__":
    build()
