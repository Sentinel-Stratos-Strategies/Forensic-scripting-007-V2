#!/usr/bin/env python3
"""Build a reviewer-safe narrative packet from a 007 run directory.

The packet is a derived report layer. It points to raw artifacts, hashes the
derived outputs, and keeps claims separated from correlations and open gaps.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


STATUS_VALUES = {"proven", "supported", "plausible", "speculative", "contradicted", "unknown"}


@dataclass
class EvidenceRow:
    evidence_id: str
    lane: str
    artifact_type: str
    path: str
    status: str
    observation: str
    limitation: str = ""


@dataclass
class ClaimRow:
    claim_id: str
    claim: str
    evidence: str
    status: str
    next_proof: str


@dataclass
class ChronologyRow:
    event_time_utc: str
    lane: str
    title: str
    source_ref: str
    confidence: str


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_from_mtime(path: Path) -> str:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except OSError:
        return ""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_text(path: Path, limit: int = 80_000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def line_count(path: Path) -> int:
    try:
        with path.open("rb") as handle:
            return sum(1 for _ in handle)
    except OSError:
        return 0


def rel(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def latest_run(base: Path) -> Path:
    candidates = sorted(base.glob("007_go_plan_*"), key=lambda p: p.stat().st_mtime if p.exists() else 0)
    if not candidates:
        raise SystemExit(f"no 007_go_plan_* runs found under {base}")
    return candidates[-1]


def parse_status_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in read_text(path).splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip()
    return out


def write_tsv(path: Path, headers: list[str], rows: Iterable[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers, delimiter="\t", extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({header: row.get(header, "") for header in headers})


def find_live_capture(run_dir: Path) -> Path | None:
    captures = sorted((run_dir / "live_capture").glob("overnight_app_capture_*"))
    return captures[-1] if captures else None


def find_recursive_root(live_capture: Path | None) -> Path | None:
    if not live_capture:
        return None
    roots = sorted((live_capture / "recursive").glob("overnight_recursive_*"))
    return roots[-1] if roots else None


def collect_launched_apps(log_path: Path) -> list[str]:
    apps: list[str] = []
    for line in read_text(log_path, limit=250_000).splitlines():
        marker = "Launching app:"
        if marker in line:
            apps.append(line.split(marker, 1)[1].strip())
    return apps


def collect_recursive_groups(recursive_root: Path | None) -> list[dict[str, str]]:
    if not recursive_root:
        return []
    directories = next(recursive_root.glob("*/directories"), None)
    if not directories:
        return []
    rows: list[dict[str, str]] = []
    for group_dir in sorted(p for p in directories.iterdir() if p.is_dir()):
        objects = group_dir / "objects.tsv"
        code = group_dir / "code_verification.tsv"
        rows.append(
            {
                "group": group_dir.name,
                "objects": str(max(line_count(objects) - 1, 0)),
                "code_candidates": str(max(line_count(code) - 1, 0)),
                "last_modified_utc": iso_from_mtime(objects) or iso_from_mtime(group_dir),
                "objects_path": str(objects) if objects.exists() else "",
                "code_path": str(code) if code.exists() else "",
            }
        )
    return rows


def collect_evidence(run_dir: Path, live_capture: Path | None, recursive_root: Path | None) -> list[EvidenceRow]:
    rows: list[EvidenceRow] = []

    status_file = run_dir / "GO_PLAN_STATUS.txt"
    if status_file.exists():
        rows.append(
            EvidenceRow(
                "E001",
                "run",
                "status",
                str(status_file),
                "observed",
                "007 run status file exists and records the operator-facing run state.",
            )
        )

    pcap_dir = live_capture / "pcap" if live_capture else run_dir / "live_capture"
    pcaps = sorted(pcap_dir.glob("*.pcapng")) if pcap_dir.exists() else []
    pcap_hashes = pcap_dir / "pcap_hashes.sha256"
    if pcaps:
        rows.append(
            EvidenceRow(
                "E010",
                "network",
                "pcap",
                str(pcap_dir),
                "observed",
                f"{len(pcaps)} packet capture file(s) exist; hash manifest present={pcap_hashes.exists()}.",
            )
        )

    if live_capture:
        for lane, subdir, eid in [
            ("apps", "apps", "E020"),
            ("tcc", "tcc", "E030"),
            ("process", "process", "E040"),
            ("provenance", "provenance", "E050"),
        ]:
            path = live_capture / subdir
            if path.exists():
                rows.append(
                    EvidenceRow(
                        eid,
                        lane,
                        "capture_directory",
                        str(path),
                        "observed",
                        f"{subdir} capture directory exists under the live capture.",
                    )
                )

    if recursive_root:
        status = "interrupted" if (recursive_root / "INTERRUPTED.txt").exists() else "complete" if (recursive_root / "COMPLETE").exists() else "partial"
        rows.append(
            EvidenceRow(
                "E060",
                "recursive",
                "recursive_verifier",
                str(recursive_root),
                status,
                f"Recursive verifier output exists with status={status}.",
                "Interrupted recursive runs are usable as partial evidence but do not include final post-pass summaries.",
            )
        )

    for subdir, eid, lane in [
        ("iphone_host_snapshot", "E070", "mobile"),
        ("ios_backup_app_verify", "E080", "mobile"),
        ("analysis", "E090", "analysis"),
        ("database", "E100", "database"),
        ("prelaunch", "E110", "prelaunch"),
        ("user_observed_events", "E120", "user_observed"),
        ("user_observed_ui", "E130", "user_observed"),
    ]:
        path = run_dir / subdir
        if path.exists():
            rows.append(
                EvidenceRow(
                    eid,
                    lane,
                    "run_subdirectory",
                    str(path),
                    "observed",
                    f"{subdir} exists in the run directory.",
                )
            )

    return rows


def build_claims(evidence: list[EvidenceRow], launched_apps: list[str], recursive_root: Path | None) -> list[ClaimRow]:
    evidence_ids = {row.evidence_id for row in evidence}
    claims = [
        ClaimRow(
            "C001",
            "The 007 run produced a preserved evidence directory that can be reviewed without rerunning capture.",
            "E001 E090 E100",
            "proven" if "E001" in evidence_ids else "unknown",
            "Hash the complete derived packet and keep the run directory path stable.",
        ),
        ClaimRow(
            "C010",
            "The run launched and observed the target app family set during the capture window.",
            "GO_PLAN_STATUS/go_plan.log launch lines",
            "supported" if launched_apps else "unknown",
            "Correlate launch lines with process samples and app-watch outputs.",
        ),
        ClaimRow(
            "C020",
            "The network lane produced packet-capture artifacts for the live window.",
            "E010",
            "proven" if "E010" in evidence_ids else "unknown",
            "Summarize pcap endpoints and tie them to process/app time windows.",
        ),
        ClaimRow(
            "C030",
            "The TCC/privacy lane produced local artifacts suitable for claim review.",
            "E030 E110",
            "supported" if {"E030", "E110"} & evidence_ids else "unknown",
            "Normalize TCC rows into 007 tables with service/client/status fields.",
        ),
        ClaimRow(
            "C040",
            "The recursive verifier produced useful partial object and code-verification ledgers.",
            "E060",
            "supported" if "E060" in evidence_ids else "unknown",
            "Run focused post-passes for skipped folders or complete summaries only where needed.",
        ),
        ClaimRow(
            "C050",
            "The mobile/iOS bridge lane exists as supporting context for app-family correlation.",
            "E070 E080",
            "supported" if {"E070", "E080"} & evidence_ids else "unknown",
            "Promote only rows that tie app/domain metadata to exact backup or MobileSync artifacts.",
        ),
        ClaimRow(
            "C060",
            "MDM/AXM material is present as an analysis branch, not as proof of rogue control.",
            "E090",
            "plausible" if "E090" in evidence_ids else "unknown",
            "Require direct enrollment/configuration/profile/log artifacts before escalating the claim.",
        ),
    ]

    if recursive_root and (recursive_root / "INTERRUPTED.txt").exists():
        claims.append(
            ClaimRow(
                "C070",
                "The recursive run was intentionally stopped before final post-pass summaries.",
                str(recursive_root / "INTERRUPTED.txt"),
                "proven",
                "Use focused scanner lanes instead of treating the interrupted run as final completion.",
            )
        )

    for claim in claims:
        if claim.status not in STATUS_VALUES:
            raise ValueError(f"invalid claim status: {claim.status}")
    return claims


def build_chronology(run_dir: Path, live_capture: Path | None, recursive_root: Path | None) -> list[ChronologyRow]:
    rows: list[ChronologyRow] = []
    status = parse_status_file(run_dir / "GO_PLAN_STATUS.txt") if (run_dir / "GO_PLAN_STATUS.txt").exists() else {}
    if status.get("updated_utc"):
        rows.append(ChronologyRow(status["updated_utc"], "run", f"Run status: {status.get('status', 'unknown')}", str(run_dir / "GO_PLAN_STATUS.txt"), "direct"))

    log_path = Path(status.get("log", "")) if status.get("log") else run_dir / "logs" / "go_plan.log"
    for line in read_text(log_path, limit=250_000).splitlines():
        match = re.match(r"\[(?P<ts>[^\]]+)\]\s+(?P<body>.*)$", line)
        if not match:
            continue
        body = match.group("body")
        if "Capture window starting" in body or "Launching app:" in body or "Prepared run directory:" in body:
            rows.append(ChronologyRow(match.group("ts"), "capture", body[:240], str(log_path), "direct"))

    if live_capture:
        for path in sorted(live_capture.glob("pcap/*.pcapng")):
            rows.append(ChronologyRow(iso_from_mtime(path), "network", f"PCAP artifact written: {path.name}", str(path), "direct"))

    if recursive_root:
        if (recursive_root / "INTERRUPTED.txt").exists():
            rows.append(ChronologyRow(iso_from_mtime(recursive_root / "INTERRUPTED.txt"), "recursive", "Recursive verifier interrupted intentionally.", str(recursive_root / "INTERRUPTED.txt"), "direct"))
        elif (recursive_root / "COMPLETE").exists():
            rows.append(ChronologyRow(iso_from_mtime(recursive_root / "COMPLETE"), "recursive", "Recursive verifier completed.", str(recursive_root / "COMPLETE"), "direct"))

    return sorted(rows, key=lambda row: row.event_time_utc or "")


def write_excluded_claims(path: Path, run_dir: Path) -> None:
    body = f"""# Excluded Claims

Generated: {utc_now()}

Source run: `{run_dir}`

The narrative packet does **not** claim the following as proven from this run alone:

- Rogue ABM/MDM control.
- TCC bypass.
- Preboot, Recovery, cryptex, or sealed-system compromise.
- Actor attribution or ownership.
- Vendor misconduct.
- Malware execution.
- Supply-chain root cause.

These claims require direct supporting artifacts such as configuration profiles,
MDM server records, signed/unsigned lineage evidence, entitlement drift, parent
image trust failures tied to execution, process-writer evidence, packet rows, or
TCC rows that close the exact claim.
"""
    path.write_text(body, encoding="utf-8")


def write_narrative(
    path: Path,
    run_dir: Path,
    status: dict[str, str],
    evidence: list[EvidenceRow],
    claims: list[ClaimRow],
    chronology: list[ChronologyRow],
    recursive_groups: list[dict[str, str]],
    launched_apps: list[str],
) -> None:
    evidence_by_id = {row.evidence_id: row for row in evidence}
    recursive_status = next((row for row in evidence if row.evidence_id == "E060"), None)
    top_groups = sorted(recursive_groups, key=lambda row: int(row.get("objects") or "0"), reverse=True)[:12]

    body: list[str] = []
    body.append("# Forensic Narrative\n")
    body.append("## Executive Thread\n")
    body.append(
        "This packet turns one 007 run into a reviewer-readable storyline while preserving the evidence boundary. "
        "The run captured app-launch, network, TCC/privacy, mobile/iOS-support, analysis, and recursive-verifier artifacts. "
        "The recursive pass was intentionally stopped after high-value archive coverage, so this narrative treats recursive output as partial evidence rather than a completed full-volume crawl.\n"
    )

    body.append("## Evidence Base\n")
    body.append(f"- Source run: `{run_dir}`")
    body.append(f"- Run status: `{status.get('status', 'unknown')}`")
    body.append(f"- Run phase: `{status.get('phase', 'unknown')}`")
    body.append(f"- Evidence rows summarized: `{len(evidence)}`")
    body.append(f"- Launched app paths found in run log: `{len(launched_apps)}`")
    if recursive_status:
        body.append(f"- Recursive verifier status: `{recursive_status.status}`")
    body.append("\nKnown extraction limit: the narrative is a derived index. It does not replace raw artifacts, hash manifests, or source TSV/CSV rows.\n")

    body.append("## Chronology\n")
    for row in chronology[:80]:
        body.append(f"- `{row.event_time_utc}` [{row.lane}] {row.title} (`{row.source_ref}`)")
    if len(chronology) > 80:
        body.append(f"- ... {len(chronology) - 80} additional chronology rows are available in `CHRONOLOGY.tsv`.")
    body.append("")

    body.append("## Claim Analysis\n")
    for claim in claims:
        body.append(f"### {claim.claim_id}: {claim.claim}")
        body.append(f"- Status: `{claim.status}`")
        body.append(f"- Evidence: `{claim.evidence}`")
        body.append(f"- Next proof: {claim.next_proof}\n")

    body.append("## Entity Map\n")
    body.append("Primary local entities observed by this packet:")
    body.append(f"- Evidence run: `{run_dir}`")
    if evidence_by_id.get("E010"):
        body.append(f"- Network capture lane: `{evidence_by_id['E010'].path}`")
    if evidence_by_id.get("E060"):
        body.append(f"- Recursive verifier lane: `{evidence_by_id['E060'].path}`")
    if launched_apps:
        body.append("- App paths launched during the capture window:")
        for app in launched_apps[:30]:
            body.append(f"  - `{app}`")
        if len(launched_apps) > 30:
            body.append(f"  - ... {len(launched_apps) - 30} additional launch paths in `GENESIS_HANDOFF.json`.")
    body.append("")

    body.append("## Recursive Coverage Snapshot\n")
    if top_groups:
        body.append("| Directory Group | Objects | Code Candidates | Last Modified UTC |")
        body.append("| --- | ---: | ---: | --- |")
        for row in top_groups:
            body.append(f"| `{row['group']}` | {row['objects']} | {row['code_candidates']} | {row['last_modified_utc']} |")
    else:
        body.append("No recursive directory groups were found.")
    body.append("")

    body.append("## Gaps And Uncertainties\n")
    body.append("- Interrupted recursive runs do not include final app-bundle, container, keyword, directory-summary, or case-hash post-passes unless those files exist separately.")
    body.append("- MDM/AXM analysis rows are supporting context unless direct enrollment/profile/control artifacts are present.")
    body.append("- TCC artifacts support privacy-relevant runtime context; they do not alone prove unauthorized access or bypass.")
    body.append("- Parent image trust and child binary trust remain separate layers; valid child code does not validate an untrusted parent image.\n")

    body.append("## Next Actions\n")
    body.append("- Run focused post-passes only on skipped high-value folders instead of recrawling all of `/Volumes/Storage`.")
    body.append("- Normalize selected TCC, PCAP, recursive, and mobile rows into the 007 database.")
    body.append("- Let Genesis render this packet as Evidence Browser, Timeline Narrator, Claim Matrix, and Report Builder input.")
    body.append("- Keep excluded claims visible in reviewer packets so the report stays strong without overclaiming.\n")

    path.write_text("\n".join(body), encoding="utf-8")


def write_handoff(
    path: Path,
    run_dir: Path,
    out_dir: Path,
    evidence: list[EvidenceRow],
    claims: list[ClaimRow],
    chronology: list[ChronologyRow],
    recursive_groups: list[dict[str, str]],
    launched_apps: list[str],
) -> None:
    payload = {
        "schema": "genesis_007_narrative_handoff_v1",
        "generated_utc": utc_now(),
        "source_run": str(run_dir),
        "packet_dir": str(out_dir),
        "recommended_genesis_views": [
            "Evidence Browser",
            "Timeline Narrator",
            "Claim Matrix",
            "Report Builder",
            "AI Analyst",
        ],
        "files": {
            "narrative": str(out_dir / "FORENSIC_NARRATIVE.md"),
            "claim_matrix": str(out_dir / "CLAIM_MATRIX.tsv"),
            "evidence_base": str(out_dir / "EVIDENCE_BASE.tsv"),
            "chronology": str(out_dir / "CHRONOLOGY.tsv"),
            "excluded_claims": str(out_dir / "EXCLUDED_CLAIMS.md"),
            "hash_manifest": str(out_dir / "HASH_MANIFEST.sha256"),
        },
        "counts": {
            "evidence_rows": len(evidence),
            "claims": len(claims),
            "chronology_rows": len(chronology),
            "recursive_groups": len(recursive_groups),
            "launched_apps": len(launched_apps),
        },
        "launched_apps": launched_apps,
        "recursive_groups": recursive_groups,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_hash_manifest(out_dir: Path) -> None:
    manifest = out_dir / "HASH_MANIFEST.sha256"
    rows: list[str] = []
    for path in sorted(out_dir.iterdir()):
        if not path.is_file() or path.name == manifest.name:
            continue
        rows.append(f"{sha256_file(path)}  {path.name}")
    manifest.write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")


def build_packet(run_dir: Path, out_dir: Path) -> Path:
    run_dir = run_dir.expanduser().resolve()
    if not run_dir.is_dir():
        raise SystemExit(f"run directory does not exist: {run_dir}")

    out_dir.mkdir(parents=True, exist_ok=True)
    status = parse_status_file(run_dir / "GO_PLAN_STATUS.txt")
    live_capture = find_live_capture(run_dir)
    recursive_root = find_recursive_root(live_capture)
    log_path = Path(status.get("log", "")) if status.get("log") else run_dir / "logs" / "go_plan.log"

    launched_apps = collect_launched_apps(log_path)
    evidence = collect_evidence(run_dir, live_capture, recursive_root)
    claims = build_claims(evidence, launched_apps, recursive_root)
    chronology = build_chronology(run_dir, live_capture, recursive_root)
    recursive_groups = collect_recursive_groups(recursive_root)

    write_tsv(
        out_dir / "EVIDENCE_BASE.tsv",
        ["evidence_id", "lane", "artifact_type", "path", "status", "observation", "limitation"],
        [row.__dict__ for row in evidence],
    )
    write_tsv(
        out_dir / "CLAIM_MATRIX.tsv",
        ["claim_id", "claim", "evidence", "status", "next_proof"],
        [row.__dict__ for row in claims],
    )
    write_tsv(
        out_dir / "CHRONOLOGY.tsv",
        ["event_time_utc", "lane", "title", "source_ref", "confidence"],
        [row.__dict__ for row in chronology],
    )
    write_tsv(
        out_dir / "RECURSIVE_COVERAGE.tsv",
        ["group", "objects", "code_candidates", "last_modified_utc", "objects_path", "code_path"],
        recursive_groups,
    )
    write_excluded_claims(out_dir / "EXCLUDED_CLAIMS.md", run_dir)
    write_narrative(out_dir / "FORENSIC_NARRATIVE.md", run_dir, status, evidence, claims, chronology, recursive_groups, launched_apps)
    write_handoff(out_dir / "GENESIS_HANDOFF.json", run_dir, out_dir, evidence, claims, chronology, recursive_groups, launched_apps)

    readme = f"""# 007 Narrative Claim Packet

Generated: {utc_now()}

Source run: `{run_dir}`

Open `FORENSIC_NARRATIVE.md` first, then `CLAIM_MATRIX.tsv`.
Genesis OS should consume `GENESIS_HANDOFF.json` and render the raw paths as
click-through evidence, not copied evidence blobs.
"""
    (out_dir / "README.md").write_text(readme, encoding="utf-8")
    write_hash_manifest(out_dir)
    return out_dir


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a Genesis-ready narrative and claim packet from a 007 run.")
    parser.add_argument("--run-dir", help="007 run directory. Defaults to the latest /Volumes/Evidence/007_go_plan_* run.")
    parser.add_argument("--evidence-base", default="/Volumes/Evidence", help="Evidence base used when --run-dir is omitted.")
    parser.add_argument("--out-dir", help="Output directory. Defaults to RUN_DIR/analysis/narrative_claim_packet_TIMESTAMP.")
    args = parser.parse_args()

    run_dir = Path(args.run_dir) if args.run_dir else latest_run(Path(args.evidence_base))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(args.out_dir) if args.out_dir else run_dir / "analysis" / f"narrative_claim_packet_{stamp}"
    packet_dir = build_packet(run_dir, out_dir)
    print(packet_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
