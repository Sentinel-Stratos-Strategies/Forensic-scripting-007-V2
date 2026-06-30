#!/usr/bin/env python3
"""
Scoped forensic collector for macOS cache directories.

This is evidence-first tooling:
- preserves raw paths and mtimes
- records exact string hits
- distinguishes likely native Apple config from user-synced cache content
- emits bounded JSON/CSV/Markdown outputs for later narrative work
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable


UTC = timezone.utc

DEFAULT_INDICATORS = [
    "setupCert.plist",
    "s.mzstatic.com/sap/setupCert.plist",
    "signSapSetup",
    "fpinit.itunes.apple.com/v1/signSapSetup",
    "signSapSetupCert",
    "Apple System Integration Certification Authority",
    "DRM Technologies A01",
    "AQIAAAQW",
]

TEXT_SUFFIXES = {
    ".plist",
    ".json",
    ".txt",
    ".log",
    ".xml",
    ".html",
    ".md",
    ".csv",
    ".sqlite",
    ".db",
    ".cache",
}


@dataclass
class FileRecord:
    path: str
    size: int
    mtime_utc: str
    sha256: str
    area: str
    recent: bool
    classification: str


@dataclass
class IndicatorHit:
    path: str
    indicator: str
    area: str
    classification: str
    hit_type: str
    context: str
    mtime_utc: str


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def iso_utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def classify_path(path: Path) -> str:
    p = str(path)
    if "/CloudKit/com.apple.bird/" in p and "/MMCS/ClonedFiles/" in p:
        return "user_synced_cloud_content"
    if "/CloudKit/" in p:
        return "apple_cloudkit_cache"
    if "/com.apple.parsecd/" in p or "/com.apple.CloudTelemetry/" in p:
        return "apple_service_config"
    if "/com.apple." in p:
        return "apple_service_cache"
    if "/com.google.GeminiMacOS/" in p or "/ai.perplexity.macv3/" in p or "/com.openai." in p:
        return "third_party_app_cache"
    if "/Homebrew/" in p or "/pip/" in p or "/typescript/" in p:
        return "developer_tool_cache"
    return "uncertain"


def area_for_path(root: Path, path: Path) -> str:
    rel = path.relative_to(root)
    return rel.parts[0] if rel.parts else "."


def is_textish(path: Path) -> bool:
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    return any(s in path.name.lower() for s in ("plist", "json", "sqlite", "cache", "log", "txt"))


def safe_excerpt(data: str, needle: str, window: int = 220) -> str:
    idx = data.find(needle)
    if idx == -1:
        return ""
    start = max(0, idx - window)
    end = min(len(data), idx + len(needle) + window)
    excerpt = data[start:end]
    return excerpt.replace("\n", "\\n")


def iter_candidate_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path.is_file():
            yield path


def collect(
    root: Path,
    indicators: list[str],
    recent_hours: int,
    max_scan_bytes: int,
) -> tuple[list[FileRecord], list[IndicatorHit]]:
    records: list[FileRecord] = []
    hits: list[IndicatorHit] = []
    recent_cutoff = datetime.now(tz=UTC) - timedelta(hours=recent_hours)

    for path in iter_candidate_files(root):
        try:
            st = path.stat()
        except OSError:
            continue
        mtime = datetime.fromtimestamp(st.st_mtime, tz=UTC)
        recent = mtime >= recent_cutoff
        area = area_for_path(root, path)
        classification = classify_path(path)

        record_needed = recent or is_textish(path)
        if record_needed:
            digest = sha256_file(path) if st.st_size <= max_scan_bytes else ""
            records.append(
                FileRecord(
                    path=str(path),
                    size=st.st_size,
                    mtime_utc=iso_utc(st.st_mtime),
                    sha256=digest,
                    area=area,
                    recent=recent,
                    classification=classification,
                )
            )

        if not is_textish(path) or st.st_size > max_scan_bytes:
            continue

        try:
            data = path.read_text(errors="replace")
        except OSError:
            continue

        for indicator in indicators:
            if indicator in data:
                hits.append(
                    IndicatorHit(
                        path=str(path),
                        indicator=indicator,
                        area=area,
                        classification=classification,
                        hit_type="content",
                        context=safe_excerpt(data, indicator),
                        mtime_utc=iso_utc(st.st_mtime),
                    )
                )
    return records, hits


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("")
        return
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(
    path: Path,
    scope: Path,
    records: list[FileRecord],
    hits: list[IndicatorHit],
    recent_hours: int,
) -> None:
    recent_records = [r for r in records if r.recent]
    class_counts: dict[str, int] = {}
    for hit in hits:
        class_counts[hit.classification] = class_counts.get(hit.classification, 0) + 1

    top_recent = sorted(recent_records, key=lambda r: r.mtime_utc, reverse=True)[:25]
    top_hits = hits[:40]

    lines = [
        "# Cache Forensic Scan",
        "",
        "## Scope",
        f"- Path: `{scope}`",
        f"- Recent window: last `{recent_hours}` hours",
        f"- Files inventoried: `{len(records)}`",
        f"- Indicator hits: `{len(hits)}`",
        "",
        "## High-Level Findings",
    ]
    if not hits:
        lines.append("- No configured indicator strings were found in bounded text-like cache files.")
    else:
        for cls, count in sorted(class_counts.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"- `{cls}`: `{count}` indicator hit(s)")

    lines.extend(
        [
            "",
            "## Recent High-Signal Files",
            "| UTC Time | Classification | Path |",
            "| --- | --- | --- |",
        ]
    )
    for rec in top_recent:
        lines.append(f"| {rec.mtime_utc} | {rec.classification} | `{rec.path}` |")

    lines.extend(
        [
            "",
            "## Indicator Hits",
            "| UTC Time | Indicator | Classification | Path |",
            "| --- | --- | --- | --- |",
        ]
    )
    for hit in top_hits:
        lines.append(f"| {hit.mtime_utc} | `{hit.indicator}` | {hit.classification} | `{hit.path}` |")

    lines.extend(
        [
            "",
            "## Interpretation Guardrails",
            "- `apple_service_config` and `apple_service_cache` hits can be normal Apple bag/storebag/config activity.",
            "- `user_synced_cloud_content` hits inside `CloudKit/com.apple.bird/.../MMCS/ClonedFiles/` may reflect synced document content rather than native cache configuration.",
            "- Indicator presence alone does not establish malicious persistence, ownership, or control.",
            "",
        ]
    )
    path.write_text("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope", required=True, help="Scoped path to review")
    parser.add_argument("--outdir", required=True, help="Output directory")
    parser.add_argument("--recent-hours", type=int, default=72)
    parser.add_argument("--max-scan-bytes", type=int, default=5_000_000)
    parser.add_argument("--indicator", action="append", default=[])
    args = parser.parse_args()

    scope = Path(args.scope).resolve()
    outdir = Path(args.outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    indicators = DEFAULT_INDICATORS + args.indicator
    records, hits = collect(scope, indicators, args.recent_hours, args.max_scan_bytes)

    records_rows = [asdict(r) for r in sorted(records, key=lambda r: (not r.recent, r.mtime_utc), reverse=True)]
    hit_rows = [asdict(h) for h in sorted(hits, key=lambda h: h.mtime_utc, reverse=True)]

    (outdir / "records.json").write_text(json.dumps(records_rows, indent=2))
    (outdir / "hits.json").write_text(json.dumps(hit_rows, indent=2))
    write_csv(outdir / "records.csv", records_rows)
    write_csv(outdir / "hits.csv", hit_rows)
    write_markdown(outdir / "report.md", scope, records, hits, args.recent_hours)

    print(outdir / "report.md")
    print(outdir / "hits.csv")


if __name__ == "__main__":
    main()
