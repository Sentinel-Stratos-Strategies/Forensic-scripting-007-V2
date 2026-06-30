#!/usr/bin/env python3
"""
Read-only recursive macOS app bundle inspector.

For each supplied .app, .framework, .xpc, .appex, .systemextension, or binary path,
the script inventories nested code objects and Mach-O files, then captures:
- exact path
- filesystem metadata
- sha256
- file(1) classification
- codesign signer details and entitlements
- spctl assessment
- nearby Info.plist / embedded.provisionprofile paths

This is evidence collection, not remediation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


UTC = timezone.utc
BUNDLE_SUFFIXES = {
    ".app",
    ".framework",
    ".xpc",
    ".appex",
    ".systemextension",
    ".bundle",
    ".plugin",
    ".kext",
    ".dylib",
}
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}


@dataclass
class ArtifactRecord:
    root_target: str
    path: str
    kind: str
    size: int
    mode: str
    mtime_utc: str
    sha256: str
    file_type: str
    info_plist: str
    provisionprofile: str
    codesign_identifier: str
    codesign_team_id: str
    codesign_timestamp: str
    authorities: list[str]
    notarization_ticket: str
    entitlements: object
    spctl_result: str
    spctl_origin: str
    spctl_source: str


def run_cmd(args: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception as exc:
        return 1, str(exc)
    output = proc.stdout
    if proc.stderr:
        output = f"{output}\n{proc.stderr}".strip()
    return proc.returncode, output.strip()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def iso_utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_macho(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            head = fh.read(4)
    except OSError:
        return False
    return head in MACHO_MAGICS


def looks_executable(path: Path) -> bool:
    try:
        st = path.stat()
    except OSError:
        return False
    return bool(st.st_mode & 0o111)


def find_embedded_info(path: Path) -> tuple[str, str]:
    if path.is_dir():
        contents = path / "Contents"
        info = contents / "Info.plist"
        profile = contents / "embedded.provisionprofile"
    else:
        contents = path.parent.parent if path.parent.name == "MacOS" else path.parent
        info = contents / "Info.plist"
        profile = contents / "embedded.provisionprofile"
    return (str(info) if info.exists() else "", str(profile) if profile.exists() else "")


def parse_codesign(path: Path) -> tuple[str, str, str, list[str], str, object]:
    rc, out = run_cmd(["codesign", "-dvvv", "--entitlements", ":-", str(path)], timeout=60)
    identifier = ""
    team_id = ""
    timestamp = ""
    authorities: list[str] = []
    notarization_ticket = ""
    entitlements: object = None
    if not out:
        return identifier, team_id, timestamp, authorities, notarization_ticket, entitlements
    ent_start = out.find("<?xml")
    ent_text = out[ent_start:] if ent_start != -1 else ""
    meta_text = out[:ent_start] if ent_start != -1 else out
    for line in meta_text.splitlines():
        line = line.strip()
        if line.startswith("Identifier="):
            identifier = line.split("=", 1)[1]
        elif line.startswith("TeamIdentifier="):
            team_id = line.split("=", 1)[1]
        elif line.startswith("Timestamp=") or line.startswith("Signed Time="):
            timestamp = line.split("=", 1)[1]
        elif line.startswith("Authority="):
            authorities.append(line.split("=", 1)[1])
        elif line.startswith("Notarization Ticket="):
            notarization_ticket = line.split("=", 1)[1]
    if ent_text:
        try:
            entitlements = plistlib.loads(ent_text.encode("utf-8", errors="ignore"))
        except Exception:
            entitlements = ent_text
    return identifier, team_id, timestamp, authorities, notarization_ticket, entitlements


def parse_spctl(path: Path) -> tuple[str, str, str]:
    rc, out = run_cmd(["spctl", "-a", "-vv", str(path)], timeout=30)
    result = ""
    origin = ""
    source = ""
    if out:
        first = out.splitlines()[0].strip()
        result = first
        for line in out.splitlines()[1:]:
            line = line.strip()
            if line.startswith("origin="):
                origin = line.split("=", 1)[1]
            elif line.startswith("source="):
                source = line.split("=", 1)[1]
    return result, origin, source


def classify_path(path: Path) -> str:
    if path.is_dir() and path.suffix in BUNDLE_SUFFIXES:
        return path.suffix.lstrip(".")
    if path.is_file() and is_macho(path):
        return "macho"
    if path.is_file() and looks_executable(path):
        return "executable"
    return "file"


def iter_artifacts(target: Path) -> Iterable[Path]:
    seen: set[str] = set()
    if target.exists():
        seen.add(str(target))
        yield target
    for path in target.rglob("*"):
        if not path.exists():
            continue
        if str(path) in seen:
            continue
        if path.is_dir() and path.suffix in BUNDLE_SUFFIXES:
            seen.add(str(path))
            yield path
            continue
        if path.is_file() and (is_macho(path) or looks_executable(path)):
            seen.add(str(path))
            yield path


def build_record(root_target: Path, path: Path) -> ArtifactRecord | None:
    try:
        st = path.stat()
    except OSError:
        return None
    info_plist, provisionprofile = find_embedded_info(path)
    file_rc, file_out = run_cmd(["file", "-b", str(path)], timeout=10)
    identifier, team_id, timestamp, authorities, notarization_ticket, entitlements = parse_codesign(path)
    spctl_result, spctl_origin, spctl_source = parse_spctl(path)
    digest = ""
    if path.is_file():
        try:
            digest = sha256_file(path)
        except OSError:
            digest = ""
    return ArtifactRecord(
        root_target=str(root_target),
        path=str(path),
        kind=classify_path(path),
        size=st.st_size,
        mode=oct(st.st_mode & 0o777),
        mtime_utc=iso_utc(st.st_mtime),
        sha256=digest,
        file_type=file_out,
        info_plist=info_plist,
        provisionprofile=provisionprofile,
        codesign_identifier=identifier,
        codesign_team_id=team_id,
        codesign_timestamp=timestamp,
        authorities=authorities,
        notarization_ticket=notarization_ticket,
        entitlements=entitlements,
        spctl_result=spctl_result,
        spctl_origin=spctl_origin,
        spctl_source=spctl_source,
    )


def write_markdown(out_path: Path, records: list[ArtifactRecord]) -> None:
    lines = [
        "# Recursive Bundle Binary Inventory",
        "",
        f"- Generated UTC: `{iso_utc(datetime.now(tz=UTC).timestamp())}`",
        f"- Total artifacts: `{len(records)}`",
        "",
        "## Summary By Root Target",
    ]
    by_root: dict[str, list[ArtifactRecord]] = {}
    for rec in records:
        by_root.setdefault(rec.root_target, []).append(rec)
    for root, group in sorted(by_root.items()):
        lines.append(f"- `{root}`: `{len(group)}` artifacts")
    lines.extend(
        [
            "",
            "## Interesting Artifacts",
            "| Root | Kind | Team ID | Identifier | Path |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for rec in records:
        if rec.kind in {"app", "framework", "xpc", "appex", "systemextension", "macho"}:
            lines.append(
                f"| `{rec.root_target}` | `{rec.kind}` | `{rec.codesign_team_id}` | `{rec.codesign_identifier}` | `{rec.path}` |"
            )
    lines.extend(
        [
            "",
            "## Guardrails",
            "- Developer ID signing means Apple issued the certificate authority, not that Apple authored the software.",
            "- `spctl` rejection on a non-app nested binary can be normal when the code object is valid but not a standalone app.",
            "- Treat signer drift, ad hoc signing, missing entitlements, or mismatched nested signatures as leads requiring bundle-by-bundle review.",
        ]
    )
    out_path.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("targets", nargs="+", help="App bundle or binary paths to inspect")
    parser.add_argument("--out-dir", required=True, help="Directory for JSON and Markdown output")
    args = parser.parse_args()

    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    records: list[ArtifactRecord] = []
    for target_str in args.targets:
        target = Path(target_str).expanduser().resolve()
        for artifact in iter_artifacts(target):
            record = build_record(target, artifact)
            if record is not None:
                records.append(record)

    records.sort(key=lambda r: (r.root_target, r.path))
    json_path = out_dir / "bundle_binary_inventory.json"
    md_path = out_dir / "bundle_binary_inventory.md"
    json_path.write_text(json.dumps([asdict(r) for r in records], indent=2))
    write_markdown(md_path, records)
    print(f"Wrote {len(records)} artifact records to {json_path}")
    print(f"Wrote summary to {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
