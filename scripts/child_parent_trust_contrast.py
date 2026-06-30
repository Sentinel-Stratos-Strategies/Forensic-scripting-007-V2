#!/usr/bin/env python3
"""
Compare recursive child-code verification against a parent trust-boundary report.

This makes the "mostly valid children inside a bad/unverified parent" condition
explicit for reviewers without changing recursive_macos_volume_verify.sh.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def tab(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("\\", "\\\\").replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n")


def load_parent(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def iter_tsv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def summarize_recursive(recursive_dir: Path) -> dict[str, Any]:
    if (recursive_dir / "code_verification.tsv").exists():
        code_files = [recursive_dir / "code_verification.tsv"]
        object_files = [recursive_dir / "objects.tsv"] if (recursive_dir / "objects.tsv").exists() else []
    else:
        code_files = sorted(recursive_dir.glob("directories/*/code_verification.tsv"))
        object_files = sorted(recursive_dir.glob("directories/*/objects.tsv"))
    container_files = sorted(recursive_dir.glob("**/container_verification.tsv"))
    app_files = sorted(recursive_dir.glob("**/app_bundles.tsv"))

    class_counts: Counter[str] = Counter()
    static_counts: Counter[str] = Counter()
    codesign_counts: Counter[str] = Counter()
    authority_counts: Counter[str] = Counter()
    invalid_examples: list[dict[str, str]] = []
    valid_native = 0
    native_total = 0
    rows_total = 0

    for code_file in code_files:
        for row in iter_tsv(code_file):
            rows_total += 1
            klass = row.get("class", "")
            static_counts[row.get("static_parse", "")] += 1
            codesign_counts[row.get("codesign", "")] += 1
            class_counts[klass] += 1
            if klass in {"mach-o", "native-library"}:
                native_total += 1
                if row.get("codesign") == "valid":
                    valid_native += 1
                elif row.get("codesign") in {"invalid", "unsigned"} and len(invalid_examples) < 20:
                    invalid_examples.append(
                        {
                            "relative_path": row.get("relative_path", ""),
                            "class": klass,
                            "codesign": row.get("codesign", ""),
                            "detail_file": row.get("detail_file", ""),
                        }
                    )
            authorities = row.get("authorities", "")
            if authorities:
                authority_counts[authorities] += 1

    container_counts: Counter[str] = Counter()
    untrusted_containers: list[dict[str, str]] = []
    for container_file in container_files:
        for row in iter_tsv(container_file):
            trust = row.get("trust", "")
            container_counts[trust] += 1
            if trust and trust != "trusted" and len(untrusted_containers) < 20:
                untrusted_containers.append(
                    {
                        "relative_path": row.get("relative_path", ""),
                        "class": row.get("class", ""),
                        "trust": trust,
                        "detail_file": row.get("detail_file", ""),
                    }
                )

    app_counts: Counter[str] = Counter()
    app_rejections: list[dict[str, str]] = []
    for app_file in app_files:
        for row in iter_tsv(app_file):
            key = f"{row.get('codesign','')}/{row.get('gatekeeper','')}"
            app_counts[key] += 1
            if row.get("codesign") != "valid" or row.get("gatekeeper") != "accepted":
                if len(app_rejections) < 20:
                    app_rejections.append(
                        {
                            "relative_path": row.get("relative_path", ""),
                            "codesign": row.get("codesign", ""),
                            "gatekeeper": row.get("gatekeeper", ""),
                            "detail_file": row.get("detail_file", ""),
                        }
                    )

    object_rows = 0
    for object_file in object_files:
        try:
            with object_file.open("r", encoding="utf-8", errors="replace") as handle:
                object_rows += max(sum(1 for _ in handle) - 1, 0)
        except OSError:
            pass

    return {
        "recursive_dir": str(recursive_dir),
        "code_verification_files": len(code_files),
        "object_files": len(object_files),
        "object_rows": object_rows,
        "code_rows": rows_total,
        "native_total": native_total,
        "valid_native": valid_native,
        "class_counts": dict(class_counts),
        "static_parse_counts": dict(static_counts),
        "codesign_counts": dict(codesign_counts),
        "top_authorities": dict(authority_counts.most_common(12)),
        "invalid_native_examples": invalid_examples,
        "container_trust_counts": dict(container_counts),
        "untrusted_container_examples": untrusted_containers,
        "app_bundle_counts": dict(app_counts),
        "app_bundle_exceptions": app_rejections,
    }


def classify_boundary(parent: dict[str, Any], child: dict[str, Any]) -> str:
    status = parent.get("parent_trust_status", "")
    codesign_counts = child.get("codesign_counts", {})
    child_has_valid = int(codesign_counts.get("valid", 0)) > 0
    child_has_bad = int(codesign_counts.get("invalid", 0)) + int(codesign_counts.get("unsigned", 0)) > 0

    if status.startswith("trusted_parent") or status == "expected_sealed_mount_reports_sealed":
        if child_has_bad:
            return "trusted_parent_with_child_code_exceptions"
        return "parent_and_child_consistent"
    if child_has_valid:
        return "valid_inner_signature_inside_untrusted_or_unverified_parent"
    return "untrusted_or_unverified_parent_without_valid_child_signal"


def reviewer_sentence(parent: dict[str, Any], child: dict[str, Any], boundary: str) -> str:
    valid_native = child.get("valid_native", 0)
    native_total = child.get("native_total", 0)
    parent_status = parent.get("parent_trust_status", "review_required")
    if boundary == "valid_inner_signature_inside_untrusted_or_unverified_parent":
        return (
            f"The recursive verifier found {valid_native} valid native code signatures "
            f"out of {native_total} native code rows, but the parent layer is "
            f"`{parent_status}`. Those valid child signatures do not validate the "
            "disk image, recovery mount, APFS seal, or acquisition route."
        )
    if boundary == "trusted_parent_with_child_code_exceptions":
        return (
            "The parent layer passed available checks, but child-code exceptions remain "
            "and should be reviewed by path and detail file."
        )
    if boundary == "parent_and_child_consistent":
        return "Parent and child layers are consistent under the checks available to these tools."
    return (
        "The parent layer is untrusted or unverified, and the child-code layer does not "
        "provide a separate reason to relax that parent-level finding."
    )


def write_outputs(parent: dict[str, Any], child: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    boundary = classify_boundary(parent, child)
    sentence = reviewer_sentence(parent, child, boundary)
    result = {
        "generated_utc": utc_now(),
        "parent": parent,
        "child_summary": child,
        "boundary_classification": boundary,
        "reviewer_safe_sentence": sentence,
    }
    (out_dir / "trust_boundary_contrast.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    headers = [
        "parent_target",
        "parent_status",
        "boundary_classification",
        "code_rows",
        "native_total",
        "valid_native",
        "codesign_valid",
        "codesign_invalid",
        "codesign_unsigned",
        "reviewer_safe_sentence",
    ]
    values = {
        "parent_target": parent.get("target_path", ""),
        "parent_status": parent.get("parent_trust_status", ""),
        "boundary_classification": boundary,
        "code_rows": child.get("code_rows", 0),
        "native_total": child.get("native_total", 0),
        "valid_native": child.get("valid_native", 0),
        "codesign_valid": child.get("codesign_counts", {}).get("valid", 0),
        "codesign_invalid": child.get("codesign_counts", {}).get("invalid", 0),
        "codesign_unsigned": child.get("codesign_counts", {}).get("unsigned", 0),
        "reviewer_safe_sentence": sentence,
    }
    with (out_dir / "trust_boundary_contrast.tsv").open("w", encoding="utf-8") as handle:
        handle.write("\t".join(headers) + "\n")
        handle.write("\t".join(tab(values[h]) for h in headers) + "\n")

    md = [
        "# Parent/Child Trust Boundary Contrast",
        "",
        f"- Generated UTC: `{result['generated_utc']}`",
        f"- Parent target: `{parent.get('target_path', '')}`",
        f"- Parent status: `{parent.get('parent_trust_status', '')}`",
        f"- Boundary classification: `{boundary}`",
        "",
        "## Reviewer-Safe Reading",
        "",
        sentence,
        "",
        "## Child-Code Summary",
        "",
        f"- Code rows: `{child.get('code_rows', 0)}`",
        f"- Native rows: `{child.get('native_total', 0)}`",
        f"- Valid native signatures: `{child.get('valid_native', 0)}`",
        f"- Codesign counts: `{child.get('codesign_counts', {})}`",
        f"- Static parse counts: `{child.get('static_parse_counts', {})}`",
        "",
        "## Boundary Rule",
        "",
        (
            "A signed child object can remain perfectly valid inside a parent artifact "
            "whose image, seal, mount route, or acquisition path is untrusted. Child "
            "validity is evidence about the child file only."
        ),
        "",
    ]
    invalid_examples = child.get("invalid_native_examples", [])
    if invalid_examples:
        md.extend(["## Native Code Exceptions", ""])
        for item in invalid_examples[:10]:
            md.append(
                f"- `{item.get('codesign')}` `{item.get('relative_path')}` "
                f"detail=`{item.get('detail_file')}`"
            )
        md.append("")
    (out_dir / "trust_boundary_contrast.md").write_text("\n".join(md), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Contrast child-code verification with parent trust.")
    parser.add_argument("--recursive-dir", required=True, help="Recursive verifier volume directory")
    parser.add_argument("--parent-report", required=True, help="parent_trust_boundary.json from parent_trust_boundary_check.py")
    parser.add_argument("--out-dir", required=True, help="Directory for contrast outputs")
    args = parser.parse_args()

    recursive_dir = Path(args.recursive_dir).expanduser().resolve()
    parent_report = Path(args.parent_report).expanduser().resolve()
    out_dir = Path(args.out_dir).expanduser().resolve()
    if not recursive_dir.exists():
        raise SystemExit(f"recursive dir does not exist: {recursive_dir}")
    if not parent_report.exists():
        raise SystemExit(f"parent report does not exist: {parent_report}")

    parent = load_parent(parent_report)
    child = summarize_recursive(recursive_dir)
    write_outputs(parent, child, out_dir)
    print(out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
