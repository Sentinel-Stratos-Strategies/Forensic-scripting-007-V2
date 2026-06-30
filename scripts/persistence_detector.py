#!/usr/bin/env python3
"""
Persistence & Stealth Detector for LLM/AI Components

This detector focuses on persistence mechanisms that could hide LLM/AI
workloads on a system. It inspects cron jobs, systemd unit files,
shell startup profiles, and other autorun surfaces for AI-specific
keywords, API keys, and suspicious network calls.
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List


class PersistenceDetector:
    """Detects AI/LLM persistence mechanisms across the system."""

    def __init__(self) -> None:
        self.findings: List[Dict[str, object]] = []

        # Indicators that hint at AI/LLM workloads
        self.llm_keywords = [
            "llm",
            "gpt",
            "bert",
            "llama",
            "transformer",
            "huggingface",
            "inference",
            "model",
            "tokenizer",
            "embedding",
            "ollama",
        ]

        # API and credential markers worth flagging
        self.api_keywords = [
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "HUGGINGFACEHUB_API_TOKEN",
            "COHERE_API_KEY",
            "AI21_API_KEY",
        ]

        # Cron directories and files to inspect
        self.cron_targets = [
            Path("/etc/crontab"),
            Path("/etc/cron.d"),
            Path("/etc/cron.daily"),
            Path("/etc/cron.hourly"),
            Path("/etc/cron.weekly"),
            Path("/etc/cron.monthly"),
            Path("/var/spool/cron"),
            Path("/var/spool/cron/crontabs"),
        ]

        # systemd unit search paths
        self.systemd_dirs = [
            Path("/etc/systemd/system"),
            Path("/usr/lib/systemd/system"),
            Path("/lib/systemd/system"),
        ]

        # Shell profile locations that often store autorun logic
        self.shell_profiles = [
            Path("~/.bashrc").expanduser(),
            Path("~/.profile").expanduser(),
            Path("~/.zshrc").expanduser(),
            Path("/etc/profile"),
            Path("/etc/bash.bashrc"),
            Path("/etc/zsh/zshrc"),
        ]

    def _line_has_indicator(self, line: str) -> bool:
        return any(keyword.lower() in line.lower() for keyword in self.llm_keywords)

    def _line_has_api_key(self, line: str) -> bool:
        return any(key in line for key in self.api_keywords)

    def scan_cron_jobs(self) -> None:
        """Inspect cron entries for AI/LLM indicators or suspicious network calls."""

        print("[*] Scanning cron jobs for persistent AI/LLM tasks...")

        for target in self.cron_targets:
            try:
                if target.is_dir():
                    entries = [p for p in target.iterdir() if p.is_file()]
                elif target.is_file():
                    entries = [target]
                else:
                    continue

                for entry in entries:
                    try:
                        with entry.open("r", errors="ignore") as handle:
                            for line_num, raw_line in enumerate(handle, 1):
                                line = raw_line.strip()
                                if not line or line.startswith("#"):
                                    continue

                                if self._line_has_indicator(line) or self._line_has_api_key(line):
                                    self.findings.append(
                                        {
                                            "type": "cron_job",
                                            "path": str(entry),
                                            "line": line_num,
                                            "content": line[:200],
                                        }
                                    )

                                # Flag outbound calls to public AI endpoints
                                if re.search(r"curl|wget", line, re.IGNORECASE) and re.search(
                                    r"openai|anthropic|huggingface|cohere|ollama|replicate|hf\.space",
                                    line,
                                    re.IGNORECASE,
                                ):
                                    self.findings.append(
                                        {
                                            "type": "cron_network_call",
                                            "path": str(entry),
                                            "line": line_num,
                                            "content": line[:200],
                                        }
                                    )
                    except (PermissionError, FileNotFoundError):
                        continue
            except (PermissionError, FileNotFoundError):
                continue

    def scan_systemd_units(self) -> None:
        """Search systemd units for AI/LLM-related services or model loaders."""

        print("[*] Scanning systemd unit files for hidden AI/LLM services...")

        for unit_dir in self.systemd_dirs:
            if not unit_dir.exists():
                continue

            for service_file in unit_dir.glob("*.service"):
                try:
                    with service_file.open("r", errors="ignore") as handle:
                        for line_num, raw_line in enumerate(handle, 1):
                            line = raw_line.strip()
                            if not line or line.startswith("#"):
                                continue

                            if line.lower().startswith("description=") and self._line_has_indicator(line):
                                self.findings.append(
                                    {
                                        "type": "systemd_description",
                                        "path": str(service_file),
                                        "line": line_num,
                                        "content": line[:200],
                                    }
                                )

                            if line.lower().startswith("execstart=") and (
                                self._line_has_indicator(line)
                                or self._line_has_api_key(line)
                                or re.search(r"--model|--weights|--token", line, re.IGNORECASE)
                            ):
                                self.findings.append(
                                    {
                                        "type": "systemd_execstart",
                                        "path": str(service_file),
                                        "line": line_num,
                                        "content": line[:200],
                                    }
                                )
                except (PermissionError, FileNotFoundError):
                    continue

    def scan_shell_profiles(self) -> None:
        """Inspect shell startup files for exported API keys or LLM tooling."""

        print("[*] Scanning shell profiles for AI/LLM persistence hooks...")

        for profile in self.shell_profiles:
            try:
                if not profile.exists():
                    continue

                with profile.open("r", errors="ignore") as handle:
                    for line_num, raw_line in enumerate(handle, 1):
                        line = raw_line.strip()
                        if not line or line.startswith("#"):
                            continue

                        if self._line_has_indicator(line) or self._line_has_api_key(line):
                            self.findings.append(
                                {
                                    "type": "shell_profile",
                                    "path": str(profile),
                                    "line": line_num,
                                    "content": line[:200],
                                }
                            )
                        elif re.search(r"alias .*(ollama|python.*-m.*serve)", line, re.IGNORECASE):
                            self.findings.append(
                                {
                                    "type": "shell_alias",
                                    "path": str(profile),
                                    "line": line_num,
                                    "content": line[:200],
                                }
                            )
            except (PermissionError, FileNotFoundError):
                continue

    def scan_system(self) -> None:
        """Run all persistence checks."""

        print(f"[*] Starting persistence detection at {datetime.now()}")
        print("-" * 80)

        self.scan_cron_jobs()
        self.scan_systemd_units()
        self.scan_shell_profiles()

    def generate_report(self) -> None:
        """Print a human-readable report of persistence findings."""

        print("\n" + "=" * 80)
        print("PERSISTENCE DETECTION REPORT")
        print("=" * 80)

        if not self.findings:
            print("[+] No AI/LLM persistence mechanisms detected.")
            print("[*] Note: Some persistence locations may require elevated privileges.")
            return

        grouped: Dict[str, List[Dict[str, str]]] = {}
        for finding in self.findings:
            grouped.setdefault(finding["type"], []).append(finding)

        if grouped.get("cron_job"):
            print(f"\n[!] Found {len(grouped['cron_job'])} cron entry(ies) with AI/LLM indicators:")
            for item in grouped["cron_job"][:10]:
                print(f"    {item['path']}:{item['line']} → {item['content']}")
            if len(grouped["cron_job"]) > 10:
                print(f"    ... and {len(grouped['cron_job']) - 10} more")

        if grouped.get("cron_network_call"):
            print(f"\n[!] Found {len(grouped['cron_network_call'])} cron entry(ies) calling external AI endpoints:")
            for item in grouped["cron_network_call"][:10]:
                print(f"    {item['path']}:{item['line']} → {item['content']}")
            if len(grouped["cron_network_call"]) > 10:
                print(f"    ... and {len(grouped['cron_network_call']) - 10} more")

        if grouped.get("systemd_description"):
            print(f"\n[!] Found {len(grouped['systemd_description'])} systemd unit description(s) mentioning AI/LLM:")
            for item in grouped["systemd_description"][:10]:
                print(f"    {item['path']}:{item['line']} → {item['content']}")

        if grouped.get("systemd_execstart"):
            print(f"\n[!] Found {len(grouped['systemd_execstart'])} systemd ExecStart entries referencing AI/LLM usage:")
            for item in grouped["systemd_execstart"][:10]:
                print(f"    {item['path']}:{item['line']} → {item['content']}")
            if len(grouped["systemd_execstart"]) > 10:
                print(f"    ... and {len(grouped['systemd_execstart']) - 10} more")

        if grouped.get("shell_profile"):
            print(f"\n[!] Found {len(grouped['shell_profile'])} shell profile entry(ies) with AI/LLM hooks:")
            for item in grouped["shell_profile"][:10]:
                print(f"    {item['path']}:{item['line']} → {item['content']}")
            if len(grouped["shell_profile"]) > 10:
                print(f"    ... and {len(grouped['shell_profile']) - 10} more")

        if grouped.get("shell_alias"):
            print(f"\n[!] Found {len(grouped['shell_alias'])} shell alias(es) that launch AI tooling:")
            for item in grouped["shell_alias"][:10]:
                print(f"    {item['path']}:{item['line']} → {item['content']}")

        print("\n" + "=" * 80)

    def export_json(self, filename: str = "persistence_report.json") -> None:
        """Export findings to JSON."""

        report_data = {"timestamp": datetime.now().isoformat(), "findings": self.findings}

        with open(filename, "w") as handle:
            json.dump(report_data, handle, indent=2)

        print(f"[+] Report exported to {filename}")


def main() -> None:
    detector = PersistenceDetector()
    detector.scan_system()
    detector.generate_report()
    detector.export_json()


if __name__ == "__main__":
    main()
