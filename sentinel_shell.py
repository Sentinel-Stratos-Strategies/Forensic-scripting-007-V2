#!/usr/bin/env python3
"""
Sentinel Shell.

Friendly no-dependency terminal launcher for Forensic Scripting 007 V2.
The menu is intentionally conservative: it explains and stages workflows, but it
does not start privileged or evidence-heavy capture without an explicit command.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CORAL = "\033[38;2;245;116;66m"
GRAPE = "\033[38;2;117;30;153m"
BLUE = "\033[38;2;31;194;214m"
WHITE = "\033[38;2;243;241;244m"
MUTED = "\033[38;2;190;176;190m"

PROJECT_ROOT = Path(__file__).resolve().parent


@dataclass(frozen=True)
class MenuItem:
    key: str
    label: str
    command_hint: str
    suggested_command: str
    phases: tuple[str, ...]


MENU: tuple[MenuItem, ...] = (
    MenuItem(
        "01",
        "Evidence Collection",
        "capture evidence sources",
        "./run_forensic_suite.sh --input /Volumes/Storage --output /Volumes/Evidence --case case_name --allow-writable",
        ("preflight", "database setup", "collector routing", "ready for capture"),
    ),
    MenuItem(
        "02",
        "Timeline + Narrative Packet",
        "build chronology, claims, handoff",
        "python sentinel_shell.py --once 02 --run-dir /Volumes/Evidence/007_go_plan_YYYYMMDDTHHMMSSZ",
        ("locate run", "read chronology inputs", "build claim rows", "write narrative handoff"),
    ),
    MenuItem(
        "03",
        "Artifact Analysis",
        "inspect files, metadata, logs",
        "python scripts/storage_metadata_package.py --source /path/to/source --out-dir ./results/metadata",
        ("source check", "metadata pass", "hash manifest", "artifact summary"),
    ),
    MenuItem(
        "04",
        "Memory Carving",
        "reserved lane for memory fragments",
        "docs/history.md",
        ("scope warning", "tool check", "operator handoff", "reserved"),
    ),
    MenuItem(
        "05",
        "Persistence Hunt",
        "scan launch agents, services, profiles",
        "python scripts/persistence_detector.py --help",
        ("launch surfaces", "profile hints", "service hints", "report path"),
    ),
    MenuItem(
        "06",
        "Apple / iCloud Forensics",
        "inspect macOS and iCloud artifacts",
        "python scripts/hydrate/icloud_local_inventory.py --help",
        ("apple tool check", "local inventory", "mobile bridge", "handoff"),
    ),
    MenuItem(
        "07",
        "Network Trace",
        "review DNS, routes, connections",
        "./scripts/check_007_go_plan_status.sh /Volumes/Evidence '007_go_plan_*'",
        ("interface check", "pcap pointer", "process context", "status summary"),
    ),
    MenuItem(
        "08",
        "Report Builder",
        "generate investigator-ready output",
        "python scripts/build_one_pass_exhibits_packet.py --help",
        ("evidence index", "claim matrix", "exhibit order", "reviewer packet"),
    ),
    MenuItem(
        "09",
        "Tool Chest",
        "list scripts and utilities",
        "python sentinel_shell.py --tool-chest",
        ("scan scripts", "group tools", "print commands", "ready"),
    ),
    MenuItem(
        "00",
        "Exit",
        "close Sentinel Shell",
        "",
        ("close",),
    ),
)


ASCII_LOGO = r"""
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
"""


class Theme:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def paint(self, value: str, color: str = WHITE, *styles: str) -> str:
        if not self.enabled:
            return value
        return "".join(styles) + color + value + RESET


def terminal_width() -> int:
    return max(72, min(96, shutil.get_terminal_size((80, 24)).columns))


def clear(enabled: bool) -> None:
    if enabled:
        os.system("cls" if os.name == "nt" else "clear")


def print_box_line(text: str = "", width: int = 78, color: str = CORAL, theme: Theme | None = None) -> None:
    theme = theme or Theme(False)
    safe = text[: width - 4]
    padding = " " * max(0, width - 4 - len(safe))
    print(f"{theme.paint('║', color)} {safe}{padding} {theme.paint('║', color)}")


def render_header(theme: Theme, title: str = "S E N T I N E L   S H E L L") -> None:
    width = terminal_width()
    print(theme.paint("╔" + "═" * (width - 2) + "╗", CORAL))
    print_box_line("", width, CORAL, theme)
    for line in ASCII_LOGO.strip("\n").splitlines():
        print_box_line(line.center(width - 4), width, CORAL, theme)
    print_box_line("", width, CORAL, theme)
    print_box_line(title.center(width - 4), width, CORAL, theme)
    print_box_line("Digital Forensics Toolkit".center(width - 4), width, CORAL, theme)
    print_box_line("", width, CORAL, theme)
    print(theme.paint("╠" + "═" * (width - 2) + "╣", CORAL))


def render_menu(theme: Theme) -> None:
    clear(theme.enabled and sys.stdout.isatty())
    width = terminal_width()
    render_header(theme)
    print_box_line("", width, CORAL, theme)
    print_box_line("CASE STATUS : OPEN", width, CORAL, theme)
    print_box_line("QUESTION    : What truth are we hunting today?", width, CORAL, theme)
    print_box_line("", width, CORAL, theme)
    for item in MENU:
        key = f"[{item.key}]"
        line = f"{key} {item.label:<28} :: {item.command_hint}"
        color = BLUE if item.key == "00" else GRAPE
        print_box_line(line, width, color, theme)
    print_box_line("", width, CORAL, theme)
    print(theme.paint("╚" + "═" * (width - 2) + "╝", CORAL))
    print()
    print(theme.paint("sentinel://case/open >", BLUE), end=" ")


def session_bar(theme: Theme, label: str, percent: int, started: float) -> None:
    width = 32
    filled = int(width * percent / 100)
    bar = "#" * filled + "-" * (width - filled)
    elapsed = time.monotonic() - started
    line = f"[{bar}] {percent:3d}% | {label:<24} | {elapsed:05.1f}s"
    print(theme.paint(line, BLUE if percent < 100 else CORAL))


def run_session(item: MenuItem, theme: Theme, fast: bool = False) -> None:
    print()
    print(theme.paint(f"Selected: {item.label}", CORAL, BOLD))
    print(theme.paint(f"Lane: {item.command_hint}", MUTED))
    print()
    started = time.monotonic()
    total = max(1, len(item.phases))
    for index, phase in enumerate(item.phases, 1):
        session_bar(theme, phase, int((index - 1) * 100 / total), started)
        time.sleep(0.05 if fast else 0.35)
    session_bar(theme, "ready", 100, started)
    print()
    if item.suggested_command:
        print(theme.paint("Suggested next command:", MUTED))
        print(f"  {item.suggested_command}")
    else:
        print(theme.paint("Case console closed.", MUTED))


def tool_chest(theme: Theme) -> None:
    print(theme.paint("Tool Chest", CORAL, BOLD))
    print(theme.paint("Reusable scripts available in this checkout:", MUTED))
    for path in sorted((PROJECT_ROOT / "scripts").glob("*.py")):
        print(f"  python {path.relative_to(PROJECT_ROOT)} --help")
    for path in sorted((PROJECT_ROOT / "scripts").glob("*.sh")):
        print(f"  bash {path.relative_to(PROJECT_ROOT)}")


def latest_007_run(base: Path = Path("/Volumes/Evidence")) -> Path | None:
    if not base.exists():
        return None
    candidates = [path for path in base.glob("007_go_plan_*") if path.is_dir()]
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime)


def build_narrative_packet(theme: Theme, run_dir: str | None = None, out_dir: str | None = None) -> int:
    script = PROJECT_ROOT / "scripts" / "build_narrative_claim_packet.py"
    if not script.exists():
        print(theme.paint("Narrative builder is missing from scripts/.", CORAL))
        return 1

    resolved_run = Path(run_dir).expanduser() if run_dir else latest_007_run()
    if resolved_run is None:
        print(theme.paint("No /Volumes/Evidence/007_go_plan_* run was found.", CORAL))
        print("  Plug in the Evidence volume or pass --run-dir /path/to/run.")
        return 1
    if not resolved_run.exists():
        print(theme.paint(f"Run directory does not exist: {resolved_run}", CORAL))
        return 1

    command = [sys.executable, str(script), "--run-dir", str(resolved_run)]
    if out_dir:
        command.extend(["--out-dir", str(Path(out_dir).expanduser())])

    print()
    print(theme.paint("Building Genesis narrative handoff from:", MUTED))
    print(f"  {resolved_run}")
    print()
    result = subprocess.run(command, cwd=PROJECT_ROOT, check=False)
    if result.returncode != 0:
        print(theme.paint("Narrative packet build failed.", CORAL))
        return result.returncode
    print()
    print(theme.paint("Narrative packet build completed.", CORAL, BOLD))
    return 0


def normalize_choice(choice: str) -> str:
    value = choice.strip()
    if value.isdigit():
        return value.zfill(2)
    return value


def find_item(choice: str) -> MenuItem | None:
    normalized = normalize_choice(choice)
    return next((item for item in MENU if item.key == normalized), None)


def run_once(
    choice: str,
    theme: Theme,
    fast: bool = False,
    run_dir: str | None = None,
    narrative_out_dir: str | None = None,
) -> int:
    item = find_item(choice)
    if item is None:
        print(theme.paint("Unknown selection. Evidence does not support that option.", CORAL))
        return 2
    if item.key == "02":
        run_session(item, theme, fast=fast)
        return build_narrative_packet(theme, run_dir=run_dir, out_dir=narrative_out_dir)
    if item.key == "09":
        run_session(item, theme, fast=fast)
        print()
        tool_chest(theme)
        return 0
    run_session(item, theme, fast=fast)
    return 0


def interactive(theme: Theme) -> int:
    while True:
        render_menu(theme)
        try:
            choice = input()
        except KeyboardInterrupt:
            print()
            print(theme.paint("Interrupted. Closing Sentinel Shell.", CORAL))
            return 130
        item = find_item(choice)
        if item is None:
            print(theme.paint("Unknown selection. Evidence does not support that option.", CORAL))
            time.sleep(1.0)
            continue
        if item.key == "00":
            run_session(item, theme, fast=True)
            return 0
        run_once(item.key, theme)
        input(theme.paint("\nPress Enter to return to Sentinel Shell...", MUTED))


def check_environment() -> int:
    checks: Iterable[tuple[str, bool]] = (
        ("project root", PROJECT_ROOT.exists()),
        ("requirements.txt", (PROJECT_ROOT / "requirements.txt").exists()),
        ("recursive verifier", (PROJECT_ROOT / "recursive_macos_volume_verify.sh").exists()),
        ("suite launcher", (PROJECT_ROOT / "run_forensic_suite.sh").exists()),
        ("python executable", bool(sys.executable)),
    )
    failed = 0
    for label, ok in checks:
        print(f"{label:<22} {'OK' if ok else 'MISSING'}")
        failed += 0 if ok else 1
    result = subprocess.run(
        [sys.executable, "-m", "py_compile", str(Path(__file__).resolve())],
        cwd=PROJECT_ROOT,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"{'self compile':<22} {'OK' if result.returncode == 0 else 'MISSING'}")
    failed += 0 if result.returncode == 0 else 1
    return 1 if failed else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sentinel Shell TUI launcher")
    parser.add_argument("--once", metavar="KEY", help="run one menu lane and exit")
    parser.add_argument("--demo", action="store_true", help="run a quick non-interactive demo")
    parser.add_argument("--tool-chest", action="store_true", help="print available script helpers")
    parser.add_argument("--check", action="store_true", help="check local launcher environment")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI color output")
    parser.add_argument("--run-dir", help="007 run directory for the timeline/narrative lane")
    parser.add_argument("--narrative-out-dir", help="optional output directory for the narrative packet")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    theme = Theme(enabled=not args.no_color and sys.stdout.isatty())
    if args.check:
        return check_environment()
    if args.tool_chest:
        tool_chest(theme)
        return 0
    if args.demo:
        return run_once("01", theme, fast=True)
    if args.once:
        return run_once(args.once, theme, fast=True, run_dir=args.run_dir, narrative_out_dir=args.narrative_out_dir)
    return interactive(theme)


if __name__ == "__main__":
    raise SystemExit(main())
