#!/usr/bin/env python3
"""Constrained forensic MCP server for local evidence review.

This server is intentionally narrower than a general AppleScript or shell
bridge. It provides read-oriented forensic helpers over allowlisted roots and
records each tool invocation in a JSONL audit log.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover - optional MCP integration
    FastMCP = None


HOME = Path.home()

DEFAULT_ROOTS = (
    str(HOME / "Forensic_007"),
    str(HOME / "Hydrate"),
    str(HOME / "The_Genesis_Method"),
    str(HOME / ".codex"),
    "/Volumes/Evidence",
    "/Volumes/Ellis",
    "/Volumes/Storage",
)

DEFAULT_AUDIT_LOG = (
    "/Volumes/Evidence/forensic_console_mcp/audit.jsonl"
)

TEXT_EXTENSIONS = {
    ".applescript",
    ".bash",
    ".c",
    ".cfg",
    ".conf",
    ".css",
    ".csv",
    ".env",
    ".gitignore",
    ".h",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".log",
    ".m",
    ".md",
    ".plist",
    ".py",
    ".rb",
    ".sh",
    ".swift",
    ".toml",
    ".ts",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
    ".zprofile",
    ".zshenv",
    ".zshrc",
}

SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|pat)\s*[:=]\s*['\"]?[^'\"\s,}]+"),
    re.compile(r"ghp_[A-Za-z0-9_]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]+"),
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"ya29\.[A-Za-z0-9_-]+"),
)

ALLOWED_COMMANDS: dict[str, tuple[str, ...]] = {
    "file": ("file",),
    "shasum256": ("shasum", "-a", "256"),
    "xattr": ("xattr", "-l"),
    "codesign": ("codesign", "-dv", "--verbose=4"),
    "spctl": ("spctl", "-a", "-vv"),
    "otool_l": ("otool", "-L"),
    "strings": ("strings", "-a"),
    "plutil": ("plutil", "-p"),
    "sqlite_tables": ("sqlite3",),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def configured_roots() -> list[Path]:
    raw = os.environ.get("FORENSIC_MCP_ROOTS")
    root_strings = [p for p in raw.split(os.pathsep) if p] if raw else list(DEFAULT_ROOTS)
    roots: list[Path] = []
    for root in root_strings:
        path = Path(root).expanduser()
        try:
            resolved = path.resolve(strict=False)
        except OSError:
            continue
        if resolved not in roots:
            roots.append(resolved)
    return roots


def audit_log_path() -> Path:
    return Path(os.environ.get("FORENSIC_MCP_AUDIT_LOG", DEFAULT_AUDIT_LOG)).expanduser()


ROOTS = configured_roots()
AUDIT_LOG = audit_log_path()


def audit(tool: str, params: dict[str, Any], status: str, detail: str | None = None) -> None:
    event = {
        "ts_utc": utc_now(),
        "tool": tool,
        "status": status,
        "params": params,
        "detail": detail,
    }
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


def to_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True, default=str)


def resolve_allowed(path_text: str, *, must_exist: bool = False) -> Path:
    path = Path(path_text).expanduser()
    resolved = path.resolve(strict=must_exist)
    for root in ROOTS:
        if resolved == root or root in resolved.parents:
            return resolved
    raise ValueError(f"path is outside configured forensic roots: {resolved}")


def metadata(path: Path, *, include_hash: bool = False) -> dict[str, Any]:
    stat = path.lstat()
    item: dict[str, Any] = {
        "path": str(path),
        "exists": path.exists(),
        "is_file": path.is_file(),
        "is_dir": path.is_dir(),
        "is_symlink": path.is_symlink(),
        "mode_octal": oct(stat.st_mode & 0o7777),
        "size": stat.st_size,
        "uid": stat.st_uid,
        "gid": stat.st_gid,
        "mtime_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "ctime_utc": datetime.fromtimestamp(stat.st_ctime, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    if path.is_symlink():
        item["symlink_target"] = os.readlink(path)
    if include_hash and path.is_file():
        item["sha256"] = sha256_file(path)
    return item


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def is_textish(path: Path) -> bool:
    if path.name in {".zprofile", ".zshenv", ".zshrc", ".bashrc", ".bash_profile"}:
        return True
    if path.suffix.lower() in TEXT_EXTENSIONS:
        return True
    guessed, _ = mimetypes.guess_type(path.name)
    return bool(guessed and (guessed.startswith("text/") or guessed in {"application/json", "application/xml"}))


def redact(text: str) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(lambda m: m.group(0).split("=", 1)[0].split(":", 1)[0] + "=<REDACTED>", redacted)
    return redacted


def bounded(value: int, *, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, value))


class MissingMCP:
    def tool(self):
        def decorate(func):
            return func
        return decorate

    def run(self):
        raise RuntimeError("mcp package is not installed; run with --self-test or install optional MCP dependencies")


if FastMCP is None:
    mcp = MissingMCP()
else:
    mcp = FastMCP("forensic-console")


@mcp.tool()
def list_allowed_roots() -> str:
    """Return the configured filesystem roots this server can inspect."""
    data = {"roots": [str(root) for root in ROOTS], "audit_log": str(AUDIT_LOG)}
    audit("list_allowed_roots", {}, "ok")
    return to_json(data)


@mcp.tool()
def stat_path(path: str, include_hash: bool = False) -> str:
    """Stat an allowlisted path and optionally hash regular files with SHA-256."""
    params = {"path": path, "include_hash": include_hash}
    try:
        resolved = resolve_allowed(path, must_exist=True)
        data = metadata(resolved, include_hash=include_hash)
        audit("stat_path", params, "ok")
        return to_json(data)
    except Exception as exc:
        audit("stat_path", params, "error", str(exc))
        raise


@mcp.tool()
def list_dir(path: str, max_entries: int = 200, include_hidden: bool = True) -> str:
    """List direct children of an allowlisted directory."""
    params = {"path": path, "max_entries": max_entries, "include_hidden": include_hidden}
    try:
        resolved = resolve_allowed(path, must_exist=True)
        if not resolved.is_dir():
            raise ValueError(f"not a directory: {resolved}")
        limit = bounded(max_entries, minimum=1, maximum=1000)
        entries = []
        for child in sorted(resolved.iterdir(), key=lambda item: item.name.lower()):
            if not include_hidden and child.name.startswith("."):
                continue
            entries.append(metadata(child))
            if len(entries) >= limit:
                break
        audit("list_dir", params, "ok", f"returned={len(entries)}")
        return to_json({"path": str(resolved), "entries": entries, "truncated": len(entries) >= limit})
    except Exception as exc:
        audit("list_dir", params, "error", str(exc))
        raise


@mcp.tool()
def read_text(path: str, max_bytes: int = 65536, redact_secrets: bool = True) -> str:
    """Read a text-like file from an allowlisted root with optional secret redaction."""
    params = {"path": path, "max_bytes": max_bytes, "redact_secrets": redact_secrets}
    try:
        resolved = resolve_allowed(path, must_exist=True)
        if not resolved.is_file():
            raise ValueError(f"not a regular file: {resolved}")
        if not is_textish(resolved):
            raise ValueError(f"refusing to read non-text-like file: {resolved}")
        limit = bounded(max_bytes, minimum=1, maximum=1024 * 1024)
        raw = resolved.read_bytes()[:limit]
        text = raw.decode("utf-8", errors="replace")
        if redact_secrets:
            text = redact(text)
        audit("read_text", params, "ok", f"bytes={len(raw)}")
        return to_json({"path": str(resolved), "bytes_returned": len(raw), "content": text})
    except Exception as exc:
        audit("read_text", params, "error", str(exc))
        raise


@mcp.tool()
def search_text(root: str, pattern: str, max_matches: int = 200) -> str:
    """Search text under an allowlisted root with ripgrep and exclude archive files."""
    params = {"root": root, "pattern": pattern, "max_matches": max_matches}
    try:
        resolved = resolve_allowed(root, must_exist=True)
        if not resolved.is_dir():
            raise ValueError(f"not a directory: {resolved}")
        limit = bounded(max_matches, minimum=1, maximum=1000)
        rg = shutil.which("rg")
        if not rg:
            raise RuntimeError("ripgrep (rg) is not available")
        command = [
            rg,
            "--hidden",
            "--line-number",
            "--no-heading",
            "--max-count",
            str(limit),
            "--glob",
            "!*.zip",
            "--glob",
            "!*.dmg",
            "--glob",
            "!*.iso",
            "--glob",
            "!*.pkg",
            pattern,
            str(resolved),
        ]
        proc = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        lines = proc.stdout.splitlines()[:limit]
        audit("search_text", params, "ok", f"matches={len(lines)} rc={proc.returncode}")
        return to_json({"root": str(resolved), "matches": lines, "returncode": proc.returncode, "stderr": proc.stderr[:2000]})
    except Exception as exc:
        audit("search_text", params, "error", str(exc))
        raise


@mcp.tool()
def run_allowed_command(name: str, target_path: str, extra_args: list[str] | None = None, timeout_seconds: int = 30) -> str:
    """Run a named forensic read command against one allowlisted target path."""
    params = {"name": name, "target_path": target_path, "extra_args": extra_args or [], "timeout_seconds": timeout_seconds}
    try:
        if name not in ALLOWED_COMMANDS:
            raise ValueError(f"command is not allowlisted: {name}")
        resolved = resolve_allowed(target_path, must_exist=True)
        args = list(extra_args or [])
        if any(arg.startswith("-") for arg in args):
            raise ValueError("extra_args may not contain command flags")
        if name == "sqlite_tables":
            command = [*ALLOWED_COMMANDS[name], str(resolved), ".tables"]
        else:
            command = [*ALLOWED_COMMANDS[name], *args, str(resolved)]
        proc = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=bounded(timeout_seconds, minimum=1, maximum=120),
            check=False,
        )
        audit("run_allowed_command", params, "ok", f"rc={proc.returncode}")
        return to_json(
            {
                "command": name,
                "argv": command,
                "returncode": proc.returncode,
                "stdout": redact(proc.stdout[:20000]),
                "stderr": redact(proc.stderr[:20000]),
            }
        )
    except Exception as exc:
        audit("run_allowed_command", params, "error", str(exc))
        raise


@mcp.tool()
def append_case_note(note: str) -> str:
    """Append an investigator note to the case folder audit notes file."""
    params = {"note_length": len(note)}
    try:
        notes_path = AUDIT_LOG.parent / "case_notes.md"
        notes_path.parent.mkdir(parents=True, exist_ok=True)
        with notes_path.open("a", encoding="utf-8") as handle:
            handle.write(f"\n## {utc_now()}\n\n{note.rstrip()}\n")
        audit("append_case_note", params, "ok", str(notes_path))
        return to_json({"notes_path": str(notes_path), "status": "appended"})
    except Exception as exc:
        audit("append_case_note", params, "error", str(exc))
        raise


def self_test() -> int:
    print(to_json({"roots": [str(root) for root in ROOTS], "audit_log": str(AUDIT_LOG)}))
    missing = [str(root) for root in ROOTS if not root.exists()]
    if missing:
        print(to_json({"warning": "some roots do not currently exist", "missing": missing}), file=sys.stderr)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Constrained forensic MCP server")
    parser.add_argument("--self-test", action="store_true", help="print resolved roots and exit")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    audit("server_start", {"argv": sys.argv, "pid": os.getpid(), "started_monotonic": time.monotonic()}, "ok")
    mcp.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
