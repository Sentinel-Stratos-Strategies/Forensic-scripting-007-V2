#!/usr/bin/env python3
import csv
import hashlib
import os
import plistlib
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PDF = Path("/tmp/codex-remote-attachments/019f07f5-8758-7323-9774-b0915bc4572a/D5AA268D-BEA8-44C7-90A7-A8DDF1BC38C6/1-Executive-Summary-3.pdf")
OUT = ROOT / "reports" / "one_pass_big_swing_20260627"
OVERNIGHT = Path("/Volumes/Ellis/overnight_app_capture_20260627T072505Z")
OVERNIGHT_PGREP = OVERNIGHT / "process/sample_026/pgrep_targets.txt"
OVERNIGHT_NETSTAT = OVERNIGHT / "process/sample_026/netstat_anv.txt"
OVERNIGHT_CORRELATED_LOG = OVERNIGHT / "logs/correlated_unified_log.log"


@dataclass
class Item:
    group: str
    app: str
    artifact_type: str
    path: str
    exists: str = ""
    size: str = ""
    created: str = ""
    modified: str = ""
    sha256: str = ""
    trust: str = ""
    notes: str = ""


def run(args, timeout=20):
    try:
        return subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    except Exception as exc:
        return subprocess.CompletedProcess(args, 1, "", str(exc))


def iso(ts):
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return ""


def sha256(path: Path):
    if not path.is_file():
        return ""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def stat_item(path: Path):
    if not path.exists():
        return "no", "", "", "", ""
    st = path.stat()
    created = iso(getattr(st, "st_birthtime", st.st_ctime))
    return "yes", str(st.st_size), created, iso(st.st_mtime), sha256(path)


def read_text(path: Path, limit=40000):
    try:
        return path.read_text(errors="replace")[:limit]
    except Exception:
        return ""


def matching_lines(path: Path, patterns, limit=25):
    if not path.exists():
        return []
    out = []
    compiled = [re.compile(p) for p in patterns]
    try:
        with path.open(errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if any(p.search(line) for p in compiled):
                    out.append(line)
                    if len(out) >= limit:
                        break
    except Exception:
        return out
    return out


def first_match(lines, pattern):
    rx = re.compile(pattern)
    return next((line for line in lines if rx.search(line)), "")


def line_ts(line):
    m = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+[-+]\d{4})", line)
    if m:
        return m.group(1)
    return "2026-06-27T_sample_026"


def brief(line, limit=700):
    return line[:limit] + ("..." if len(line) > limit else "")


def plist_value(app: Path, key: str):
    p = app / "Contents" / "Info.plist"
    try:
        with p.open("rb") as f:
            return str(plistlib.load(f).get(key, ""))
    except Exception:
        return ""


def codesign_summary(path: Path):
    if not path.exists():
        return ""
    p = run(["codesign", "-dv", "--verbose=4", str(path)], timeout=25)
    txt = p.stderr + p.stdout
    keep = []
    for line in txt.splitlines():
        if any(x in line for x in ["Identifier=", "TeamIdentifier=", "Authority=", "CDHash=", "not signed", "Format="]):
            keep.append(line.strip())
    return " | ".join(keep)


def spctl_summary(path: Path):
    if not path.exists():
        return ""
    p = run(["spctl", "-a", "-vvv", "--type", "execute", str(path)], timeout=25)
    return " | ".join((p.stdout + p.stderr).splitlines()[:3])


def pdf_text():
    if not PDF.exists():
        return ""
    try:
        from pypdf import PdfReader
        reader = PdfReader(str(PDF))
        return "\n".join((page.extract_text() or "") for page in reader.pages)
    except Exception as exc:
        return f"PDF extraction failed: {exc}"


def add_item(items, group, app, typ, path, notes="", trust=""):
    p = Path(path)
    exists, size, created, modified, digest = stat_item(p)
    items.append(Item(group, app, typ, str(p), exists, size, created, modified, digest, trust, notes))


def build_inventory():
    items = []
    add = lambda group, app, typ, path, notes="", trust="": add_item(items, group, app, typ, path, notes, trust)

    add("A-working-spine", "all", "raw evidence index", ROOT / "reports/atlas_backward_chain_20260627/raw_evidence_index.tsv")
    add("A-working-spine", "all", "backward matrix", ROOT / "reports/atlas_backward_chain_20260627/backward_chain_matrix.md")
    add("A-working-spine", "all", "reviewer summary", ROOT / "reports/atlas_backward_chain_20260627/reviewer_summary.md")
    add("A-working-spine", "all", "duplication template", ROOT / "reports/atlas_backward_chain_20260627/duplication_process_template.md")
    add("A-working-spine", "all", "executive summary pdf", PDF)

    add("B-clone-runtime", "Codex", "code sign clone capture", "/Volumes/Storage/Ellis_Archive/Investigations/Desktop_Investigative_Materials_20260619/code_sign_clone_capture_20260618_020903")
    add("B-clone-runtime", "Codex", "code_sign_clone_paths", "/Volumes/Storage/Ellis_Archive/Investigations/Desktop_Investigative_Materials_20260619/code_sign_clone_capture_20260618_020903/code_sign_clone_paths.txt")
    add("B-clone-runtime", "Codex", "code_sign_clone_live_refs", "/Volumes/Storage/Ellis_Archive/Investigations/Desktop_Investigative_Materials_20260619/codex_clone_triage_20260618T080722Z/code_sign_clone_live_refs.txt")
    add("B-clone-runtime", "Codex", "app_vs_code_sign_clone_diff", "/Volumes/Storage/Ellis_Archive/Investigations/Desktop_Investigative_Materials_20260619/codex_clone_triage_20260618T080722Z/app_vs_code_sign_clone_diff.txt")
    add("B-clone-runtime", "Codex", "logs_around_clone_signal", "/Volumes/Storage/Ellis_Archive/Investigations/Desktop_Investigative_Materials_20260619/codex_clone_triage_20260618T080722Z/logs_around_clone_signal.txt")
    add("B-clone-runtime", "Atlas", "atlas_ps", "/Volumes/Storage/Ellis_Archive/Investigations/6:25/tcc_playbook/atlas_ps.txt")
    add("B-clone-runtime", "Atlas", "atlas_pgrep", "/Volumes/Storage/Ellis_Archive/Investigations/6:25/tcc_playbook/atlas_pgrep.txt")
    add("B-clone-runtime", "Atlas", "atlas_bundle_ids", "/Volumes/Storage/Ellis_Archive/Investigations/6:25/tcc_playbook/atlas_bundle_ids.txt")
    add("B-clone-runtime", "Atlas", "overnight sample pgrep", OVERNIGHT_PGREP, "sample_026 durable process evidence for staged Atlas and Chrome launches")
    add("B-clone-runtime", "Atlas", "overnight sample netstat", OVERNIGHT_NETSTAT, "sample_026 durable network evidence tied to Atlas/Chrome process names")
    add("B-clone-runtime", "Atlas", "overnight correlated unified log", OVERNIGHT_CORRELATED_LOG, "tccd/syspolicyd/network log support for staged Atlas and Chrome runtime")
    add("B-clone-runtime", "all", "Application Support hits", "/Volumes/Storage/Ellis_Archive/scripts/validation_results/live_mdm_network_20260620T020252Z/appdata/osboot_application_support_keyword_hits_with_paths.txt")
    add("B-clone-runtime", "Chrome", "Google Chrome executables", "/Volumes/Storage/Ellis_Archive/Investigations/evidence_vault_gemini_workspace_etc/deep_bundle_scans/Google Chrome.app_executables.txt")

    atlas_app = Path("/Volumes/Storage/Ellis_Archive/Investigations/6:25/app_disection/RUN_20260624T231938Z_with_apps/03_app_inbox/444523816394_ChatGPT Atlas 2.app")
    chrome_app = Path("/Volumes/Storage/Ellis_Archive/Investigations/6:25/app_disection/RUN_20260624T231938Z_with_apps/03_app_inbox/bfa04b72c56a_Google Chrome.app")
    atlas_clone = Path("/Volumes/Storage/Ellis_Archive/Investigations/root_directories/folders/65/yf0kb9255g14pdx4qtlgh9k80000gn/X/com.openai.atlas.web.code_sign_clone/code_sign_clone.jaejjn/ChatGPT Atlas.app.bundle")
    comet_clone = Path("/Volumes/Storage/Ellis_Archive/Investigations/root_directories/folders/65/yf0kb9255g14pdx4qtlgh9k80000gn/X/ai.perplexity.comet.code_sign_clone/code_sign_clone.UUtmtW/Comet.app.bundle")
    for app, fam in [(atlas_app, "Atlas"), (chrome_app, "Chrome"), (atlas_clone, "Atlas"), (comet_clone, "Comet")]:
        trust = codesign_summary(app) + " || " + spctl_summary(app)
        notes = f"bundle_id={plist_value(app, 'CFBundleIdentifier')}; executable={plist_value(app, 'CFBundleExecutable')}; version={plist_value(app, 'CFBundleShortVersionString')}"
        add("B-clone-runtime", fam, "app bundle", app, notes, trust)

    for fam, exe in [
        ("Atlas", atlas_app / "Contents/MacOS/ChatGPT Atlas"),
        ("Chrome", chrome_app / "Contents/MacOS/Google Chrome"),
        ("Atlas", atlas_clone / "Contents/MacOS/ChatGPT Atlas"),
        ("Comet", comet_clone / "Contents/MacOS/Comet"),
    ]:
        add("B-clone-runtime", fam, "executable", exe)

    for fam, path in [
        ("Atlas", "/Volumes/Storage/Ellis_Archive/Investigations/root_directories/folders/65/yf0kb9255g14pdx4qtlgh9k80000gn/C/com.openai.atlas"),
        ("Atlas", "/Volumes/Storage/Ellis_Archive/Investigations/root_directories/folders/65/yf0kb9255g14pdx4qtlgh9k80000gn/C/com.openai.atlas.web"),
        ("Atlas", "/Volumes/Storage/Ellis_Archive/Investigations/root_directories/folders/65/yf0kb9255g14pdx4qtlgh9k80000gn/T/com.openai.atlas.web.6uuBre"),
        ("Atlas", "/Volumes/Storage/Ellis_Archive/Investigations/root_directories/folders/65/yf0kb9255g14pdx4qtlgh9k80000gn/X/com.openai.atlas.web.code_sign_clone"),
        ("Chrome", "/Volumes/Storage/Ellis_Archive/Investigations/root_directories/folders/65/yf0kb9255g14pdx4qtlgh9k80000gn/C/com.google.Chrome"),
        ("Codex", "/Volumes/Storage/Ellis_Archive/Investigations/root_directories/folders/65/yf0kb9255g14pdx4qtlgh9k80000gn/C/com.openai.codex"),
        ("Comet", "/Volumes/Storage/Ellis_Archive/Investigations/root_directories/folders/65/yf0kb9255g14pdx4qtlgh9k80000gn/X/ai.perplexity.comet.code_sign_clone"),
    ]:
        add("B-clone-runtime", fam, "C/T/X lane", path)

    for path in [
        "/Volumes/Storage/Ellis_Archive/scripts/validation_results/USB_verify_v2_20260620T020051Z/container_only_c7534faa40127127/container_details/cd20cf375f705de2_recover_snap.dmg.txt",
        "/Volumes/Storage/Ellis_Archive/scripts/validation_results/USB_verify_v2_20260620T020051Z/container_only_c7534faa40127127/container_details/cd20cf375f705de2_recover_snap.dmg_contents/container_details/d1d89bf826de11e3_arm64eBaseSystem.dmg.txt",
        "/Volumes/Storage/Ellis_Archive/scripts/results/OS_BOOT_verify_20260620T005707Z/01_recover_snap.dmg_stat.txt",
        "/Volumes/Storage/Ellis_Archive/scripts/results/OS_BOOT_verify_20260620T005707Z/01_recover_snap.dmg_ls.txt",
        "/Volumes/Storage/Ellis_Archive/scripts/results/OS_BOOT_verify_20260620T005707Z/01_recover_snap.dmg_xattr.txt",
        "/Volumes/Storage/Ellis_Archive/scripts/results/OS_BOOT_verify_20260620T005707Z/01_recover_snap.dmg_file.txt",
        "/Volumes/Storage/Ellis_Archive/.codex/worktrees/a8d6/Hydrate_Tools/recovery_snapshot_review_20260616/dmg_sha256.txt",
        "/Volumes/Storage/Ellis_Archive/.codex/worktrees/a8d6/Hydrate_Tools/recovery_snapshot_review_20260616/dmg_stat.txt",
    ]:
        add("C-image-door", "system", "DMG/image evidence", path)

    for path in [
        "/Volumes/Storage/Ellis_Archive/Investigations/6:25/tcc_playbook/04_SSH_BACKDOOR_REPORT.md",
        "/Volumes/Storage/Ellis_Archive/Investigations/Desktop_Investigative_Materials_20260619/authorized_keys_before_clear.txt",
        "/Volumes/Storage/Ellis_Archive/Investigations/Desktop_Investigative_Materials_20260619/ssh_key_backup_20260618_024838/ssh_copy/authorized_keys",
        "/Volumes/Storage/Ellis_Archive/.codex/worktrees/a8d6/Hydrate_Tools/skill_ingest_20260616/extracted/9-com.apple.mdm.xml.txt",
        "/Volumes/Storage/Ellis_Archive/Investigations/6:17/mdm_discovery_capture_20260617_112157/codex_mcp_local_hunt_20260617/parsed/shell/z_files_interest_hits.txt",
        "/Volumes/Storage/Ellis_Archive/Investigations/evidence_vault_gemini_workspace_etc/03_Container_Terminal_Evasion/zsh_history_backup.txt",
        "/Volumes/Storage/Ellis_Archive/Investigations/Desktop_Investigative_Materials_20260619/ownership_window_capture_20260618_021423/ownership_baseline.txt",
    ]:
        add("D-ssh-mdm-key", "system", "management/key evidence", path)

    return items


def process_snapshot_rows():
    p = run(["ps", "-axo", "pid,ppid,user,stat,lstart,command"], timeout=20)
    rows = []
    for line in p.stdout.splitlines():
        if re.search(r"ChatGPT Atlas|Google Chrome|Codex|Comet", line, re.I):
            rows.append(line)
    return rows


def timeline_rows(items):
    rows = []
    for it in items:
        if it.created:
            rows.append([it.created, it.group, it.app, "artifact_created_or_birth", it.path, "filesystem stat", "", it.sha256, it.trust, it.notes, "no"])
        if it.modified and it.modified != it.created:
            rows.append([it.modified, it.group, it.app, "artifact_modified", it.path, "filesystem stat", "", it.sha256, it.trust, it.notes, "no"])

    for line in process_snapshot_rows():
        app = "Atlas" if "ChatGPT Atlas" in line else "Codex" if "Codex" in line else "Chrome" if "Google Chrome" in line else "Comet"
        path = line[line.find("/"):].strip() if "/" in line else line
        rows.append(["2026-06-27T_observed_current_process", "B-clone-runtime", app, "launch/process_observed", path, "ps current", line[:80], "", "", "current process snapshot; may postdate examiner interaction", "partial"])

    for line in matching_lines(
        OVERNIGHT_PGREP,
        [
            r"^(70835|71244|71246|71248|71252|71253|71255|71283|71284) ",
            r"^(68338|68356|68360|68361|68362|68364|68365) ",
        ],
        limit=24,
    ):
        app = "Atlas" if "ChatGPT Atlas" in line else "Chrome" if "Google Chrome" in line else "all"
        event = "launch/process_observed"
        if "network.mojom.NetworkService" in line:
            event = "network_service_process"
        elif "Crashpad" in line or "crashpad" in line:
            event = "crashpad_process"
        elif "Application Support" in line:
            event = "application_support_bridge"
        path = line[line.find("/"):].strip() if "/" in line else line
        rows.append(["2026-06-27T_sample_026", "B-clone-runtime", app, event, path, str(OVERNIGHT_PGREP), line.split()[0], "", "", brief(line), "no"])

    for line in matching_lines(
        OVERNIGHT_NETSTAT,
        [r"ChatGPT Atlas", r"Google Chrome"],
        limit=18,
    ):
        app = "Atlas" if "ChatGPT Atlas" in line else "Chrome" if "Google Chrome" in line else "all"
        rows.append(["2026-06-27T_sample_026", "B-clone-runtime", app, "network_observation", "", str(OVERNIGHT_NETSTAT), "", "", "", brief(line), "no"])

    log_patterns = [
        r"AUTHREQ_ATTRIBUTION.*com\.openai\.atlas",
        r"AUTHREQ_ATTRIBUTION.*AtlasUpdateHelper",
        r"static code for: identifier com\.openai\.atlas",
        r"WindowServer.*com\.openai\.atlas",
        r"kTCCService(AddressBook|Calendar).*AtlasUpdateHelper",
        r"com\.google\.Chrome.*68338",
        r"Applications-Staged-From-Sentinel_OS/Google Chrome\.app",
    ]
    for line in matching_lines(OVERNIGHT_CORRELATED_LOG, log_patterns, limit=24):
        app = "Atlas" if "atlas" in line.lower() or "AtlasUpdateHelper" in line else "Chrome" if "Chrome" in line else "all"
        event = "tccd_log"
        if "WindowServer" in line:
            event = "TCC_windowserver_check"
        elif "Google Chrome" in line or "com.google.Chrome" in line:
            event = "chrome_runtime_log"
        rows.append([line_ts(line), "B-clone-runtime", app, event, "", str(OVERNIGHT_CORRELATED_LOG), "", "", "", brief(line), "no"])

    log = Path("/Volumes/Storage/Ellis_Archive/Investigations/Desktop_Investigative_Materials_20260619/codex_clone_triage_20260618T080722Z/logs_around_clone_signal.txt")
    for line in read_text(log, 200000).splitlines():
        if "com.openai.codex" in line and re.match(r"\d+:\d{4}-\d{2}-\d{2}", line):
            m = re.match(r"\d+:(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+[-+]\d{4})", line)
            ts = m.group(1) if m else ""
            rows.append([ts, "B-clone-runtime", "Codex", "tccd/log/process", "", str(log), "", "", "", line[:500], "partial"])

    tcc_files = [
        Path("/Volumes/Ellis/overnight_app_capture_20260627T072505Z/tcc/final/_Users_fresh_Library_Application_Support_com.apple.TCC_TCC.db.target_rows.csv"),
        Path("/Volumes/Ellis/live_rescue_os_tcc_network_scan_20260627T181118Z/tcc/_Volumes_Storage_Ellis_Archive_Investigations_6_25_Library_Application_Support_com.apple.TCC_TCC.db.target_rows.csv"),
    ]
    for f in tcc_files:
        for line in read_text(f, 100000).splitlines():
            if any(x in line for x in ["com.openai.codex", "com.openai.atlas", "com.google.Chrome", "ai.perplexity.comet"]):
                app = "Codex" if "codex" in line else "Atlas" if "atlas" in line else "Chrome" if "Chrome" in line else "Comet"
                rows.append(["", "B-clone-runtime", app, "TCC_row", "", str(f), "", "", "", line, "no"])

    rows.sort(key=lambda r: r[0] or "9999")
    return rows


def write_csv(path, header, rows):
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def sectioned(title, proven, supported, unknown):
    def bullets(xs):
        return "\n".join(f"- {x}" for x in xs) if xs else "- None isolated in this pass."
    return f"# {title}\n\n## Proven\n\n{bullets(proven)}\n\n## Strongly supported\n\n{bullets(supported)}\n\n## Still unknown\n\n{bullets(unknown)}\n"


def write_packets(items, pdf_excerpt):
    durable_proc = read_text(OVERNIGHT_PGREP, 250000).splitlines()
    atlas_proc = [r for r in durable_proc if "ChatGPT Atlas" in r] or [r for r in process_snapshot_rows() if "ChatGPT Atlas" in r]
    atlas_outer = next((r for r in atlas_proc if "444523816394_ChatGPT Atlas 2.app/Contents/MacOS/ChatGPT Atlas" in r and "Contents/Support" not in r), "")
    atlas_runtime = next((r for r in atlas_proc if "Contents/Support/ChatGPT Atlas.app/Contents/MacOS/ChatGPT Atlas" in r), "")
    atlas_network = next((r for r in atlas_proc if "network.mojom.NetworkService" in r), "")
    atlas_video = next((r for r in atlas_proc if "video_capture.mojom.VideoCaptureService" in r), "")
    atlas_audio = next((r for r in atlas_proc if "audio.mojom.AudioService" in r), "")
    atlas_tccd = matching_lines(
        OVERNIGHT_CORRELATED_LOG,
        [
            r"AUTHREQ_ATTRIBUTION.*com\.openai\.atlas",
            r"WindowServer.*com\.openai\.atlas",
            r"AUTHREQ_ATTRIBUTION.*AtlasUpdateHelper",
            r"kTCCService(AddressBook|Calendar).*AtlasUpdateHelper",
        ],
        limit=8,
    )
    atlas_netstat = matching_lines(OVERNIGHT_NETSTAT, [r"ChatGPT Atlas"], limit=6)
    chrome_proc = [r for r in durable_proc if "Google Chrome" in r]
    chrome_outer = first_match(chrome_proc, r"^68338 .*Applications-Staged-From-Sentinel_OS/Google Chrome\.app")
    chrome_network = first_match(chrome_proc, r"network\.mojom\.NetworkService")
    chrome_log = matching_lines(
        OVERNIGHT_CORRELATED_LOG,
        [r"pid=68338 proc=Google Chrome bundleID=com\.google\.Chrome", r"Applications-Staged-From-Sentinel_OS/Google Chrome\.app"],
        limit=6,
    )
    def proc_brief(line):
        parts = line.split(None, 5)
        if len(parts) < 6:
            return line
        return f"pid={parts[0]} ppid={parts[1]} user={parts[2]} start='{parts[4] if len(parts) > 4 else ''}' command={parts[5][:500]}"

    atlas_proven = [
        "`444523816394_ChatGPT Atlas 2.app` is a hash-prefixed staged/renamed bundle whose internal `CFBundleIdentifier` is `com.openai.atlas`.",
        f"Overnight sample `process/sample_026/pgrep_targets.txt` shows the staged Atlas outer executable launched from `/Volumes/Storage/.../03_app_inbox/444523816394_ChatGPT Atlas 2.app/Contents/MacOS/ChatGPT Atlas`: `{brief(atlas_outer)}`.",
        f"Nested runtime evidence under `Contents/Support/ChatGPT Atlas.app`: `{brief(atlas_runtime)}`.",
        "The Atlas runtime command bridges into `/Users/fresh/Library/Application Support/com.openai.atlas/browser-data/host`.",
        f"Atlas network-service process includes `network.mojom.NetworkService`, `chatgpt.com,openai.com`, and `ChatGPTBrowser`: `{brief(atlas_network)}`.",
        f"Atlas audio/video helper roles were observed: audio=`{brief(atlas_audio, 260)}` video=`{brief(atlas_video, 260)}`.",
        f"`tccd`/WindowServer support for `com.openai.atlas` and the staged path appears in `logs/correlated_unified_log.log`: `{brief(' | '.join(atlas_tccd), 900)}`.",
        f"Network support tied to `ChatGPT Atlas` appears in `process/sample_026/netstat_anv.txt`: `{brief(' | '.join(atlas_netstat), 900)}`.",
    ]
    atlas_supported = [
        "Preserved C/T/X artifacts support the same Atlas family: `C/com.openai.atlas`, `C/com.openai.atlas.web`, `T/com.openai.atlas.web.6uuBre`, and `X/com.openai.atlas.web.code_sign_clone`.",
        "Atlas helper roles include Chromium-normal renderer/GPU/network/storage behavior; audio/video helpers are observable if present in the live process table.",
        "The staged-path launch plus Application Support bridge makes Atlas the best next live-capture target.",
    ]
    atlas_unknown = [
        "Writer process for the staged Atlas app is not closed.",
        "Mover/rename process for the hash-prefixed folder is not closed.",
        "Atlas-specific raw TCC/tccd rows are isolated as support, but the granting/denial meaning still needs per-service review.",
        "Mount/upstream image route for the staged path is not closed.",
    ]
    (OUT / "ATLAS_PACKET.md").write_text(sectioned("ATLAS_PACKET", atlas_proven, atlas_supported, atlas_unknown))

    chrome_proven = [
        "`bfa04b72c56a_Google Chrome.app` is a hash-prefixed staged/renamed bundle whose internal `CFBundleIdentifier` is `com.google.Chrome`.",
        "Local codesign/spctl checks for the staged Chrome bundle report a notarized Google Developer ID app.",
        "Google Drive/local exhibit names preserve screenshot-era Chrome `X/com.google.Chrome.code_sign_clone/code_sign_clone.bWSM6F/Google Chrome.app.bundle` evidence.",
        "`C/com.google.Chrome` is present in the preserved `/private/var/folders/65/...` family.",
        f"Overnight sample `process/sample_026/pgrep_targets.txt` proves live launch from `/Volumes/Storage/Applications-Staged-From-Sentinel_OS/Google Chrome.app`: `{brief(chrome_outer)}`.",
        f"Chrome network helper process is present in the same sample: `{brief(chrome_network)}`.",
    ]
    chrome_supported = [
        "Chrome parallels Atlas on renamed outer folder plus preserved internal identity plus clone-family evidence.",
        f"Correlated log support exists for PID 68338 / `com.google.Chrome`: `{brief(' | '.join(chrome_log), 700)}`.",
    ]
    chrome_unknown = [
        "The hash-prefixed `bfa04b72c56a_Google Chrome.app` preserved bundle is not proven to be the same live-launched Chrome instance.",
        "Chrome TCC/tccd meaning is not fully isolated in this pass.",
        "Writer/mover process remains unknown.",
    ]
    (OUT / "CHROME_PACKET.md").write_text(sectioned("CHROME_PACKET", chrome_proven, chrome_supported, chrome_unknown))

    codex_proven = [
        "June 18 Codex `code_sign_clone` evidence exists under `/private/var/folders/65/.../X/com.openai.codex.code_sign_clone/code_sign_clone.mBmRzs/Codex.app.bundle`.",
        "Codex clone signing and Gatekeeper evidence identify `com.openai.codex` and OpenAI Team ID `2DC432GLL2` in preserved/Drive-backed outputs.",
        "TCC rows for `com.openai.codex` exist in captured TCC target rows.",
        "June 18 logs include `tccd`/syspolicyd/runningboardd support around `com.openai.codex` launch/signing activity.",
        "Current Codex runtime path is `/Applications/Codex.app`, not a Storage hash-prefixed staged path.",
    ]
    codex_supported = [
        "Codex is a strong clone-family/TCC support lane.",
        "In this slice, Codex is not yet a true parallel to the Atlas staged Storage launch lane.",
    ]
    codex_unknown = [
        "Whether Codex was copied/renamed into a staged Storage app lane is not proven here.",
        "Creator process for the June 18 `code_sign_clone` artifact remains unknown.",
    ]
    (OUT / "CODEX_PACKET.md").write_text(sectioned("CODEX_PACKET", codex_proven, codex_supported, codex_unknown))

    system_proven = [
        "DMG/image evidence files exist for `recover_snap.dmg` and `arm64eBaseSystem.dmg` in OS_BOOT/USB verification outputs.",
        "SSH/key-adjacent artifacts exist: `authorized_keys_before_clear`, `ssh_key_backup_20260618_024838`, `ssh_copy`, and `agent` paths.",
        "MDM/profile-adjacent artifacts exist, including `9-com.apple.mdm.xml` and MDM client preference paths.",
        "Ownership baseline evidence exists under the June 18 desktop investigative material set.",
    ]
    system_supported = [
        "Image/key/profile artifacts deserve timeline alignment with June 17-18 C/T/X and Codex clone events.",
        "The image-door lane is a route hypothesis, not a compromise finding by itself.",
    ]
    system_unknown = [
        "No process is yet proven to have mounted or exposed the upstream image/path that led to the staged app lane.",
        "No process is yet proven to have copied, renamed, or staged the Atlas bundle.",
        "No single surviving path currently closes image-door -> clone/staging -> live launch.",
    ]
    (OUT / "SYSTEM_ROUTE_DRAFT.md").write_text(sectioned("SYSTEM_ROUTE_DRAFT", system_proven, system_supported, system_unknown))

    controls = """# NORMAL_BEHAVIOR_CONTROLS

## Proven

- Chromium-family apps normally spawn helper processes for renderer, GPU, storage, network, crashpad, audio, and video roles.
- Chromium-family apps normally write profile/runtime data below Application Support paths.
- Signed app bundles can validate with `codesign` and `spctl` even when their outer folder name has been changed.
- macOS `/private/var/folders/<bucket>/<token>/{C,T,X}` lanes can contain app cache, temp, and code-signing related working material.
- Current examiner commands opened evidence paths; these accesses must be treated as examiner activity unless independently predating the examination.

## Strongly supported

- Helper-tree and Application Support behavior alone are not suspicious; the meaningful question is whether the staged/renamed path, C/T/X clone artifacts, and launch bridge share a writer/mover/mount chain.
- The preserved `code_sign_clone` artifacts may reflect expected signing/update/verification behavior unless the creator process or abnormal placement is proven.
- A hash-prefixed app folder can be produced by an evidence extraction or app-dissection workflow; folder rename alone is not enough for root-cause claims.

## Still unknown

- Which process created the next Atlas/Chrome/Codex `code_sign_clone` artifact.
- Which process moved or renamed the staged Atlas folder.
- Which mount/image route, if any, exposed the upstream source for the staged app path.
- Whether image-door artifacts survive control analysis as causal rather than coincidental.
"""
    (OUT / "NORMAL_BEHAVIOR_CONTROLS.md").write_text(controls)

    live = """# LIVE_CAPTURE_PLAN

## Proven

- Atlas is the strongest live target because it is currently proven from staged path -> nested runtime -> Application Support bridge -> network-service process.

## Strongly supported

- A targeted capture is better than another broad scan because the missing questions are writer, mover, mount, launcher, and runtime bridge.

## Still unknown

- The writer, mover/rename, and upstream mount/image route are not closed.

## Scope

Watch only:

- `/private/var/folders/*/*/X/*code_sign_clone*`
- `/private/var/folders/*/*/C/com.openai*`
- `/private/var/folders/*/*/C/com.google*`
- `/private/var/folders/*/*/T/com.openai*`
- `/private/var/folders/*/*/T/com.google*`
- `/Volumes/Storage/Ellis_Archive/Investigations/*/app_disection`
- `/Volumes/Storage/Applications-Staged-From-Sentinel_OS`
- `/Users/fresh/Library/Application Support/com.openai.atlas`
- `/Users/fresh/Library/Application Support/Google/Chrome`
- user/system TCC DB snapshots and recent `tccd` log stream
- process tree and network activity for Atlas PID family

## Capture Questions

- What mounted it?
- What wrote it?
- What renamed it?
- What launched it?
- What runtime bridge followed?
"""
    (OUT / "LIVE_CAPTURE_PLAN.md").write_text(live)

    excluded = """# EXCLUDED_CLAIMS

## Proven

- This packet intentionally excludes root-cause and actor claims that are not closed by writer/mover/mount evidence.

## Strongly supported

- The evidence is worth triage as separate vendor-scoped lanes even without platform attribution closure.

## Still unknown

- Apple attribution is not claimed.
- MDM attribution is not claimed.
- Recovery/Preboot root cause is not claimed.
- Zero-click or remote code execution is not claimed.
- Supply-chain compromise is not claimed.
- Malicious vendor behavior is not claimed.
- Image-door compromise is not claimed from DMG existence alone.
- Examiner-caused file opens are not treated as original activity.
"""
    (OUT / "EXCLUDED_CLAIMS.md").write_text(excluded)

    template = f"""# DUPLICATION_PROCESS_TEMPLATE

Use this template to reproduce the packet from a new endpoint or a fresh capture without replaying this whole thread.

## Inputs

- Screenshot/path fingerprint
- Preserved filesystem evidence
- Process snapshot
- TCC/tccd extracts
- Network/process capture
- Image/mount artifacts
- Normal-behavior controls

## Output Files

Create these first:

1. `MASTER_INVENTORY.csv`
2. `MERGED_TIMELINE.csv`
3. `NORMAL_BEHAVIOR_CONTROLS.md`
4. vendor/app packets
5. `SYSTEM_ROUTE_DRAFT.md`
6. `LIVE_CAPTURE_PLAN.md`
7. `HASH_MANIFEST.sha256`
8. `EXCLUDED_CLAIMS.md`

## Method

1. Start from the last provable runtime event.
2. Work backward to staged path, clone family, C/T/X lanes, image/mount/key/profile lanes.
3. Separate every row into `Proven`, `Strongly supported`, or `Still unknown`.
4. Mark examiner-created reads as examiner activity.
5. Do not merge app/vendor lanes until writer/mover/mount evidence closes.

## Reviewer Test

A skeptical reviewer must be able to answer:

- What is proven?
- What is only strongly supported?
- What is still missing?
- Which vendor owns which packet?
- Why does this deserve triage if platform attribution remains unknown?

## Source PDF Excerpt

{pdf_excerpt[:4000]}
"""
    (OUT / "DUPLICATION_PROCESS_TEMPLATE.md").write_text(template)


def write_hash_manifest():
    rows = []
    for p in sorted(OUT.iterdir()):
        if p.is_file() and p.name != "HASH_MANIFEST.sha256":
            rows.append(f"{sha256(p)}  {p.name}")
    (OUT / "HASH_MANIFEST.sha256").write_text("\n".join(rows) + "\n")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    pdf_excerpt = pdf_text()
    items = build_inventory()
    write_csv(
        OUT / "MASTER_INVENTORY.csv",
        ["artifact_group", "app_family", "artifact_type", "path", "exists", "size", "created", "modified", "sha256", "trust_state_if_known", "notes"],
        [[i.group, i.app, i.artifact_type, i.path, i.exists, i.size, i.created, i.modified, i.sha256, i.trust, i.notes] for i in items],
    )
    write_csv(
        OUT / "MERGED_TIMELINE.csv",
        ["timestamp", "artifact_group", "app_family", "event_type", "path", "source", "process_if_known", "hash_if_known", "trust_state_if_known", "notes", "examiner_noise_flag"],
        timeline_rows(items),
    )
    write_packets(items, pdf_excerpt)
    write_hash_manifest()
    print(OUT)


if __name__ == "__main__":
    main()
