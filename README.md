# Forensic Scripting 007 V2

Forensic Scripting 007 V2 is a reusable, local-first DFIR toolkit for building
reviewable macOS and iOS-adjacent evidence packets. It is designed to collect,
verify, normalize, and narrate evidence without storing private case data inside
the repository.

The project focuses on repeatable evidence workflows:

- recursive file and code inventory
- macOS app and bundle trust review
- parent image/container trust checks
- TCC and privacy-context collection
- packet-capture handoff support
- iOS backup app metadata correlation
- normalized SQLite evidence schemas
- claim matrix and narrative handoff generation for Genesis-style reporting

This repository is a toolkit, not an evidence archive. Keep raw evidence,
generated runs, `.env` files, packet captures, disk images, app bundles, and
private reports outside git.

## Project Layout

```text
.
|-- atlas_submission_capture.sh          # App comparison and reviewer packet capture
|-- recursive_macos_volume_verify.sh     # Recursive macOS/static evidence verifier
|-- run_forensic_suite.sh                # Venv-backed suite launcher
|-- sentinel_shell.py                    # Friendly terminal launcher with session progress
|-- database/                            # 007 SQLite schemas
|-- docs/                                # Product-safe documentation
|-- examples/                            # Safe example manifests
|-- scripts/                             # Reusable collectors, detectors, and helpers
|-- scripts/hydrate/                     # Hydrate/mobile intake helpers
|-- tests/                               # Fixture and smoke tests
|-- SECURITY.md                          # Security policy
`-- requirements.txt                     # Python dependencies
```

## Requirements

### macOS

Recommended:

- macOS 13 or newer
- Python 3.10+
- `pip`
- Git
- Xcode Command Line Tools

Install the basic Apple developer tools:

```bash
xcode-select --install
```

Optional but useful:

```bash
brew install python git sqlite ripgrep jq
brew install wireshark
```

Some capture lanes use system tools such as `codesign`, `spctl`, `otool`,
`sqlite3`, `log`, `lsof`, `netstat`, `tcpdump`, and optionally `tshark`.

### Linux

Linux can run the Python detectors, database setup, narrative builder, review
helpers, and some generic filesystem scans. macOS-specific trust checks will be
skipped, unavailable, or reduced because Linux does not provide Apple tools such
as `codesign`, `spctl`, `otool`, `log show`, or TCC databases.

Debian/Ubuntu setup:

```bash
sudo apt update
sudo apt install -y \
  git \
  python3 \
  python3-venv \
  python3-pip \
  sqlite3 \
  ripgrep \
  jq \
  tcpdump \
  tshark
```

Fedora setup:

```bash
sudo dnf install -y \
  git \
  python3 \
  python3-pip \
  sqlite \
  ripgrep \
  jq \
  tcpdump \
  wireshark-cli
```

Linux users should treat this repo as a portable analysis and normalization
toolkit. For full Apple bundle-signing, Gatekeeper, TCC, and unified-log review,
run the macOS lanes on macOS.

## Clone And Set Up

Clone the repository:

```bash
git clone https://github.com/Sentinel-Stratos-Strategies/Forensic-scripting-007-V2.git
cd Forensic-scripting-007-V2
```

Create a Python virtual environment:

```bash
python3 -m venv .venv
```

Activate it on macOS or Linux:

```bash
source .venv/bin/activate
```

Upgrade packaging tools:

```bash
python -m pip install --upgrade pip setuptools wheel
```

Install project dependencies:

```bash
python -m pip install -r requirements.txt
```

Confirm the environment:

```bash
python --version
python -m pip --version
```

Launch the friendly terminal UI from the activated environment:

```bash
python sentinel_shell.py
```

For a quick non-interactive smoke test:

```bash
python sentinel_shell.py --check
python sentinel_shell.py --demo --no-color
```

When finished, deactivate the environment:

```bash
deactivate
```

## Quick Validation

Run these checks after cloning or before opening a pull request:

```bash
python3 -m py_compile sentinel_shell.py scripts/*.py scripts/hydrate/*.py
python3 sentinel_shell.py --check
python3 sentinel_shell.py --demo --no-color
bash -n atlas_submission_capture.sh recursive_macos_volume_verify.sh run_forensic_suite.sh scripts/*.sh tests/*.sh
bash tests/test_recursive_macos_volume_verify.sh
bash tests/test_narrative_claim_packet.sh
```

Expected result: the commands exit successfully. The recursive verifier fixture
prints a temporary output directory and a `PASS` line.

## Basic Usage

### Launch Sentinel Shell

Sentinel Shell is a no-dependency terminal menu for operators who want a more
human entry point after cloning the repo and activating the venv.

```bash
source .venv/bin/activate
python sentinel_shell.py
```

The launcher shows the main evidence lanes, suggested next commands, and a
session progress bar for each selected lane. It does not start privileged or
long-running capture by itself; use the suggested command shown on screen when
you are ready to run a specific workflow.

Lane `02` is the Genesis narrative tie-in. It finds the newest
`/Volumes/Evidence/007_go_plan_*` run and builds the timeline, claim matrix,
evidence base, reviewer narrative, excluded-claims page, and
`GENESIS_HANDOFF.json`.

Useful launcher modes:

```bash
python sentinel_shell.py --check          # verify local launcher prerequisites
python sentinel_shell.py --tool-chest     # list reusable helper scripts
python sentinel_shell.py --once 02        # build narrative packet for the latest Evidence run
python sentinel_shell.py --once 02 --run-dir /Volumes/Evidence/007_go_plan_YYYYMMDDTHHMMSSZ
python sentinel_shell.py --once 08        # preview one lane and exit
python sentinel_shell.py --demo --no-color
```

### Run The Suite

The main launcher creates or uses a local `.venv`, installs
`requirements.txt`, runs the detector suite, and can invoke the recursive
verifier.

Example macOS run:

```bash
./run_forensic_suite.sh \
  --input /Volumes/Storage \
  --output /Volumes/Evidence \
  --case atlas_storage \
  --hash-mode all \
  --max-text-mb 16 \
  --allow-writable
```

Use an output directory that is separate from the source evidence. On large
inputs, recursive output can grow quickly.

### Recursively Verify A Folder Or App

```bash
./recursive_macos_volume_verify.sh \
  --out-base ./results \
  --case atlas_recursive \
  "/Applications/ChatGPT Atlas.app"
```

The verifier inventories files, records hashes, classifies objects, captures
static metadata, and runs macOS trust checks where available. It does not execute
suspect binaries.

### Build An App Comparison Packet

Create a manifest:

```bash
cat > manifest.csv <<'CSV'
name,suspect_app,baseline_app,process_match,pcap_glob,extra_glob
Atlas,/Applications/ChatGPT Atlas.app,/Applications/ChatGPT Atlas Fresh.app,ChatGPT Atlas,,
CSV
```

Run the capture:

```bash
./atlas_submission_capture.sh manifest.csv ./results --pcap-duration 0
```

The output is a reviewer-oriented packet with app inventory, signing data,
process context, optional packet-capture references, hashes, and supporting
artifacts.

### Check Parent Trust Versus Child Code Trust

Use this when a copied disk image, mounted volume, package, cryptex, Preboot, or
Recovery-derived tree may contain valid signed children inside an untrusted or
unverified parent container.

```bash
python3 scripts/parent_trust_boundary_check.py \
  "/path/to/copied/image_or_directory" \
  --expected-sealed \
  --out-dir ./results/parent_trust

python3 scripts/child_parent_trust_contrast.py \
  --recursive-dir ./results/atlas_recursive_YYYYMMDDTHHMMSSZ/path_group \
  --parent-report ./results/parent_trust/parent_trust_boundary.json \
  --out-dir ./results/trust_contrast
```

### Build A Genesis Narrative Handoff

For a completed or interrupted 007 run:

```bash
python3 scripts/build_narrative_claim_packet.py \
  --run-dir /Volumes/Evidence/007_go_plan_YYYYMMDDTHHMMSSZ
```

Or use Sentinel Shell from the activated venv:

```bash
python sentinel_shell.py --once 02 \
  --run-dir /Volumes/Evidence/007_go_plan_YYYYMMDDTHHMMSSZ
```

Inside the interactive TUI, choose lane `02` to build the packet from the latest
`/Volumes/Evidence/007_go_plan_*` run.

The narrative packet includes:

- `FORENSIC_NARRATIVE.md`
- `CLAIM_MATRIX.tsv`
- `EVIDENCE_BASE.tsv`
- `CHRONOLOGY.tsv`
- `RECURSIVE_COVERAGE.tsv`
- `EXCLUDED_CLAIMS.md`
- `GENESIS_HANDOFF.json`
- `HASH_MANIFEST.sha256`

These files are meant to help a reviewer distinguish observed evidence from
interpretation and open questions.

### Initialize 007 Databases

```bash
python3 scripts/init_007_databases.py \
  --out-dir ./results/databases
```

The schemas in `database/` separate core evidence, graph relationships, and
report/output tables.

## macOS Privilege Notes

Some optional lanes need elevated privileges, especially packet capture, certain
system logs, and protected database snapshots. Prefer authenticating in the same
terminal session before starting long runs:

```bash
sudo -v
```

Then run the capture command from that same terminal. Do not put passwords or
tokens on the command line.

## Linux Notes

Linux users can run:

```bash
python3 scripts/anomaly_detector.py --help
python3 scripts/signature_detector.py --help
python3 scripts/build_narrative_claim_packet.py --help
python3 scripts/init_007_databases.py --help
```

Expect macOS-specific commands to be unavailable. Linux results should be
labeled as portable/static analysis unless the evidence was collected from
macOS with the macOS tools.

## Output Safety

Recommended output pattern:

```text
/path/to/source-evidence      # read-only or staged input
/path/to/output-evidence      # generated results
```

Do not write generated results into the source evidence tree unless you are
working on a disposable copy and explicitly intend to do that.

The repository ignores common local output and evidence formats, including:

- `.env` and `.env.*`
- virtual environments
- packet captures
- SQLite databases
- disk images
- app bundles
- archives
- generated run folders
- local reports

## Security Model

This toolkit is conservative by design:

- no quarantine stripping
- no mutation of source evidence by default
- no execution of suspect app binaries
- credentials must stay in local environment variables or keychain prompts
- private evidence stays outside git
- claims must separate facts, support, inference, and exclusions

See:

- `SECURITY.md`
- `docs/security/repository-security-policy.md`
- `docs/security/credential-handling-policy.md`
- `docs/security/github-hardening-checklist.md`

## GitHub Security Setup

This repo includes:

- daily Dependabot checks for Python and GitHub Actions
- CodeQL workflow for Python
- CI workflow for syntax and fixture validation
- issue templates
- pull request template
- local hardening helper: `scripts/github_repo_harden.sh`

After the first push and first CI run, protect `main` and require CI/CodeQL
checks before merge.

## Contributing

Before opening a pull request:

1. Keep changes product-safe and reusable.
2. Do not include private evidence or secrets.
3. Run the validation commands.
4. Update docs when behavior changes.
5. Use the pull request template.

## License

See `LICENSE`.
