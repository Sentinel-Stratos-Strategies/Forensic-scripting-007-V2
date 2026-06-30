# Repository Security Policy

## Product Boundary

This repository is the reusable 007 V2 toolkit. It is not a private case file and
not an evidence storage location.

Allowed:

- reusable scripts
- database schemas
- product-safe documentation
- tests and fixtures
- review context that does not expose secrets or private evidence

Not allowed:

- `.env` files or token values
- packet captures
- disk images
- app bundles
- mobile backups
- generated evidence runs
- private reports or case exports

## Required Local Checks

Run these before push or pull request:

```bash
python3 -m py_compile scripts/*.py scripts/hydrate/*.py
bash -n atlas_submission_capture.sh recursive_macos_volume_verify.sh run_forensic_suite.sh scripts/*.sh tests/*.sh
bash tests/test_recursive_macos_volume_verify.sh
bash tests/test_narrative_claim_packet.sh
```

## GitHub Controls

Target controls after the first clean push:

- Dependabot version updates: daily
- Dependabot security updates: enabled where account permissions allow
- CodeQL: enabled for Python
- CI: required before merge
- Branch protection or ruleset on `main`
- Delete branches after merge
- Disable wiki unless intentionally used

## Branch Rule

`main` is product-stable. Work should land through short branches and reviewed
pull requests unless emergency cleanup is required.
