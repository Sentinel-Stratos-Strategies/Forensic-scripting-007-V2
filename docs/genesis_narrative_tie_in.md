# Genesis Narrative Tie-In

This is the bridge between the private 007 evidence backend and the Genesis OS
human-facing report layer.

## Purpose

007 captures and normalizes evidence. Genesis should not recapture evidence or
make stronger claims than 007 supports. The tie-in packet gives Genesis a stable
handoff:

- `FORENSIC_NARRATIVE.md`
- `CLAIM_MATRIX.tsv`
- `EVIDENCE_BASE.tsv`
- `CHRONOLOGY.tsv`
- `RECURSIVE_COVERAGE.tsv`
- `EXCLUDED_CLAIMS.md`
- `GENESIS_HANDOFF.json`
- `HASH_MANIFEST.sha256`

## Build A Packet

```bash
python3 scripts/build_narrative_claim_packet.py \
  --run-dir /Volumes/Evidence/007_go_plan_YYYYMMDDTHHMMSSZ
```

The default output is:

```text
/Volumes/Evidence/007_go_plan_YYYYMMDDTHHMMSSZ/analysis/narrative_claim_packet_TIMESTAMP
```

## Product Boundary

Genesis may render the packet as:

- Evidence Browser
- Timeline Narrator
- Claim Matrix
- Report Builder
- AI Analyst

Genesis must keep these layers separate:

1. observed fact
2. correlation
3. inference
4. open question

## Claim Rules

Allowed claim statuses:

- `proven`
- `supported`
- `plausible`
- `speculative`
- `contradicted`
- `unknown`

Do not promote ABM/MDM control, TCC bypass, preboot/cryptex compromise, malware,
actor attribution, vendor misconduct, or supply-chain root cause unless direct
artifacts support that exact claim.

## Why This Exists

Full recursive evidence runs are expensive. The narrative tie-in lets a stopped,
interrupted, or completed 007 run become useful without rerunning capture. It
also gives Genesis a polished view while keeping raw evidence local and hashed.
