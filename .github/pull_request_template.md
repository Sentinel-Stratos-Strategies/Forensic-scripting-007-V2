## Summary

- 

## Safety Boundary

- [ ] No `.env`, tokens, passwords, private evidence, PCAPs, disk images, app bundles, or generated run outputs are included.
- [ ] New outputs write outside source evidence paths by default.
- [ ] New claims distinguish observed facts, supported interpretations, and excluded claims.

## Validation

- [ ] `python3 -m py_compile scripts/*.py scripts/hydrate/*.py`
- [ ] `bash -n atlas_submission_capture.sh recursive_macos_volume_verify.sh run_forensic_suite.sh scripts/*.sh tests/*.sh`
- [ ] `bash tests/test_recursive_macos_volume_verify.sh`
- [ ] `bash tests/test_narrative_claim_packet.sh`

## Review Notes

- 
