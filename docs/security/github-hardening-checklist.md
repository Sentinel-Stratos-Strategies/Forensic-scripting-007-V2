# GitHub Hardening Checklist

Run this checklist after the first clean V2 push lands on `main`.

## Confirm Current State

```bash
gh repo view Sentinel-Stratos-Strategies/Forensic-scripting-007-V2
gh api repos/Sentinel-Stratos-Strategies/Forensic-scripting-007-V2/actions/permissions
gh api repos/Sentinel-Stratos-Strategies/Forensic-scripting-007-V2/rulesets
gh api repos/Sentinel-Stratos-Strategies/Forensic-scripting-007-V2/branches/main/protection
```

## Enable Repository Safety Switches

```bash
gh api -X PATCH repos/Sentinel-Stratos-Strategies/Forensic-scripting-007-V2 \
  -f has_issues=true \
  -f has_wiki=false \
  -f delete_branch_on_merge=true \
  -f allow_squash_merge=true \
  -f allow_merge_commit=false \
  -f allow_rebase_merge=true

gh api -X PUT repos/Sentinel-Stratos-Strategies/Forensic-scripting-007-V2/vulnerability-alerts
gh api -X PUT repos/Sentinel-Stratos-Strategies/Forensic-scripting-007-V2/automated-security-fixes
```

## Protect `main`

Apply protection after CI and CodeQL exist online:

- require pull request before merge
- require at least one approval
- dismiss stale approvals
- require status checks:
  - `test`
  - CodeQL Python analysis
- restrict force pushes
- restrict deletions

## Current Probe Result

Before the first V2 push:

- New V2 repo exists and is public.
- Actions are enabled.
- `main` has no branch protection yet.
- Repository rulesets are empty.
- Vulnerability-alert check is available through the authenticated `gh` session.
- The PAT stored in local `.env` could read the repo but could not access admin
  security endpoints.
