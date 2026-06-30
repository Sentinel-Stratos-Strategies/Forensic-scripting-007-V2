#!/usr/bin/env bash
set -euo pipefail

repo="${1:-Sentinel-Stratos-Strategies/Forensic-scripting-007-V2}"

if ! command -v gh >/dev/null 2>&1; then
  echo "gh is required" >&2
  exit 1
fi

gh api -X PATCH "repos/${repo}" \
  -f has_issues=true \
  -f has_wiki=false \
  -f delete_branch_on_merge=true \
  -f allow_squash_merge=true \
  -f allow_merge_commit=false \
  -f allow_rebase_merge=true >/dev/null

gh api -X PUT "repos/${repo}/vulnerability-alerts" >/dev/null || {
  echo "warning: could not enable vulnerability alerts; check repository/admin permissions" >&2
}

gh api -X PUT "repos/${repo}/automated-security-fixes" >/dev/null || {
  echo "warning: could not enable automated security fixes; check repository/admin permissions" >&2
}

cat <<EOF
Repository hardening requested for ${repo}.

Next manual step after first CI run:
- protect main
- require pull requests
- require CI and CodeQL checks
- block force pushes and deletions
EOF
