# Security Policy

Forensic-scripting-007-V2 is a reusable DFIR toolkit. The repository must not contain
private evidence, tokens, passwords, `.env` files, packet captures, disk images, app
bundles, personal reports, or case-specific artifacts.

## Supported Branch

Security fixes target `main`.

## Reporting Vulnerabilities

Use GitHub's private vulnerability reporting when it is available for this repository.
If private reporting is unavailable, open a minimal public issue that describes the
affected component without posting secrets, exploit payloads, private evidence, or
sensitive paths.

## Secret Handling

- Never commit `.env`, API keys, personal access tokens, backup passwords, private
  certificates, mobile configuration profiles, or live credentials.
- If a secret is accidentally committed, revoke it first, then remove it from git
  history before treating the repository as clean.
- Prefer environment variables or local keychain prompts for credentials.
- Test fixtures must use placeholders only.

## Evidence Handling

- Raw evidence stays outside the repository.
- Generated outputs belong in ignored local directories or external evidence storage.
- Product documentation may describe evidence formats, but it must not include private
  case facts unless those facts are intentionally published in a separate evidence
  package.

## Review Standard

Before merge or release:

- Python files must compile.
- Shell scripts must pass syntax checks.
- Fixture tests must pass.
- Secret scan must return no live credentials.
- New forensic claims must separate observed facts, supported interpretations, and
  excluded claims.
