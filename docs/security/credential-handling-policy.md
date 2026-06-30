# Secret Handling Policy

## Never Commit

- `.env`
- `.env.*`
- personal access tokens
- API keys
- private certificates
- mobile configuration profiles
- backup passphrases
- OAuth tokens
- live cookies or session material

## Local Use

Use environment variables, keychain prompts, or ignored local `.env` files. Do not
print secret values into logs, reports, terminal transcripts, test fixtures, or PR
comments.

## If A Secret Leaks

1. Revoke or rotate the secret immediately.
2. Remove the secret from the working tree.
3. Remove it from git history if it was committed.
4. Re-run a secret scan.
5. Document the incident without repeating the secret value.

## Reviewer Rule

It is acceptable to document that a secret existed or was rotated. It is never
acceptable to paste the secret itself into this repository.
