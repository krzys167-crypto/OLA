# OLA repository security baseline

Status: proposed baseline; not a production security certification.

## Verified starting point (2026-11-05)

- Repository: `krzysztofcieciwa07-ship-it/OLA`.
- Default branch: `main`.
- An active repository ruleset named `SECURITY.md` was observed, but its rules only prohibit branch deletion and non-fast-forward updates.
- The connected GitHub App installation selects all repositories on the connected account. Narrowing this scope must be performed in GitHub installation settings by the account owner.
- Branch-protection API access was not available through the connected integration; required reviews and status checks remain unverified.

## Required `main` protection

1. Require a pull request before merging.
2. Require at least one approval from someone other than the PR author.
3. Require CODEOWNERS review for covered changes.
4. Dismiss stale approvals when new commits are pushed.
5. Require approval of the most recent reviewable push where supported.
6. Require stable CI checks on the exact head SHA, including tests, static analysis, secret scanning, dependency review and provenance gates where available.
7. Require branches to be up to date where practical.
8. Block force pushes and branch deletion.
9. Avoid routine bypass actors; document and audit emergency bypass separately.

A CODEOWNERS file alone does not enforce review. The ruleset must explicitly require code-owner review. A single-owner CODEOWNERS entry is not independent review; add a trusted independent reviewer before treating this gate as satisfied.

## Automation permissions

- Default workflow token permissions to `contents: read`.
- Grant write permissions only to the job and step that need them.
- Pin third-party Actions to immutable full commit SHAs.
- Use `persist-credentials: false` on checkout unless authenticated Git operations are required.
- Prefer OIDC and short-lived credentials; never commit production credentials.
- Scheduled agents may inventory, test, report and open draft PRs. They must not autonomously merge, deploy, rotate credentials, alter visibility, delete data or change access controls.

## Required automated checks

- Secret scanning and push protection.
- CodeQL or equivalent static analysis.
- Dependency vulnerability review and lockfile checks.
- Workflow/action pinning and least-privilege review.
- Unit/integration tests and exact-SHA provenance.
- Artifact digest and attestation verification for release outputs.
- Independent IGOR verification; a skipped verifier is not a pass.

Do not add duplicate workflows until existing checks have been mapped for triggers, permissions, coverage and failure modes.

## Multi-profile repository hygiene

For every profile and repository, record owner, visibility, default branch, fork/source relationship, last activity, language, license, security policy, CODEOWNERS, rulesets, Actions permissions, secret-scanning status, dependency alerts, open PRs/issues and canonical purpose.

Classify repositories as `CORE`, `ACTIVE`, `ARCHIVE_CANDIDATE`, `UPSTREAM_FORK`, `EXPERIMENTAL` or `UNKNOWN`. Do not delete, transfer, privatize or archive based only on matching repository names. Compare immutable commit SHAs, Git object history, fork relationships and contents first.

## Evidence and acceptance

Every remediation must identify repository, exact source SHA, changed paths, checks run, check results and reviewer. Record unavailable controls as `UNKNOWN`, never `VERIFIED`. Successful CI proves only the checks it actually executed; it does not establish production readiness.

## Current limitations

This file is a remediation baseline, not proof that account-wide settings have changed. The connected integration cannot currently verify all branch-protection settings or private-repository security controls. Account-level hardening and independent reviewer configuration remain pending owner action.
