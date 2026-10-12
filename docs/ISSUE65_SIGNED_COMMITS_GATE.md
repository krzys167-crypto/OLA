# Issue #65 — fail-closed owner GPG signature verification

This change is proposed on an independent draft PR, NOT merged. The existing PR #64 remains frozen.

## Trusted execution
- `.github/workflows/commit-signature-gate.yml` runs via **pull_request_target** from `main`, checks out the **base SHA only**, and NEVER runs untrusted PR code. It becomes usable only once merged into trusted `main`.
- `scripts/verify_github_signatures.py` reads GitHub PR metadata and every paged commit, checks frozen head/base ancestry, GitHub `verified=true` and `reason=valid`, verifies detached PGP payload via GPG, matches approved **primary** fingerprint and valid nonexpired/nonrevoked UID to the Git author email, and rechecks frozen refs. Failures return nonzero and `BLOCKED` JSON.
- Administrator must configure repository variable `OLA_ALLOWED_SIGNER_FPRS` (40 or 64 hex fingerprint(s)) from a trusted source. Public keys must be published at `https://github.com/krzysztofcieciwa07-ship-it.gpg`. Missing variable or public key FAILS CLOSED.
- `commit-signature-contract-tests.yml` proves test behavior but is **not itself a security enforcement gate**. This draft PR's GitHub-generated commit is UNSIGNED until the owner signs it in a controlled ZBook operation. No false claim of ready-to-merge.
- Repository administration must configure this workflow as **required**; branch protection was unreadable (403) and enforcement is NOT confirmed. A signed PR still requires fresh CI, independent review and Human Gate before main release/deploy.
- This gate rejects non-linear PR histories and incomplete pagination. Large or diverged PRs must be rebased (with signed preservation proof) before passing.
