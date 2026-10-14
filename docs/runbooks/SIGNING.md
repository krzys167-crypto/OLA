# Runbook: owner-signed commits and the signature gate

Audience: the repository owner (administrator). Nothing in this runbook has been applied to the live repository — every step below is an owner action.

## 1. Where things stand

| Fact | Evidence |
|---|---|
| The signer gate workflow (`commit-signature-gate.yml`) and `scripts/verify_github_signatures.py` were merged by #66 and **reverted from `main` by #87**. `main` therefore has no signature gate today. | `git log main` |
| PR #89 restores the gate; PR #103 contains that content. | every file changed by #89 is identical in #103 (`scripts/pr_triage.sh`, column `on103`) |
| All 82 commits that PR #103 adds on top of `main` are unsigned. 72 of 79 PR head commits in the repository are unsigned. | `git log --format=%G? main..refs/pull/103/head` |
| The gate triggers on `pull_request_target` with `branches: [main]`. A PR whose base is not `main` is never checked. | workflow file |
| Branch protection could not be read earlier (HTTP 403), so enforcement of any rule on `main` is **unconfirmed**. | `docs/ISSUE65_SIGNED_COMMITS_GATE.md` |

## 2. What the gate actually requires

`scripts/verify_github_signatures.py` blocks (fail-closed) unless **every** PR commit:

1. has exactly one parent and the chain is linear from the frozen base SHA — **merge commits are rejected**;
2. is `verified: true, reason: valid` on GitHub **and** carries a detached **PGP** signature (an SSH signature, although GitHub shows it as "Verified", is rejected here);
3. verifies with `gpg` against the public keys published at `https://github.com/krzysztofcieciwa07-ship-it.gpg`;
4. is signed by a **primary key fingerprint listed in the repository variable `OLA_ALLOWED_SIGNER_FPRS`** (40 or 64 hex);
5. has an author e-mail that matches a valid, non-expired, non-revoked UID on that key.

It also rejects PRs with more than 250 commits, head/base drift during the run, and fork PRs. A missing variable or missing public key blocks.

Consequences to plan for:

- A commit that GitHub signs for you (web-flow: the squash/merge button) is **not** an allowed signer. That is fine for the *result* of a squash merge, because the gate checks the PR's commits, not the merge result — but it means PR branches must carry your own GPG-signed commits.
- Rewriting history to sign commits changes every SHA. Evidence bound to an exact head SHA (artifact names, provenance, digests) no longer applies; CI must run again on the new head.

## 3. Bootstrap order (the gate cannot gate its own introduction)

`pull_request_target` runs the workflow definition from the **base** branch. While the workflow is absent from `main`, no PR is checked and the required check can never report. So:

1. **Create / locate your GPG key** and make sure the author e-mail used in commits is a UID on it.
   ```bash
   gpg --full-generate-key                     # or use the existing key
   gpg --list-secret-keys --keyid-format=long
   git config --global user.signingkey <KEYID>
   git config --global commit.gpgsign true
   git config --global gpg.format openpgp      # not "ssh"
   gpg --armor --export <KEYID>                # add to GitHub → Settings → SSH and GPG keys
   gpg --fingerprint <KEYID>                   # primary fingerprint, 40 hex without spaces
   ```
2. **Get the content of #103 onto `main` as one owner-signed commit** (see §4). This single commit is the one unavoidable manual trust step.
3. After it merges, set the repository variable (Settings → Secrets and variables → Actions → Variables):
   `OLA_ALLOWED_SIGNER_FPRS = <primary fingerprint>`
4. **Negative test** — open a throw-away PR to `main` with one *unsigned* commit. The check `signed-commits` must go red. Open a second PR with a signed commit; it must go green. Close both.
5. **Only now** add `signed-commits` to the required status checks of the ruleset (§5). Adding it earlier makes the first PR unmergeable.
6. Set the repository variable `OLA_REQUIRE_REAL_OPENAI=true` once the `ci-openai` environment secret is confirmed present, so real-LLM gates stop passing as no-ops.

## 4. Options for landing PR #103 (owner decision)

| | A. One signed commit, same tree (recommended) | B. Re-sign all 82 commits | C. Squash-merge in the UI |
|---|---|---|---|
| Result on `main` | 1 owner-signed commit | 82 owner-signed commits | 1 web-flow-signed commit |
| SHAs / evidence | New head; CI re-runs | All SHAs change; CI re-runs | Merge result is new; PR head evidence stays on the PR |
| Passes the signer gate | Yes | Yes | The PR is not gated (gate absent from `main`), merge result is not checked |
| History granularity | Lost (kept in the old branch) | Kept | Lost |
| Effort / risk | Low | High (rebase of 82 commits, conflict risk) | Lowest, but owner key never signs the introduction of the gate |

Option A, concretely — the tree is byte-identical to the reviewed PR head, so the review stays valid:

```bash
git fetch origin main pull/103/head:pr103
TREE=$(git rev-parse pr103^{tree})
BASE=$(git rev-parse origin/main)
NEW=$(git commit-tree -S "$TREE" -p "$BASE" -m "feat: land PR #103 (squashed, owner-signed)")
git branch landing/pr103 "$NEW"
git verify-commit landing/pr103             # must report a good signature
git diff --stat pr103 landing/pr103         # must be empty
git push origin landing/pr103               # open a PR against main; wait for fresh CI
```

Keep the `pr103` branch as the audit trail. Do **not** force-push over it.

## 5. Ruleset

`.github/rulesets/main-protection.json` is a proposal. Review it, then apply (needs repository admin; this was not done by the assistant):

```bash
gh api -X POST repos/krzysztofcieciwa07-ship-it/OLA/rulesets --input .github/rulesets/main-protection.json
```

Phase 2 (after step 4 of §3): add this entry to `required_status_checks.required_status_checks`:

```json
{ "context": "signed-commits" }
```

Notes:
- `required_approving_review_count` is `0` because a single maintainer cannot approve their own PR; the Human Gate and required checks carry the control. Raise it when a second reviewer exists.
- `bypass_actors` is empty. Keep a break-glass path in mind: with no bypass actor, a broken required check blocks every merge until the ruleset is edited by an admin.
- `required_signatures` accepts web-flow signatures, so UI squash merges keep working.

## 6. Recovery and rotation

- **Lost / rotated key:** publish the new key, update `OLA_ALLOWED_SIGNER_FPRS` (comma-separated list allowed — keep the old fingerprint only while old PRs are open), then remove the old one.
- **Gate blocks a legitimate PR:** read the `signed-commit-evidence-<PR>-<run>` artifact (`signature-gate-result.json`); the `reason` names the failing rule. Do not loosen the script to unblock a merge.
- **Compromise suspected:** revoke the key on GitHub, clear the variable (the gate then blocks everything — intended), investigate, restore with a new fingerprint.
