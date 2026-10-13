# OLA Docker Build Cloud - fail-closed distribution

**Status: PREPARED / NO-GO.** This publishes only a reviewed Docker Hub image artifact, not the OLA production backend and not a customer-facing result. Never equate CI SUCCESS with production VERIFIED.

## 1. Build-only CI (safe PR / push)

New workflow: .github/workflows/ola-docker-cloud.yml

- Every PR to main and every push to main checks out the source SHA and builds with local Buildx. 
- No Docker PAT or cloud builder access is exposed to untrusted PRs.
- Build uses cacheonly output, push=false. No image is published automatically.
- Unit tests check the fail-closed release policy.

## 2. Publisher setup (only after signed main source and independent review)

- Configure actual GitHub main branch ruleset(s): required commit signatures, required status checks, no force updates, no deletion, no bypass. Verify main.protected=true and actual rule enforcement. Do not disable security gates for a passing build.
- Configure GitHub environment production with REQUIRED independent reviewer(s), prevent_self_review=true, and protected-branches-only. If the environment is missing/unprotected, release preflight must fail.
- Approve actual owner GPG fingerprints from an independent trusted source. Store fingerprints (not private keys) as GitHub repository variable OLA_ALLOWED_SIGNER_FPRS.
- Have the owner sign a frozen, single-parent release commit preserving the reviewed tree of OLA PRs. Run all required FINAL PRODUCTION GATE checks on that exact signed SHA.
- Set GitHub repository variables DOCKER_USER=krzysztof1678 and OLA_DOCKER_RELEASE_ENABLED=true only after all gates are configured. Store a least-privilege Docker Hub access token only in GitHub Actions secret DOCKER_PAT.
- Validate Docker Build Cloud builder ownership/access for endpoint krzysztof1678/ola (Buildx >=0.37.0), and verify Docker Hub image repository krzysztof1678/ola exists and permits pushes. These are not proven by the workflow code alone.

## 3. Manual registry publication

After successful source-bound FINAL PRODUCTION GATE push run and independent environment approval, manually dispatch OLA Docker Cloud - signed evidence release on main. Enter the *exact* signed main commit as the release_sha input.

Release preflight checks:
- requested SHA equals current protected main;
- active main rulesets require signing/status checks, non-fast-forward and deletion blocks;
- production environment has independent reviewer, prevent_self_review=true, protected branches only;
- allowlist contains trusted owner fingerprints; GitHub commit signature verified;
- FINAL PRODUCTION GATE push run for the *same* SHA concluded SUCCESS;
- downloaded manifest has ATTESTED_PENDING_HUMAN and signer proof matches the allowlist;
- independent policy validates manifest SHA, source image checksum, attestations and blocked Human Gate claims.

Only after these preconditions does Docker login receive DOCKER_PAT and Docker Build Cloud publish immutable tag krzysztof1678/ola:sha-<source_sha>. It publishes OCI provenance/SBOM, verifies digest with imagetools inspect, and prints immutable digest. No mutable latest tag is used.

## 4. Final customer GO remains separate

The immutable registry artifact MUST still be deployed to reviewed persistent infrastructure with production-only configuration, API key rotation, independent Human Gate, authenticated health/rollback, tamper/replay and environment stability proof. Docker registry success is never proof of a running application.

Stripe LIVE Checkout to payment confirmation to source-bound OLA execution to independent evidence verification to customer delivery must be validated against real Stripe LIVE records (not sandbox). No unapproved live charges should be generated during these checks.

Fail closed on UNKNOWN. This workflow deliberately does not deploy or charge anyone.
