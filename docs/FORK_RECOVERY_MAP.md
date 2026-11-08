# Recovery map — divergent OLA fork

Snapshot: 2026-11-09  
Source: [krzys167-crypto/OLA](https://github.com/krzys167-crypto/OLA)  
Canonical destination: [krzysztofcieciwa07-ship-it/OLA](https://github.com/krzysztofcieciwa07-ship-it/OLA)

## 1. Comparison facts

- The second-account repository is a fork of the canonical OLA repository.
- Fork `main`: `d2dd11c8dd964d4c846bcab4e74b2d02b77a9f4a`.
- Canonical `main`: `6dff9c43ccd5a6892a50d1f59363d232b07ceafb`.
- GitHub compare reports **235 commits ahead / 54 behind** (diverged).
- Tree comparison reports **179 paths unique to the fork**.
- The fork-side aggregate compare returned 217 changed files, about **15,997 additions / 555 deletions**. This aggregate is not the same as the count of unique current-tree paths.
- The fork is not a disposable duplicate. A wholesale merge would combine two distinct histories and likely reintroduce stale/redundant code.

## 2. Recoverable work by domain

| Domain | Unique content identified | Technical coupling | Recommendation |
|---|---|---|---|
| CFR / Certificate Apocalypse | `app/cfr.py`, `app/identity.py`, `app/ed25519_point.py`, scenario directory, CFR and identity tests | Needs Ed25519 identity/enrollment routes, OLA routes in `app/main.py`, tenant evidence chain compatibility and crypto dependency review | **High-value candidate; recover as a separately reviewed integration, not a directory copy.** |
| Certificate Apocalypse lab | 16 source files under `cfr_scenarios/certificate-apocalypse/`: process mode, Docker Compose, TLS faults, probes, assertions, metrics, manifest and witness client | Local process and Docker Compose modes; README says k3d/Kubernetes is not provided. Server submit/witness modes call CFR API endpoints that are absent from current canonical main | Recover lab after clarifying offline/Compose contract and either integrating CFR API or disabling server-submit claims until ready. |
| OLA pipeline package | `ola_pipeline/` (18 unique paths), `app/pipeline_bridge.py`, pipeline tests | Standalone NINA→provider→evidence→IGOR→gate→replay path; bridge uses SQLAlchemy and several existing OLA modules. Potential overlap with current OLA orchestration and evidence path | Audit against current runtime first; do not run as a second execution engine. Choose reuse/adaptation or reject. |
| Decision Fabric | `app/decision_fabric.py`, workflow and tests | External Jev HTTP provider (httpx), decision contracts and evidence | Keep as candidate adapter; verify actual provider, failure handling, cost and current overlap before integration. |
| Security modules | `app/firewall.py`, `app/http_guard.py`, `app/anchor_external.py`, `app/ambient.py`, `app/payment_binding.py`, `app/revenue_proof.py`, `app/receipt.py` | Different authorization and runtime assumptions; some depend on `ola_pipeline`, Ed25519 identity, hash-chain or SQLAlchemy | Separate threat-model and test review per module. No bulk copy. |
| Sales automation | `sales/`, `docs/sales/`, `scripts/sales_mail.py`, `scripts/sales_pipeline.py`, sales workflow | Outbound communication and external account integration; contains a prospects file and sample session artifacts | **Privacy hold. Do not recover prospects or sample artifacts.** Only policy/templates may be considered after review. |
| Governance | `governance/controls.json` and supporting controls scripts | Policy definitions may overlap with current OLA safety gates | Map each control to current enforcement and tests before reuse. |

## 3. Hard compatibility checks before any code recovery

1. **Source/API contract:** current canonical `app/main.py` is a different revision and currently does not expose the fork's `/cfr/*` and `/identity/*` endpoint family. CFR client scripts therefore cannot be described as server-connected in canonical OLA yet.
2. **Ed25519 identity:** the fork's identity layer depends on cryptographic primitives and its own identity/enrollment contract. Review trust roots, role binding, nonce replay, revocation and tenant scoping before reuse.
3. **Persistence:** CFR records are appended through the hash-chain layer. Verify exact schema and append-only guarantees against canonical `app/hashchain.py` and current database implementation.
4. **Dependencies:** canonical `requirements.txt` is pinned and does not currently list the `cryptography` package imported by the fork identity module. Do not silently add dependency or alter versions; confirm need and pin after a reproducible test.
5. **Tests:** fork tests import its wider `app.main`, identity and database setup. They are not automatically portable to canonical main. Port contracts, not assumptions.
6. **Evidence claims:** CI from the old fork or a local scenario run is not production runtime proof. Every recovered module needs exact canonical commit SHA, test run, artifacts and independent review.

## 4. Certificate Apocalypse boundaries

The recovered scenario is technically useful, but its README explicitly states:
- process mode runs local TLS services;
- container mode uses Docker Compose with six roles (init, four services, monitor);
- service ports are published on localhost;
- one fault variant is selected per run and the host derives from the per-run seed;
- visible and hidden certificate assertions are used, including exact SAN and CA-preservation checks;
- health stability window is 10 seconds;
- restarts and downtime affect scoring;
- **k3d / Kubernetes is not provided**;
- the host is still not a trusted boundary, even in container mode.

Do not market or label this as a Kubernetes range until a k3d deployment, cluster isolation and corresponding tests actually exist.

## 5. Privacy and credential hold

The old public fork contains:
- `sales/prospects.csv`: 18 rows, columns include `contact`, `last_action` and `note`. Values were not read or disclosed.
- `docs/sales/sample/`: example session envelopes and artifact files. Do not assume all are synthetic without inspecting provenance.
- its separate source project `krzys167-crypto/quantum-ai-chatbot` still tracks `.env` and `.env.example`. The latter contains credential-shaped values for Anthropic, Google OAuth, a Google service-account private key and ElevenLabs. Values were not tested or disclosed. Treat as exposed, rotate, sanitize and review Git history.

The connected chatbot fork was remediated on its current `main` (tracked `.env` removed, `.env.example` replaced with placeholders, ignore rules hardened), but older blobs remain in its history. The source account remains unremediated because the current GitHub installation has no write access to that account.

## 6. Recovery order

1. Connect the `krzys167-crypto` GitHub account with write authorization so the source-side credential exposure and privacy files can be remediated.
2. Rotate potentially exposed Anthropic, Google OAuth, Google service-account and ElevenLabs credentials; revoke old keys. History cleanup comes after rotation.
3. Recover **CFR + Certificate Apocalypse** as one isolated integration PR only after route, identity, persistence and dependency compatibility checks pass.
4. Audit `ola_pipeline` for overlap with current NINA/IGOR runtime. Reuse components only where a single execution path can be preserved.
5. Review Decision Fabric and security modules individually.
6. Exclude prospects, contact data and sample customer/session artifacts from code recovery unless provenance and privacy review explicitly clears them.
7. After recovery, retire only verified superseded branches and PRs. Preserve old refs until every unique commit is accounted for.

## 7. Current disposition

**NO wholesale merge. NO deletion of the divergent fork. NO production claim.**

The fork contains real, reusable engineering work, but the modules form a connected architecture with additional dependencies and route contracts. Recovery must be staged and proven on the canonical OLA source SHA.
