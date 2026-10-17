# OLA DI-OS — cross-environment source and duplicate recovery audit
**Snapshot:** 2026-10-17 · **Status:** PARTIAL / read-only content scan. **No deploy, no merge, no workstation execution.**

## 1. Authoritative locations, not competing sources of truth

- **Canonical Git remote:** `krzysztofcieciwa07-ship-it/OLA`; `main` examined at `1aadf7d2edc5abe345ec1d08a26d5331b51e5bc3`. Current task ledger exists **only on PR #108 branch** until merge; see `.ola/continuity/registry.json`. The older `main` runtime checkpoint machinery must not be rebuilt.
- **ChatGPT Library:** folders `/OLA/AUDITS` (11 files), `/OLA/WORKSTATION` (6 scripts), `/AI_STUDIO` (release audit and source archive), `/Ola Di-OS/TRACEFORGE` (archive), plus extensive root-level candidate bundles, forensic reports, Windows installers, mobile preview packages and duplicate filename variants.
- **Google Drive:** `/Google Drive/ola-evidence-gateway` (source directories and documentation), `/Google Drive/OLA-DI-OS-CLAUDE-START` (Git bundle, source lock, patches, tests), and **`/Google Drive/OLA DI-OS — AKTUALNY PROJEKT — 2ca9d8f.zip`** (distinct local candidate). Library's Drive recursion is unsupported; visible folders were traversed selectively.
- **Dropbox:** `/Dropbox/Folder zespołu Krzys167` was browsable but returned no direct children in this access path; do not infer Dropbox contains no OLA work.
- **Physical environments:** HP ZBook Windows/PowerShell/Docker/Ollama; MacBook historical sources; Android Z Flip 3 mobile source/preview; Linux CI/build/test environment; GitHub Actions; hosted services. No physical ZBook or MacBook was connected and executed during this audit.

## 2. Archive integrity and byte-level results (independently calculated)

| Source archive | Archive SHA-256 | Contents actually scanned | Relevant limitation |
|---|---|---:|---|
| Library `/OLA/AUDITS/OLA_DI_OS_FULL_ECOSYSTEM_AUDIT_2026-10-12.zip` | `499876bf23a1b537bd786d6a4e6edc556227c9c468e6bdfed6ccf00e4cf14e63` | 77 entries + 348 nested historical files | SHA matches adjacent standalone `.zip.sha256`; embedded historical manifest claims 344/344 verified. All **344/344 historical manifest entries were independently re-hashed from the nested ZIP**, with **0 missing and 0 mismatched**; nested archive has 348 file entries in total. Historical source ≠ live proof. |
| Google Drive `OLA DI-OS — AKTUALNY PROJEKT — 2ca9d8f.zip` | `abc89360023eb36d230b7ede6511531ea69eedbc4febd712cca35cab118ee856` | 400 entries (including .git and non-source material) | `KONTROLA-PACZKI.json`: all **200/200** source file bytes independently match declared SHA-256 **and** Git blob hashes; no absent or extra manifest source paths. |
| Library `OLA-ADR001-stage4.zip` | `650745cc7adbf480ca46...` (abbreviated) | 61 entries | Overlaps newer candidate by **38 byte-identical, nonempty files** — do not reapply those components indiscriminately. |
| Library `OLA-MACBOOK-SOURCE.zip` | `3c5b353699e1c247895e...` (abbreviated) | 300 entries | Historical Mac/Tauri/project trees; contains generic `.git/hooks` fixtures that should not count as product duplication. |
| Library `OLA-ZFLIP3-NATIVE-ANDROID-SOURCE-2026-10-16.zip` | `b912eb42036813ef9f34...` (abbreviated) | 37 entries | Android source/media/bridge; build, install and live phone operation **not** verified by file presence. |
| Library `OLA-KANDYDAT-49282db-ZBook (1).zip` | `e8d21aae5dc37b7bf34a...` (abbreviated) | 8 outer entries | Includes nested branch/preview/evidence archives; not execution proof without checking inner artifacts. |
| Library `ola-final-production-60378da7.zip` | `defdd25d6c7b73e1f32b...` (abbreviated) | 4 entries | Manifest explicitly says `commit_signature_gate=BLOCKED`, `human_gate=PENDING`, `production_deployment=NOT_PERFORMED`, `go_no_go=NO-GO`, `final_status=BLOCKED`. |
| Library AI STUDIO 3.6.0 `.tar.gz` | `29b9c6614e8af1a702e01993e766240760ee55837f1a68d0d94925fb7f99d890` | 50 regular files | Code and documentation, not production attestation. |

Seven ZIP archives (without expanding nested ZIPs) contained **887** file entries; the AI STUDIO tar had another **50**, and the nested historical ZIP had **348**. These are archive *entries*, not 1,285 independent components or features. Cross-ZIP SHA analysis detected **55 exact-content groups shared between ZIP archives**, many being generic Git fixtures. The relevant, confirmed product-code overlap is the **38 common source bytes across ADR-001 stage4 and the 16 October ZBook package**. Same filenames in unrelated projects do **not** prove duplication; same relative names with different hashes require targeted review and must not be overwritten automatically.

## 3. Recovered already-written implementations

- **Evidence v2 exists in the later Google Drive candidate.** It contains `app/hashchain.py` with versioned hashing, a `hashchain_v2` import, and v2 record-id/type binding. The read `OLA/main` version of `app/hashchain.py` still uses legacy v1 hashing without these fields. **Action: compare/correlate with staged PRs #79/#103/#107; do not create a fresh v2 implementation by default.**
- **Local signed-review/tenant work exists, not production approval.** Google Drive `OLA-ZBOOK/DRUGIE-POSWIADCZENIE-WINDOWS.md` and local `scripts/provision_additional_tenant_key.py` describe additional keys but explicitly do not establish independent human identities or narrow reviewer RBAC. Native Windows test and user identity proof remain missing.
- **Source provenance is pinned, but the local candidate is not automatically a pushed release.** `OLA-ZBOOK/GOTOWY-PROJEKT.json`: HEAD `2ca9d8f839f9df6da34474f11c6f87461be2c63c`, tree `969a1a10a28204e173fc23c0d6c98c5ae36ad935`, branch `codex/additional-tenant-key-20261016`, clean, `remote_tracking_refs=[]`, `zbook_connected=false`. Package README claims Linux tests **529 Python + 45 Node** and simulated browser/API, **not native Windows/model validation**; claims are file statements, not rerun test evidence in this audit.
- **Claude handoff is also a candidate, not a deployment.** Google Drive `OLA-DI-OS-CLAUDE-START/SOURCE-LOCK.json`: local head `978fc950...`, source from PR #105, unsigned/unpushed; `WYNIK-TESTOW.json` reports **34 isolated tests** and `windows_native=NOT_RUN`, `candidate_github_ci=NOT_RUN`, `product_e2e=NOT_RUN`. Preserve and reconcile, not promote automatically.
- **Previously published global audit already mapped 76 OLA branch HEAD trees and 92 repo refs**, but explicitly says `TREE_FILES_ONLY_NOT_COMMIT_HISTORY`. `/OLA/AUDITS/OLA_DI_OS_76_GALEZI_AUDYT_2026-10-12.csv` has 76 branch rows plus header, and the frozen main SHA. Do not redo those 76 SHA-based comparisons without a changed input. Fresh branches/SHAs require deltas only.

## 4. Environment and consistency policy

1. Treat `GitHub commit`, `Library package`, `Google Drive bundle`, `Windows workstation`, `CI pass`, `production deployment`, and `payment` as separate evidence domains. Only signed verifiable links may connect them.
2. File identity: `source_uri + exact ref/SHA + relative path + SHA-256 + package date + environment`. Keep exact byte-identical duplicates as historical references, not second source modules. Different hashes are version conflicts until assessed.
3. **Never delete, overwrite, unpack onto a live directory, execute untrusted archive scripts, or rewrite protected Git history** during recovery. Archive inventory is read-only.
4. Keep `bootstrap_inventory_incomplete=true` until the remaining Library root pages, connected paths, nested releases, git history and physical runtime attestations are reconciled.
5. Priority for `OLA-CONT-002`: (a) compare candidate code to #107/active main; (b) reconcile existing 76-branch index and PR hashes; (c) link remaining library packages by SHA and coverage; (d) obtain an authorized native ZBook proof separately. **Do not implement already present functionality.**

**No production GO:** [PR #108](https://github.com/krzysztofcieciwa07-ship-it/OLA/pull/108) remains unmerged and unsigned. No external CI result supersedes signature and independent reviewer checks.

## 5. Follow-up validations of this same recovery pass

- GitHub commit API at 2026-10-17: `GET /commits/2ca9d8f839f9df6da34474f11c6f87461be2c63c` and `GET /commits/978fc95001d78ac050d32e219a8ccb0401c179c6` returned **422: No commit found for SHA**. This confirms those exact local source commits were not available in the queried upstream GitHub repository; it does **not** prove their code is invalid or absent in another branch/bundle.
- The historical 344-manifest verification was repeated by recomputing SHA-256 and byte lengths for each named nested original: **344 PASS, 0 mismatch, 0 missing**. This independently validates bytes preserved in the archived ZIP but not authorship, commits, runtime or production.
- Library `ola-final-production-60378da7.zip` includes `production-manifest-sha256.txt` and independent policy log `MANIFEST_POLICY=PASS state=BLOCKED production=NO-GO`; policy PASS here means the *fail-closed NO-GO decision* is correctly encoded, **not** production readiness.
- Source/code overlap between stage4 and local 2ca9d8f source already measured by exact SHA-256: **38 identical nonempty files**. Preserve both versions and do not delete either based solely on duplicates.
