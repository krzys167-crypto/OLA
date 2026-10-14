# Pull request triage

Generated from the git graph with `scripts/pr_triage.sh` against `main` @ `1aadf7d` and PR #103 @ `c78135d` (2026-10-14).

**Limits — read first.** The script uses only `refs/pull/*/head`. It cannot see whether a PR is open, closed, draft or merged on GitHub, who reviewed it, or which checks passed (API access to the repository was not enabled for this analysis). "Candidate to close" below means *the git evidence says nothing unique is left*; confirm in the GitHub UI before closing anything.

## Summary

| Bucket | PRs | Count | Meaning |
|---|---|---|---|
| A. Already in `main` (ancestry) | #1, #2, #5, #6, #7, #8, #9, #10, #11, #15, #16, #26, #36, #53, #54, #62 | 16 | Head commit is reachable from `main`. Nothing to merge. |
| B. Content already on `main` | #42, #68, #87 | 3 | Every file the PR touched is identical on `main` — squash-merged or superseded. |
| C. Content fully in #103 | #66, #79, #89, #90 | 4 | Every touched file is identical in #103. Redundant once #103 lands. |
| D. Stacked inside #103 | #100, #101, #102 | 3 | Heads are ancestors of #103; they land with it. |
| E. #103 itself | #103 | 1 | +82 commits, 95 files (17 workflows), 0 behind `main`, all unsigned. |
| F. Large and separate | #60, #76, #88 | 3 | ≥100 commits or ≥50 files and not in #103. Each needs its own decision. |
| G. Stale (≥50 behind `main`) | #3, #4, #12, #13, #14, #17, #18, #21, #27, #35, #37, #39, #40, #41, #43, #44, #45, #46, #48, #49, #50, #51, #52, #55, #56, #57 | 26 | Old branch point; high chance they are superseded. Rebase or close. |
| H. Active, touch workflows | #59, #61, #64, #71, #73, #95, #96, #98, #99 | 9 | Small, recent; change CI. Review for overlap with #103's workflow changes. |
| I. Active, no workflow change | #58, #74, #75, #80, #82, #83, #84, #85, #86, #91, #92, #93, #94, #97 | 14 | Small test/security fixes. Cheapest to land, most likely to conflict only on tests. |

Totals: 79 PR refs = A 16 + B 3 + C 4 + D 3 + E 1 + F 3 + G 26 + H 9 + I 14.

## Observations

1. **#103 is a tip, not a leaf.** It carries 82 commits, three of which are the separately numbered #100–#102. Reviewing it as one unit is the real bottleneck; the signing runbook ([SIGNING.md](runbooks/SIGNING.md)) recommends landing it as one owner-signed commit with an identical tree.
2. **The signer gate is currently off on `main`.** Commit `5df5e5d` (referenced as #66) added it; commit `1aadf7d` (#87, bucket B) reverted it; #89, which restores it, is fully contained in #103 (bucket C). Landing #103 re-enables it; merging #89 alone is redundant.
3. **Signatures:** 7 of 79 PR heads carry a signature (#1, #2, #50, #51, #52, #82, #87) and all 7 have `GitHub` as committer, i.e. web-flow signatures, not the owner's own key. **No PR head is signed by a personal key**, and none of #103's 82 commits is signed at all. The owner-key gate would block every one of these PRs as they stand.
4. **Bucket F** (#60, #76, #88) are the largest PRs outside #103. Each touches 15–20 workflow files, 10 of which are also changed by #103 (which changes 17); expect merge conflicts in `.github/workflows/`.
5. **Order of work that minimises rework:** close A/B/C (after confirming) → land #103 → rebase G and H onto the new `main` → merge I in small batches.

## Bucket detail

### A. Already in `main`
| PR | head | date | +/- vs main | files (wf) | signed | subject |
|---|---|---|---|---|---|---|
| #1 | `16e39fc` | 2026-09-07 | +0/-275 | 0 (0) | yes | Update README.md |
| #2 | `cae4f6e` | 2026-09-12 | +0/-272 | 0 (0) | yes | Update README.md |
| #5 | `f3e3563` | 2026-09-15 | +0/-193 | 0 (0) | no | fix: enforce high-risk human-owner review before allow-list |
| #6 | `fd6483e` | 2026-09-16 | +0/-186 | 0 (0) | no | fix: bind mutation gate to provenance verifier |
| #7 | `26eaa7a` | 2026-09-18 | +0/-164 | 0 (0) | no | ci: verify Nina Igor against PR source commit |
| #8 | `7da337e` | 2026-09-19 | +0/-162 | 0 (0) | no | test: prove real Nina run through API and human gate |
| #9 | `5226cd5` | 2026-09-19 | +0/-161 | 0 (0) | no | ci: bind Nina runtime proof to exact source SHA |
| #10 | `e0f91c1` | 2026-09-19 | +0/-160 | 0 (0) | no | fix: verify runtime artifact against environment commit |
| #11 | `3f7221b` | 2026-09-19 | +0/-159 | 0 (0) | no | test: replay real Nina runtime end to end |
| #15 | `e7f7345` | 2026-09-19 | +0/-150 | 0 (0) | no | Preview: add restrained 3D AI hero to revenue surface |
| #16 | `1b1b92c` | 2026-09-19 | +0/-148 | 0 (0) | no | fix: make revenue surface sandbox check case-insensitive |
| #26 | `f12e792` | 2026-09-22 | +0/-111 | 0 (0) | no | test: close provenance replay and human gate integrity checks |
| #36 | `3cbd638` | 2026-09-23 | +0/-113 | 0 (0) | no | test: expand Jev evaluation into typed decision vector |
| #53 | `d4c49a1` | 2026-09-30 | +0/-55 | 0 (0) | no | test: fix human review assertion path |
| #54 | `943e76d` | 2026-10-01 | +0/-38 | 0 (0) | no | fix: make final evidence gate deterministic |
| #62 | `9990e9f` | 2026-10-06 | +0/-4 | 0 (0) | no | ci: verify production gates on exact main event |

### B. Content already on `main`
| PR | head | date | +/- vs main | files (wf) | signed | subject |
|---|---|---|---|---|---|---|
| #42 | `06e6d58` | 2026-09-27 | +3/-88 | 3 (0) | no | feat: add OLA workstation implementation kit |
| #68 | `528b960` | 2026-10-10 | +2/-3 | 4 (2) | no | fix(ollama): extend bounded real inference to 12h NINA-IGOR reusable gate |
| #87 | `3ec4473` | 2026-10-11 | +1/-1 | 12 (3) | yes | Revert "security: trusted-base GPG signer gate for OLA production evidence (f…" |

### C. Content fully in #103
| PR | head | date | +/- vs main | files (wf) | signed | subject |
|---|---|---|---|---|---|---|
| #66 | `5af49ea` | 2026-10-10 | +17/-3 | 12 (3) | no | test(issue69): use actual push event in signed-main positive fixture |
| #79 | `1ddcad6` | 2026-10-11 | +2/-1 | 2 (0) | no | test: reject tampered evidence record type, identity, tenant and hash order |
| #89 | `16e18cb` | 2026-10-11 | +12/-0 | 12 (3) | no | security: restore source binding, GPG checks and fail-closed production manifest |
| #90 | `69bf460` | 2026-10-12 | +8/-0 | 5 (1) | no | fix(outbox): fail closed on conflicting deduplicated payloads |

### D. Stacked inside #103
| PR | head | date | +/- vs main | files (wf) | signed | subject |
|---|---|---|---|---|---|---|
| #100 | `09b7aaa` | 2026-10-12 | +3/-0 | 58 (14) | no | ci(nina-igor): bind real Ollama execution to exact PR HEAD and fail closed on proof mutati |
| #101 | `9641e15` | 2026-10-13 | +8/-0 | 62 (14) | no | test(stripe): verify webhook and success route refuse sandbox in LIVE mode |
| #102 | `2507659` | 2026-10-13 | +14/-0 | 67 (15) | no | docs(docker): document safe manual registry release and production NO-GO policy |

### E. #103
| PR | head | date | +/- vs main | files (wf) | signed | subject |
|---|---|---|---|---|---|---|
| #103 | `c78135d` | 2026-10-14 | +82/-0 | 95 (17) | no | fix(e2e): independently validate mixed v1/v2 hashes in container proof steps |

### F. Large and separate
| PR | head | date | +/- vs main | files (wf) | signed | subject |
|---|---|---|---|---|---|---|
| #60 | `8afdb7d` | 2026-10-04 | +127/-15 | 36 (15) | no | fix: validate base status fields before independent human approval |
| #76 | `41d3fde` | 2026-10-11 | +183/-1 | 78 (19) | no | Harden Stripe transport and CI trust boundaries; bind image to exact source |
| #88 | `951c783` | 2026-10-11 | +184/-1 | 84 (20) | no | Fix console product gate and add real browser runtime proof |

### G. Stale
| PR | head | date | +/- vs main | files (wf) | signed | subject |
|---|---|---|---|---|---|---|
| #3 | `1aec886` | 2026-09-15 | +5/-246 | 4 (0) | no | feat: expose six-agent runtime endpoint |
| #4 | `be1a2fd` | 2026-09-15 | +2/-197 | 2 (0) | no | fix: implement executable 391-agent runtime boundary |
| #12 | `60c2748` | 2026-09-19 | +2/-159 | 1 (1) | no | ci: run independent IGOR gate on main |
| #13 | `0392c10` | 2026-09-19 | +1/-157 | 1 (1) | no | fix: make IGOR tamper check validate mutated file |
| #14 | `b49fe4f` | 2026-09-19 | +8/-156 | 5 (1) | no | Pass Stripe webhook configuration into CI runtime |
| #17 | `e099fa3` | 2026-09-21 | +9/-160 | 5 (0) | no | Allow Stripe return to resume paid execution |
| #18 | `271fd22` | 2026-09-21 | +18/-123 | 9 (0) | no | accept legacy webhook fixture while enforcing OLA offer |
| #21 | `ecbbcc4` | 2026-09-21 | +8/-122 | 3 (1) | no | fix: independently require response id for real LLM provenance |
| #27 | `eb5faaa` | 2026-09-22 | +1/-111 | 1 (1) | no | fix: align IGOR human gate assertion with pending hold |
| #35 | `f0afbd3` | 2026-09-23 | +4/-117 | 4 (1) | no | ci: prove gate funnel and impact endpoints with real curl |
| #37 | `f176695` | 2026-09-23 | +12/-92 | 4 (1) | no | fix: repair multiline live Jev workflow step |
| #39 | `e762252` | 2026-09-24 | +7/-88 | 6 (1) | no | ci: add stability and state continuity gate |
| #40 | `a435c71` | 2026-09-25 | +15/-88 | 13 (1) | no | fix(cfr18): install pytest in forensic gate |
| #41 | `6f31be7` | 2026-09-26 | +14/-88 | 8 (4) | no | security: update pytest past known vulnerable release |
| #43 | `afd5a57` | 2026-09-28 | +17/-87 | 7 (3) | no | fix: normalize real task E2E environment indentation |
| #44 | `7c8af8a` | 2026-09-28 | +16/-87 | 8 (4) | no | ci: enable CodeQL for Python and GitHub Actions |
| #45 | `d877ba1` | 2026-09-28 | +3/-87 | 1 (1) | no | fix: scope CodeQL alert gate to PR ref |
| #46 | `1aa06a2` | 2026-09-28 | +1/-87 | 1 (1) | no | security: add CodeQL Actions and Python gate |
| #48 | `b688b12` | 2026-09-29 | +48/-87 | 20 (8) | no | fix: skip OpenAI-only provenance steps when credential is absent |
| #49 | `bf953c4` | 2026-09-29 | +15/-86 | 7 (1) | no | fix: separate objective policy verification from human promotion |
| #50 | `94d58d4` | 2026-10-01 | +1/-75 | 8 (1) | yes | security: integrate fail-closed human gate and cryptographic replay (#51) |
| #51 | `e85e451` | 2026-10-01 | +1/-62 | 6 (1) | yes | fix: repair CI regressions after autoflow hardening (#52) |
| #52 | `498dba3` | 2026-09-30 | +1/-58 | 2 (1) | yes | fix: enforce independent human gate in CI contracts (#53) |
| #55 | `a982ca8` | 2026-10-01 | +58/-85 | 32 (20) | no | security: reject non-finite and invalid market inputs |
| #56 | `acb308d` | 2026-10-01 | +86/-85 | 36 (21) | no | fix: keep supply-chain Scorecard push on main only |
| #57 | `df4e73f` | 2026-10-01 | +8/-86 | 7 (1) | no | ci: verify evidence signing and workstation hardening |

### H. Active, touch workflows
| PR | head | date | +/- vs main | files (wf) | signed | subject |
|---|---|---|---|---|---|---|
| #59 | `8f3f280` | 2026-10-02 | +21/-15 | 4 (4) | no | fix(final-gate): accept provenance correlation context filename |
| #61 | `7d2ec1b` | 2026-10-06 | +7/-15 | 6 (1) | no | ci: allow manual TRACEFORGE v0 proof dispatch |
| #64 | `ca0ed48` | 2026-10-10 | +4/-3 | 2 (2) | no | fix(security): avoid untrusted GitHub context in shell conditional |
| #71 | `a6677aa` | 2026-10-10 | +3/-3 | 3 (1) | no | test(watchdog): accept in-progress CLI empty conclusion without false health |
| #73 | `ac4264d` | 2026-10-10 | +3/-1 | 3 (1) | no | security: enforce SARIF rule-level severity in CodeQL CI |
| #95 | `17aeb58` | 2026-10-12 | +33/-0 | 21 (8) | no | fix: include v2 key hash helper in standalone Ollama proof job |
| #96 | `cb22c66` | 2026-10-12 | +38/-0 | 41 (11) | no | security: atomically authorize Human Gate approvals with concurrent review regression |
| #98 | `37b8c9d` | 2026-10-12 | +39/-0 | 41 (11) | no | security: make Human Gate approval atomic across verification and append |
| #99 | `431bcf4` | 2026-10-12 | +18/-0 | 10 (2) | no | fix(human-gate): validate derived EXECUTION_ALLOWED separately from five evidence statuses |

### I. Active, no workflow change
| PR | head | date | +/- vs main | files (wf) | signed | subject |
|---|---|---|---|---|---|---|
| #58 | `6beb0af` | 2026-10-02 | +5/-28 | 2 (0) | no | fix: remove accidental escape from evidence route |
| #74 | `5fb0b59` | 2026-10-10 | +3/-1 | 2 (0) | no | fix: preserve REVIEW contract while rejecting boolean approval bypass |
| #75 | `75a1088` | 2026-10-11 | +4/-1 | 2 (0) | no | test: anonymous checkout status must not read execution records |
| #80 | `7479fba` | 2026-10-11 | +2/-1 | 2 (0) | no | security: IGOR rejects conflicting SHA, provider or model within the same run |
| #82 | `9f1e7ff` | 2026-10-11 | +1/-1 | 1 (0) | yes | Potential fix for code scanning alert no. 1: Use of a broken or weak cryptographic hashing |
| #83 | `04e1e18` | 2026-10-11 | +11/-1 | 9 (0) | no | fix: restore human review contract without permitting unknown risk |
| #84 | `be81319` | 2026-10-11 | +2/-1 | 2 (0) | no | test: reject truthy nonboolean approvals and malformed reviewers |
| #85 | `fd38ac2` | 2026-10-11 | +2/-1 | 2 (0) | no | test: replay rejects invalid sequence and hash field types |
| #86 | `61e0d62` | 2026-10-11 | +2/-1 | 2 (0) | no | test(intelligence): cover CVE provenance and fail-closed source handling |
| #91 | `543e4ac` | 2026-10-12 | +2/-0 | 2 (0) | no | test: reproduce and prevent cross-tenant hash chain acceptance |
| #92 | `51ff6b3` | 2026-10-12 | +2/-0 | 2 (0) | no | test: IGOR blocks null-result and spliced provenance |
| #93 | `d581991` | 2026-10-12 | +3/-0 | 2 (0) | no | test: reserved runtime keys and large evidence payloads fail closed |
| #94 | `9ca60c2` | 2026-10-12 | +2/-0 | 2 (0) | no | security: verify evidence chain, latest candidate and single-use approval at Human Gate |
| #97 | `4f45bfb` | 2026-10-12 | +2/-0 | 2 (0) | no | security: bind payment execution results to exact verified Stripe checkout session |

## Reproduce

```bash
git fetch --no-tags origin '+refs/pull/*/head:refs/remotes/prs/*'
scripts/pr_triage.sh main 103 > pr-triage.tsv
```
