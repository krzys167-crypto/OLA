# OLA Project Continuity v1

## What exists and what this adds

Already in OLA: `scripts/state_continuity_runtime.py` and `.github/workflows/state-continuity.yml` test persistent runtime evidence checkpoints across a container restart. Do **not** replace them. This feature adds a Git-tracked *task index*, not another event store and not a substitute for Evidence Gateway, signatures or independent verification.

Source of truth: `.ola/continuity/registry.json`, reviewed via PR. Git history records changes. This initial ledger has `bootstrap_inventory_incomplete=true`; it is NOT an exhaustive account of historical OLA tasks and must not be presented as one.

## Data contract

Each task has a permanent `id`, `title`, `priority` (0 highest), `state` (TODO, IN_PROGRESS, BLOCKED, DONE), `verification` (UNVERIFIED, PARTIAL, BLOCKED, VERIFIED), `proof` and `watched_files` mapping file paths to SHA-256 hashes.

DONE + VERIFIED needs a 40-digit commit SHA, an actual GitHub Actions verification-run URL and hashes of relevant watched source files. The CLI checks *format*, not the truth of a GitHub link or independence of the verifier; an operator must independently examine the run, commit and signatures. Existing branch progress is not production GO.

- SKIP: DONE/VERIFIED and relevant watched hashes match; do not re-execute.
- REVERIFY: DONE/VERIFIED but watched hashes differ or files are missing; investigate changed inputs, do not automatically reimplement.
- BLOCKED: blocked task; never execute from a generic "dalej".
- RUN: unfinished task; resume using existing checkpoint.
- NONE: no eligible task in the current, potentially incomplete inventory.

## Commands

Requires Python 3.9+ (standard library), works with PowerShell, Docker or CI:

```powershell
python scripts/project_continuity.py status
python scripts/project_continuity.py next
python scripts/project_continuity.py check OLA-CONT-001
python scripts/project_continuity.py add OLA-NEW-001 --title "New task" --priority 2
python scripts/project_continuity.py set OLA-NEW-001 --state IN_PROGRESS
```

After **independent CI review** and only with real data:

```powershell
python scripts/project_continuity.py set OLA-NEW-001 --state DONE --verification VERIFIED --source-commit <40-char-commit-sha> --verification-url https://github.com/krzysztofcieciwa07-ship-it/OLA/actions/runs/<actual-run-id> --watch scripts/project_continuity.py --watch tests/test_project_continuity.py
```

Do not call a run VERIFIED solely because its link looks valid. Commit ledger updates through reviewed PR. Verified tasks cannot be reopened without `--reopen-reason`. A new chat must read fresh state and fetch earlier evidence before proposing changes; if the inventory is incomplete, search repo history/PRs before creating any allegedly new work. Instructions for ChatGPT Project: `docs/CHATGPT_PROJECT_INSTRUCTIONS.md`.

## Checks

```bash
python3 -m unittest discover -s tests -p 'test_project_continuity.py' -v
python3 scripts/project_continuity.py status
python3 scripts/project_continuity.py next
```

CI workflow: `.github/workflows/project-continuity.yml`.

## Known limitations

This ledger is versioned in Git, not locked for distributed writers; concurrent editors require Git PR conflict resolution. GitHub Actions URLs are not independently authenticated by the CLI. The initial inventory is incomplete and new ChatGPT chats do not fetch external files unless tooling and project instructions are available. Production-grade next step is API idempotency keys, true distributed write fencing and external cryptographic attestation. Full historical reconciliation must be independently reviewed before changing `bootstrap_inventory_incomplete` to false.
