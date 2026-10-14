# OLA DI-OS — Five-layer architecture and Command Center integration

**Scope:** Existing OLA repository, stacked DRAFT PR #103 on PR #102. This is an evidence-based implementation map, **not** a certification or declaration that the ZBook has been updated.

## Canonical layers and evidence boundaries

| Layer | Existing implementation | Operational surface in Command Center | Proof and remaining gaps |
|---|---|---|---|
| **L1 Evidence Chain** | `app/hashchain.py`, `app/models.py`, SQLite append-only triggers in `app/database.py`, `app/replay.py`, Evidence Graph v0.1 | Tenant-scoped `GET /control/overview` verifies complete local chain; `GET /control/runs/{id}` reconstructs actual run replay and record hashes; individual `GET /evidence/{id}` | Local hash integrity does not establish externally signed source. Up to 5000 events are scanned; over that limit status **UNKNOWN**, never false VERIFIED. PostgreSQL multi-tenant production data store is a separate architecture milestone, not present in this runtime. |
| **L2 Policy Gate** | `app/execution_safety_gate.py`, `app/decision_report.py`, `app/nina_igor.py` | Last candidate policy status shown explicitly as **RECORDED**, not independently verified; blocked operations do not run | Full policy registry, roles and risk-level permissions for each host command need independent review and audit |
| **L3 Decision Core** | `app/main.py`, `app/decision_report.py`, `app/rules.py`, `app/hashchain.py` | `/nina-run` writes decision candidate with run ID, source declaration, tip hash and HUMAN_GATE:REVIEW; `/control/overview` shows recent candidate history | Correct source must be pinned to signed SHA at release; no claim that an unsigned commit or model declaration is independently attested |
| **L4 Multi-Agent Runtime** | `app/nina.py`, `app/agent_runtime.py`, `app/igor.py`, `app/agent_registry.py`, `app/chat_runtime.py` | NINA chat supports **configured Ollama or OpenAI** without fake answers. Six-agent execution + real provider provenance + IGOR + replay via `/nina-run`; outages now return BLOCK with `runtime.blocked` evidence. Local commands restricted to opt-in ZBook executor | Chat is **CHAT_ONLY**, not agent proof. Local Executor remains an independent Windows approval boundary, not unrestricted NINA shell access. Model availability needs actual host inference test |
| **L5 Governance** | `app/human_gate.py`, `/nina-run/{id}/approve`, `scripts/verify_github_signatures.py`, `.github/workflows/final-production-gate.yml`, signature docs | Operator key is verified by `GET /auth/session`; different approver key and fresh tip hash required; Command Center never promotes itself to production VERIFIED | Signature fingerprint allowlist, protected main, signed source commit, independent human approval, artifact attestation, on-device verification and signed production result are **not established by CI alone** |

## One system / two credentials / one local operational dashboard

- **OLA tenant API key:** issued by `scripts/provision_local_operator.py` only in a properly configured deployment with private `OLA_API_KEY_PEPPER`. Its v2 PBKDF2 hash is stored; raw credential is printed once. It permits authorized tenant API calls, **not Windows commands**.
- **Windows Local Executor token:** minted for one foreground PowerShell process on `127.0.0.1:18110`. Origin/Host checks, registered actions, one-shot confirmation for state-changing commands and a local JSONL execution journal. It is separate from the tenant key and cannot promote a Human Gate.
- **ZBook preview:** `127.0.0.1:18081`; original OLA `127.0.0.1:18080` untouched. `workstation/OLA-Preview-Auth.ps1` defaults to read-only; `-CreatePreview -ExpectedSha <40-hex> [-Model <already-listed-ollama-model>]` provisions a **new** missing preview with persistent Docker volume, fresh secret and pinned source. **Never** overwrites an existing container or volume. `-IssueKey` requires an existing configured preview.
- **No new ZIP packages:** all source remains in one GitHub branch / original controlled checkout.

## Implemented safety invariants

1. **No false VERIFIED:** model/runtime unavailable -> BLOCK; missing signed source -> release NO-GO; recorded status != independently verified attestation.
2. **No partial-chain verification:** every tenant read starts at genesis. Missing, oversized or corrupt local evidence returns UNKNOWN/BLOCK.
3. **No cross-tenant evidence disclosure:** API key resolves tenant ID; queries and ID lookups are tenant-scoped.
4. **No race on canonical evidence tip:** serialized SQLite `BEGIN IMMEDIATE` append writer used for chat, audit and six-agent records; append-only DB triggers remain.
5. **No fake model output:** Ollama/OpenAI chat sends actual provider request; on errors responds BLOCK; full NINA required-LLM outage adds a `runtime.blocked` record and returns BLOCK.
6. **No unsanctioned OS access:** local browser offers only registered commands; start/unpause preflights exact name, image, non-privileged config, loopback port and current state.
7. **No irreversible migration without proof:** pre-existing preview with missing pepper remains unchanged; backup, migration and rollback design required before replacement.
8. **No production payment or release action from Command Center:** Stripe endpoint existence does not prove LIVE transactions; registry publishing and merge remain distinct reviewed gates.

## Acceptance checks on exact staging SHA

- `python -m pytest -q tests/test_command_center_live_api.py tests/test_chat_provider_parity.py tests/test_nina_provider_outage.py tests/test_operator_onboarding.py`
- Whole `python -m pytest -q`, Docker build & health, browser AURORA E2E, Windows local executor HTTP negative tests.
- Real Ollama model availability and inference on the operator ZBook, startup with a **persistent** private SQLite volume and app-specific pepper, provisioning one operator key and verifying `/auth/session`.
- Actual tenant-specific NINA execution → evidence → independent IGOR → replay → human gate candidate; tamper, replay and concurrent writes must fail closed.
- Only after independent signature verification, source/image attestation and a second human review can signed production artifact/digest GO be discussed.

## Explicitly incomplete / not silently invented

- No verified existing ZBook migration, credential binding or model invocation at the time of writing. GitHub CI does not operate the physical machine.
- No public/remote access to Windows executor, arbitrary PowerShell, automatic NINA host execution, unattended deployments or universal API token.
- No working frontend services proven for **Files, CRM, Store**, or independently deployed **AI Studio 3.6**, CFR and NOVA in this PR. Their UI entries remain disabled or separately qualified until relevant contracts and running services can be verified.
- SQLite is the current running backend. The historically described PostgreSQL production implementation must be recovered and independently reconciled before any claim that it is serving this Docker image.
- Operator secrets, bank/Stripe credentials, customer data, source-signing keys and local environment state are not stored in GitHub documentation.

**Release decision: DRAFT / NO-GO until exact signed source, independent production gates and physical ZBook evidence.**
