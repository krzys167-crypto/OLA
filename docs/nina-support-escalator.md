# Support-to-Engineering Escalator — NINA Parallel DAG module

## Existing engine, reviewed graph

This module **reuses** the existing `app.workflow_engine.WorkflowEngine`.
There is no second agent scheduler, no new production endpoint and no
unrestricted shell execution.

```
Intercom conversation (read-only)
      ├──> isolated repro attempt ───┐
      └──> GitHub code search ────────┤  parallel after input
                                     └─> Jira candidate (no write)
                                              |
                                              v
                              independent IGOR checks full evidence
                                              |
                           +------------------+--------------------+
                           |                                       |
                    CANNOT_REPRODUCE                      REPRODUCED_DRAFT
                   attempts, no Jira                    explicit human/host
                                                         authorization gate
                                                                |
                                             Jira create-or-get by stable key
                                                                |
                                                Slack internal escalation
                                                                |
                                                   Intercom internal note
                                                                |
                                                  Intercom mark escalated
```

The four-node template is **reviewed and deterministic**, not an arbitrary
model-generated plan. Repro and code search start independently after an
authenticated conversation read. Their wall-clock overlap is measured and
reported; no measured overlap is claimed when callbacks complete instantly.

## Configuration and real-provider boundaries

Call `run_support_escalation` from an authenticated tenant-scoped host. Provide:

* `intercom_reader(conversation_id)`: a genuine authorized Intercom read,
  including conversation ID, permalink, plan tier, version/platform context,
  support report, original steps, support notes and **digests** of log/screenshot
  attachments. Customer names, raw logs, secrets and screenshot bytes should
  not be placed into this append-only evidence chain.
* `repro_runner(safe_conversation)`: must run in a restricted *ephemeral*
  container with no production credentials, network/mount access limited to
  approved fixtures, resource caps and **strictly allowlisted test commands**.
  Do **not** interpolate or execute customer-provided steps as shell commands.
  Returns `reproduced`, exact attempted commands or HTTP requests, and the
  exact trigger/expected/observed outcome and sha256 of captured evidence if
  reproduced. Unreproduced attempts must say so.
* `code_searcher(safe_conversation)`: read-only code search against a
  pinned repository SHA, with a grounded GitHub source permalink for the
  suspected component. Do not invent a culprit when code evidence is missing.
* `append` and `fetch_records`: the existing `app.main.append_record`
  and `app.main.read_tenant_evidence` callbacks, with the tenant and source
  SHA pinned. Connector-specific wire clients are intentionally not bundled;
  ChatGPT plugin connections do **not** automatically transfer credentials to
  OLA's runtime.

The exact accepted dictionaries are covered by
`tests/test_support_escalator.py`. The capture deliberately limits content
sizes and stores attachment digests rather than raw log bytes. It records
support report text, so hosts must redact secrets and personal data **before**
calling the module. The local hash chain is not a privacy boundary.

## Independent gate and non-repro cases

`app.igor_support_escalation.verify_escalation_records` is an independent
reader; it never calls the repro runner or Jira. It verifies the full tenant
hash chain, source SHA, DAG dependencies, linked source records, reproduction
attempts, cited source path, candidate content and timing evidence. Its
`VERIFIED` scope is **LOCAL_HASH_CHAIN_AND_CAPTURED_RUNTIME_EVENTS** with
captured source links, not authenticated Intercom/Jira provider facts, nor
independent proof that the container truly ran the claimed command.

`CANNOT_REPRODUCE` returns exact attempts and observed results; `jira_draft`
is `None`; **no Jira issue is created**. Source mismatch, unsigned/untrusted
data, missing evidence, unknown component or IGOR failure block the result.

## External write handoff (explicit, non-automatic)

`publish_escalation(candidate, authorized=True,
evidence_reader=read_tenant_evidence, jira_create_or_get=...,
slack_post_once=..., intercom_note_once=..., intercom_mark_once=...)`
first **re-reads and re-verifies** the exact run evidence, source commit, chain
tip and unchanged Jira draft. It refuses mutated/stale candidates and
unreproduced cases. Without approval or a callable authorized adapter, no
writes occur.

Provider adapters must enforce permission checks, approved Jira project and
Slack channel, secrets isolation and provider-backed **atomic idempotency**
under the supplied stable correlation/stage key. Jira creation must be
`create_or_get` (not blind create), and Slack/Intercom operations must be
`*_once` using a persistent dedup mechanism. There is no generic universal
idempotency primitive in remote services; provide it at the adapter boundary.

Writes are ordered Jira → Slack → Intercom internal note → mark escalated.
If any stage fails, code reports partial completion and the correlation key.
Do not retry blindly: reconcile provider state first to avoid duplicate
tickets/messages. Returning receipts does not constitute external
independent attestation.

Publishing is **not invoked automatically** by `run_support_escalation`.
This module does not grant GitHub reviewer approval, run CI merge, push main,
perform production deployment or impersonate a human reviewer.

## Current integration status

- Library runtime and unit fixtures can run without account connection.
- Intercom, Jira and Slack **server adapters are unconnected** until an
  authorized operator configures them. Do not claim customer tickets were read
  or actually reproduced.
- No concrete conversation ID or engineering Jira project is configured.
- Only unit tests reproduce a synthetic bug and issue handoff with mocks;
  never call this a real customer escalation.
- The final output is a source-grounded Jira candidate or explicit
  `CANNOT_REPRODUCE`. A real Jira issue + Slack note + Intercom update require
  the exact adapters and authorization described above.

Run the existing DAG test suite via
`python -m pytest -q tests/test_support_escalator.py`.
