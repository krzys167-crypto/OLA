# NINA Parallel DAG — Sprint Retro Facilitator

## Scope

Reusable feature module, **not** a second agent engine. The existing
`app.workflow_engine.WorkflowEngine(max_workers=2)` runs a reviewed four-node
DAG:

```
[linear: read closed cycle] ──┐
                             ├─> [synthesis: real LLM] ─> [document: Markdown]
[slack: read sprint] ────────┘
```

The two reads are independent and actually run in parallel. NINA owns the
allowed template; the structure is **not a generatively planned DAG**. The
existing IGOR verifier checks the *entire* tenant hash chain and the captured
DAG, while `app.igor_sprint_retro.verify_sprint_retro_records` independently
checks source references, exact time window, citations and document SHA-256.
Neither checker authenticates external providers or independently proves that
a cited message semantically supports the claim.

## Connected data and exact contract

Invoke `app.sprint_retro.run_sprint_retro` only from an authorized host with
real, least-privilege read-only Linear and Slack adapters, plus the existing
`append_record` / `read_tenant_evidence` callbacks. There are **no bundled
credentials** and no assumption that a ChatGPT-connected account is accessible
to the OLA server. Adapters must never publish, mutate issues or send messages.

- `linear_reader(cycle_id)` returns `{"cycle_id": "...", "closed": true,
  "tickets": [...]}`. Each item requires `id`, `title`, `url` (an actual
  Linear issue permalink), `outcome` (`shipped` / `slipped`),
  `cycle_time_hours` (nonnegative numeric or `null` if not independently
  derivable), and `rescoped` (a historical boolean from issue activity).
  Require real cycle and issue history before setting either duration or
  rescope; never infer these from current issue state.
- `slack_reader(channel_id, start, end)` returns `{"channel_id": "...",
  "messages": [...]}`; each message has an authentic
  `url` (Slack archive permalink), `text`, `sent_at` (offset-aware ISO 8601),
  and `reactions` (string list). The adapter must include relevant replies,
  not just root messages, and must exhaust its selected scoped pages or fail
  closed on partial retrieval, rate limits or permission errors. Sentiment
  signals such as "blocked", "surprised", "nice", or celebration emojis are
  inputs to analysis, not proof of the whole team's views.
- `synthesizer(tickets, messages)` is optional for the service API. When omitted,
  it invokes the existing configured **real** OLA LLM. Response JSON must have
  exactly `went_well`, `dragged`, `try_next_sprint` (each 3–5
  `{"text":"...", "refs":["https://..."]}` bullets), plus a single
  `process_change` and a `confidence` number 0–1. Every referenced URL must
  occur in the captured Linear or Slack data.

The engine limits source items and output size; a missing/incomplete source,
model failure, unknown evidence, invalid link, wrong cycle, wrong Slack channel,
out-of-window message, inconsistent chain or non-overlapping source reads
produces `BLOCK` (`RetroBlocked`) with **no released document**.

## Output and boundary

Success returns one `document` Markdown string, `document_sha256`, run ID
and IGOR report. The document has sections **Went well**, **Dragged**, and
**Try next sprint**, each with 3–5 inline source links, followed by one
proposed process change and a subjective confidence estimate.

`COMPLETED_UNVERIFIED` and `human_gate=NOT_APPROVED` are intentional:
verification covers captured integrity and linkage, NOT autonomous publishing,
real-world adoption, external provider attestation or deployment approval.
An accountable human checks the interpretation before circulating the draft.

This module has **no public HTTP route**, scheduler, automatic Slack send,
Linear write action or external document creation. An authorized host must
connect genuine readers and explicitly choose where to deliver the approved
Markdown document.

## Execution example (requires actual authorized reader implementations)

```python
from app.main import append_record, read_tenant_evidence
from app.sprint_retro import run_sprint_retro

result = run_sprint_retro(
    tenant_id=authenticated_tenant_id,
    requester_id=authenticated_requester_id,
    cycle_id=verified_closed_cycle_id,
    channel_id=allowed_team_channel_id,
    start=sprint_start_iso,
    end=sprint_end_iso,
    linear_reader=authorized_linear_adapter.read_closed_cycle,
    slack_reader=authorized_slack_adapter.read_signals,
    append=append_record,
    fetch_records=read_tenant_evidence,
)
# Draft content: result["document"]; no auto-publish.
```

## Verifications

`python -m pytest -q tests/test_sprint_retro.py`

CI: `.github/workflows/nina-parallel-dag.yml` on exact PR head, with
`tests/test_sprint_retro.py` added to the existing DAG suite.
No new workflow engine, PR, side-effectful connector, or production deploy.
