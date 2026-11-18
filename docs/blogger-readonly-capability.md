# OLA Blogger read-only capability v1

## Scope
- Google Blogger API v3 `blogs.get` only.
- Numeric blog ID and fixed HTTPS Google API endpoint.
- No publish, edit, delete, arbitrary URL, arbitrary method, shell, or arbitrary outbound destination.
- API key comes from `GOOGLE_BLOGGER_API_KEY` and is sent in `X-Goog-Api-Key`.
- No API key or upstream response body is returned or logged.
- Upstream response bytes are streamed and capped at 65,536 bytes before JSON parsing.

## NINA integration
The capability is centrally registered in `app.nina.REGISTERED_CAPABILITIES`. The default `NinaOrchestrator` includes this registry alongside generic tools. Its generic `execute()` returns `DISPATCH_REQUIRED` for dedicated capabilities instead of sending them to `run_agent_task`. The Blogger dispatcher invokes the bounded adapter directly after NINA's central allow-list decision.

## Evidence and IGOR
The dispatcher appends start/result/end events to the existing tenant-scoped `pipeline_bridge` hash chain. It then calls `IgorVerifier.verify_capability_records`, a dedicated non-agent evidence contract that checks the full tenant chain, tenant scope, exact current-run event order, run binding, and blog ID binding. It does not fabricate LLM/provider/model provenance for a non-LLM API call.

Blogger-specific checks additionally validate tool binding, fixed `blogs.get` operation, returned blog identity, HTTPS URL shape, and result digest. `VERIFIED` means local chain and semantic checks passed. It does not prove Google cryptographically signed the response or that blog content is true/current.

## Human Gate
A successful metadata read ends at `REVIEW_REQUIRED`. A separate `POST /blogger/review` endpoint accepts exactly:
`run_id`, `blog_id`, `human_approved` (JSON boolean), `human_actor`, and `human_reason`.

The endpoint re-verifies the original Blogger evidence, passes only a `VERIFIED` candidate to the existing `HumanGate.evaluate`, and appends one immutable `blogger.human_review` event to the same tenant chain. Duplicate review for a run is rejected. An approval returns `HUMAN_APPROVED`; rejection or failed verification returns `BLOCK`. Both outcomes explicitly return `execution: NOT_PERFORMED`. Human approval does not authorize Blogger writes or arbitrary execution.

**Identity limitation:** the current endpoint authenticates the tenant API key, but `human_actor` is caller-attested text, not independently authenticated reviewer identity or a second factor. Therefore this is an auditable HumanGate decision record, not proof that a named human personally approved it. Production use still requires binding review authority to an authenticated principal/role and an independently controlled credential or approval channel.

## Configuration
Set `GOOGLE_BLOGGER_API_KEY` in the server secret store. Never commit `.env` or the key. Restrict the key to Blogger API v3 and the expected server environment where supported.

## Validation
Run `python -m compileall -q app tests` and `pytest -q`. Adapter tests should use mocked HTTP only. A live smoke test requires an operator-supplied key and an explicitly chosen blog ID. CI must pass before merge; no production readiness is implied by this branch.
