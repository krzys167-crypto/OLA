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

## Human Gate — remaining blocker
Successful reads end at `REVIEW_REQUIRED`. The capability does not create a review request or collect a human decision. The existing `HumanGate.evaluate` requires an explicit `ReviewDecision` with a non-empty actor and a real boolean approval; the metadata endpoint has no such input and therefore cannot approve. A separate authenticated review workflow with reviewer authorization, immutable decision evidence, and replay protection is still required before Human Gate can be called end-to-end.

No automatic approval, publishing, or write operation is available.

## Configuration
Set `GOOGLE_BLOGGER_API_KEY` in the server secret store. Never commit `.env` or the key. Restrict the key to Blogger API v3 and the expected server environment where supported.

## Validation
Run `python -m compileall -q app tests` and `pytest -q`. Adapter tests should use mocked HTTP only. A live smoke test requires an operator-supplied key and an explicitly chosen blog ID. CI must pass before merge; no production readiness is implied by this branch.
