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

Blogger-specific checks additionally validate tool binding, fixed `blogs.get` operation, returned blog identity, HTTPS URL shape, result digest, and the initiating API-key principal. `VERIFIED` means local chain and semantic checks passed. It does not prove Google cryptographically signed the response or that blog content is true/current.

## Review gate and identity boundary
`POST /blogger/review` calls the existing `HumanGate.evaluate` only after re-verifying the original Blogger run. The review request must use a different API key from the key that initiated the run. The reviewer identity is derived from the authenticated API-key record; caller-supplied actor names are rejected. A deterministic evidence ID makes the review event one-time even when requests race. The review event is appended to the tenant chain.

**Important limitation:** an API-key principal is not proof of a natural person's identity or authority. The current schema has no user/role mapping for API keys. The result is therefore labelled as approval by a separate authenticated key, not as verified human identity. Before production, add an identity provider or reviewer-role mapping, explicit authorization policy, and audit of key issuance/revocation. Until then, keep the system in `REVIEW_REQUIRED` for any workflow that requires legally attributable human approval.

No automatic Blogger write, publishing, or external execution is available. The review endpoint records a decision only; it does not execute any subsequent action.

## Configuration
Set `GOOGLE_BLOGGER_API_KEY` in the server secret store. Never commit `.env` or the key. Restrict the key to Blogger API v3 and the expected server environment where supported.

## Validation
Run `python -m compileall -q app tests` and `pytest -q`. Adapter tests should use mocked HTTP only. A live smoke test requires an operator-supplied key and an explicitly chosen blog ID. CI must pass before merge; no production readiness is implied by this branch.
