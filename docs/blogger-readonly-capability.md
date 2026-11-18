# OLA Blogger read-only capability v1

## Scope
- Google Blogger API v3 `blogs.get` only.
- Numeric blog ID and fixed HTTPS Google API endpoint.
- No publish, edit, delete, arbitrary URL, arbitrary method, shell, or arbitrary outbound destination.
- API key comes from `GOOGLE_BLOGGER_API_KEY` and is sent in `X-Goog-Api-Key`.
- No API key or upstream response body is returned or logged.
- Upstream response bytes are streamed and capped at 65,536 bytes before JSON parsing.

## OLA integration boundary
`app/blogger_capability.py` is a dedicated capability dispatcher. The capability is registered in the central `app.nina.REGISTERED_TOOLS` allow-list; the dispatcher uses the default `NinaOrchestrator` and cannot extend the registry locally. It calls the fixed adapter and appends start/result/end events using the existing `pipeline_bridge` tenant evidence chain.

It deliberately does not call `NinaOrchestrator.execute()`: that method sends allowed tasks to the general agent runtime and is not a tool-specific adapter dispatcher. The existing `/nina-run` endpoint is not modified. Blogger is exposed through the separate authenticated `POST /blogger/metadata` route.

## Verification meaning and remaining gates
`verify_blogger_evidence` verifies the tenant hash chain, exactly three ordered events for the current run, current-run tenant binding, blog/run/tool binding, fixed operation, identity fields, and result digest. `VERIFIED` means only that these local integrity/consistency checks pass. It does not prove Google cryptographically signed the response or that blog content is true/current.

**IGOR is not yet integrated with this Blogger event schema.** The existing `IgorVerifier` requires agent-runtime provenance fields (such as source commit, task, result, and optionally provider/model/nonce). Blogger events do not contain that provenance contract; passing them to IGOR with fabricated values would create a false verification. A dedicated, reviewed evidence contract or a safe adapter into IGOR is required before claiming full IGOR verification.

Successful reads end at `REVIEW_REQUIRED`. This capability does not create a review request or collect a human decision. The existing `HumanGate.evaluate` requires an explicit `ReviewDecision` with a non-empty actor and a real boolean approval; the metadata endpoint has no such input and therefore cannot approve. A separate authenticated review workflow with reviewer authorization, immutable decision evidence, and replay protection is required before the Human Gate can be called end-to-end.

No automatic approval, publishing, or write operation is available.

## Configuration
Set `GOOGLE_BLOGGER_API_KEY` in the server secret store. Never commit `.env` or the key. Restrict the key to Blogger API v3 and the expected server environment where supported.

## Validation
Run `python -m compileall -q app tests` and `pytest -q`. Adapter tests should use mocked HTTP only. A live smoke test requires an operator-supplied key and an explicitly chosen blog ID. CI must pass before merge; no production readiness is implied by this branch.
