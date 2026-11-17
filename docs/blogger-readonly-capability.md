# OLA Blogger read-only capability v1

## Scope
- Google Blogger API v3 blogs.get only.
- Numeric blog ID and fixed HTTPS Google API endpoint.
- No publish, edit, delete, arbitrary URL, arbitrary method, shell, or arbitrary outbound destination.
- API key comes from GOOGLE_BLOGGER_API_KEY and is sent in X-Goog-Api-Key.
- No API key or upstream response body is returned or logged.

## OLA integration boundary
app/blogger_capability.py is a dedicated capability dispatcher. It asks NINA's allow-list to authorize blogger.read_metadata, calls the fixed adapter, and appends start/result/end events using the existing pipeline_bridge tenant evidence chain.

It deliberately does not call NinaOrchestrator.execute(): the current method sends every allowed task to the general agent runtime, not a tool-specific dispatcher. The existing /nina-run endpoint is not modified by this change. A separate authenticated FastAPI route and request schema require a follow-up review.

## Verification meaning
verify_blogger_evidence checks the existing tenant hash chain, event order, run/blog binding, fixed operation, and result digest. VERIFIED means only that local evidence checks pass. It does not prove Google cryptographically signed the response or that blog content is true/current.

Successful reads end at REVIEW_REQUIRED. There is no automatic approval, publishing, or write operation. Human approval must use the existing HumanGate separately.

## Configuration
Set GOOGLE_BLOGGER_API_KEY in the server secret store. Never commit .env or the key. Restrict the key to Blogger API v3 and the expected server environment where supported.

## Validation
Run python -m compileall -q app tests and pytest -q. Adapter tests should use mocked HTTP only. A live smoke test requires an operator-supplied key and an explicitly chosen blog ID.
