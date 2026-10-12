# OLA DI-OS — API key v2 controlled rotation (NO-GO until owner runs)

**Scope:** legacy `ApiKey.key_hash = SHA256(raw)` → deterministic PBKDF2-HMAC-SHA256 (310,000 iterations) with a REQUIRED per-deployment high-entropy `OLA_API_KEY_PEPPER`. The new verifier has **no SHA-256 fallback**. The stored digest remains 64 lowercase hex chars; SQLite table shape, key IDs and tenant IDs are preserved.

## Dependencies and decision

1. Stop **all** writers to the SQLite database, including Docker instances, webhook workers and agents. Inventory the actual database. This repo's current `app/database.py` points to SQLite at `OLA_EG_DB_PATH` (default `ola.db`); **do not apply these steps to Supabase/PostgreSQL**.
2. Back up the entire SQLite database to a restricted location independently before any changes. Create a new, unpredictable pepper for the environment, e.g. `openssl rand -hex 32`, and store it in a secret manager accessible to the OLA process. **Never** use the public `CI-ONLY-...` test pepper in production.
3. Perform a dry run: `python scripts/reissue_api_keys_v2.py --db /data/ola.db --backup /secure/ola-pre-v2.db --receipt /secure/new-keys.json` (no changes).
4. Only on an offline, review-approved copy, rotate all credentials:
   `python scripts/reissue_api_keys_v2.py --db /data/ola.db --backup /secure/ola-pre-v2.db --receipt /secure/new-keys.json --apply --runtime-stopped`.
5. The script makes its own consistent SQLite backup and a **0600 token receipt**, creates cryptographically random new tokens, and updates all `api_keys.key_hash` values transactionally while retaining `api_keys.id` and `tenant_id`. It prints only counts/status, never tokens. This is intentionally a **breaking credential rotation**; old keys stop working.
6. Deliver each new token to its rightful tenant via an authenticated, encrypted private channel. Do not upload key receipts, backup database, or `OLA_API_KEY_PEPPER` to GitHub or CI artifacts. Delete key receipts only after each recipient confirms.
7. Validate old tokens are refused and new tokens work per tenant; include cross-tenant denial, concurrent worker, restart, Human Gate reviewer separation, and rollback/recovery exercises using synthetic accounts. Start the new app with the same deployment pepper; losing/changing the pepper makes all keys invalid.
8. Only after signed-GitHub source binding, signature-fingerprint allowlist, protected `main`, reviewed CI, and human approval may a controlled production cutover be authorized.

**Safe rollback:** before accepting any new production writes, stop all writers and restore the offline full-database backup. Once new business writes occur, do NOT roll back a whole SQLite file blindly; use a reviewed forward-recovery plan, as rollback would lose accepted evidence/payments.

**CI policy:** workflows intentionally set the documented **public, disposable CI test pepper** to keep deterministic isolated Docker tests reproducible. This is never a production secret and must not be copied to LIVE deployments.

## Verification requirements

- Missing or short pepper **fails closed**, with no legacy SHA fallback.
- Legacy hashes are not accepted by the new runtime. A pre-cutover key reissue is mandatory, not optional.
- Dry-run is read-only and must not create backup/receipt.
- Reissue preserves tenant and key IDs, emits new random tokens to a private file, makes SQLite backup, and never logs tokens.
- Repeat E2E, Ollama, CodeQL, Evidence, Replay, integrity and production-artifact workflows on exact candidate SHA.
- Commit/PR must be GitHub/GPG verified by an authorized owner; independent reviewer, registered trust allowlist and active `main` ruleset remain separate requirements.

**State until operator has performed actual rotation and validated the live environment: STAGED / NO-GO.**
