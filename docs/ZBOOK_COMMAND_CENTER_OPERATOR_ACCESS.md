# OLA Command Center — ZBook operator access (staging only)

**Source:** stacked draft PR #103 (based on PR #102). Never promote unsigned staging commits directly to `main`.

## Two separate authentication domains

- **OLA Core API:** `SETTINGS → X-API-Key → Zweryfikuj klucz` calls real read-only `GET /auth/session`, authenticated by the API. On success the panel displays **UWIERZYTELNIONY** for this session. The key is held in the browser input, not browser storage; closing/resetting clears it.
- **Local Executor:** `LOCAL EXECUTOR / ZBOOK → Token lokalny` authenticates the separate host-only bridge on `http://127.0.0.1:18110`, with its own ephemeral token printed in the bridge's foreground PowerShell. The Core key never confers Windows execution rights.

**NEVER paste either secret into ChatGPT, issues, log uploads, screenshots, commits or shared reports.** No universal default credential exists.

## Already-configured local preview: operator procedure

In PowerShell on the ZBook, using the locally checked-out **reviewed** PR #103 source (do not download a ZIP):

```powershell
$root = 'D:\OLA-Control\command-center-pr103'
& "$root\workstation\OLA-Preview-Auth.ps1"
```

This is **read-only** and verifies the exact container name, loopback port, running state, present `OLA_API_KEY_PEPPER` and installed provisioning module. If it prints **PREVIEW_AUTH_READY**, the operator can **explicitly** create one preview tenant and a high-entropy API key:

```powershell
& "$root\workstation\OLA-Preview-Auth.ps1" -IssueKey
```

The generated `X_API_KEY_ONCE` is displayed **only once** in the ZBook terminal and its PBKDF2-HMAC-SHA256-v2 digest is stored in SQLite under a new tenant. No other tenant is overwritten. Enter the key into the local browser's Settings, then click **Zweryfikuj klucz**. The test endpoint returns 200 for accepted credentials, 401 for invalid/missing credentials or 503 if the deployment pepper is missing. It never returns the raw key.

The command refuses duplicate creation for the default named tenant, so it cannot be used to silently reissue or reuse another tenant's key. Future key rotation and recovery need a dedicated authorized procedure.

## If the preview says AUTH_NOT_CONFIGURED

**Stop — do not run an older workstation installer or reset the database.**

The preview container's environment lacks a deployment-specific `OLA_API_KEY_PEPPER`. Docker container environment cannot safely be changed in place. A new image/configuration and container must be prepared with a unique secret and a persistent data volume, and the existing SQLite data must be transactionally backed up and restored under an approved, rollback-capable migration.

There is deliberately **no automatic container delete/recreate** in this procedure: the existing preview may hold evidence records. A previous preview run used `--tmpfs /data`, which can lose its contents if discarded or recreated.

The operator should collect **non-secret** readiness facts only and review the data migration separately. Do not disclose the pepper. The preview's `/health` returning 200 does not prove API-key authentication is usable.

## Local Executor startup

```powershell
& "$root\workstation\OLA-Local-Executor.ps1"
```

Use the displayed `LOCAL TOKEN` only inside the local Command Center. **Do not** reuse the OLA Core API key. The bridge process runs under your Windows account and stops with Ctrl+C.

Actions are fixed to the allowlist: Docker inventory, OLA container state, Ollama model list, WSL list, Git status and loopback health checks. Two guarded operations (`start`, `unpause`) require browser confirmation and a one-time server nonce, and now independently verify the exact image `ola-zbook-local:test`, port `127.0.0.1:18080`, non-privileged configuration and expected current state.

The journal is at `D:\OLA-Control\local-executor.jsonl` (or LocalAppData fallback). It records timestamps, exit codes and output hashes, **not independent or production verification**.

## Boundaries

- No arbitrary PowerShell, `cmd`, user-supplied arguments, `git push`, deployment, payment, signing or merge is exposed from the browser.
- A valid Core tenant API key does **not** authorize the Windows bridge.
- `ROUTE READY`, `API ONLINE` or `LOCAL_EXECUTED` do **not** imply NINA → IGOR → HUMAN GATE production verification.
- The currently running local containers are **not** updated by GitHub commits; after approval, sync and rebuild the preview against a pinned, reviewed SHA, with database backup and rollback.
- Production remains **NO-GO** pending original release gates and independent signing.


## New ZBook preview from scratch — ONLY if no preview exists

Existing data must take priority. First use the read-only check:

```powershell
$root = 'D:\OLA-Control\command-center-pr103'
& "$root\workstation\OLA-Preview-Auth.ps1"
```

If the result is `PREVIEW_NOT_FOUND`, `workstation/OLA-Preview-Auth.ps1` now has a **separate explicit** `-CreatePreview` mode. It is deliberately refused when the container or named data volume is already present, source SHA is unknown, working tree is dirty, Docker/Git/Ollama are missing, or selected model is not listed by host Ollama.

After the operator verifies that the local branch points to the **approved** full 40-hex source SHA:

```powershell
& "$root\workstation\OLA-Preview-Auth.ps1" -CreatePreview -ExpectedSha '<reviewed-source-sha>'
```

The command builds only a preview image locally, binds `127.0.0.1:18081:8000`, uses a new persistent named volume `ola-cc-preview-data` for `/data`, stores a fresh 48-byte cryptographic pepper in the current Windows account's restricted LocalAppData secret file, pins `OLA_RUNTIME_COMMIT`, and configures `OLLAMA_BASE_URL=http://host.docker.internal:11434`. It chooses an already-listed **local** Ollama model and sets `OLA_LLM_MODE=required` (errors BLOCK, no fake deterministic success). It does **not** pull a model or choose a cloud model automatically.

For a cloud model, an operator must explicitly name an available model after reviewing provider account and usage:

```powershell
& "$root\workstation\OLA-Preview-Auth.ps1" -CreatePreview -ExpectedSha '<reviewed-source-sha>' -Model 'gemma4:cloud'
```

`GET /health` is checked before reporting the preview created. This **does not** prove real model inference or production readiness. Then execute `-IssueKey` once on the existing, configured preview and verify via `GET /auth/session`.

**Never** use `-CreatePreview` to repair an existing preview. The earlier `--tmpfs /data` setup can contain important unexported database state; safe replacement requires operator-authorized snapshot/backup and a rollback plan. This script intentionally does not rename, delete, unpause, stop or overwrite an existing container or volume.

## Updated read-only Control Plane and provider details

- `GET /control/overview`: full tenant-local chain integrity, recent evidence events and run candidates, declared source SHA, configured LLM identity and explicit RELEASE NO-GO. **RECORDED** is not independently VERIFIED.
- `GET /control/runs/{run_id}`: rechecks tenant isolation, stored evidence hashes and replay; returns scope `LOCAL_HASH_AND_REPLAY_ONLY`, not signed release evidence.
- `/chat`: Ollama-first if configured, optional OpenAI via `OLA_CHAT_PROVIDER`; returns BLOCK when unavailable. `CHAT_ONLY` scope never authorizes a host command.
- `/nina-run`: required provider failures now return BLOCK with a `runtime.blocked` evidence record instead of unhandled HTTP 500, without pretending that a partial agent run succeeded.
- `LOCAL EXECUTOR`: 10 fixed Windows actions still require a separate local token and browser-origin checks; never substitute the OLA tenant key.

