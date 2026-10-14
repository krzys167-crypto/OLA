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
