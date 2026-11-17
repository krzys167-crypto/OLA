# OLA — lokalne staging i odtworzenie Evidence

To jest rzeczywisty test kontenera Docker, ale **nie publiczne wdrożenie**. Listener jest ograniczony do `127.0.0.1:18080`. Test używa syntetycznego tenanta i tymczasowego wolumenu.

## Uruchomienie

Wymagane: Docker Engine + Compose v2, Python 3.12+, Git.

```bash
export OLA_RUNTIME_COMMIT="$(git rev-parse HEAD)"
export OLA_API_KEY_PEPPER="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export OLA_EVIDENCE_V4_ACTIVE_KEY_ID="staging-local-ephemeral"
export OLA_EVIDENCE_V4_KEYRING_JSON="$(python -c 'import base64,json,secrets; print(json.dumps({"staging-local-ephemeral":base64.b64encode(secrets.token_bytes(32)).decode()}))')"
python scripts/staging_rehearsal.py
unset OLA_API_KEY_PEPPER OLA_EVIDENCE_V4_KEYRING_JSON OLA_EVIDENCE_V4_ACTIVE_KEY_ID
```

Pepper i klucz V4 są jednorazowe, losowe i przeznaczone wyłącznie do lokalnego stagingu; nie trafiają do artefaktu. Nie używaj ich w produkcji. Skrypt sprawdza czysty checkout, dokładny SHA, build-info w obrazie, /readyz, auth 401, syntetyczny audit, pełny hash-chain, blokadę mutacji, restart, backup SQLite do snapshotu, restore do osobnej bazy, integrity_check i stabilność health przez 12 sekund. Wynik PASS powstaje dopiero po poprawnym usunięciu testowego wolumenu.

## Granice

`READY` oznacza wyłącznie gotowość lokalnego CORE. `system_acceptance` pozostaje `NOT_VERIFIED`. Nie jest to dowód TLS/public DNS, hostingu produkcyjnego, zewnętrznego backupu, MFA, monitoringu SLO, rollbacku produkcji ani realnego obciążenia klientów.
