# OLA + AI STUDIO 3.6.0: integracja zachowawcza

**Nie zastępuj OLA Core. Nie ruszaj `main`.** To pierwszy, testowalny krok integracji: istniejące Studio jest uruchamiane jako **osobny proces** na `127.0.0.1:8001`, a OLA Core pozostaje na `127.0.0.1:8000`. **Nie oznacza to wspólnego SSO, wspólnych tenantów ani jednej bazy dowodowej.**

## Poziom dowodów

- Oryginalny pakiet: `AI_STUDIO_3.6.0_FULL_AUTONOMOUS_EU_COMPLIANCE_PRODUCTION.tar.gz` (51 219 B).
- Przypięty SHA-256: `29b9c6614e8af1a702e01993e766240760ee55837f1a68d0d94925fb7f99d890`.
- Zweryfikowano 50 zwykłych plików wewnątrz archiwum. Oryginalne testy: 15/15 PASS lokalnie (Python 3.13); smoke FastAPI: `/`, `/api/health`, `/api/compliance/disclosure` HTTP 200.
- Nie dowodzi to działania produkcyjnej domeny, płatności ani zewnętrznych modeli.

## Uruchomienie na ZBook (Windows 11 + Docker Desktop + Python)

1. Umieść oryginalne archiwum obok `RUN-OLA-AI-STUDIO-360.ps1` i katalogu `scripts/` (nie wypakowuj go ręcznie do `Temp`).
2. W PowerShell: `powershell -ExecutionPolicy Bypass -File .\RUN-OLA-AI-STUDIO-360.ps1`.
3. Skrypt weryfikuje SHA i strukturę TAR przed ekstrakcją, nie nadpisuje istniejącej instalacji, uruchamia własny kontener bez uprawnień roota i potwierdza `http://127.0.0.1:8001/api/health`.
4. Otwórz `http://127.0.0.1:8001/`. Core nadal na port 8000.

**Staging tylko lokalny.** Kontener jest przypięty do loopback, sekret podpisujący musi być skonfigurowany osobno przed trybem `ENVIRONMENT=production`. W staging dane znajdują się w oddzielnym katalogu `data/`. `.env` jest tworzony z `.env.example` ze środowiskiem `development` i pustymi kluczami dostawców; nie włączaj publicznych płatności przed osobnym E2E.

## Otwarte bramy (NO-GO dla pełnej produkcji)

- Wspólny model uwierzytelniania i tenantów OLA↔Studio.
- Scentralizowane Evidence NINA→IGOR, replay, podpisy, źródła i tożsamość wdrożenia.
- Reverse proxy HTTPS i konfiguracja produkcyjnej domeny.
- PostgreSQL, kopie zapasowe, test odtwarzania, rate limit globalny.
- Prawdziwe end-to-end płatności i audyt zgodności prawnej.
- Weryfikacja LIVE na docelowym ZBook/hostingu.

*Ten bridge jest stanem PARTIAL, nie gotową zunifikowaną produkcją.*