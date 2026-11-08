# GitHub — plan metadanych dla wszystkich publicznych repozytoriów
Snapshot: 2026-11-09 · **PROPOZYCJE, NIE ZMIANY WYKONANE**.

Ten dokument nie dowodzi działania usług. Opisy i topics wymagają ręcznej zmiany w **Settings → General / About**. Połączenie GitHub użyte do tego PR nie udostępnia funkcji edycji opisu, tematów ani homepage repozytorium.

| Repo | Proponowany opis (maks. 160 znaków) | Topics (propozycja) | Homepage |
|---|---|---|---|
| [OLA](https://github.com/krzysztofcieciwa07-ship-it/OLA) | OLA di-OS core: FastAPI execution gates, evidence records, agent workflows and reproducible verification (development). | `ola-dios`, `fastapi`, `evidence`, `ai-agents`, `security` | Zostawić puste, dopóki publiczne API/portal nie przejdzie testów. |
| [vantage](https://github.com/krzysztofcieciwa07-ship-it/vantage) | Vantage: experimental deny-by-default execution and provenance verification gate for OLA di-OS. | `ola-dios`, `security-gate`, `provenance`, `prototype` | Brak zweryfikowanego serwisu, pozostawić puste. |
| [ola-evidence-gateway](https://github.com/krzysztofcieciwa07-ship-it/ola-evidence-gateway) | OLA Evidence Gateway specification and evidence model (documentation only, not a running service). | `ola-dios`, `specification`, `evidence`, `documentation` | **Usunąć** niepowiązany adres pogodowy; nie zastępować niezweryfikowaną domeną. |
| [quantum-ai-chatbot](https://github.com/krzysztofcieciwa07-ship-it/quantum-ai-chatbot) | Experimental Supabase-backed AI chatbot fork; separate from OLA's NOVA communicator. | `chatbot`, `supabase`, `experimental`, `fork` | Pozostawić tylko po przetestowaniu aktualnego adresu. |
| [ai](https://github.com/krzysztofcieciwa07-ship-it/ai) | Fork of AI SDK for TypeScript — upstream research/reference; not an integrated OLA service. | `ai-sdk`, `typescript`, `fork`, `reference` | Zachować stronę oficjalnego projektu z oznaczeniem pochodzenia. |
| [cli](https://github.com/krzysztofcieciwa07-ship-it/cli) | Fork of GitHub CLI — external development tool, not OpenAI Codex CLI. | `github-cli`, `golang`, `fork`, `reference` | Zachować URL oficjalnego GitHub CLI. |
| [MetaGPT](https://github.com/krzysztofcieciwa07-ship-it/MetaGPT) | Fork of MetaGPT multi-agent framework — research/reference, not verified as an OLA runtime. | `metagpt`, `multi-agent`, `fork`, `reference` | Zachować tylko jeśli strona nadal odpowiada aktualnemu upstream. |
| [swarmclaw](https://github.com/krzysztofcieciwa07-ship-it/swarmclaw) | Fork of SwarmClaw agent runtime — reference implementation, not verified as an OLA module. | `agents`, `runtime`, `fork`, `reference` | Zachować oficjalny adres upstream. |
| [uygulamali-kriptografi](https://github.com/krzysztofcieciwa07-ship-it/uygulamali-kriptografi) | Fork of an applied cryptography learning project (Rust and mdBook). | `cryptography`, `rust`, `mdbook`, `education`, `fork` | Puste, chyba że strona podręcznika zostanie potwierdzona. |

## Przed zatwierdzeniem zmian

- Zweryfikować każdy proponowany opis z rzeczywistym zakresem kodu oraz zgodnością z licencją/upstream.
- Nie usuwać, nie archiwizować, nie zmieniać domyślnej gałęzi i nie synchronizować forków automatycznie.
- Utrzymać 2 samodzielne repozytoria OLA/vantage jako priorytet, a forki jako oddzielne źródła zależności.
- Oddzielnie udokumentować wynik bezpieczeństwa projektu chatbota: publiczny `.env` nie powinien przechowywać sekretów serwerowych; wskazany plik zawierał nazwane pola klienta Supabase, ale to nie zastępuje audytu Git historii.
- Nie promować "10/10" na podstawie samego uporządkowania GitHub.

## Repozytoria przypięte na profilu — sugestia

1. OLA — rdzeń.
2. vantage — kontrola wykonania.
3. ola-evidence-gateway — tylko jeśli opis jasno mówi "documentation-only".
4. quantum-ai-chatbot — tylko po kontroli bezpieczeństwa i ustaleniu odrębnej roli.

Pozostałe forki są dostępne w zakładce Repositories; nie trzeba ich prezentować jako własnych modułów OLA.

Powiązane: [katalog repozytoriów](REPOSITORY_CATALOG.md) · [rejestr JSON](REPOSITORY_CATALOG.json).
