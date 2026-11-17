# Katalog repozytoriów OLA di-OS — stan i źródło prawdy

Snapshot: **2026-11-12 11:54 UTC** · kontrolowane konto GitHub: **krzysztofcieciwa07-ship-it** · zakres: 9 repozytoriów publicznych tego konta oraz wskazane repozytoria powiązane z kontem **krzys167-crypto**.

> Ten dokument jest rejestrem pochodzenia i odpowiedzialności, nie deklaracją gotowości produktu. STATUS ≠ CI ≠ RUNTIME ≠ VERIFIED. Wartości SHA oraz liczby gałęzi/PR zostały odświeżone z GitHub API 2026-11-12 11:54 UTC. Nie wolno podejmować merge, usuwania repozytorium ani synchronizacji forków na podstawie samej nazwy.

## 1. Jedno źródło prawdy dla własnych produktów

| Produkt | Kanoniczne repozytorium | Główna gałąź / SHA | Gałęzie | Otwarte PR-y | Decyzja |
|---|---|---|---:|---:|---|
| OLA di-OS | [krzysztofcieciwa07-ship-it/OLA](https://github.com/krzysztofcieciwa07-ship-it/OLA) | main · e0b5ca8eefb58cb151f2dddf61552c201bacabad | 198 | 92 | **JEDYNE KANONICZNE REPO OLA** |
| Vantage | [krzysztofcieciwa07-ship-it/vantage](https://github.com/krzysztofcieciwa07-ship-it/vantage) | main · 991445100a3ddfae85bef0d0f9f7680373658d5f | 28 | 7 | **JEDYNE KANONICZNE REPO VANTAGE** |

Reguła od teraz: nowe zmiany OLA rozwijamy wyłącznie w kanonicznym repozytorium OLA, a Vantage wyłącznie w kanonicznym repozytorium Vantage. Drugie konto nie jest równoległym miejscem rozwoju. Nie oznacza to jednak, że każda jego gałąź jest zbędna — patrz sekcja 3.

### Stan porządku w repo OLA

- 198 gałęzi i 92 otwarte pull requesty (odczyt GitHub API, 2026-11-12 11:38 UTC). Żadna para otwartych PR-ów nie ma identycznego head SHA. W całym repo znaleziono 5 grup identycznych head commitów obejmujących 18 gałęzi; żadna z nich nie ma przypiętego otwartego PR-a. Kandydaci są wyszczególnieni w rejestrze JSON. Reguła repozytorium blokuje usuwanie refów, a dostępna integracja nie udostępnia operacji DELETE — gałęzie zachowano.
- Klasyczna ochrona `main` nie jest aktywna (`protected: false`). Aktywny ruleset 25853037 blokuje usuwanie gałęzi i force-push, ale nie wymaga niezależnego review ani obowiązkowych kontroli CI.
- PR #212 z ujednoliceniem standardu repozytorium został scalony 2026-11-11 do SHA `5e60c800b8135ad51aee6786396202e0c22d800e`. CI na tym SHA przeszło; nie jest to samo w sobie dowód wdrożenia produktu.
- Aktualny `main` to SHA `e0b5ca8eefb58cb151f2dddf61552c201bacabad`. Historyczny run `43203128596` wykazał `startup_failure`; naprawa uprawnień reusable workflow została scalona w PR #224, a run `43207319361` zakończył się `SUCCESS`. PR #226 dodał tenant-scoped `GET /evidence` z read-only i paginacją; przeszedł 21/21 kontroli i został scalony. Po scaleniu run `43210488311` ponownie potwierdził pełny przepływ 12h: preflight, Ollama/NINA, niezależny IGOR, atestację i fail-closed classification. To potwierdza konkretne przepływy runtime, nie całe wdrożenie produktu.

### Stan porządku w repo Vantage

- 28 gałęzi i 7 otwartych PR-ów (odczyt GitHub API, 2026-11-12 11:54 UTC). PR #15 zamknięto jako zastąpiony istniejącą polityką bezpieczeństwa w `main`; PR #13 zamknięto jako zastąpiony przez #14, który zawiera całą jego historię oraz 8 kolejnych commitów.
- Klasyczna ochrona `main` jest wyłączona (`protected: false`); nie znaleziono aktywnego rulesetu repozytorium.
- PR #32 ze standardem repozytorium i poprawką weryfikacji provenance został scalony 2026-11-11 do SHA `991445100a3ddfae85bef0d0f9f7680373658d5f`. `Vantage Verify`, niezależny verifier provenance i CFR-18 przeszły na `main`.
- PR #19 pozostaje otwarty jako Draft. Pozostałe PR-y i gałęzie CFR-18 wymagają klasyfikacji przed zamknięciem lub usunięciem.

## 2. Dziewięć publicznych repozytoriów na koncie kanonicznym

| Repozytorium | Pochodzenie | Rola | Rzeczywisty stan |
|---|---|---|---|
| [OLA](https://github.com/krzysztofcieciwa07-ship-it/OLA) | własne | rdzeń runtime OLA | kanoniczne; produkcja systemu nie jest potwierdzona |
| [vantage](https://github.com/krzysztofcieciwa07-ship-it/vantage) | własne | prototyp gate i CFR-18 | kanoniczne dla Vantage; nie deklarować jako produkt produkcyjny |
| [ola-evidence-gateway](https://github.com/krzysztofcieciwa07-ship-it/ola-evidence-gateway) | fork z krzys167-crypto | specyfikacja Evidence Gateway | 5 ścieżek w main; brak serwera, API, testów i kontenera |
| [quantum-ai-chatbot](https://github.com/krzysztofcieciwa07-ship-it/quantum-ai-chatbot) | fork z krzys167-crypto | eksperymentalny chatbot | osobny eksperyment; nie jest dowodem istnienia NOVA |
| [ai](https://github.com/krzysztofcieciwa07-ship-it/ai) | fork Vercel AI SDK | zewnętrzna referencja | nie jest modułem OLA |
| [cli](https://github.com/krzysztofcieciwa07-ship-it/cli) | fork GitHub CLI | zewnętrzna referencja | nie jest Codex CLI ani własnym CLI OLA |
| [MetaGPT](https://github.com/krzysztofcieciwa07-ship-it/MetaGPT) | fork MetaGPT | zewnętrzna referencja | brak potwierdzonej integracji z OLA |
| [swarmclaw](https://github.com/krzysztofcieciwa07-ship-it/swarmclaw) | fork SwarmClaw | zewnętrzna referencja | brak potwierdzonej integracji z OLA |
| [uygulamali-kriptografi](https://github.com/krzysztofcieciwa07-ship-it/uygulamali-kriptografi) | fork materiału edukacyjnego | edukacja / referencja | nie jest komponentem produkcyjnym OLA |

Konto ma także prywatne repozytorium Vantage-v0.3: jedną gałąź `main`, pojedynczy `README.md`, rozmiar repozytorium 0 KB i brak kodu źródłowego. To pusty placeholder, nie drugi aktywny projekt Vantage. Zachować do decyzji właściciela; nie rozwijać równolegle.

## 3. Drugie konto — forks i rozbieżne źródła

Podłączona instalacja GitHub obejmuje konto `krzysztofcieciwa07-ship-it`; repozytoria z prefiksem `krzys167-crypto` są widoczne jako pochodzenie części forków, ale nie mam potwierdzonego dostępu administracyjnego do tego konta. Nie zakładam, że należy ono do innej osoby ani że wolno je modyfikować. Poniżej opisuję tylko odczytane relacje — to nie jest pełna inwentaryzacja drugiego konta.

| Repozytorium drugiego konta | Relacja do kanonicznego repo | Odczyt / decyzja |
|---|---|---|
| [krzys167-crypto/OLA](https://github.com/krzys167-crypto/OLA) | fork kanonicznego OLA | **ROZBIEŻNE, NIE USUWAĆ**. main SHA d2dd11c8…; porównanie z kanonicznym main: 235 commitów ahead i 54 behind. Ma 179 ścieżek unikalnych względem kanonicznego drzewa, w tym cfr_scenarios/, governance/, ola_pipeline/, sales/, tools/ oraz requirements.lock. Wymaga selektywnego odzysku zmian, nie pełnego merge. Dodatkowo publicznie śledzi sales/prospects.csv (18 wierszy; kolumny obejmują contact, last_action i note) oraz docs/sales/sample z artefaktami i kopertami dowodowymi. To potencjalne dane osobowe/informacje handlowe: wartości nie były odczytywane ani publikowane; przed dalszym utrzymywaniem forka publicznie wymagany jest przegląd prywatności i historii. |
| [krzys167-crypto/vantage](https://github.com/krzys167-crypto/vantage) | fork kanonicznego Vantage | main jest 1 commit behind; 2 gałęzie. Traktować jako kopię historyczną, bez dalszego równoległego rozwoju. |
| [krzys167-crypto/ola-evidence-gateway](https://github.com/krzys167-crypto/ola-evidence-gateway) | niezależne repo źródłowe | main zawiera wyłącznie README. To specyfikacja, nie uruchamialny gateway. |
| [krzys167-crypto/quantum-ai-chatbot](https://github.com/krzys167-crypto/quantum-ai-chatbot) | źródło eksperymentalnego chatbota | osobna aplikacja, nie kanoniczna NOVA. |

### Zasady dla konta drugiego

1. Nie dodawać nowych funkcji do forków OLA/Vantage.
2. Nie synchronizować forków automatycznie.
3. Nie usuwać rozbieżnego forka OLA — najpierw spisać unikalne commity i odzyskać wartościowe części do kanonicznego repo przez osobne, sprawdzalne PR-y.
4. Po odzysku i zatwierdzeniu dopiero archiwizować stare kopie. Nie wykonywać destrukcyjnych operacji bez sprawdzenia, czy historia i gałęzie są zachowane.

## 4. .env w eksperymentalnym chatbotcie

Stan po naprawie bieżącej gałęzi forka (2026-11-09): w krzysztofcieciwa07-ship-it/quantum-ai-chatbot usunięto śledzony .env (commit 4c12c366…), zastąpiono wartości .env.example placeholderami (commit df217a2c…) i rozszerzono .gitignore o .env.* z wyjątkiem .env.example (commit f0f23fec…). Bieżące drzewo main nie zawiera .env. Poprzednie blob-y nadal pozostają w historii Git. W źródłowym repo krzys167-crypto/quantum-ai-chatbot nadal istnieją śledzone .env i .env.example. W źródłowym .env.example znaleziono wartości o formatach/cechach pasujących do poświadczeń Anthropic, Google OAuth, prywatnego klucza konta serwisowego Google oraz ElevenLabs. Nie testowano ich i nie ujawniano; ich aktywność jest UNKNOWN, ale należy je traktować jak publicznie ujawnione i obrócić. Źródłowy plik i historię Git musi naprawić właściciel drugiego konta po uzyskaniu dostępu. Nie kopiować ani nie używać tych wartości. Klucz VITE_SUPABASE_ANON_KEY jest przeznaczony dla klienta, ale nadal wymaga poprawnych RLS i ograniczeń projektu. Nie przypisywać chatbota do OLA ani NOVA.

## 5. Evidence Gateway — decyzja architektoniczna

Oba repozytoria Evidence Gateway zawierają dokumentację, nie działający serwis. Nie należy utrzymywać ich jako osobnego produktu lub backendu. Docelowo:
- specyfikacja i kontrakty pozostają w OLA/docs/;
- jeśli potrzebna będzie osobna usługa, musi powstać z realnym kodem, kontraktem API, testami, kontenerem, właścicielem i wdrożeniem;
- do tego czasu status: SPECIFICATION_ONLY.

## 6. Kolejność rzeczywistego porządkowania

1. **Najpierw odzysk forka OLA:** porównać 235 unikalnych commitów / dodatkowe katalogi i sporządzić listę zmian do odzyskania. Nie scalać całości.
2. **Potem ograniczyć OLA do jednego stosu integracyjnego:** zachować wyłącznie PR-y z aktualnym właścicielem, celem i kryteriami akceptacji; stare PR-y rozstrzygać jako merge, superseded lub closed, po kontroli ich unikalnych commitów.
3. **Usunąć tymczasowe gałęzie CI Vantage #20–30** po zabezpieczeniu potrzebnych artefaktów.
4. **Zostawić tylko dwa kanoniczne repozytoria produktowe:** OLA i Vantage. Evidence Gateway pozostaje specyfikacją w dokumentacji OLA; chatbot pozostaje osobnym eksperymentem.
5. Dopiero po tym zmieniać nazwy, archiwizować lub usuwać kopie i forki.

## 7. Standard dowodu

- SOURCE_PRESENT: kod znajduje się w repozytorium.
- CI_PASS: konkretne workflowy przeszły na konkretnym SHA.
- RUNTIME_VERIFIED: określona instancja i endpoint zostały sprawdzone w podanym czasie.
- RELEASE_ACCEPTED: kod, testy, provenance, niezależny review, deployment i krytyczne E2E są przypięte do tego samego SHA.

Nie wolno utożsamiać zielonego CI, otwartego PR, gotowego Preview ani obecności pliku z ukończonym produktem.


## Mapa odzysku rozbieżnego forka

Techniczna klasyfikacja 179 unikalnych ścieżek, ich zależności, ograniczenia CFR/Certificate Apocalypse, ryzyka prywatności i bezpieczna kolejność selektywnego odzysku znajduje się w [FORK_RECOVERY_MAP.md](FORK_RECOVERY_MAP.md).

## 8. Aktualna ochrona i standard pracy

- OLA: ruleset 25853037 blokuje deletion i non-fast-forward; brak wymaganych review i status checks. `main` nie jest oznaczony jako klasycznie protected.
- Vantage: brak aktywnych rulesetów; `main` nie jest oznaczony jako protected.
- Standard repozytoriów jest już w `main`: `CONTRIBUTING.md`, `docs/ENGINEERING_STANDARD.md`, `.github/PULL_REQUEST_TEMPLATE.md`, szablony issue, Dependabot i `.gitignore`.
- W Vantage workflow Actions zostały przypięte do niezmiennych SHA; niezależna weryfikacja provenance obsługuje podpisy PR (`refs/pull/<n>/merge`) i branch (`refs/heads/<branch>`).
- Brak ochrony `main` pozostaje ryzykiem administracyjnym. Nie mogę jej włączyć przez dostępne akcje GitHub w tej integracji; wymagane jest ustawienie reguł w GitHub Settings.
