# Katalog repozytoriów OLA di-OS — stan i źródło prawdy

Snapshot: **2026-11-09** · kontrolowane konto GitHub: **krzysztofcieciwa07-ship-it** · zakres: 9 repozytoriów publicznych tego konta oraz wskazane repozytoria powiązane z kontem **krzys167-crypto**.

> Ten dokument jest rejestrem pochodzenia i odpowiedzialności, nie deklaracją gotowości produktu. STATUS ≠ CI ≠ RUNTIME ≠ VERIFIED. Wartości SHA i liczby gałęzi/PR są migawką z 2026-11-09. Nie wolno podejmować merge, usuwania repozytorium ani synchronizacji forków na podstawie samej nazwy.

## 1. Jedno źródło prawdy dla własnych produktów

| Produkt | Kanoniczne repozytorium | Główna gałąź / SHA | Gałęzie | Otwarte PR-y | Decyzja |
|---|---|---|---:|---:|---|
| OLA di-OS | [krzysztofcieciwa07-ship-it/OLA](https://github.com/krzysztofcieciwa07-ship-it/OLA) | main · 6dff9c43ccd5a6892a50d1f59363d232b07ceafb | 163 | 74 | **JEDYNE KANONICZNE REPO OLA** |
| Vantage | [krzysztofcieciwa07-ship-it/vantage](https://github.com/krzysztofcieciwa07-ship-it/vantage) | main · 3bd9492861 | 27 | 9 | **JEDYNE KANONICZNE REPO VANTAGE** |

Reguła od teraz: nowe zmiany OLA rozwijamy wyłącznie w kanonicznym repozytorium OLA, a Vantage wyłącznie w kanonicznym repozytorium Vantage. Drugie konto nie jest równoległym miejscem rozwoju. Nie oznacza to jednak, że każda jego gałąź jest zbędna — patrz sekcja 3.

### Stan porządku w repo OLA

- 163 gałęzie, z czego żadna nie jest oznaczona jako klasycznie chroniona w odpowiedzi GitHub Branches API.
- 74 otwarte pull requesty. 50 ma bazę main; pozostałe są oparte o inne gałęzie, więc tworzą zależności i stosy integracyjne.
- Aktywny łańcuch prac stagingowych z 8 listopada: #189 → #191 → #192 → #195; #190 jest również oparty na #189. PR #194 i #193 celują bezpośrednio w main.
- PR-y #189–195 są nadal otwarte; #189, #190, #191, #192, #193, #194 i #195 pozostają Draft. Nie są scalonym wydaniem.
- Aktualny main to SHA 6dff9c43… . CI na gałęzi lub PR nie zmienia SHA main i nie oznacza wdrożenia.

Znany aktywny ruleset 25853037 wymusza ochronę przed usunięciem gałęzi i non-fast-forward. Nie zawiera wymagania niezależnego review ani obowiązkowych kontroli CI. Bezpośredni odczyt klasycznej ochrony branch był niedostępny dla integracji, dlatego nie deklarujemy pełnej ochrony main.

### Stan porządku w repo Vantage

- 27 gałęzi i 9 otwartych PR-ów.
- 11 gałęzi ci/cfr18-* odpowiada tymczasowym wyzwalaczom/testom PR #20–30, które zostały zamknięte bez merge. To kandydaci do usunięcia po zachowaniu potrzebnych artefaktów.
- PR #19 jest aktualnym kandydatem zmian CFR-18, ale pozostaje Draft i wymaga niezależnego review.

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

Konto ma także prywatne repozytorium Vantage-v0.3: 0 gałęzi, brak plików i pusty stan kodu. Nie jest drugim aktywnym repozytorium Vantage. Zachować do czasu decyzji właściciela, nie rozwijać równolegle.

## 3. Drugie konto — forks i rozbieżne źródła

Podłączona instalacja GitHub obejmuje konto krzysztofcieciwa07-ship-it; drugie konto krzys167-crypto nie jest dostępne jako osobna instalacja do zarządzania. Poniżej bezpośrednio odczytano tylko wymienione repozytoria — to nie jest pełna inwentaryzacja całego drugiego konta.

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

W drzewie main potwierdzono śledzony plik .env zarówno w krzysztofcieciwa07-ship-it/quantum-ai-chatbot, jak i w repo źródłowym krzys167-crypto/quantum-ai-chatbot. Odczytano wyłącznie nazwy zmiennych z forka: VITE_SUPABASE_URL i VITE_SUPABASE_ANON_KEY; wartości nie zostały ujawnione. Nie znaleziono nazw zmiennych sugerujących service-role/private key w tym pliku. Klucz anon jest przeznaczony do użycia klientowego, ale nadal wymaga poprawnych RLS i ograniczeń projektu. Plik należy zastąpić bezpiecznym .env.example, dodać .env do ignore i osobno sprawdzić historię oraz konfigurację Supabase. Nie przypisywać tego eksperymentu do OLA ani NOVA.

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
