# FiveM Dumper - AllInOne (C++)

Nativ C++ FiveM resource dumper es dekódoló. **Nulla kulso fuggoseg** — minden
Windows beepitett API vagy sajat implementacio.

## Felepites

```bash
cmake -B build -G "Visual Studio 17 2022"
cmake --build build --config Release --parallel
build\Release\fivem_dumper.exe
```

A `build.bat` ugyanezt hajtja vegre (`Release`, `--parallel`). A configure lepset
nem szabad kihagyni: a beagyazott payload es a SHA-256 manifest a configure
idoben keletkezik, ezert egy mar meglevo build faban is ujra kell futnia.

| komponens | forras |
|-----------|--------|
| HTTP | WinHTTP (Windows beepitett) |
| AES-256-CBC | BCrypt (Windows beepitett) |
| SHA256 / HMAC-SHA256 | sajat (`src/crypto/Sha256.cpp`) |
| ChaCha20 (8/12 bajt nonce) | sajat (`src/crypto/ChaCha20.cpp`) |
| JSON parser | sajat (`src/utils/Json.cpp`) |
| memoria-scan | Toolhelp32 + VirtualQueryEx + ReadProcessMemory |

## Hasznalat

1. Inditsd el a FiveM-et es csatlakozz a szerverhez
2. `fivem_dumper.exe` — a token es az IP-k automatikusan kerulnek a jatek
   memoriajabol
3. Valassz szervert a listabol (vagy gepeld be az IP-t/domain-t)
4. Valassz resource-okat: index (`1,3`), tartomany (`5-8`), NEV
   (`pma-voice, ox_lib`), mind (`all`), vagy `q` = megszakitas

### Feature-k

- **Onallo exe**: a teljes `Bin/` mappa (Unpacker + FXServer komponensek) es a
  kulso VC++ runtime DLL-ek az exe-be vannak agyazva (RCDATA). Elso futaskor
  a `%LOCALAPPDATA%\FiveMDumper\payload` konyvtarba kicsomagolodnak, meret +
  SHA256 alapot ellenorizve; ha pl. antivirus torol/nyul hozza, automatikusan
  ujracsomagolodik. A kesz `fivem_dumper.exe` barmely gepen elindithato meg
  kulon fajlok nelkul (a projektgyokerben levo `Bin/` mappot egyebkent elonyben
  reszesiti).
- Interaktív resource-kivalaszto (index / range / nev, reszleges egyezessel)
- Validacios ciklus: nem valaszolo IP nem crashel, ujra kerdez
- **Automatikus szervernev**: a név a névtelen `GET /dynamic.json` végpont
  `hostname` mezőjéből jön (`sv_hostname`) — nem kell begépelni. FX-color
  jelölés (^0-^9, ^^, ^s) eltávolítva; a `default FXServer` /
  `FXServer, but unconfigured` placeholder neveket nem fogadja el.
- Szervernev-cache (`server_name.txt`) — a lista mutatasi a nevet, és a
  dynamic.json sikertelensége esetén ez a fallback a prompt előtt
- Progressbar toltodesnel es dekodolasnel
- Checkpoint (`checkpoint.json`) — Ctrl-C / kick / timeout utan folytatas
- Szerverneves mappa: `Servers/<nev>/Output/...`
- **Dekodolas kihagyasa**: ha egy resource-ban sincs `.fxap`, a 2. fazis
  azonnali atnevezessel lezarul (nincs grants-betoltes, nincs fajlonkenti muvelet)
- **Manifest-backfill**: ha az RPF-kitomorigatas nem termel fxmanifest-et, azt
  kulon lekeri a `/files` vegponrol; ha az unpack egyaltalan nem sikert, a nyers
  `.rpf` megmarad
- Titkosított (`.fxap`) resource-ok: full FXAP -> ChaCha20 -> (AES klienskulcs)
  -> unluac Lua-decompile
- Connection reset / timeout: automatikus 3x retry, exponential backoff
- A warning-ok csak a `dumper.log`-ba mennek, a konzol tiszta

### Kornyezeti valtozok (opcionalisak)

| Valtozo | Jelentes |
|---------|----------|
| `DUMPER_TOKEN` | token a memoria-scan nelkul |
| `DUMPER_SERVER_IP` | fix szerver (interaktív kerdezes nelkul) |
| `DUMPER_SERVER_NAME` | fix mappa/szerver nev |
| `DUMPER_RESOURCE` | csak ez az egy resource |
| `DUMPER_WORKERS` | parhuzamos letoltesok szama (1-64, alapertelmezett 24) |
| `DUMPER_TEST_MODE=1` | nem interaktív mod |

## Konyvtarszerkezet

```
Servers/<szervernev>/
  Resources/Grants.txt
  Output/<resource>/...      <- a kesz, dekodolt fajlok
%LOCALAPPDATA%/FiveMDumper/payload/   <- az exe-bol kicsomagolt Bin/ es jar
                                        (onallo exe: nem kell kulon letolteni)
```

## Megjegyzések

- Az `unluac` jar az exe-ben van, de a Lua-dekompilacioshoz a gepen futtathato
  **Java** kell (a jar onmaga nem hivatalos vegrehajthato).
- A beagyazott payload merete megközelitoleg ~215 MB, igy a kesz exe megközelitoleg
  ~217 MB. A pontos meret az aktualis `Bin/` tartalmatol fugg (a `Bin/` nem resze a
  git reponek).
- Titkositas nelkuli szervertol minden siman kimetszodik; `.fxap`-os
  resource-oknal a grants-token hatarozza meg, melyik kulcs kell.
