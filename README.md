# FiveM Dumper - AllInOne (C++)

Nativ C++ FiveM resource dumper es dekódoló. **Nulla kulso fuggoseg** — minden
Windows beepitett API vagy sajat implementacio.

## Felepites

```bash
cmake -B build -S .
cmake --build build --config Release
build\Release\fivem_dumper.exe
```

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

- Interaktív resource-kivalaszto (index / range / nev, reszleges egyezessel)
- Validacios ciklus: nem valaszolo IP nem crashel, ujra kerdez
- Szervernev-cache (`server_name.txt`) — a lista mutatasi a nevet
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
| `DUMPER_TEST_MODE=1` | nem interaktív mod |

## Konyvtarszerkezet

```
Servers/<szervernev>/
  Resources/Grants.txt
  Output/<resource>/...      <- a kesz, dekodolt fajlok
Bin/Unpacker.exe             <- RPF kitomorigeto (kell!)
Tools/Decompile/unluac54.jar <- Lua decompiler (Java kell hozza!)
```

## Megjegyzesek

- Az `unluac` Lua-dekompilacioshoz Java kell.
- Titkositas nelkuli szervertol minden siman kimetszodik; `.fxap`-os
  resource-oknal a grants-token hatarozza meg, melyik kulcs kell.
