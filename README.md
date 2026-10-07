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
- Titkosított (`.fxap`) resource-ok: ket reteges FXAP -> ChaCha20 -> Lua-decompile
  (reszletek lent, a "Resource dekódolás" szakaszban)
- Connection reset / timeout: automatikus 3x retry, exponential backoff
- A warning-ok csak a `dumper.log`-ba mennek, a konzol tiszta
- **AI regiszternevezo (opcionalis)**: a strukturális tisztitas utan felajanlja,
  hogy egy helyi kis modell (Qwen2.5-Coder-0.5B fine-tune) a megmaradt SHX
  regisztereket ertelmes nevekre csereli. Reszletek lent.

### AI regiszternevezo

A tisztitas (`Output_clean`) utan a program kerdez: "AI agent betoltese?".
Ha igen, elinditja az `ai/deploy/llama-server.exe`-t a
`ai/deploy/qwen_lua_ck40_q4km.gguf` modellel (localhost, GPU-val), chunkonkent
rename map-et kér, majd a determinisztikus applier szabályai szerint irja at a
regisztereket az `Output_clean` fajlokban:

- csak egesz azonosito-poziciok irnak at; string/comment/p.Tabla-kulcs
  poziciok, lokalis-arnyekolas, globalis-utkozes es duplikatum mind elutasitasra kerul
- a feldolgozott fajlokat `luac -p` ellenorzi (ha talalhato); hiba eseten a fajl
  visszaallit
- az elutasitas-okak a `dumper.log`-ba kerulnek; a modell configja a `src/ai/LlmNaming.cpp`-ben
- az AI kornyezet nem resze a git reponek: a `ai/deploy` mappanak az exe mellett
  kell lennie; nelkule a lepes csendben kihagyodik
- `DUMPER_AI_CLEANUP=1`-lel kerdes nelkul fut; tesztmode-ban es ha nincs AI
  kornyezet, a kerdes nem is jon

### Kornyezeti valtozok (opcionalisak)

| Valtozo | Jelentes |
|---------|----------|
| `DUMPER_TOKEN` | token a memoria-scan nelkul |
| `DUMPER_SERVER_IP` | fix szerver (interaktív kerdezes nelkul) |
| `DUMPER_SERVER_NAME` | fix mappa/szerver nev |
| `DUMPER_RESOURCE` | csak ez az egy resource |
| `DUMPER_WORKERS` | parhuzamos letoltesok szama (1-64, alapertelmezett 24) |
| `DUMPER_KEEP_TEMP` | a `Temp`, `TempCompiled` es `Unpacked` konyvtarakat megtartja hibakereseshez; csak a levaltas letege szamit (barmely ertek, ures sztring is), alapertelmezetten torolva |
| `DUMPER_TEST_MODE=1` | nem interaktív mod |
| `DUMPER_CLEANUP=1` | strukturális Lua-tisztítás nem interaktív módban is |
| `DUMPER_AI_CLEANUP=1` | AI regiszternevezo kerdes nelkuli futtatasa |
| `DUMPER_LUAC` | luac.exe utvonal az AI-nevezes luac ellenorzeshez |
| `CK_CLIENT_KEY_API_URL` | a klienskulcs-szolgaltatas cime (alapertelmezett `https://grantsclk.ckcloud.de5.net`); a `CK_GRANTS_CLK_API_URL` nevet is elfogadja |

## Resource dekódolás

Egy titkosított eroforrassal a dumper ket reteget bont fel:

1. **Kulso FXAP reteg** — a fajl `FXAP` fejleccel indul; a nonce a 74. bajttol
   olvasott 12 bajt, a titkositott tartalom a 86. bajtol indul. A kulcs fix.
2. **Belső reteg** — a felbontott blokk egy változó hosszuságú meta-blokkot tartalmaz
   (a fajl SHA-256-ja es az eredeti utvonala), **majd utana** a 12 bajtos nonce, majd
   a titkositott tartalom. A meta-blokk hossza fajlonkent valtozik (valós adatokon
   74–105 bajt), ezért a nonce helye nem szamithato ki fix offsetbol — az
   `uint16` hosszmezőből olvasandó ki. A regi, fix 80/92 offset csak 74 bajtos
   meta-blokknal lenne helyes.

A `.fxap` fejlece az eroforr azonositojat tartalmazza, ez alapjan ket kulcs juthat
szobaja:

| kulcs | forras | mire jo |
|-------|-------|---------|
| grants | a grants token `grants` mezjeje | szerveroldali fajlok |
| kliens | a `grants_clk`-bol a kulcsszolgaltatas adja vissza | kliensoldali `.lua` |

**Mindig a fajlhoz reallo kulcs nyitja ki**, nem eroforr-szinten dontunk: egyes
fajlok a grants, masok a kliens kulccsal jonnek ki, ezert minden fajlon mindketto
kulcsot megprobaljuk, es az elso validalt eredmeny nyer.

Stream fajlok (`.awc .ybn .ydd .ydr .yft .ymap .ymf .ytd .ytyp`) az `RSC7`/`RSC8`
fejlec alapjan ellenorzotten kerulnek kiirasra, hogy ne keruljon oda ellenorizetlen
szemely.

A kliens kulcs szolgaltatasaval a 78%-ban 64 bajtos `grants_clk` nem keresheti meg:
a szolgaltatas csak a kanonikus 48 bajtos alakot fogadja el, es a token 64 bajtos
erteke sem prefixként, sem suffixként nem tartalmazza azt. Az ilyen eroforraknál a
szerveroldali fajlok dekodolodnak, a kliensoldali `.lua` pedig `<fajl>.raw`nevrel a
titkosított eredeti peldanykent megmarad.

## Lua olvashatosag

A 2. fazis utan a program felajanlja a dekodedolt `.lua` fajlok javitasat. **A
dekódolt `Output` soha nem modszul** — minden javitas kulon mappaba kerul.

### Strukturális tisztitas (`Output_clean`)

Determinisztikus, hatokor-tudatos, offline, egeszre percek alatt:

1. **Banner torles** — a decompiler fejlece (a fajl elején alló komment-blokk) elnyilik.
   A fajl belsejeben levo kommentek megmaradnak.
2. **Valtozonevek** — az unluac szintetikus nevei (`SHX0_1`, `L3_2`) a bevezető kötés
   alapján nevet kapnak (`SHX0_1 = {}` -> `table1`, `SHX3_1 = false` -> `flag1`).
   Ket okbol szokas megmaradni:
   - ha a kotes nem egyertelmu (`f()` hivas, oszetett kifejezes)
   - ha anev globalist vagy builtint fogyna (pl. `SHX7_1 = RegisterNetEvent`), mert
     atnevezeskor a kotes jobb oldala mar a lokalisra mutatna, es a globalis elkapas
     elcsuszna. Ilyenkor az eredeti `SHX`/`L` nev marad.
3. **Ujra indentalas** — 4 spaces per blokk, a forras sorzarasaval megtartva.
4. **Egyszer használt alias beágyazása** — a decompiler gyakran minden értéket egy
   eldobható lokálon keresztül vezet:

   ```lua
   local SHX0_1, text1
   SHX0_1 = print
   text1 = "Hello, World!"
   SHX0_1(text1)
   ```

   ebből `print("Hello, World!")` lesz. A feltételek, hogy ez biztonságos:

   - a lokál **keresztelés nélkül** van deklarálva (nincs inicializáló)
   - **pontosan egyszer** van hozzárendelve, egyetlen literállal vagy sima globális
     nevet kap
   - **pontosan egyszer** van olvasva, és az **a hozzárendelés után** következik —
     ez az, ami kizárja a lezáró elemet korábban becsülő függvényt
   - nem egy hívás argumentuma összetett kifejezés, és nem `:metódus` hívás
     literállal

   A lánc rekurzívan összeáll: a `text1` is beágyazódik, így egy menet alatt a
   teljes `print("Hello, World!")` keletkezik.

A `goto` / `::label::` blokkokat **nem** alakitjuk at: parser nelkul a ciklusos
atiranyitas viselkodest valtoztatna. A talalt blokkok szam jelzesre kerul.

### Ellenorzes

A tisztítás **állításokat töröl**, ezért a token-egyezés önmagában nem elég.
A `luac -p`-vel ellenőrizünk: a 12 valódi resource 160 fájljából a dekódolat
állapotban 108-ból 18 eleve érvénytelen (a decompiler kimenete nem mindig valid
Lua), és **tisztítás után ugyanaz a 18 marad érvénytelen, új hiba nélkül**.

> Az `SHX7_1 = RegisterNetEvent` név szándékosan marad. Átnevezni
> `RegisterNetEvent`-re csak úgy lehetne, ha a globális nevet elrejtenénk — de akkor
> a kötés jobb oldala (`RegisterNetEvent = RegisterNetEvent`) már a *lokálisra* mutatna.
> Ezért az ilyen nevet nem szabad elrejteni: egy félrevezető nevű változó jobb, mint egy
> eltört kód.

## Konyvtarszerkezet

```
Servers/<szervernev>/
  Resources/Grants.txt
  Output/<resource>/...      <- a kesz, dekodolt fajlok
  Output_clean/<resource>/   <- strukturálisan tisztított Lua (nem irja felul az Outputot)
%LOCALAPPDATA%/FiveMDumper/payload/   <- az exe-bol kicsomagolt Bin/ es jar
                                        (onallo exe: nem kell kulon letolteni)
```

## Megjegyzések

- Az `unluac` jar az exe-ben van (`v1.2.3.511`), de a Lua-dekompilacioshoz a gepen
  futtathato **Java** kell (a jar onmaga nem hivatalos vegrehajthato). Ha a
  deforditas meghiusul, a program megprobalja a `--disassemble` / `--assemble`
  korulforditast a hibas cimkek javitasaval; ha ez sem sikerul, a bytecode
  `<fajl>.luac` es a lista `<fajl>.asm` neven megmarad.
- A beagyazott payload merete megközelitoleg ~215 MB, igy a kesz exe megközelitoleg
  ~217 MB. A pontos meret az aktualis `Bin/` tartalmatol fugg (a `Bin/` nem resze a
  git reponek).
- Titkositas nelkuli szervertol minden siman kimetszodik; `.fxap`-os
  resource-oknal a grants-token hatarozza meg, melyik kulcs kell.
