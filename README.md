# FiveM Dumper - AllInOne (C++)

Natív C++ FiveM resource dumper és dekódoló. Nincs külső függősége: a HTTP, az AES és a
memóriaolvasás a Windows beépített API-ját használja, a többi (SHA-256, ChaCha20, JSON)
saját implementáció.

## Fordítás

```
build.bat
build\Release\fivem_dumper.exe
```

A `build.bat` a `vswhere`-val megkeresi, melyik Visual Studio van telepítve C++
x64/x86 eszközökkel, és azt használja. VS 2019, 2022 és 2026 is megy, a verziót nem
kell kézzel belőni.

```
DUMPER_GENERATOR="Visual Studio 16 2019" build.bat   # explicit generátor felülírása
cmake -B build -DCMAKE_CXX_STANDARD=17                # régi toolset, ha a C++20 nem megy
```

Kézzel:

```
cmake -B build -G "Visual Studio 18 2026"
cmake --build build --config Release --parallel
```

A configure lépést nem szabad kihagyni: a beágyazott payload és a SHA-256 manifest a
configure idejében készül, ezért egy meglévő build fában is újra kell futnia. A build
tree a generátort a cache-ben őrzi, és a CMake nem engedi másik Visual Studioval
létrehozott fát újrahasználni — a `build.bat` ezt felismeri és törli a régit, hogy ne
kelljen a `build\` mappát kézzel takarítani.

### A `Bin/` mappa

A `Bin/` nincs a repóban (2,4 GB), de a build összeállítja a tartalmát RCDATA
payloadba, amit a program futáskor kicsomagol:

| bemenet | mi kell belőle |
|---|---|
| `Bin/citizen/`, `Bin/*.dll`, `Bin/Unpacker.exe` | az FXServer komponensei |
| `Bin/vertex-fixer/` | a vertex-javító és a .NET függőségei (9 fájl, 9,2 MB) |

A `Bin/vertex-fixer/` a `FivemDecryptFixer.Cli`, a `CodeWalker.Core`, a `SharpDX` és a
`CK.VertexBridge`. Ha ez hiányzik, a program a vertex javítást csendben kihagyja, és a
dekompilált Lua ettől még működik.

| komponens | forrás |
|---|---|
| HTTP | WinHTTP (Windows beépített) |
| AES-256-CBC | BCrypt (Windows beépített) |
| SHA256 / HMAC-SHA256 | saját (`src/crypto/Sha256.cpp`) |
| ChaCha20 (8/12 bájt nonce) | saját (`src/crypto/ChaCha20.cpp`) |
| JSON parser | saját (`src/utils/Json.cpp`) |
| memória-scan | Toolhelp32 + VirtualQueryEx + ReadProcessMemory |

## Használat

1. Indítsd el a FiveM-et és csatlakozz a szerverhez
2. `fivem_dumper.exe` — a token és az IP-k automatikusan a játék memóriájából kerülnek ki
3. Válassz szervert a listából, vagy írd be az IP-t
4. Válassz resource-okat: index (`1,3`), tartomány (`5-8`), név (`pma-voice, ox_lib`),
   összes (`all`), vagy `q` = megszakítás

### Amit a dumper csinál

Az exe önmagában megáll: a teljes `Bin/` mappa és a VC++ runtime DLL-ek RCDATA
erőforrásként benne vannak, első futáskor kicsomagolódnak a
`%LOCALAPPDATA%\FiveMDumper\payload` mappába, méret és SHA256 alapján ellenőrizve. Ha
egy antivírus belenyúl, újracsomagolódik. A kész exe bármilyen gépen elindul külön
fájlok nélkül.

- Szervernév automatikusan a `GET /dynamic.json` végpont `hostname` mezőjéből
  (`sv_hostname`), nem kell begépelni. Az FX-színjelölések (^0-^9, ^^, ^s) eltűnnek,
  a `default FXServer` / `FXServer, but unconfigured` placeholder neveket nem fogadja el
- Név-cache `server_name.txt`-ben: a lista mutatja a nevet, és ha a dynamic.json kiesik,
  ez a fallback még a kérdés előtt
- Progress bar a letöltésnél és a dekódolásnál
- Checkpoint (`checkpoint.json`): Ctrl-C, kick vagy timeout után onnan folytatja, ahol
  abbahagyta. Csak akkor törlődik, ha minden kiválasztott resource kész lett
- A warningök csak a `dumper.log`-ba mennek, a konzol tiszta marad
- Titkosított (`.fxap`) resource-ok: FXAP -> ChaCha20 -> Lua-dekompilálás, két rétegben
  (lásd lent)
- Connection reset és timeout esetén 5 próbálkozás, exponenciális backoff (2/4/8/16 mp),
  így egy szerver-újraindítás ablakát is átviszi
- Dekódolás kihagyása: ha egy resource-ban nincs `.fxap`, a 2. fázis azonnali átnevezéssel
  lezárul, nincs grants-betöltés és nincs fájlonkénti művelet
- Manifest-backfill: ha az RPF-kitömörítés nem termel fxmanifestet, azt külön lekéri a
  `/files` végpontról; ha az unpack egyáltalán nem sikerül, a nyers `.rpf` megmarad
- **Konfiguráció gyorsítótár és szerver-újraindítás-tűrés**: az első sikeres `/client`
  válasz `Servers/<név>/config.json`-be kerül. Ha később a szerver nem válaszol
  (újraindult) vagy a tokent visszautasítja, a dumper ezt a cache-t tölti be, és folytatja
  — a játék kapcsolata csak új tokenhez kell, nem az egész dumphoz
- **Központi tároló (IP alapján)**: minden sikeres konfiguráció felmegy a
  `DUMPER_STORE_URL` (alapértelmezés `http://188.97.125.55:8920`) alatti tárolóba,
  `GET/POST /v1/servers/<safeName(baseUrl)>`. A dumper mindig először a szerveren
  próbálkozik, utána a tárolóban — ha ott megvan az IP konfigurációja, a dump
  játék-kapcsolat és token nélkül is működik. Ha sehol nincs adat, a dumper egyszeri
  fellépést kér, és csak akkor tölti fel a tárolót

### Környezeti változók

| Változó | Jelentés |
|---------|----------|
| `DUMPER_TOKEN` | token a memória-scan nélkül |
| `DUMPER_SERVER_IP` | fix szerver, interaktív kérdezés nélkül |
| `DUMPER_SERVER_NAME` | fix mappa- és szervernév |
| `DUMPER_RESOURCE` | csak ez az egy resource |
| `DUMPER_WORKERS` | párhuzamos letöltések száma (1-64, alapértelmezett 24) |
| `DUMPER_KEEP_TEMP` | megtartja a `Temp`, `TempCompiled` és `Unpacked` mappákat hibakereséshez. Bármilyen érték számít, az üres string is; alapértelmezetten törölve |
| `DUMPER_TEST_MODE=1` | nem interaktív mód |
| `DUMPER_CONFIG` | a `config.json` útvonala a token és játék-kapcsolat nélküli dumpoláshoz (pl. másik gépről másolva; az IP-t a `DUMPER_SERVER_IP` adja meg) |
| `CK_CLIENT_KEY_API_URL` | a klienskulcs-szolgáltatás címe (alapértelmezett `https://grantsclk.ckcloud.de5.net`); a `CK_GRANTS_CLK_API_URL` nevet is elfogadja. **`off` = teljesen hálózat nélküli futás** |

### Hálózat nélküli futás

| függőség | állapot |
|----------|--------|
| `Grants.txt` kulcstoken | **helyi**, a `Servers/<név>/Resources/Grants.txt` fájlból |
| `grants` szerverkulcs | **helyi**, a tokenből |
| központi tároló (`Servers/`) | **helyi**, a `store/` mappa; a válasz `http://127.0.0.1:8920` |
| klienskulcs (`/v1/derive`) | **hálózat kell neki**, lásd lentebb |

```
set DUMPER_STORE_URL=http://127.0.0.1:8920
set CK_CLIENT_KEY_API_URL=off
```

A **klienskulcs az egyetlen**, ami nem helyben áll. A szolgáltatás kulcs*táblát*
tartoztat egy Cloudflare Workers KV-ben (`/health` szerint `workers-kv-read-only`), nem
számolt algoritmust: így a `grants_clk`-ból helyben nem állítható elő. Aki csak a
**szerverkulcsos** fájlokra van szüksége, annak a fenti két változóval nincs hálózatra
szüksége; a többi fájl ilyenkor nyersen marad.

A `CK_CLIENT_KEY_API_URL=off` nem csak ezt az egy értéket kapcsolja ki, hanem
**megszakítja** a kérdezést: ha a szolgáltatás nem érhető el (nincs válasz, DNS- vagy
connecthiba), a dumper nem próbálja meg újra a többi resource-nál. Ez azért számít,
mert egy valódi szerveren 969 `grants_clk` bejegyzet van, és a connect időtúlépés
mindegyiken újra lefutna — az első hívás 30 mp, a többi 0 mp, a megszakító nélkül ez
körülbelül 8 órát vinne el.

A megszakító **szállítási hibára** kapcsol (nincs HTTP státusz egyáltalán). Ha a
szolgáltatás **válaszol**, de az adott resource nincs benne (`HTTP 400`), az **nem**
kapcsolja ki: a szolgáltatás él, csak erre az értékre nincs válasz.

## Resource dekódolás

Egy titkosított erőforrással a dumper két réteget bont fel:

1. **Külső FXAP réteg** — a fájl `FXAP` fejléccel indul; a nonce a 74. bájtól olvasott
   12 bájt, a titkosított tartalom a 86. bájttól indul. A kulcs fix.
2. **Belső réteg** — a felbontott blokk egy változó hosszúságú meta-blokkot tartalmaz
   (a fájl SHA-256-ja és az eredeti útvonala), **majd utána** a 12 bájtos nonce, majd a
   titkosított tartalom. A meta-blokk hossza fájlonként változik (valós adatokon
   74-105 bájt), ezért a nonce helye nem számítható ki fix offsetből — a `uint16`
   hosszmezőből kell kiolvasni. A régi, fix 80/92 offset csak 74 bájtos meta-blokknál
   lenne helyes.

A `.fxap` fejléc az erőforrás azonosítóját tartalmazza, ez alapján két kulcs juthat a
szobájába:

| kulcs | forrás | mire jó |
|-------|-------|---------|
| grants | a grants token `grants` mezője | szerveroldali fájlok |
| kliens | a `grants_clk`-ból a kulcsszolgáltatás adja vissza | kliensoldali `.lua` |

**Mindig a fájlhoz reáló kulcs nyitja ki**, nem erőforrás-szinten döntünk: egyes fájlok
a grants, mások a kliens kulccsal jönnek ki, ezért minden fájlon mindkettőt
megpróbáljuk, és az első validált eredmény nyer.

A stream fájlok (`.awc .ybn .ydd .ydr .yft .ymap .ymf .ytd .ytyp`) az `RSC7`/`RSC8`
fejléc alapján ellenőrzötten kerülnek kiírásra, hogy ne kerüljön oda ellenőrizetlen
személy.

A klienskulcs szolgáltatásával a 78%-ban 64 bájtos `grants_clk` nem kereshető meg: a
szolgáltatás csak a kanonikus 48 bájtos alakot fogadja el, és a token 64 bájtos értéke
sem prefixként, sem suffixként nem tartalmazza azt. Az ilyen erőforrásnál a szerveroldali
fájlok dekódolódnak, a kliensoldali `.lua` pedig `<fájl>.raw` néven a titkosított
eredeti példányként megmarad.

## Könyvtárszerkezet

```
Servers/<szervernév>/
  Resources/Grants.txt
  Output/<resource>/...      <- a kész, dekódolt fájlok
%LOCALAPPDATA%/FiveMDumper/payload/   <- az exe-ből kicsomagolt Bin/ és jar
                                        (önálló exe: nem kell külön letölteni)
```

## Megjegyzések

- Az `unluac` jar az exe-ben van (`v1.2.3.511`), de a Lua-dekompiláláshoz a gépen
  futtatható **Java** kell, a jar önmagában nem végrehajtható. Ha a defordítás meghiúsul,
  a program megpróbálja a `--disassemble` / `--assemble` körülfordítást a hibás címkék
  javításával; ha ez sem sikerül, a bytecode `<fájl>.luac` és a lista `<fájl>.asm`
  néven megmarad.
- A beágyazott payload mérete megközelítőleg 215 MB, így a kész exe megközelítőleg
  217 MB. A pontos méret az aktuális `Bin/` tartalomtól függ (a `Bin/` nem része a git
  repónak).
- Titkosítás nélküli szervertől minden simán kiemetsződik; `.fxap`-os resource-oknál a
  grants-token határozza meg, melyik kulcs kell.