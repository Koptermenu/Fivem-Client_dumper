# `adhesive.dll` — patch-mechanizmusok: rekord, redirect, stub, caller és aktiválás

## 1. Vizsgálati határ, módszertan és jelölés

### 1.1 Amit ez a dokumentum készített, és amit nem

- **Vizsgált példány:** `reverse/adhesive.dll`, SHA-256 `91cc0aa006d7315cb042c8fa8dca6c1e074a307bba7dcc9eb5509c8a7b81934e`, méret `53 575 264` bájt (`0x3317E60`).
- **Vizsgálat típusa:** kizárólag statikus fájl- és PE-elemzés. A DLL-t **nem futtattam, nem töltöttem be, nem hookoltam és nem patcheltem**.
- **Amit nem adok:** konkrét patch-bájtot, patch-cím receptet, eljárást a mechanizmus kikapcsolására, bypass- vagy exploit-útmutatást, és nem adok olyan lépést, amellyel a vizsgált védelem vagy ellenőrzés megkerülhető. A leírt kifejezések (`rec + 0x00`, `patch_site`, `rec[0x28][i]`) **szimbolikus leírójelölések**, nem végrehajtható előállítási lépések; egyetlen konkrét írási bájtérték sem szerepel alább.
- **Amit adok:** a célpont szimbolikus alakja, a közvetlen hívási viszonyok, az aktiválási feltételek, a hibakezelés, a globális állapot és a bizonyossági szint minden állításhoz.
- **Címtartomány:** minden cím RVA, ahol nincs másként jelölve. A `RAW` a specimen fájlban mért nulla alapú offset. Az `.text` szekcióban `RAW = RVA − 0xC00`, a `.rdata`/`.data`/`.tls`/`.rsrc`/`.reloc` szekciókban `RAW = RVA − 0x1600`.

### 1.2 A felhasznált evidence-készlet

| Fájl | Szerep ebben a dokumentumban |
|---|---|
| `reverse/evidence/patch_record_table.json` | A `0x38` bájtos rekord, a hat globális, a flagbitek, a patcher-modell, a hívók és a `118` invariant (`anchor_failures: 0`) |
| `reverse/evidence/patch_mechanisms_1e270.csv` | Ugyanez lapos, `50` soros táblázatként |
| `reverse/evidence/patch_mechanisms_1dff0.csv` | A thread-snapshot redirect 51 mechanizmussora |
| `reverse/evidence/patch_mechanisms_helpers.csv` | A `0xC8CE70` / `0xC8F470` / `0x1754520` segédek, a globális leltár, a módszertani határok |
| `reverse/evidence/apc_sites.csv` | A hét `QueueUserAPC` callhely argumentum- és ágvizsgálata |
| `reverse/evidence/thread_context_map.json` | A redirect részletes kontextus-, handle- és sorrendtérképe, 145 invariant |
| `reverse/evidence/xref_edges.csv` | Import-thunk-, IAT-, vtable- és kódpointer-xrefek; lásd a **11.1** scope-figyelmeztetést |
| `reverse/evidence/unresolved_regions.json` | A feloldatlan régiók és a CFG-lefedettség; lásd a **11.2–11.3** fejezetet |
| `reverse/evidence/audit_handle_flow.json` | A `0xC856C0` handle-flow számok független újraszámítása. **Nem a jelen dokumentum tárgyáról szól:** a `target_document` mezője az `adhesive-14-c856c0-handle-producer-dataflow.md`, és egyetlen `contested` tétele sem érinti az itt tárgyalt `0x1D280–0x1E9D0` komponenst vagy a `0xC8CE70`/`0xC8F470`/`0x1754520` segédeket. Azért szerepel a listában, mert az újraellenőrzés során átnézve megerősítette, hogy nincs hozzá tartozó korrekció |
| `reverse/adhesive-06/07/11/12` | Korábbi dokumentumok; a **12. fejezet** a velük való konfliktusokat és korrekciókat tartalmazza |

A további két nagy evidence-fájl (`cfg_functions.csv`, `pdata_functions.csv`, együtt `142 004` runtime-function rekord) itt keresztellenőrzésre használt: a `cross_function_targets` oszlop alapján függetlenül újraszámoltam minden érintett függvény közvetlen hívóit, és a nyers `.text` bájtokon újraszámoltam a RIP-relatív globális-írásokat. Ezek az újraszámolások a **12. fejezet** korrekcióinak forrásai.

### 1.3 A két bizonyossági skála összevetése

Az evidence-készlet két skálát használ, a dokumentumcsalád pedig egy harmadikat. Ezeket egyértelműen összevetem, hogy a számok ne legyenek összekeverhetők:

| `patch_record_table.json` | `thread_context_map.json`, `patch_mechanisms_1dff0.csv` | Dokumentum-jelölés | Jelentés |
|---|---|---|---|
| `H` | `HIGH` | **`P`** | közvetlen statikus szerkezeti bizonyíték: egy utasítás, egy immediate vagy egy direktórium-bejegyzés lezárja |
| `M` | `MEDIUM` | **`L`** | a fájlból levezethető, de egy futásidejű előfeltételre conditional |
| `L` | `LOW` | **`U`** | a mechanizmus ismert, a döntő példányadat hiányzik a fájlból |
| `OPEN` | `UNRESOLVED` | **`U` + `STATUS:OPEN`** | a fájl önmagában nem dönti el |

A `patch_mechanisms_*.csv` `status` oszlopa a dokumentum `STATUS` mezőjébe megy: `OBSERVED → OBSERVED`, `ABSENT → NEGATIVE`, `ASYMMETRIC → INFERRED`, `UNRESOLVED → OPEN`.

**Fontos:** a `patch_record_table.json` összesített `overall_confidence` értéke `L`, a `thread_context_map.json` értéke `HIGH`. Ez nem ellentmondás: az első a *rekord-példányokra*, a második a *vezérlési folyamatra* vonatkozik. A kettőt egyetlen összesített számmá nem szabad összevonni.

### 1.4 BRef-formátum

```text
BRef = [RVA:<hex|N/A> | RAW:<hex|N/A> | CONF:<P|L|U> | STATUS:<OBSERVED|INFERRED|NEGATIVE|OPEN>]
```

Példák erre a dokumentumban:

```text
BRef = [RVA:0x1E270 | RAW:0x1D670 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x30D44F8 | RAW:0x30D2EF8 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x317E398 | RAW:0x317CD98 | CONF:U | STATUS:OPEN]
```

### 1.5 A „nincs közvetlen hívó" állítás három különböző jelentése

A korábbi dokumentumok a „nincs közvetlen caller" kifejezést egyetlen jelölésre használták három különböző állításra. Ez a dokumentum szétválasztja őket, mert a három különböző következménnyel jár:

1. **Nincs a dekódolt CFG-ben közvetlen `call rel32` a belépési pontra.** Ez `CONF:P`, és a `cfg_functions.csv` `cross_function_targets` oszlopával ellenőrizhető.
2. **Nincs abszolút mutató, `rva32`/`va64` literál vagy RIP-relatív hivatkozás a belépési pontra.** Ez `CONF:P`, a `patch_mechanisms_helpers.csv` `*_address_literals` soraival ellenőrizhető.
3. **A funkció ezért futásidőben nem érhető el.** Ez **nem** statikusan lezárható: a közvetett hívás, a függvénypointer, a `call [reg]`, a futásidejű kódgenerálás és a képkívüli szerző nem zárható ki a fájlból. Ez `CONF:L` vagy `CONF:U`.

A **2. fejezet** legfontosabb megállapítása éppen abból fakad, hogy a korábbi dokumentumok a 3. pontot tévesen az 1. pontból vezették le.

### 1.6 Evidence hash-pin

Ez a blokk a fenti evidence-készlet **jelenlegi lemezi állapotát** rögzíti. A hash-ek és a méretek a `reverse/evidence/` alatti fájlokról számoltak; a `16.y` fejezet mátrixa ugyanezekre az értékekre hivatkozik. A pin egyirányú: az evidence-fájlokat pineli, nem a dokumentumot, így a dokumentum saját digestje nincs és nem lehet benne.

| # | Artifact | SHA-256 | Méret (bájt) |
|---:|---|---|---:|
| H-1 | `reverse/evidence/patch_record_table.json` | `89a5201689ab0701c59ba75724825bde5ea8fdf7e96510251a21f359c5c26a5a` | 79 401 |
| H-2 | `reverse/evidence/patch_mechanisms_1e270.csv` | `ffc2234d4b620c49420e6751bb1d4db9c3d1e2fd07a7833a9f1452f4fd678090` | 14 895 |
| H-3 | `reverse/evidence/patch_mechanisms_1dff0.csv` | `2a71a42bc89e0203679a4442e331a38746cc7566ceef2940aa111011ac30aaa1` | 17 044 |
| H-4 | `reverse/evidence/patch_mechanisms_helpers.csv` | `49cb7ee8a9bfac3915c199e4911aac388987e071b61d3ac358ae2c0285ae4843` | 81 295 |
| H-5 | `reverse/evidence/apc_sites.csv` | `09bb810c8d86e8109ab9ac660e8281dc0ed9a6ac4dd20da5c6d3829db01caaed` | 26 664 |
| H-6 | `reverse/evidence/thread_context_map.json` | `ee54b448b79b26e721d1475af6a9bca3e2f9cbed4c053a115a9ec78fe675ba0b` | 82 548 |
| H-7 | `reverse/adhesive.dll` (a tárgy specimen) | `91cc0aa006d7315cb042c8fa8dca6c1e074a307bba7dcc9eb5509c8a7b81934e` | 53 575 264 |

**A pinelt fájlok számláló mezői, ugyanebből a lemezi állapotból:**

| Artifact | `anchor_count` | `anchor_failures` | Adatsor / sorszám | `CONF` |
|---|---|---:|---|---|
| H-1 `patch_record_table.json` | **118** (`summary.anchor_count`) | 0 | az `invariants` tömb `118` eleme | `P` |
| H-6 `thread_context_map.json` | **145** (`summary.anchor_count`) | 0 | az `invariants` tömb `145` eleme | `P` |
| H-2 `patch_mechanisms_1e270.csv` | **nincs ilyen mező** | – | `50` adatsor (16 oszlopos fejléc) | `P` a hiányra |
| H-3 `patch_mechanisms_1dff0.csv` | **nincs ilyen mező** | – | `51` adatsor (8 oszlopos fejléc) | `P` a hiányra |
| H-4 `patch_mechanisms_helpers.csv` | **nincs ilyen mező** | – | `119` adatsor (9 oszlopos fejléc) | `P` a hiányra |
| H-5 `apc_sites.csv` | **nincs ilyen mező** | – | `7` adatsor (8 oszlopos fejléc) | `P` a hiányra |

- **A négy `patch_mechanisms_*` / `apc_sites` CSV aggregatora számláló mezőt nem tartalmaz.** A `patch_mechanisms_1e270.csv` fejléce `id, component, kind, site_rva, site_va, record_offset, field, access, width_expr, value_expr, target_expr, readers, writers, confidence, status, note`; az `anchor_count` szó a fájlban `0`-szor fordul elő. A `16.0.2` 2. sora ezért kizárólag az **adatsorszámra** támaszkodhat, számozott anchor-aggregátumot ezekből a CSV-kből **nem** lehet levezetni.
- **Az egyetlen `anchor_count` forrás a pinnen az `H-1` és az `H-6` `summary` blokkja.** Bármelyik anchor darabszám, amely a `16` dokumentumban szerepel, e kettő valamelyikéből vagy a `16.y` mátrixából olvasandó vissza; a lapos CSV-kből származtatott anchor darabszám nem bizonyított.
- **A `16.y.3/A` stale input-digest állapota a pinnel összevetve:** az `unresolved_regions.json` `inputs.patch_cross_references` a `patch_mechanisms_1e270.csv`-re `66c8e9bc…`-ot ír, a lemezen `ffc2234d…` (`H-2`) áll. A pinnel a lemezi érték az igazolt; az eltérés forrása az `E8` belső stale állapota, nem a `16` állítása. Ugyanez az elavult jelölés marad az `E8` `rva_count = 35` mezője is: a jelenlegi CSV `21` nemüres `site_rva` értékével nem reprodukálható, ezért a pinen nem szerepelhet érvényes darabszámként.
- A `H-7` specimen digest megegyezik az 1.1. ponttal és a 14.4. pont `tárgy specimen` sorával, tehát a pin nem hoz be új ellentmondást.
- A pin **lemezállapot-leírás**, nem garancia: ha bármelyik `H-1`…`H-7` artifact regenerálódik, a pin elavul, és a `16.y` mátrix 19. sorához hasonlóan külön eltérésként kell kezelni.

---

## 2. Vezetői összefoglaló

### 2.1 A patch-komponens térképe

A vizsgált `0x1D280–0x1E9D0` tartomány **nem** egy laza funkcióhalmaz, hanem egy zárt, nyolc elemből álló belső komponens, amelynek egyetlen belépési pontja sincs a dekódolt CFG-ben:

| Szerep | RVA | Tartomány | Közvetlen hívói (a `cfg_functions.csv` szerint) | Közvetlen hívóinak száma |
|---|---|---|---|---:|
| `arena` — futtatható blokkokat ad, újrahasznosítható régiólistát tart | `0x1D280` | `0x1D280–0x1D546` | `0x1DCF0` | 1 |
| `decoder` — utasításhosszakat ad a list buildernek | `0x1D550` | `0x1D550–0x1DC79` | `0x1E590` | 1 |
| `init` — a heap-publikáló egyszeri inicializálás | `0x1DC80` | `0x1DC80–0x1DCE7` | — | **0** |
| `registrar` — allokál, feltölt, duplikátumot eldob | `0x1DCF0` | `0x1DCF0–0x1DFE1` | — | **0** |
| `list_builder` — a két bájtlista feltöltése | `0x1E590` | `0x1E590–0x1E9D0` | `0x1DCF0` | 1 |
| `rip_redirect` — felfüggesztett szál RIP-jét írja át | `0x1DFF0` | `0x1DFF0–0x1E26A` | `0x1E360` | 1 |
| `patcher` — 5/7 bájtos rel32 patch | `0x1E270` | `0x1E270–0x1E357` | `0x1E360` | 1 |
| `orchestrator` — a két patcher-hívási hely tulajdonosa | `0x1E360` | `0x1E360–0x1E583` | — | **0** |

A hívási gráf így két elszakadt, belső láncból áll:

```text
(nincs belépés)  →  [0x1E360 orchestrator]  ─0x1E400/0x1E4F6→  [0x1DFF0 redirect]
                                       ─0x1E425/0x1E4FD→  [0x1E270 patcher]
                                       ─0x1E3A4  cmp [0x1830D44F0],0   ←  ezt csak [0x1DC80 init] írja
                                       ─0x1E38F / 0x1E484 / 0x1E537 / 0x1E55A

(nincs belépés)  →  [0x1DCF0 registrar]  ─0x1E590→  [0x1E590 list_builder]  ─→  [0x1D550 decoder]
                                ─0x1D280→  [0x1D280 arena]
```

- A CALL-gráf `CONF:P`; a zárt komponens jellege `CONF:P`; a „soha nem fut" következtetés `CONF:L` (lásd az 1.5. pont 3. bekezdését).
- `BRef = [RVA:0x1E360 | RAW:0x1D760 | CONF:P | STATUS:OBSERVED]`
- `BRef = [RVA:0x1DCF0 | RAW:0x1D0F0 | CONF:P | STATUS:OBSERVED]`
- `BRef = [RVA:0x1DC80 | RAW:0x1D080 | CONF:P | STATUS:NEGATIVE]` — nincs közvetlen hívó.
- `BRef = [RVA:0x1E270 | RAW:0x1D670 | CONF:U | STATUS:OPEN]` — a futásidejű elérhetetlenség lezáratlan.

### 2.2 A négy legfontosabb korrekció

1. **A `0x1830D44F0` globális nem processz-heap handle, hanem `HeapCreate` privát heap.** A `0x1DCBE` hívás közvetlenül a `0x1DCC4` tárolást előzi, és az IAT-cél `KERNEL32!HeapCreate` (`0x2E4D418`), három nulla argumentummal. A `GetProcessHeap` a képben `7` helyről hívódik, és egyik előfordulása sem esik a `0x1D280`–`0x1E9D0` komponensbe. Részletek: **5.6** és a **12. fejezet** 1. sora.
2. **A teljes patch-komponensnek nincs statikusan elérhető belépési pontja, és a manager heap-gate-je ezért a dekódolt CFG-ben teljesíthetetlen.** A `0x1E3A4` `cmp [0x1830D44F0],0` kapu csak a `0x1DC80` `init` által teljesíthető, ennek viszont nincs közvetlen hívója. Részletek: **2.1**, **5.6**, és a **12. fejezet** 2. sora.
3. **A `0x1830D44E8` nem „egyszeri flag", hanem kézzel írt spin-zár**, és a versenypályán **korlátlan** a próbálkozás. Mindhárom használó a megszerzés után újraellenőrzi a saját feltételét. Részletek: **5.1** és a **12. fejezet** 3. sora.
4. **A `QueueUserAPC` kapcsolójának nincs írója a képben.** A `0x3254270` dword fájlban nulla és 7 olvasója van, de **0 írója**; a szomszédság-scan 11 írási referenciája egy `0xF0` bájttal arrébb lévő négy dwordra céloz. A `06` dokumentum „a globális értéke 0, akkor APC" állítása helyes volt, de nem említette, hogy a `0` fájl-inicializált alapérték, nem konfigurált érték. Részletek: **8.3** és a **12. fejezet** 9. sora.

### 2.3 Státusz-összegzés

| Mechanizmus | Szerkezet | Közvetlen caller | Aktiválás | Összesített |
|---|---|---|---|---|
| `0x1E270` rel32 patch | `OBSERVED` | megvan, de a komponensen belül | `OPEN` | `L` |
| `0x1DFF0` RIP redirect | `OBSERVED` | megvan, de a komponensen belül | `OPEN` | `L` |
| `0x1E360` manager | `OBSERVED` | nincs | `OPEN` | `L` |
| `0xC8CE70` Toolhelp telepítő | `OBSERVED` | nincs | `OPEN` | `L` |
| `0xC8F470` Toolhelp restore | `OBSERVED` | nincs | `OPEN` | `L` |
| `0x1754520` NOP fill | `OBSERVED` | nincs | `OPEN` | `L` |
| hét `QueueUserAPC` ág | `OBSERVED` | megvan hét owning függvényben | részben statikusan kiválasztott ág | `P` szerkezet / `U` végrehajtás |
| rekord-példányok | `OPEN` | — | — | `U` |

---

## 3. A `0x1E270` patch-tábla és a `0x06` flag

### 3.1 A hat globális

A rekordtábla és a hozzá tartozó állapot hat `.data` qword/dword globálison él. Mindegyik fájlban nulla:

| Név | RVA | RAW | Méret | Fájlbeli érték | Írók | Olvasók | Szerep |
|---|---|---|---:|---|---|---:|---|
| `region_free_list` | `0x30D44E0` | `0x30D2EE0` | 8 | `00 ×8` | `0x1D511` | `0x1D2E8`, `0x1D507`, `0x1DE36`, `0x1DE71` | az arena újrahasznosítható régióinak feje |
| `spin_lock` | `0x30D44E8` | `0x30D2EE8` | 4 | `00 ×4` | `0x1DCA6`, `0x1DCD9`, `0x1DD36`, `0x1DFBE`, `0x1E39D`, `0x1E563` | ugyanaz | kézzel írt spin-zár, lásd **5.1** |
| `heap_handle` | `0x30D44F0` | `0x30D2EF0` | 8 | `00 ×8` | `0x1DCC6` | 8 hely | **`HeapCreate` privát heap**, lásd **5.6** |
| `record_array` | `0x30D44F8` | `0x30D2EF8` | 8 | `00 ×8` | `0x1DEBD`, `0x1DF0E` | 9 hely | a `0x38` bájtos rekordok tömbjére mutató pointer |
| `capacity` | `0x30D4500` | `0x30D2F00` | 4 | `00 ×4` | `0x1DE9D`, `0x1DF07` | `0x1DED2`, `0x1DF07` | allokált rekorddarabszám |
| `count` | `0x30D4508` | `0x30D2F08` | 4 | `00 ×4` | `0x1DF1D` | 8 hely | élő rekorddarabszám, minden index-scan felső korlátja |

- **Eltolás észrevétel:** a `count` és a `capacity` mező nem szomszédos. A hat globális `0x30D44E0`-tól `0x30D450B`-ig egy `0x2C` bájtos blokkot alkot, és benne két `4` bájtos alignációs rés van a `0x30D44EC`–`0x30D44EF` és a `0x30D4504`–`0x30D4507` tartományban, amelyeket egyetlen hivatkozott globális sem használ. A patch-mechanizmus szempontjából ez nem releváns, de a rekordelrendezés dokumentálásakor rögzítendő. `CONF:P`.
- **Független ellenőrzés:** a nyers `.text` bájtscan RIP-relatív tárolási űrlapokra (`48 89 05`, `89 05`, `0F B1 05`, `87 05`, `C7 05`, valamint a `8B 05` / `48 83 3D` / `84 3D` / `80 0D` olvasási űrlapok) megerősítette, hogy a `heap_handle` globálist a teljes `.text`-ben **pontosan egy utasítás** írja, az `0x1DCC4`, és a `record_array`-t pontosan kettő, mindkettő a registrarban. A `spin_lock`-ra az `xchg` űrlap három helyen talál (`0x1DCDE`, `0x1DFC3`, `0x1E568`); a `lock cmpxchg` esetében a ModRM `rm=101` (`0x35`) változata szerepel, amit a scan nem ölelt fel — ezt a három `xchg` és a `patch_record_table.json` írólistája együtt fedi. `CONF:P`.
- A tábla slotból indulva **`264` (`0x108`) bájtnyi összefüggő nulla** következik a fájlban, tehát a slot és a `count` környezete teljes egészében a nem inicializált `.data` farok része. `CONF:P`.
- A slot `.data` szekcióban van, characteristics `0xC0000040` (`READ | WRITE | INITIALIZED_DATA`); nincs `MEM_EXECUTE`, és nincs image-relatív inicializáló. `CONF:P`.

BRef-ek:

```text
BRef = [RVA:0x30D44F8 | RAW:0x30D2EF8 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x30D44F0 | RAW:0x30D2EF0 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x30D44E8 | RAW:0x30D2EE8 | CONF:P | STATUS:OBSERVED]
```

### 3.2 A `0x38` bájtos rekord

A rekordtömb minden tagja `56` (`0x38`) bájt, és a lépés 8 bájtra igazított:

```text
rec = *(qword *)(0x1830D44F8) + index * 0x38
```

| Offszet | Név | Szélesség | Szimbolikus célkifejezés | Olvasók a három fogyasztóban | Írók |
|---|---|---:|---|---|---|
| `+0x00` | `anchor` | 8 | `rec + 0x00 − 5 · (rec[0x20] & 1)` | `0x1E297`, `0x1E17B`, `0x1E4C1` | `0x1DF2B` |
| `+0x08` | `destination` | 8 | `rec + 0x08` | `0x1E2ED` | `0x1DF34` |
| `+0x10` | `image_base` | 8 | `rec + 0x10 + rec[0x30][i]` | `0x1E1FD` | `0x1DF3E` |
| `+0x18` | `original_bytes` | 7 | snapshot a patch-részről | **nincs** | `0x1DFA0`, `0x1DFAA`, `0x1DFAF` |
| `+0x20` | `flags` | 1 | `rec + 0x20`, bitekkel | `0x1E29B`, `0x1E156`, `0x1E3E0`, `0x1E41C`, `0x1E4E8` | `0x1DF5A`, `0x1E336` |
| `+0x24` | `list_count` | 4 | `rec + 0x24 & 0x0F` | `0x1E161`, `0x1E834` | `0x1DF74` |
| `+0x28` | `offset_list` | 8 | `rec + 0x00 + rec[0x28][i]` | `0x1E1E9` | `0x1DF7E` |
| `+0x30` | `displacement_list` | 8 | `rec + 0x10 + rec[0x30][i]` | `0x1E1F7` | `0x1DF88` |

- **A `+0x08` olvasási szélessége észrevétel:** a `destination` mező `8` bájt széles, de a patcher **csak az alsó dwordját** olvassa a `0x1E2ED`-nél. A `patch_record_table.json` ebből azt a feltételt vezeti le, hogy a tárolt értéknek 32 bitesben kell férnie. Ez egy **lemezett** mező és egy **szűkített** olvasás közötti konzisztencia-megkötés, nem írási korlát: a registrar a `0x1DF34`-nél `8` bájtot ír. `CONF:P`.
- **A `+0x18` mező passzivitása:** az `original_bytes` mezőnek az elemzett halmazban **nincs olvasója**. A patcher nem ment vissza semmit, tehát a rendszer nem tudja ebből a rekordból visszaállítani az eredeti bájtokat. Ez a Toolhelp restore-párral szemben lényeges különbség: ott van egy caller-szállított visszamásoló rekord, itt nincs. `CONF:P`.
- A rekordelrendezés `CONF:P`, de a rekordok **tartalma** `CONF:U` (lásd a 13.2. pontot).

BRef-ek:

```text
BRef = [RVA:0x1DFAF | RAW:0x1D3AF | CONF:P | STATUS:OBSERVED]   # original_bytes, olvasó nélkül
BRef = [RVA:0x1E270 | RAW:0x1D670 | CONF:P | STATUS:OBSERVED]   # a rekord fogyasztója
BRef = [RVA:0x30D44F8 | RAW:0x30D2EF8 | CONF:U | STATUS:OPEN]    # a rekord-példányok
```

### 3.3 A patch-site kifejezés

A patcher a `0x1E2A3`–`0x1E2B8` között számolja a célcímet és a területméretet. A számítás lépései, mindegyik külön állítás:

| Lépés | RVA | Ugyanaz a bizonyíték |
|---|---|---|
| flagbjt beolvasása `rec + 0x20`-ről | `0x1E29B` | `movzx ecx, byte ptr [rbx + r14 + 0x20]` |
| bit 0 tesztelése | `0x1E2A3` | `test cl, 1` |
| az eredmény **invertálása** 0/1-re | `0x1E2A6` | `sete dl` — `dl = 1`, ha a bit 0 **tiszta** |
| ötszöröszés | `0x1E2A9` | `lea rdx, [rdx + rdx*4]` |
| hozzáadás az anchorhoz | `0x1E2AD` | `lea rsi, [rax + rdx]` |
| `−5` eltolás | `0x1E2B1` | `add rsi, -5` |
| területméret | `0x1E2B5`, `0x1E2B8` | `and ecx, 1` majd `lea rdi, [rcx*2 + 5]` |

Ebből a két variáns:

| Flag bit 0 | Patch-site | Területméret | A terület fedezi |
|---|---|---:|---|
| tiszta | `rec + 0x00` | `5` | az anchoron kezdődő `5` bájt |
| beállítva | `rec + 0x00 − 5` | `7` | `anchor − 5` … `anchor + 2` |

- **Az evidence szövegének aktuális állapota a második írásról.** A `patch_record_table.json` `address_model.second_store` mezőe már maga mondja ki a helyes irányt, nem vitatható formában: a `lands_on` mezője szerint a célcím „the anchor, which is patch site + 5, the upper edge of the seven byte window"; a `region` objektum `single_contiguous_store: false` és `write_group_count: 2` értéket ad, és két külön `write_groups` bejegyzést nevez meg (`patch_site .. patch_site + 5`, `2` írással; `patch_site + 5 .. patch_site + 7`, `1` írással); a `note` pedig így fogalmaz: „the store lands on the upper edge of the region, not below it". A korábbi „the only reference back to the lower five bytes of the region" mondat tehát már nem áll ellentmondásban a `lands_on` mezőnek — a `12. fejezet` 4. sora ezért a `06`/`07` dokumentumokra, nem az evidence-ra vonatkozik.
- **A szerkezeti állítás változatlan.** A `0x1E306` kétbájtos írás célcíme a `rec + 0x00`, azaz **az anchor**, és a hét bájtos terület a `patch_site = anchor − 5` kezdetű, tehát a `+0x00` pozíció a hét bájtos ablak **felső**, nem alsó szélén van. A `patch_site + 5 = anchor` azonosság miatt a két írás szomszédos, és együtt lefedi a teljes `7` bájtos védelmi ablakot: `5` bájt a `patch_site`-en, `2` bájt a `patch_site + 5`-en. A terület tehát **nem egyetlen folytonos írás**, hanem egy `5 + 2` bájtos, két szomszédos utasításból álló ablak. `CONF:P`.
- A területvédelem `0x40` (`PAGE_EXECUTE_READWRITE`), és a `VirtualProtect` a teljes `5`, illetve `7` bájtos ablakot kéri. `CONF:P`.

BRef-ek:

```text
BRef = [RVA:0x1E2A3 | RAW:0x1D6A3 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E2B8 | RAW:0x1D6B8 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E306 | RAW:0x1D706 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E2CB | RAW:0x1D6CB | CONF:P | STATUS:OBSERVED]
```

### 3.4 A két írási csoport és a `0x06` flag

A `0x1E2E2`–`0x1E30B` szakaszban a `+0x20` flagmező címe képződik, és a `patch_record_table.json` `address_model.region` mezője szerint **két írási csoport** van, összesen három tárolással. Az alábbi táblázat kizárólag a két csoport **statikus jellemzőit** írja le: melyik rekordmezőből származik a cél, milyen szélességű az írás, és a két csoport hogyan fedi le az ablakot. **A sorok sorrendje nem kivitelezési sorrend:** a dokumentum sem csoportok közötti, sem csoporton belüli végrehajtási sorrendet nem állít, az 1.1. pont szerint pedig konkrét írási bájtérték és eltolási konstans sem szerepel benne.

| Írási csoport | Bizonyíték-hely | Az ablakban érintett bájtok | Tárolások száma | Tárolások szélessége | A cél származási helye | A csoport statikus jellemzője |
|---|---|---|---:|---|---|---|
| 1. csoport, a `patch_site` oldala | `0x1E2EA`, `0x1E2F7` | `patch_site .. patch_site + 5` | 2 | `1` bájt a csoport kezdetén, `4` bájt a csoport kezdetétől `+1` | az írási cél maga a `patch_site`, amely a `+0x00` mezőből és a `+0x20` mező `0` bitjéből képzett szimbolikus kifejezés (3.3); a `4` bájtos tárolás értéke szimbolikusan a `+0x08` mező és a `patch_site` különbsége | két szomszédos tárolás ugyanazon `5` bájtos részen belül; a `write_groups` bejegyzés `patch_site .. patch_site + 5`, `2` írással |
| 2. csoport, az `anchor` oldala | `0x1E306` | `patch_site + 5 .. patch_site + 7` | 1 | `2` bájt | a cél a `+0x00` mező, azaz maga az **anchor** | az ablak **felső** `2` bájtja; a `lands_on` szerint „the anchor, which is patch site + 5, the upper edge of the seven byte window" |

- **A három tárolás utasításalakja** `mov byte ptr […]`, `mov dword ptr […]` és `mov word ptr […]`; egyik tárolt érték sem szerepel a dokumentumban. `CONF:P`.
- **A két csoport együtt fedi le az ablakot.** Az 1. csoport `5`, a 2. csoport `2` bájtnyi tartományt érint, és a kettő szomszédos, a közös határ a `patch_site + 5`, ami a `+0x00` mező, vagyis az anchor pozíciója. A terület tehát **nem egyetlen folytonos írás**, hanem `5 + 2` bájtos, két szomszédos utasításból álló ablak; ezt a `patch_record_table.json` `single_contiguous_store: false` és `write_group_count: 2` értékei adják meg. `CONF:P`.
- **Az ablakon kívül eső tárolás nincs:** a `7` bájtos ablakon belül a három tárolás a `patch_site + 0`, a `patch_site + 1` … `+4`, illetve a `patch_site + 5` … `+6` tartományt fedi le. `CONF:P`.
- **A `0` bit szerepe a határokban:** a `patch_record_table.json` `expr.region` szerint a teljes ablak `patch_site .. patch_site + 5 + 2 · (rec[0x20] & 1)`, vagyis a `0` bit `2` bájttal bővíti a területet, a 3.3. táblázata szerint pedig ilyenkor a `patch_site` `5` bájttal a `rec + 0x00` alá kerül. Az `5 + 2` bájtos, két csoportos lefedés a **beállított** `0` bitre zárt le: ekkor a `+0x00` pozíció az ablak felső szélén van, és a `single_contiguous_store: false`, `write_group_count: 2` állítás is erre a `7` bájtos változatra vonatkozik. `CONF:P`.
- **A csoportokhoz tartozó olvasások, önmagukban, nem lépéseként:** a flagmező címe a `0x1E2E2`–`0x1E2E6` (`lea r15, [rbx + r14]`, majd `+0x20` eltolás), a `+0x08` mező `4` bájtos olvasása a `0x1E2ED`-nél (`mov eax, dword ptr [rbx + r14 + 8]`), a `+0x20` `0` bitjének újratesztelése a `0x1E2FA`-nál (`test byte ptr [r15], 1`). Mindhárom az alábbi `0x01` bit olvasója, és egyik sem ír. `CONF:P`.

A relatív diszlokáció tárolása az 1. írási csoporton belül van: a helye `patch_site + 1`, szélessége `4`, vagyis csoport-eltolás `1`. A `patch_record_table.json` a `relative_displacement` mezőben a származtatást szimbolikusan `rec + 0x08 − patch_site − 5` alakban adja meg, és **nem bocsát ki konkrét diszlokációértéket**; ezt a gyakorlatot ez a dokumentum is követi. `CONF:P`.

- **Kontextus-korrekció a `patch_mechanisms_helpers.csv`-hez.** A `comparator_slot_write_0x1E2F7` sor a `0x1E2F7` írást `base origin=immediate:0xA`-val jelöli, azaz a `0x0A` hibakód literáljával. Ez az argumentumkövető **lineáris, backward pre-image** eredménye: a `0x0A` a `0x1E2DB`-nél kerül `esi`-be, és a tárolás ugyanazt az `esi`-alapú bázist használja, de a tárolás célja nem a `0x0A` érték. A szerkezeti értelmezés `CONF:L`, azaz az evidence `MEDIUM` szintje: a `patch_mechanisms_helpers.csv` saját `method_structural_heuristics` sora szerint az argumentumkövető basic-block elérhetőséget nem figyel, így egy nem vett ágon definiált regisztert is a path értékével jelent. A kurált horgony-modell (`patch_site + 1`) `CONF:P`.
- **A sorrendről:** a dokumentum a `7` bájtos ablak két csoportjának **végrehajtási sorrendjét nem állítja meg**; a fenti táblázat és pontok kizárólag szélesség-, cél- és lefedésleírást adnak, és a 14.1. pont ugyanezt a határt rögzíti. `CONF:P` a lefedésre, a sorrendre `nincs megadva`.

**A `0x06` flag.** A patcher a sikeres ágon a `0x1E336`-nál `or byte ptr [r15], 6` alakban **OR-ol** két bitet a `rec + 0x20`-ra:

| Bit | Név | Olvasói az elemzett halmazban | Írói |
|---|---|---|---|
| `0x01` | `two_slot_layout` — az 5/7 bájtos variáns kapcsolója | `0x1E2A3`, `0x1E2FA` | `0x1E974` (list builder), `0x1DF4F`, `0x1DF5A` (registrar) |
| `0x02` | `skip` — minden rekord-enumeráció kerülőkapuja | `0x1E156`, `0x1E3E0`, `0x1E41C`, `0x1E4E8` | `0x1E336` |
| `0x04` | `patched` — a patcher már feldolgozta | **egy sincs** | `0x1E336` |
| `0xF8` | `preserved_bits` — a 3–7. bit átvihető | **egy sincs** | `0x1DF53` (registrar merge) |

A `0x06` maszk `0x02` skip + `0x04` patched. Három tulajdonság érdemel külön kiemelést:

1. **Csak a sikerágon íródik.** A `0x1E336` a védelem-visszaállítás és a cache-öblítés **után** van a sikerágon; az első `VirtualProtect` hibáját szolgáltató `0x0A` ág a `0x1E33C`-re ugrik, és megkerüli. `CONF:P`.
2. **A kimenet ellenőrzése nélkül publikál.** A védelem-visszaállítás (`0x1E31B`) és a cache-öblítés (`0x1E330`) eredménye egyik sincs tesztelve, a flag pedig mindkettő után íródik. A rekord tehát „feldolgozott"-nak jelöli magát akkor is, ha a visszaállítás vagy az öblítés elbukott. `CONF:P`.
3. **A `patched` bit halott jelző.** Semmi az elemzett három fogyasztóban nem olvassa. Egyedüli hatása, hogy a `0x06` maszkkal együtt kerül ki; a tényleges „ne fusson át" hatást a `0x02` skip bit adja. `CONF:P`.

**Következmény a sorrendre:** mivel a `skip` bit mind a manager három, mind a redirect egy enumerációját olvassa, egy feldolgozott rekord **mindkét** mechanizmusból eltűnik. A `thread_context_map.json` `flag_visibility_window` konzisztenciaellenőrzése ezt így fogalmazza: a rekord csak azon a meneten látható az átírás számára, amely megelőzi a patcher feldolgozását. Mivel a manager a redirectet **mindkét** úton a patcher előtt hívja, a sorrend-helyesség a statikus sorrendből lezárható. `CONF:P`.

BRef-ek:

```text
BRef = [RVA:0x1E336 | RAW:0x1D736 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E29B | RAW:0x1D69B | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E3E0 | RAW:0x1D7E0 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E41C | RAW:0x1D81C | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E4E8 | RAW:0x1D8E8 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E156 | RAW:0x1D556 | CONF:P | STATUS:OBSERVED]
```

### 3.5 Védelem, visszaállítás és cache

| Lépés | RVA | Szimbólum | IAT RVA | Argumentumok | Eredmény |
|---|---|---|---|---|---|
| megnyitás | `0x1E2D1` | `KERNEL32.dll!VirtualProtect` | `0x2E4D630` | `patch_site`, `5`/`7`, `0x40`, `rsp+0x24` | **tesztelt** |
| visszaállítás | `0x1E31B` | `KERNEL32.dll!VirtualProtect` | `0x2E4D630` | `patch_site`, `5`/`7`, `rsp+0x24` (a mentett érték), `rsp+0x24` | **nem tesztelt** |
| processz-pszeudohandle | `0x1E321` | `KERNEL32.dll!GetCurrentProcess` | `0x2E4D318` | nincs | nem tesztelt |
| öblítés | `0x1E330` | `KERNEL32.dll!FlushInstructionCache` | `0x2E4D2E8` | handle, `patch_site`, `5`/`7` | **nem tesztelt** |

- A `0x1E2D7`–`0x1E2D9` `test eax, eax` / `jne` az egyetlen visszatérési érték-ellenőrzés a patcherben; a `0x0A` hibakód kizárólag ezen az egy úton keletkezik. `CONF:P`.
- Az IAT `0x2E4D630` és `0x2E4D2E8` nyers (`RAW`) értéke `0x2E4C030` és `0x2E4BCE8`. `CONF:P`.
- A visszaállítás `r8`-ban a `rsp+0x24`-ről olvasott mentett védelmet használja, tehát a `VirtualProtect` kimeneti paramétere stack-címként ismét felhasználásra kerül. `CONF:P`.

```text
BRef = [RVA:0x1E2D1 | RAW:0x1D6D1 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E31B | RAW:0x1D71B | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E321 | RAW:0x1D721 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E330 | RAW:0x1D730 | CONF:P | STATUS:OBSERVED]
```

### 3.6 Amit a patcher nem validál

A patcher **nincs** célméret- vagy oldalhatár-ellenőrzéssel felszerelve. A `patch_record_table.json` három „validációs ablakot" definiál (tábla-pointer, rekord-pointer, index) és mindhármat `checked: false` értékkel zárja:

| Bemenet | Figyelt regiszter | Betöltve | Első használat | Közbeni összehasonlítások | Ellenőrizve |
|---|---|---|---|---|---|
| tábla-pointer | `rbx` | `0x1E28A` | `0x1E297` | 0 | nem |
| rekord-pointer | `rax` | `0x1E297` | `0x1E2AD` | `0x1E2A3` | nem |
| index | `rax` | `0x1E291` | `0x1E293` | 0 | nem |

Következmények, mind `CONF:P`:

- A `rec + 0x00` értékét semmi nem hasonlítja a kép határához vagy oldalhatárhoz; egy tetszőleges futásidejű érték közvetlenül célcímként szolgál.
- A `rec + 0x08` alsó dwordja `int32` eltérést képez, és nincs `±2 GiB` körüli tartomány-ellenőrzés, tehát a relatív ugrás a `rel32` formátum határán túl is „sikeresnek" számít.
- A `5`/`7` bájtos ablak átfedhet egy oldalvéget; a `VirtualProtect` ilyenkor a szomszédos oldal teljes védelmét állítja `0x40`-re, és az eredeti értékét egyetlen dwordban őrzi. A visszaállítás emiatt a `VirtualProtect` szemantikájára bízza a tényleges részleges terület kezelését.
- A patcher **nem** ellenőrzi a `rec + 0x10` mezőt, a `rec + 0x18` snapshotot, sem a `rec + 0x24` nibblet.

### 3.7 A kapacitás és a duplikátumszűrés

A registrar a `0x1DEAD`-nél `32 × 0x38 = 1792` bájtot kér az első allokációhoz, a `0x1DEE1`-nél növekedéskor `új_kapacitás × 0x38` bájtot, és a `0x1DF06`-nél megkétszerezi a kapacitást. A `0x1DDCC` duplikátum-scan a `rec + 0x00` értékét hasonlítja, tehát **anchor-alapú** az egyediség, nem index-alapú. `CONF:P`.

BRef-ek:

```text
BRef = [RVA:0x1DEAD | RAW:0x1D2AD | CONF:P | STATUS:OBSERVED]   # 32 * 0x38 = 1792 bájt
BRef = [RVA:0x1DDCC | RAW:0x1D1CC | CONF:P | STATUS:OBSERVED]   # anchor-alapú duplikátumszűrés
BRef = [RVA:0x1E293 | RAW:0x1D693 | CONF:P | STATUS:OBSERVED]   # index * 0x38 a patcherben
BRef = [RVA:0x1E4BD | RAW:0x1D8BD | CONF:P | STATUS:OBSERVED]   # index * 0x38 a manager lookupban
BRef = [RVA:0x1E152 | RAW:0x1D552 | CONF:P | STATUS:OBSERVED]   # index * 0x38 a redirectben
```

A `0x38` lépés tehát **négy** független funkcióban jelenik meg; ez a rekordelrendezés legszilárdabb keresztellenőrzése az evidence-készletben.

---

## 4. A `0x1DFF0` thread-snapshot RIP redirect — nem bytecode patcher

### 4.1 Az enumeráció

A `0x1DFF0` függvény a saját processz szálait gyűjti `THREADENTRY32` listába. A `patch_mechanisms_1dff0.csv` 51 sora ezt minden lépésre dokumentálja; a lényegi sorok:

| Lépés | RVA-k | Tartalom | `STATUS` |
|---|---|---|---|
| snapshot | `0x1E022`, `0x1E027`, `0x1E029` | `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)` a `0x2BED400` thunkon át, IAT `0x2E4D290` | `OBSERVED` |
| érvénytelen handle | `0x1E02E`, `0x1E032` | `rax == 0xFFFFFFFFFFFFFFFF` → az egész mechanizmus kihagyása | `OBSERVED` |
| első olvasás | `0x1E03B`, `0x1E04B` | `Thread32First`, `dwSize` előre beállítva `0x1C`-re | `OBSERVED` |
| szerkezetméret-kapu | `0x1E054`, `0x1E059` | `[rsp+0x30] >= 0x10`, különben a szál teljes kiesése | `OBSERVED` |
| tulajdonos-szűrő | `0x1E05F`, `0x1E063`, `0x1E069` | `th32OwnerProcessID` (`+0x0C`) == `GetCurrentProcessId()` | `OBSERVED` |
| önkizárás | `0x1E071`, `0x1E075`, `0x1E07B` | `th32ThreadID` (`+0x08`) != `GetCurrentThreadId()` | `OBSERVED` |
| allokáció | `0x1E08F`…`0x1E0AB` | `HeapAlloc(*(0x1830D44F0), 0, 0x200)` = 128 bejegyzés, a blokk `rcx+0x00`-ba | `OBSERVED` |
| növekedés | `0x1E187`…`0x1E1A0` | `HeapReAlloc(…, capacity*2*4)` | `OBSERVED` |
| hozzáfűzés | `0x1E1B9`…`0x1E1C4` | `out.array[count++] = th32ThreadID` | `OBSERVED` |
| üres-lista-kapu | `0x1E0C0`, `0x1E0CA` | `rcx+0x00 != 0 AND rcx+0x0C != 0` | `OBSERVED` |
| következő olvasás | `0x1E1C7`, `0x1E1D7` | `Thread32Next`, `dwSize` újrabevágva minden hívás előtt | `OBSERVED` |

- **A `0x5A` jogkombináció pontos olvasata.** `OpenThread(0x5A, FALSE, tid)` a `THREAD_SUSPEND_RESUME` + `THREAD_GET_CONTEXT` + `THREAD_SET_CONTEXT` + `THREAD_QUERY_INFORMATION` összeg. A `thread_context_map.json` `access_mask_matches_usage` ellenőrzése egy művelethez egy jogot párosít, és a ténylegesen használt műveletek: suspend, get context, set context. A `THREAD_QUERY_INFORMATION` jogot a vizsgált ág nem használja. Ez **nem** ellentmondás — a maszk lehet szélesebb a használtnál —, de a „pontosan a használt jogok" állításnál pontosabb így fogalmazni. `CONF:P` a maszkre, `CONF:L` a jogfelesleg értelmezésére.
- Az allokáció és a későbbi `HeapFree` ugyanazt a `0x1830D44F0` globálist használja, tehát a szálazonosító-tömb és a rekordtömb egy allokátoron osztozik. A `caller_heap_ownership` sor ezt `OBSERVED`, `HIGH` jelöléssel rögzíti. `CONF:P`.
- A `out` blokk 16 bájt, és belépéskor **egyetlen 128 bites tárolással** nullázódik a `0x1E01F`-nél; ez lefedi a pointert, a kapacitást és a darabszámot egyben. `CONF:P`.

```text
BRef = [RVA:0x1E029 | RAW:0x1D429 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E0F4 | RAW:0x1D4F4 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E0A5 | RAW:0x1D4A5 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E01F | RAW:0x1D41F | CONF:P | STATUS:OBSERVED]
```

### 4.2 A context puffer

| Tulajdonság | Érték | Bizonyíték |
|---|---|---|
| `ctx` | `rsp + 0x30` | `0x1E117` `lea rdx, [rsp + 0x30]` |
| struktúraméret | `0x4D0` | `thread_context_map.json` `context_buffer` |
| keretméret | `0x508` | a struktúra pontosan a cookie-slotig ér |
| `ContextFlags` | `0x100001` a `CONTEXT+0x30`-on, azaz `rsp+0x60` | `0x1E10F` `mov dword ptr [rsp + 0x60], 0x100001` |
| `CONTEXT.Rip` | `ctx + 0xF8`, azaz `rsp + 0x128` | `0x1E173` olvassa, `0x1E204` írja |
| érintett mezők | kizárólag `ContextFlags` és `Rip` | `thread_context_map.json` `fields_touched` |
| **nem** érintett | a teljes általános célú regisztercsoport és minden más mező | `no_general_purpose_registers_captured`, `ABSENT` |

- **A maszk pontos olvasata.** `0x100001 = 0x100000 | 1`. A `0x100000` a `CONTEXT_CONTROL` csoportjelölő, az `1` a `CONTEXT` x86-64 definíciójának control-szelektorja. A `thread_context_map.json` helyesen megjegyzi, hogy „csak a control mezők kértetnek". `CONF:P`.
- **A keret-átfedés kezelése.** Ugyanaz a stack-slot szolgálja a `THREADENTRY32`-t az enumeráció alatt és a `CONTEXT`-ot a szálkezelés alatt. A `frame_slot_aliasing` ellenőrzés szerint a két használat nem fedezi egymást, mert az enumeráció a snapshot-handle lezárásával zárul, és csak utána nyílik az első context. A `0x1E0DC` invariant ezt rögzíti. `CONF:P`.

```text
BRef = [RVA:0x1E10F | RAW:0x1D50F | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E173 | RAW:0x1D573 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E204 | RAW:0x1D604 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E117 | RAW:0x1D517 | CONF:P | STATUS:OBSERVED]
```

### 4.3 A RIP-újraképzés

A mechanizmus magja két, párhuzamosan indexelt bájtlista:

```text
illesztés:    rec + 0x00 + rec[0x28][i]  ==  CONTEXT.Rip
csere:        rec + 0x10 + rec[0x30][i]
darabszám:    rec + 0x24 & 0x0F
```

| Tulajdonság | Érték | `STATUS` | Bizonyosság |
|---|---|---|---|
| illesztési szélesség | `8` bájtos pontos egyenlőség | `OBSERVED` | `CONF:P` |
| `0x28` elem | `1` bájt, nulla kiterjesztésű, `0`–`255` | `OBSERVED` | `CONF:P` |
| `0x30` elem | `1` bájt, `0`–`255` | `OBSERVED` | `CONF:P` |
| számláló maszkja | `0xF` | `OBSERVED` | `CONF:P` |
| beépített elemkapacitás | `8` | `OBSERVED` | `CONF:P` |
| ablakplafon | `0x32` (`50`) bájt a builderben, a `0x1E82F`-nél | `OBSERVED` | `CONF:P` |
| `i` index megosztása | egyetlen ciklusszámláló hajtja mindkét betöltést | `OBSERVED` | `CONF:P` |
| egy rekordra egy alkalmazás | a `0x1E1E7` a rekordhaladáson lép ki, nem vissza a bejegyzésciklusba | `OBSERVED` | `CONF:P` |

A `patch_record_table.json` öt konzisztencia-ellenőrzése ehhez:

| `id` | Szabály | Verdikt | Bizonyosság |
|---|---|---|---|
| `list_cap_matches_stride` | a darabszám a `0x28`/`0x30` által birtokolt `8` bájton belül marad | `enforced_by_builder` | `CONF:P` |
| `count_nibble_fits_cap` | a maszkolt számláló szélesebb a kapnál, tehát nem vág le bejegyzést | `consistent_with_cap` | `CONF:P` |
| `zero_count_means_empty` | nulla nibble inert rekordot ad | `inert_record` | `CONF:P` |
| `parallel_lists_share_index` | az `i` index mindkét listát közösen választja | `parallel_by_construction` | `CONF:P` |
| `defined_but_unused_tail` | a registrar mindig mind a `8` bájtot elmenti, függetlenül a számlálótól | `defined_but_unused` | `CONF:L` |

- **A `0x32` ablakplafon miért lényeges:** mindkét listaelem `1` bájt, a kezdőeltolás és az utolsó kurzor is `≤ 0x32`. A `window_cap_keeps_bytes` ellenőrzés ezt lezárja: a bájttáblák nem tudnak átcsordulni. `CONF:P`.
- **A `0x30` elem szemantikája nem a kezdőeltolás, hanem az „utolsó" kurzor.** A `list_provenance_0x30` sor szerint az elem „a window cursor past that instruction", vagyis az átírt `RIP` az eredeti utasítás **utáni folytatásra** kerül az újraépített képben, nem magára az utasításra. Ez a mechanizmus vezérlés-áthelyezés, nem utasítás-betűzés. `CONF:P`.
- **Az `i` index visszacsatolása.** A `0x1E204` a keret-másolatot az alkalmazás **előtt** írja, így a következő rekord már a csereértékhez hasonlít. Ez a `record_chain_continuation` sor lényege, és egyben az alkalmazások számának felső korlátja is: egy szálra legfeljebb a vizsgált rekordok száma alkalmazás jut. `CONF:P` a szerkezetre, `CONF:L` a gyakorlati gyakoriságra.

```text
BRef = [RVA:0x1E1E9 | RAW:0x1D5E9 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E1F2 | RAW:0x1D5F2 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E1F7 | RAW:0x1D5F7 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E202 | RAW:0x1D602 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E221 | RAW:0x1D621 | CONF:P | STATUS:OBSERVED]
```

### 4.4 Amit a redirect nem tesz

| Negatívum | Bizonyíték | `STATUS` | Bizonyosság |
|---|---|---|---|
| nem hív `ResumeThread`-et a `0x1DFF0`–`0x1E26A` tartományban | a resume IAT-slotot csak a manager hivatkozza, a `0x1E484` és a `0x1E537` helyen | `ABSENT` | `CONF:P` |
| nem ír futtatható bájtot | nincs védelmi és nincs cache-öblítő import a tartományban | `ABSENT` | `CONF:P` |
| nem ír általános célú regisztert | a maszk csak a control csoportot kéri | `ABSENT` | `CONF:L` |
| nem ad vissza státuszt | nincs return-érték és nincs kimeneti flag | `OBSERVED` | `CONF:P` |
| nincs általános mutató, nincs RIP-relatív hivatkozás, nincs thunk | az egyetlen hivatkozás a két közvetlen call és a kivételkönyvtár-bejegyzés; a `rva32` literál egy RIP-diszlokáció, nem mutató | `ABSENT` | `CONF:P` |
| a `rec + 0x10` mezőt nem teszteli nullára | csak az összeget hasonlítja nullához | `OBSERVED` | `CONF:L` |
| a `SuspendThread` eredményét nem teszteli | a hívás után nincs összehasonlítás | `OBSERVED` | `CONF:P` a hiányra, `CONF:L` a verseny-következményre |
| a `SetThreadContext` eredményét nem teszteli | nincs összehasonlítás a következő utasításig | `OBSERVED` | `CONF:L` |

- **A `SuspendThread` ellenőrizetlensége miatti verseny:** ha a felfüggesztés nem lépett életbe, a `GetThreadContext` és a `SetThreadContext` egy futó szál ellen versenyez, a manager pedig ettől függetlenül elvégzi az egy `ResumeThread`-et. A függvényben nincs suspend-számláló-olvasás, tehát a kód nem tudja megkülönböztetni a „sikerült" és a „nem sikerült" esetet. `CONF:L`.
- **A `SetThreadContext` ellenőrizetlensége miatti láncolódás:** a `0x1E204` a keret-másolatot az alkalmazás előtt írja, ezért egy elutasított `SetThreadContext` után is a csereérték van a `[rsp+0x128]`-ban, és a **következő rekord már ahhoz hasonlít**. A `set_context_result_unchecked` sor ezt `MEDIUM`, azaz `CONF:L` szinten adja. `CONF:L`.
- **A nulla kép-alap ellenőrizetlensége:** a `rec + 0x10` mezőt külön nem teszteli, csak a `rec + 0x10 + rec[0x30][i]` összeget. Ha a kép-alap nulla, de a célbájt nem nulla, a kapu átmegy, és egy igen kis érték kerül a `RIP`-be. A mező írója a registrar, amely az arena blokkjából veszi; hogy publikálhat-e nullát, a rekordelrendezésből nem dönthető el. `CONF:U`.
- **A `0x1E400` és `0x1E4F6` a két közvetlen hívó, és semmi más nem hívja a függvényt.** A `subject_not_address_taken` sor ezt `ABSENT`, `HIGH` jelöléssel rögzíti. `CONF:P`.

```text
BRef = [RVA:0x1E109 | RAW:0x1D509 | CONF:P | STATUS:OBSERVED]   # SuspendThread eredménye nincs tesztelve
BRef = [RVA:0x1E214 | RAW:0x1D614 | CONF:L | STATUS:INFERRED]
BRef = [RVA:0x1E1FD | RAW:0x1D5FD | CONF:U | STATUS:OPEN]
BRef = [RVA:0x1DFF0 | RAW:0x1D3F0 | CONF:P | STATUS:NEGATIVE]   # nincs általános mutató
```

### 4.5 Miért nem bytecode patcher

A `patch_mechanisms_1dff0.csv` `no_code_write` sora a `no_resume_in_subject` mellett kimondja, hogy „a mechanizmus csak vezérlésáthelyezés, a bájtszintű patchelés külön funkció". Ezt a dokumentum három, egymástól független megfigyeléssel erősíti:

1. **Nincs írás védett vagy futtatható területre.** A `0x1DFF0`–`0x1E26A` tartományban egyetlen `VirtualProtect` és egyetlen `FlushInstructionCache` hivatkozás sincs; az `xref_edges.csv` megerősíti, hogy a `0x1E000`–`0x1E36F` forrás-tartományban kizárólag a redirect és a patcher IAT-hívásai vannak, és a patcher hívásai a `0x1E2D1`–`0x1E330` szakaszban, azaz már a patcherben esnek. `CONF:P`.
2. **A két írás a frame-re és az out blokkra történik.** A `0x1E01F` egy `movups` az out blokk nullázására, a `0x1E204` a `CONTEXT.Rip` frame-másolatát írja. `CONF:P`.
3. **A célcím eredete futásidejű állapot.** A csereérték a `rec + 0x10` mezőből és egy `1` bájtos listából képződik, és a slot fájlban nulla. `CONF:P`.

A kettő közti felelősséghatár tehát: a `0x1DFF0` **eldönti, hol legyen a szál**, a `0x1E270` **átírja a bájtokat**. A manager az 5. fejezetben leírt sorrendben hívja őket, így a szál előbb elhagyja az eredeti címet, és csak utána változnak meg az ott futó bájtok.

---

## 5. A `0x1E360` manager és a caller sorrend

### 5.1 A zár

A `0x1830D44E8` globális három funkcióban is szerepel, és mindhárom ugyanazt a kézzel írt `lock cmpxchg` / `xchg` párt használja:

| Funkció | Felvétel | Leadás | Tartalom |
|---|---|---|---|
| `init` `0x1DC80` | `0x1DCA3` | `0x1DCD8` | `Sleep(0\|1)` visszavonás a `0x1DC8F`–`0x1DC9E` blokkban |
| `registrar` `0x1DCF0` | `0x1DD33` | `0x1DFBD` | `Sleep` a `0x1DD28`-nál |
| `orchestrator` `0x1E360` | `0x1E39A` | `0x1E562` | `Sleep` a `0x1E38F`-nél |

A versenypálya a `0x1E386`–`0x1E398` blokk:

1. `xor ecx, ecx`;
2. `cmp rsi, 0x20`; `setae cl` — a `Sleep` argumentuma `0` vagy `1` millisecond;
3. `call Sleep`;
4. `inc rsi` — **szám nélküli** növelés;
5. `jmp` vissza a `lock cmpxchg`-re.

- **Korrekció, és a forrás is megváltozott.** A `patch_record_table.json` `table.globals[spin_lock].purpose` mezőe **most már maga is** a spin-zár értelmezést adja: „hand rolled interlocked spin lock, the contention counter is unbounded and every holder re-checks its own precondition, so it is a mutual exclusion lock and not a one shot initialiser", és a `lock.kind` mező `hand_rolled_interlocked_spin_lock`. Az „egyszeri flag" megfogalmazás **máshonnan** jön: a `thread_context_map.json` `activation.ordering_matrix` 5. lépése még „releases the once flag", a `callers[].preconditions` még „the once flag at 0x1830D44E8 is taken", és a `patch_mechanisms_1dff0.csv` `caller_lock_discipline` sora még „a hand rolled once flag"-et ír. Mindhárom használó a megszerzés után **újraellenőrzi a saját feltételét** — `init`: `cmp [heap], 0` a `0x1DCAD`-nél; `registrar`: `cmp [heap], 0` a `0x1DD3D`-nál; `orchestrator`: `cmp [heap], 0` a `0x1E3A4`-nél. Ez egy kézzel írt **kölcsönös kizárás** minimális alakja, nem egy futásszámos inicializáló flag. `CONF:P`.
- **A korlátlan próbálkozás már nem csak a dokumentum saját újraszámolása:** a `patch_record_table.json` `lock.contention_path` mezőe `attempt_cap: null` és `timeout: null` értékeket ad, a `threshold` `0x20`, a `sleep_argument` „0 below 0x20, 1 millisecond at and above it", és mindhárom használónál a `retry_counter_bounded: false`. Nincs timeout, nincs attempt cap, nincs megvalósulási garancia. A `0x06` dokumentumokhoz képest ez az új tény; a `06` §5.3 „egyszeri" jelölése ma már sem a spin-zárra, sem a `patch_record_table.json`ra nem igaz. `CONF:P`.
- **Kilépési konzisztencia:** az orchestrator összes kilépési útja a `0x1E560`-re convergeál, ahol `xor eax, eax` majd `xchg [0x1830D44E8], eax` történik. A zár tehát **pontosan egyszer**, minden úton elengedésre kerül, beleértve a `2`, `4`, `5` és a patcherből jövő hibakódokat is. A `lock.single_release_point` mező ezt `0x1E560`-val rögzíti. `CONF:P`.
- A `0x1E562` előtti `xor eax, eax` a return-regisztert is nullázza; a `0x1E575` `mov eax, esi` állítja vissza a valódi értéket. A zár elengedése tehát nem befolyásolja a visszatérési értéket. `CONF:P`.

```text
BRef = [RVA:0x1E39A | RAW:0x1D79A | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E386 | RAW:0x1D786 | CONF:P | STATUS:OBSERVED]   # korlátlan újrapróbálkozás
BRef = [RVA:0x1E562 | RAW:0x1D962 | CONF:P | STATUS:OBSERVED]   # egyetlen elengedési pont
BRef = [RVA:0x1DCA3 | RAW:0x1D0A3 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1DD33 | RAW:0x1D133 | CONF:P | STATUS:OBSERVED]
```

### 5.2 A tömegút

Belépési feltételek sorrendben:

1. `0x1E3A4`: `cmp qword ptr [0x1830D44F0], 0` — a heap-publikálás kapuja. Ha nulla, `mov esi, 2` és kilépés, **minden callhely előtt**. `CONF:P`.
2. `0x1E3B8`: `test rdi, rdi` / `jne 0x1E4A0` — a `rdi` argumentum nulla a tömegútra, nem nulla az egy-rekord útra. `CONF:P`.
3. `0x1E3C1`: az élő rekorddarabszám betöltése. Ha nulla, `xor esi, esi` és kilépés — **nulla siker**. `CONF:P`.
4. `0x1E3D3`: a rekordtömb betöltése. A `0x1E3DC`–`0x1E3ED` az első **skip bit nélküli** indexet keresi; ha nincs ilyen, `xor esi, esi` és kilépés — **szintén nulla siker**. `CONF:P`.
5. `0x1E3F6`–`0x1E400`: `lea rcx, [rsp+0x28]`, `mov edx, -1`, `call 0x1DFF0`. A `−1` a szentély: a redirect ekkor az **összes** rekordot végigjárja, és a limit a `count` lesz. `CONF:P`.
6. `0x1E405`: a darabszám **újból** betöltése a redirect után; `0x1E411`: a rekordtömb **újból** betöltése. A `table_pointer_refresh` ellenőrzés ezt védelmi intézkedésnek nevezi: egy futásidejű növekedés nem hagyhat elavult mutatót. `CONF:P`.
7. `0x1E418`–`0x1E447`: a patch-ciklus `0x38` lépéssel. Minden iterációban skip-bit teszt, majd `mov ecx, edi` és `call 0x1E270`. **Sikertelen patch esetén a ciklus azonnal leáll** (`test eax, eax`, `jne 0x1E449`), és a patcher kódja lesz a visszatérési érték. `CONF:P`.
8. `0x1E449`–`0x1E499`: az out blokk visszaolvasása, majd a resume-ciklus: `OpenThread(0x5A, FALSE, tid)` → `ResumeThread` → `CloseHandle`, `0x1E493`-nál növelt kurzorral. `CONF:P`.
9. `0x1E54E`–`0x1E55A`: `HeapFree(*(0x1830D44F0), 0, out.array)`. `CONF:P`.

**Fontos félreértelmezés-kerülő:** a 3. és a 4. pont **nulla értékkel tér vissza, és egyetlen callhelyet sem ér el**. Ez nem azt jelenti, hogy „a patch megtörtént", hanem azt, hogy „nincs mit tenni". A kód nem különbözteti meg a sikeres-no-op-ot a sikeres-tevéstől. `CONF:P`.

### 5.3 Az egy-rekord út

1. `0x1E4A0`: a darabszám betöltése, `mov esi, 4` — **a 4-es kód már itt beáll**. Ha a darabszám nulla, `je 0x1E560`, tehát `4`. `CONF:P`.
2. `0x1E4B4`–`0x1E4CD`: lineáris keresés `rec + 0x00` alapján a `rdi` argumentumra, `0x38` lépéssel. Ha nincs találat, `jmp 0x1E560`, tehát `4`. `CONF:P`.
3. `0x1E4D4`–`0x1E4D7`: a kapott index összevetése a szentélyértékkel. A `patch_mechanisms_1dff0.csv` `caller_dead_sentinel_branch` sora megállapítja, hogy a keresés csak a számláló alatti indexre sikerülhet, ami ezen az úton nem nulla, tehát **az ág nem vehető fel**. `CONF:P`.
4. `0x1E4E3`: `mov esi, 5` — **az 5-ös kód az ugrás előtt áll**, tehát akkor is ez lesz a visszatérési érték, ha a skip bit eldobja a rekordot.
5. `0x1E4E8`: skip-bit teszt; beállított bitre `jne 0x1E560`, tehát `5`. `CONF:P`.
6. `0x1E4EF`–`0x1E4F6`: `lea rcx, [rsp+0x28]`, `mov edx, ebx`, `call 0x1DFF0`. A redirect **egyetlen** rekordot dolgoz fel: a kezdőindex és a limit egyaránt a talált index. `CONF:P`.
7. `0x1E4FB`–`0x1E502`: `mov ecx, ebx`, `call 0x1E270`, `mov esi, eax` — a patcher státusza itt **közvetlenül** lesz a manager státusza, overwrite nélkül. `CONF:P`.
8. `0x1E518`–`0x1E54C`: a resume-ciklus **duplikált blokkja**; a `0x1E504` `mov rdi, [rsp+0x28]` újraolvassa az out blokkot. `CONF:P`.

**A két út közötti lényegi különbség:** a tömegút a patcher **nulla** eredményét is sikernek tekinti, és csak nem-nulla hibán áll meg; az egy-rekord út a patcher státuszát **továbbadja**. A `caller_status_codes` sor ezt így összegzi: „nincs kód a meg nem történt redirectért, a szubjektumnak nincs return értéke, és a tömegút eldobja, amit a szubjektum a return regiszterben hagy". `CONF:P`.

- **A kettős `OpenThread` észrevétel:** a manager a resume-hoz **úra megnyitja** mindegyik azonosítót, tehát a resume nem azon a handle-n történik, amelyen a redirect felfüggesztett. A `thread_handles` harmadik bejegyzése ezt `independent_handle: true` jelöléssel és külön megjegyzéssel rögzíti. Az előny: a resume akkor is működik, ha a szubjektum handle-je már lezárva lett. `CONF:P`.

### 5.4 A visszatérési kódok

| Kód | Ki állítja | Hol | Megjegyzés |
|---:|---|---|---|
| `0` | `0x1E3CC`, `0x1E3EF`, `0x1E40B` | tömegút | siker **vagy** no-op; a kettő nem megkülönböztethető |
| `0` | `0x1E33A` | patcher | sikerág |
| `2` | `0x1E3AE` | tömegút és egy-rekord út | a heap-nincs-publikálva kapu |
| `4` | `0x1E4A6` | egy-rekord út | nulla darabszám, vagy nincs egyező anchor |
| `5` | `0x1E4E3` | egy-rekord út | a talált rekord skip bitet visel |
| `0x0A` | `0x1E2DB` | patcher | az első `VirtualProtect` hibája; a tömegúton megállítja a ciklust |
| a patcher kódja | `0x1E502` | egy-rekord út | közvetlen továbbadás |

- A `2`, `4`, `5`, `0x0A` értékek mind **statikus kódolásúak**; egyik sem egy külső API státusza. `CONF:P`.
- A **redirect** eredete nincs kódolva sehol: se a tömegúton, se az egy-rekord úton. `CONF:P`.

```text
BRef = [RVA:0x1E400 | RAW:0x1D800 | CONF:P | STATUS:NEGATIVE]   # a redirect eredete nincs kódolva
BRef = [RVA:0x1E502 | RAW:0x1D902 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E3A4 | RAW:0x1D7A4 | CONF:P | STATUS:OBSERVED]
```

### 5.5 Az ötlépéses sorrend

A `thread_context_map.json` `ordering_matrix` öt lépése és a `patch_mechanisms_1dff0.csv` `caller_ordering_redirect_before_patch` sora együtt a következő sorrendet adják, mindkét úton:

| Lépés | RVA | Művelet | `STATUS` |
|---:|---|---|---|
| 1 | `0x1E0C0` | a szálak enumerálása az out blokkba | `OBSERVED` |
| 2 | `0x1E109` | felfüggesztés, `RIP` olvasás, átírás, context alkalmazás, handle lezárás | `OBSERVED` |
| 3 | `0x1E336` | a patcher felülírja a bájtokat és felemeli a `0x06` maszkot | `OBSERVED` |
| 4 | `0x1E484` | a caller újra megnyitja mindegyik gyűjtött szálat, folytatja, majd lezárja azt a handle-t | `OBSERVED` |
| 5 | `0x1E55A` | a caller felszabadítja az azonosító-tömböt és elengedi a zarást | `OBSERVED` |

A `redirect_precedes_patch` ellenőrzés ezt két cím-párral rögzíti: a `0x1E400` megelőzi a `0x1E425`-öt, és a `0x1E4F6` megelőzi a `0x1E4FD`-t. **A sorrend statikusan helyes:** a szál addig függesztve van, amíg az eredeti címen futó bájtok még változatlanok, és a resume csak a 4. lépésben történik, a 3. lépés után. `CONF:P`.

- **A sorrend mindkét irányban lezárt:** sem a `0x1E400`, sem a `0x1E4F6` nem futhat olyan szálon, amelynek a `RIP`-je már a patchelt területre mutatna, mert a `0x06` flagot a 3. lépés írja, és a 2. lépés már befejeződött. `CONF:P`.

```text
BRef = [RVA:0x1E400 | RAW:0x1D800 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E425 | RAW:0x1D825 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E4F6 | RAW:0x1D8F6 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E4FD | RAW:0x1D8FD | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E484 | RAW:0x1D884 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1E55A | RAW:0x1D95A | CONF:P | STATUS:OBSERVED]
```

### 5.6 A heap-kapcsolat — a korrekció helye

Ez a pont a jelen dokumentum legfontosabb új megállapítása.

**Megfigyelés.** A `0x1DC80` `init` a `0x1DCB7`–`0x1DCBE` között három `xor`-ral nullázza mindhárom argumentumot, majd meghívja az `IAT 0x2E4D418` slotot. Az `xref_edges.csv` 44835. sora ezt a slotot `KERNEL32.dll!HeapCreate`-ként azonosítja. A következő utasítás, a `0x1DCC4`, `mov qword ptr [0x1830D44F0], rax` — vagyis a `HeapCreate` visszatérési értékét tárolja el. A nyers bájtok: a `0x1DCBE` `ff 15 54 f7 e2 02`, aminek RIP-célja `0x1DCBE + 6 + 0x2E2F754 = 0x2E4D418`; a `0x1DCC4` `48 89 05 25 68 0b 03`, aminek RIP-célja `0x1DCC4 + 7 + 0x30B6825 = 0x1830D44F0`. `CONF:P`.

**Következmény 1 — a heap privát, nem processz-heap.** Az evidence ezt most már nem is tagadja: a `patch_record_table.json` `heap.is_process_heap` mezője `false`, a `heap.kind` mezője `private_heap`, a `table.globals[heap_handle].purpose` szerint „private KERNEL32!HeapCreate(0, 0, 0) handle, zero in the file and published by its only writer, the init that itself has no direct caller", a `capacity_model.allocator` pedig „KERNEL32!HeapAlloc and KERNEL32!HeapReAlloc on the private heap published at 0x1830D44F0". A megmaradt ellentmondás tehát a `06` és `11` dokumentum hallgatólagos processz-heap feltételezésében áll, nem az evidence-ban. A globális egy `HeapCreate(0, 0, 0)` eredménye, tehát **saját**, külön heap; a `heap.why_not_the_process_heap` felsorolja a négy okot. A `GetProcessHeap` a képben `7` helyről hívódik (`0x16B3`, `0x1843`, `0x8A529C`, `0x8A8F15`, `0x955AB4`, `0x959DD2`, `0xB70391`), és a `call_sites_in_component` lista **üres**. A komponens egyetlen allokátor-hozzáférése a `0x1DEB5` `HeapAlloc` és a `0x1DEF1` `HeapReAlloc`, mindkettő a `0x1830D44F0`-et olvassa. A rekordtömb és a szálazonosító-tömb tehát ugyanazon a privát heapen osztozik. `CONF:P`.

**Következmény 2 — az `init` hibakódja `9`, nem `0`.** A `0x1DCCB`–`0x1DCD3` `xor ecx, ecx`; `test rax, rax`; `sete cl`; `lea esi, [rcx + rcx*8]` — a visszatérés `0` siker esetén és `9`, ha a `HeapCreate` nullát ad. A `patch_record_table.json` ezt továbbra sem dokumentálja, mert az `init` szerepe a `producers` listában a heap-létrehozásra és a publikálásra szűkül, kilépési érték mező nélkül. `CONF:P`.

**Következmény 3 — a heap-gate teljesíthetetlen a dekódolt CFG-ben.** A `heap_handle` globálist a teljes `.text`-ben **egyetlen** utasítás írja, a `0x1DCC4` (az evidence `writers_in_file` listája a `0x1DCC6` RIP-diszlokáció-mezőpozíciót adja ugyanazon utasításból), az `init` belsejében. Az `init`-nek viszont **nincs közvetlen hívója**: `init_direct_call_sites_in_file: []`, `init_direct_call_site_count: 0`. Az `activation` mező ezt összefoglalva kimondja: `reachable_inside_decoded_cfg: false`, `static_chain_confidence: "H"`, `runtime_reachability_confidence: "L"`, és a `gated_call_sites` pontosan a két diszpatches hely: `0x1E425` és `0x1E4FD` (`gated_call_site_count: 2`). Ezért a `0x1E3A4` kapu a dekódolt CFG-ben mindig zárt, és a manager `2`-vel tér vissza, mielőtt bármelyik callhelyhez érne. A statikus adatlánc `CONF:P`; a „soha nem fut" következtetés az 1.5. pont 3. bekezdése miatt nem zárható statikusan, ezért `CONF:L`. A `thread_context_map.json` `heap_gate` mezője a `2`-es kódot helyesen adja meg, de nem mondja ki, hogy a kapu a komponensen belül teljesíthetetlen.

```text
BRef = [RVA:0x1DCBE | RAW:0x1D0BE | CONF:P | STATUS:OBSERVED]   # HeapCreate(0, 0, 0)
BRef = [RVA:0x1DCC4 | RAW:0x1D0C4 | CONF:P | STATUS:OBSERVED]   # mov [0x1830D44F0], rax
BRef = [RVA:0x2E4D418 | RAW:0x2E4BE18 | CONF:P | STATUS:OBSERVED]   # IAT: KERNEL32!HeapCreate
BRef = [RVA:0x1E3A4 | RAW:0x1D7A4 | CONF:L | STATUS:INFERRED]   # teljesíthetetlen gate a dekódolt CFG-ben
```

---

## 6. A `0xC8CE70` / `0xC8F470` Toolhelp stub és restore pár

### 6.1 A telepítő

A `0xC8CE70`–`0xC8CF24` függvény a `KERNEL32!CreateToolhelp32Snapshot` export **első 16 bájtját** elmenti egy hívó által adott rekordba, majd az első 8 bájtot egy olyan stubbal írja felül, amely `0xFFFFFFFF` értékkel tér vissza. Ez az egyetlen név alapján azonosítható, önálló inline hook a mintában.

| Lépés | RVA | Tartalom |
|---|---|---|
| belépés | `0xC8CE75` | `mov rsi, rcx` — a hívó rekordja `rsi`-ben |
| gate olvasás | `0xC8CE78` | `mov eax, dword ptr [0x317E3A0]` — fájlban `0` |
| TEB-őr | `0xC8CE7E`–`0xC8CE97` | TLS-index a `0x33070EC`-ről, `gs:[0x58]`, majd `cmp eax, [rcx+0x44]`; `jle 0xC8CEDE` |
| gate-megnyitás | `0xC8CE99`–`0xC8CEA0` | `lea rcx, [0x317E3A0]`, `call 0x2AB27B0` — megosztott belső segéd |
| feloldási kapu | `0xC8CEA5`–`0xC8CEAC` | `cmp dword ptr [0x317E3A0], -1`; `jne 0xC8CEDE` |
| modul | `0xC8CEAE`–`0xC8CEB5` | `GetModuleHandleA` (IAT `0x2E4D380`) az ASCII `kernel32.dll`-re (`0x2E112EE`) |
| export | `0xC8CEBB`–`0xC8CEC5` | `GetProcAddress` (IAT `0x2E4D3B0`) a névre (`0x2E0CA9C`) |
| publikálás | `0xC8CECB` | `mov [0x317E398], rax` — a feloldott cím a cache-be |
| gate-zárás | `0xC8CED2`–`0xC8CED9` | `lea rcx, [0x317E3A0]`, `call 0x2AB2864` |
| védelem | `0xC8CEDE`–`0xC8CEF4` | `VirtualProtect` (IAT `0x2E4D630`), méret `0x10` immediate, védelem `0x40` immediate, `r9 = rsi+0x10` |
| mentés | `0xC8CEFA`–`0xC8CF04` | `mov rax, [0x317E398]`, `movups xmm0, [rax]`, `movups [rsi], xmm0` |
| stub | `0xC8CF07`–`0xC8CF17` | öt szűk konstans-tárolás `rax`-bázison, `2`/`1`/`4`/`1` bájt szélességekkel, összesen `8` bájt |

- **A rekord szerkezete a hívó felelőssége.** Az `rsi` a hívó `RCX`-e. A `0xC8CEDE` `lea r9, [rsi + 0x10]` a `VirtualProtect` kimeneti „régi védelem" paramétere, tehát a rekord **legalább `0x18` bájt**, a `0x10`–`0x17` bájtos mező az eredeti oldalvédelem. A `0xC8CF04` a `0x00`–`0x0F` bájtra ment. A `06` és `07` dokumentum ezt helyesen írja le. `CONF:P`.
- **A célcím nem a `GetProcAddress` eredménye.** A feloldás a `0x317E398` cache-be ír, és az írási ág a `0xC8CEE2`-nél és a `0xC8CEFA`-nál **a cache globálist** olvassa újra. Ez a `symmetry_target_source` sor `ASYMMETRIC` minősítésének pontos mechanizmusa, és van egy fontos mellékhatása: **a feloldási ág kihagyása esetén** — amikor a gate már `0xFFFFFFFF` — az írási ág a cache aktuális tartalmát használja, amely a fájl képén nulla. Ekkor a `movups` és a szűk tárolások a nullcímre mennek. A `06`/`07` dokumentumok csak annyit mondanak, hogy a célcím „ASLR/runtime-feloldás miatt nem statikus"; a pontos állítás az, hogy a célcím **fájlben inicializált, írható globális állapotból** jön, ezért ismételt belépések között változhat. `CONF:P`.
- **Nincs `FlushInstructionCache` a telepítőben.** `ABSENT`, `CONF:P`. A 16 bájtos export-előtag módosítása után nincs utasítás-cache öblítés, és a `07` dokumentummal ellentétben a telepítő **nem is őrzi meg a régi oldalvédelmet** — azt a hívó rekordja tartja.
- **A `VirtualProtect` eredménye nincs tesztelve.** `ABSENT`, `CONF:P`. Ha a védelemváltás sikertelen, a `0xC8CF01`–`0xC8CF17` írások az eredeti, nem írható lapon futnak.

```text
BRef = [RVA:0xC8CE70 | RAW:0xC8C270 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0xC8CEF4 | RAW:0xC8C2F4 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x317E398 | RAW:0x317CD98 | CONF:U | STATUS:OPEN]   # a célcím innen jön
BRef = [RVA:0x317E3A0 | RAW:0x317CDA0 | CONF:P | STATUS:OBSERVED]   # telepítő gate
```

### 6.2 A visszaállító

| Lépés | RVA | Tartalom |
|---|---|---|
| belépés | `0xC8F475` | `mov rsi, rcx` |
| modul | `0xC8F478`–`0xC8F47F` | `GetModuleHandleA` az ASCII `kernel32.dll`-re |
| export | `0xC8F48C`–`0xC8F48F` | `GetProcAddress` a névre — **saját maga** oldja fel |
| visszaírás | `0xC8F495`–`0xC8F498` | `movups xmm0, [rsi]`, `movups [rax], xmm0` — az `rax` itt a frissen feloldott cím |
| régi védelem | `0xC8F49B`, `0xC8F49F` | `mov r8d, [rsi+0x10]`, `add rsi, 0x10` |
| méret | `0xC8F4A3` | `mov edx, 0x10` |
| cél és kimenet | `0xC8F4A8`, `0xC8F4AB` | `mov rcx, rax`, `mov r9, rsi` |
| átadás | `0xC8F4B3` | `jmp [0x2E4D630]` — **tail-jump** a `VirtualProtect`-ra |

- **A visszatérési érték.** A `tail-jump` miatt a hívó `RAX`-ában a `VirtualProtect` eredménye jelenik meg; a `patch_mechanisms_helpers.csv` `toolhelp_restore_protect_tail_transfer` sora helyesen fogalmaz: „tail transfer, no return value is observable at this site". A pontos állítás: a `VirtualProtect` eredménye **átadódik** a hívónak, de a helyen **nincs** rá vizsgálat. `CONF:P`.
- **Nincs null-ellenőrzés egyik feloldási eredményre sem.** Ha a modul vagy az export feloldása meghiúsul, a `0xC8F498` `movups [rax], xmm0` 16 bájtot ír a nullcímre. Ez a `06`/`07` dokumentumok azon megállapításának tükörképe, amely szerint a sikertelen feloldás a telepítőnél hibás utasításmódosítást okoz. `CONF:P`.
- **Nincs `FlushInstructionCache` a visszaállítóban sem.** `ABSENT`, `CONF:P`. A visszaírás után az utasítás-cache nincs öblítve, ugyanúgy, mint a telepítés után.
- **A visszaállító `RCX`-et nem ellenőrzi a `VirtualProtect` előtt** sem: a `0xC8F4A8` `mov rcx, rax` közvetlenül a feloldás eredményét használja. `CONF:P`.

```text
BRef = [RVA:0xC8F470 | RAW:0xC8E870 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0xC8F498 | RAW:0xC8E898 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0xC8F4B3 | RAW:0xC8E8B3 | CONF:P | STATUS:OBSERVED]
```

### 6.3 A két fél aszimmetriája

| Tulajdonság | Telepítő `0xC8CE70` | Visszaállító `0xC8F470` | `STATUS` |
|---|---|---|---|
| célcím forrása | a `0x317E398` **cache** | a **saját** `GetProcAddress` eredménye | `ASYMMETRIC` |
| a `0x317E398`-at hivatkozza | igen, 3 statikus referencia | nem | `ASYMMETRIC` |
| `16` bájtos ablak | `0x10` immediate | `0x10` immediate | azonos |
| nem igazított 128 bites mozgás | `0xC8CF01` | `0xC8F495` | azonos |
| `VirtualProtect` eredménye | nem tesztelt | nincs tesztelés a helyen | azonos hiány |
| gate-őr | TEB-őr + `0xFFFFFFFF` összehasonlítás | **nincs** | aszimmetrikus |
| a régi védelem megőrzése | a caller rekordjába írja | a caller rekordjából olvassa | szimmetrikus, ha ugyanaz a rekord |
| `FlushInstructionCache` | nincs | nincs | azonos hiány |
| közvetlen hívó | nincs | nincs | `UNRESOLVED` |

A `patch_mechanisms_helpers.csv` `symmetry_protection_restore_path` sora a helyes feltételt fogalmazza meg: „a felek csak akkor szimmetrikusak, ha ugyanazt a rekordot használják újra". Ehhez hozzá kell tenni, hogy **a feloldott export címének is változatlannak kell lennie** a két belépés között, különben a telepítő egy és a visszaállító egy másik címre ír. `CONF:P`.

- **A kép-szintű leltár is ezt mondja:** a `symmetry_image_inventory` sor szerint a képben 6 funkcióban van védelmi hívás, ezek közül 2-ben van nem igazított másolás, és a `matching spans` mező **mostantól neveti is ezt a kettőt**: `0xC8CE70-0xC8CF24, 0xC8F470-0xC8F4BA`. `CONF:P`.
- **A `matching spans` mező olvasata — és miért nem jelent teljes szimmetriát.** A mező a két **közös tulajdonság** alapján nevezi meg a párt, nem bájtszintű egyezés alapján: a 6 védelmi-hívó funkcióból pontosan 2 tartalmaz nem igazított másolást is, és ez a kettő a Toolhelp-pár. A `symmetry_save_restore_shape` és a `symmetry_size_argument` sor valóban azonosít egyezést (`unaligned instruction count install=2 restore=2`, `size argument=immediate:0x10` mindkét oldalon, `identical=True`), de a `symmetry_target_source` `ASYMMETRIC`, és a `symmetry_protection_restore_path` szerint a szimmetria csak **azonos rekord újrahasznosításakor** áll fenn. A korábbi „`matching spans: 0`" olvasat ezért a jelen evidence-val nem egyeztethető össze. `CONF:P`.

### 6.4 A globálisok és a literálok

| Globális / literál | RVA | RAW | Fájlbeli érték | Referenciák a `0xC8CE70`-ben | Jelentés |
|---|---|---|---|---:|---|
| export-cím cache | `0x317E398` | `0x317CD98` | `00 ×8` | 3 | a feloldott export címe, írható |
| telepítő gate | `0x317E3A0` | `0x317CDA0` | `00 ×4` | 4 | egyszeri feloldási kapu, `0xFFFFFFFF` sentinel |
| TLS-index | `0x33070EC` | `0x3305AEC` | `00 ×8` | 1 | a TEB TLS-tömb indexe a `0xC8CE7E`-nél |
| ASCII `kernel32.dll` | `0x2E112EE` | `0x2E0FCEE` | — | 1 | `.rdata`, a `GetModuleHandleA` argumentuma |
| export-név | `0x2E0CA9C` | `0x2E0B49C` | — | 1 | `.rdata`, a `GetProcAddress` argumentuma |

- A gate fájlbeli `0` értéke azt jelenti, hogy a feloldási ág **fegyverben van**; a `0xC8CEA5` `cmp …, -1` a sentinel-ellenőrzés. `CONF:P`.
- A `0x317E3A0` gate-t a `0xC8CE99`/`0xC8CED2` két, a `0x2AB27B0` és `0x2AB2864` megosztott belső segéd fogja közre. A `patch_mechanisms_helpers.csv` `activation_shared_helper_*` sorai kép-szintű statikus hívási helyet számolnak: a `0x2AB27B0` **1 438**, a `0x2AB2864` **1 433** helyről hívódik (`static call sites in the image`), a `0x2AB3500` pedig 2 408-ról. Ezek projekt-szintű cikluskezelő és stack-cookie segédek, nem a Toolhelp-párhoz tartozó privát kód; a `target_expr` oszlop mindháromnál ezt írja: „utility behaviour, not a subject-specific activation path". `CONF:P`.
- A `0x317E398` és `0x317E3A0` a `.data` szekcióban van, characteristics `0xC0000040`, tehát futásidőben írható, és nincs image-relatív inicializáló. `CONF:P`.

---

## 7. A `0x1754520` NOP-fill segéd

### 7.1 A célcím újrabázelése

Ez a rész a `06` és a `11` dokumentumban **nincs** leírva, és a `patch_mechanisms_helpers.csv` `activation_fill_helper_target_window` sora csak részben fedi.

A függvény első dolga, hogy **a caller első argumentumát egy ablakon belül újrabázeli**:

| Lépés | RVA | Tartalom |
|---|---|---|
| argumentum másolása | `0x1754535` | `mov rax, rcx` |
| felső 2 bit kivágása | `0x1754538` | `shr rax, 0x1e` |
| felső korlát feltevés | `0x175453C`, `0x1754546` | `movabs r8, 0x13FFFFFFF` majd `add r8, 0x6000001` → `r8 = 0x146000000` |
| bázis betöltése | `0x175454D` | `mov rsi, [0x3227D40]` — fájlban `0` |
| összeadás | `0x1754554` | `add rsi, rcx` |
| felső korlát | `0x1754557`, `0x175455A` | `cmp rcx, r8`; `cmova rsi, rcx` — `rcx > 0x146000000` esetén változatlan |
| alsó korlát | `0x1754561`, `0x1754565` | `cmp rax, 5`; `cmovb rsi, rcx` — `(rcx >> 30) < 5`, azaz `rcx < 0x140000000` esetén változatlan |

- **Az ablak pontos határai:** `0x140000000 ≤ rcx ≤ 0x146000000`, ami **`96 MiB`**, `5 GiB`-nél kezdődően. Az alsó korlát a shiftből és a `cmp rax, 5`-ből, a felső a `0x13FFFFFFF + 0x6000001` összefogásból adódik. A `patch_mechanisms_helpers.csv` sora mindkét határt helyesen nevezi meg. `CONF:P`.
- **A bázis a fájl képén nulla**, tehát a fájlbeli képen az újrabázelés **nem végez semmit**. `CONF:P`.
- **A rebase ugyanarra az `rsi`-re hat.** A `0x175456E` `mov rcx, rsi` az első `VirtualProtect` címére, a `0x1754584` `mov byte ptr [rsi + rax], …` a kitöltőciklus céljára, a `0x175459A` `mov rcx, rsi` a visszaállítás címére. A védelem, a kitöltés és a visszaállítás tehát ugyanazt a különben újrabázelt címet használja, vagyis **nincs védelemablak-eltérés** a három művelet között. `CONF:P`.
- **A `0x3227D40` globális nyolc bájt széles `.data` mező**, fájlban nulla, és a `patch_mechanisms_helpers.csv` szerint egyetlen statikus referencia mutat rá, a `0x175454D`. Tehát az értéke futásidőben máshol nem állítható a képen belül. `CONF:P`.

```text
BRef = [RVA:0x1754565 | RAW:0x1753965 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x3227D40 | RAW:0x3226740 | CONF:P | STATUS:OBSERVED]
```

### 7.2 A kitöltés és a védelem

| Lépés | RVA | Tartalom |
|---|---|---|
| stack cookie betöltése | `0x1754526` | `mov rax, [0x30B9140]` — ugyanaz a globális, mint a patchernél és a managernél |
| cookie-ellenőrzés zárása | `0x17545AE` | `call 0x2AB3500` |
| első védelem | `0x1754577` | `VirtualProtect` (IAT `0x2E4D630`), `r8d = 0x40`, `rdx` = a caller hosszargumentuma, `r9 = rsp+0x2C` |
| nulla hossz | `0x175457D`, `0x1754580` | `test rdi, rdi`; `je 0x1754590` — a kitöltés kimarad, a **visszaállítás nem** |
| kitöltőciklus | `0x1754582`–`0x175458E` | egy konstans bájt ismétlése, `rax` kurzor, `rdi` felső korlát, visszafelé ágazó ciklus |
| visszaállítás | `0x17545A0` | `VirtualProtect`, `r8d = [rsp+0x2C]`, `rdx = rdi` |

- **A hosszargumentum konzisztenciája:** a második `VirtualProtect` `rdx`-e a `0x175459D` `mov rdx, rdi` miatt ugyanaz a hossz, mint az elsőn. A `patch_mechanisms_helpers.csv` a második helyen `rdx=register:rdx`-et ír, ami technikailag igaz, de a jelentése az, hogy a caller hosszargumentuma **változatlanul átmegy** mindkét hívásba. `CONF:P`.
- **MSVC-instrumentáltság:** a függvény stack cookie-t használ és a `0x2AB3500` ellenőrzőt hívja, ugyanazt a két elemet, mint a patch-komponens. A `patch_mechanisms_helpers.csv` `activation_shared_helper_0x2AB3500` sora a kép összes `2 408` hívási helye közül a komponensre és a segédre a következőket nevezi meg: `0x1DFCB` (registrar), `0x1E250` (redirect), `0x1E344` (patcher), `0x1E570` (manager), `0x1E9B5` (list builder) és `0x17545AE` (NOP-fill). Vagyis a cookie-ellenőrzés **mind az öt** `0x1D280`–`0x1E9D0`-beli funkcióban jelen van, nem csak a patcherben és a managerben. A Toolhelp-pár **nem** cookie-instrumentált. `CONF:P`.
- **A cookie-cím globális közös:** a `fill_helper_global_ref_0x1754526` sor a `0x30B9140` `.data` qword 64 bites olvasását adja meg, és a `thread_context_map.json` `api_surface.stack_guard` ugyanezt a globálist nevezi meg a `0x1DFF0` `0x1E00A` cookie-betöltéséhez, `check_rva: 0x2AB3500` őrrel. `CONF:P`.
- **A `0x17545B3` `nop`** a függvény utolsó `ret`-je előtt van, a `0x17545BB` végén `int3` jelenik meg; a `.pdata` `0x1754520–0x17545BB` tartomány tehát pontosan a kód végéig tart. `CONF:P`.

```text
BRef = [RVA:0x1754520 | RAW:0x1753920 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1754577 | RAW:0x1753977 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x17545A0 | RAW:0x17539A0 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1754584 | RAW:0x1753984 | CONF:P | STATUS:OBSERVED]
```

### 7.3 Amit a segéd nem tesz

| Negatívum | Bizonyíték | `STATUS` | Bizonyosság |
|---|---|---|---|
| nem menti el az eredeti bájtokat | nincs írás a caller rekordjába a ciklus körül | `ABSENT` | `CONF:P` |
| nem hív `FlushInstructionCache`-t | nincs ilyen import a tartományban | `ABSENT` | `CONF:P` |
| nem ad siker- vagy hibakódot | a `0x17545A6` a cookie-ellenőrzéssel foglalkozik, nem a védelmi eredménnyel | `ABSENT` | `CONF:P` |
| nem ellenőrzi egyik `VirtualProtect` eredményét | nincs `test` a `0x1754577` és a `0x17545A0` után | `ABSENT` | `CONF:P` |
| nem ellenőrzi a hossz határait | a `0x175457D` csak nullát vizsgál; az írás előtt nincs oldalméret-ellenőrzés | `OBSERVED` | `CONF:P` |
| nincs közvetlen hívója és nincs statikus függőpointere | a teljes képben egyetlen `rva32` előfordulás, a kivételkönyvtár bejegyzése | `UNRESOLVED` | `CONF:P` a hiányra |

- **A `06` és `11` dokumentum szerinti NOP-minősítés:** a `06` §10.2 egy adott bájtérték ismétléséről ír. Ez a dokumentum szándékosan nem ismétli az értéket; a szerkezeti állítás — egyetlen konstans bájt ismétlése adott hosszban — itt `CONF:P`.
- **A `06` §10.2 állítása, hogy a függvény „a normál user-mode címtartományban az első argumentumot használja célcímként"**, pontosításra szorul: a `0x1754520` az argumentumot **feltétel nélkül** használja, de a `0x140000000`–`0x146000000` ablakon belül egy `.data` bázissal újrabázeli. A `06` állítás tehát a gyakori esetet írja le, az ablakviselkedést nem említi. `CONF:P`.

---

## 8. A hét `QueueUserAPC` ág és a globális kapcsoló

### 8.1 A hét callhely

| Callhely | Owning függvény (IMAGE_RUNTIME_FUNCTION) | `RCX` (a routine) | `RDX` (a handle) | `R8` |
|---|---|---|---|---|
| `0x1F907F4` | `[0x1F90720, 0x1F90A5B)` | `lea rcx, [rip − 0x1F8F681]` a `0x1F907EA`-nél | `[rsi+0xA8]+0x8` | `0` |
| `0x1F90A17` | `[0x1F90720, 0x1F90A5B)` | `lea rcx, [rip − 0x1F8F8A4]` a `0x1F90A0D`-nél | `[rsi+0x48]+0x8` | `0` |
| `0x1F91968` | `[0x1F918D0, 0x1F91A41)` | `lea rcx, [rip − 0x1F907F5]` a `0x1F9195E`-nél | `[rcx+0xA8]+0x8` | `0` |
| `0x20668B5` | `[0x2066740, 0x20669EE)` | `lea rcx, [rip − 0x2065742]` a `0x20668AB`-nél | `[rsi+0x1A0]+0x8` | `0` |
| `0x2067DDB` | `[0x2067D50, 0x2067EF3)` | `lea rcx, [rip − 0x2066C68]` a `0x2067DD1`-nél | `[rsi+8]` | `0` |
| `0x20C0E25` | `[0x20C0D90, 0x20C0E81)` | `lea rcx, [rip − 0x20BFCB2]` a `0x20C0E1B`-nél | `[rsi+0x60]+0x8` | `0` |
| `0x20C0F33` | `[0x20C0E90, 0x20C0F9B)` | `lea rcx, [rip − 0x20BFDC0]` a `0x20C0F29`-nél | `[rsi+0x38]+0x8` | `0` |

- Mind a hét `RCX` ugyanarra az `RVA 0x1170` címre mutat, mindegyik `R8 = 0`, és mindegyik `RDX` egy thread-object-szerkezet `+0x8` mezőjéből olvasott natív handle. `CONF:P`.
- A `QueueUserAPC` IAT-slot `0x2E4D4F8`; a hét callhely mindegyike `static-live`: a blokk egy regisztrált `IMAGE_RUNTIME_FUNCTION` belső ágcélja, tehát nincs szükség külön belépési pontra. `CONF:P`.
- A hét hely mindegyike a `0x3254270` kapcsolót olvassa egy saját `mov eax, [rip+disp]` utasítással, majd `test eax, eax` és `je` ággal választ. `CONF:P`.

```text
BRef = [RVA:0x1F907F4 | RAW:0x1F8FBF4 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1F90A17 | RAW:0x1F8FE17 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1F91968 | RAW:0x1F90D68 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x20668B5 | RAW:0x2065CB5 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x2067DDB | RAW:0x20671DB | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x20C0E25 | RAW:0x20C0225 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x20C0F33 | RAW:0x20C0333 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x2E4D4F8 | RAW:0x2E4BEF8 | CONF:P | STATUS:OBSERVED]
```

### 8.2 A közös cél

| Tulajdonság | Érték | Bizonyosság |
|---|---|---|
| az `RVA 0x1170` tartalma | egyetlen `ret` (`c3`), utána `15` bájt `0xCC` kitöltés, majd egy `0x55` | `CONF:P` |
| `IMAGE_RUNTIME_FUNCTION` bejegyzése | nincs | `CONF:P` |
| kép-szintű RIP-relatív hivatkozások | 59, ebből 1 építi az adott call argumentumát | `CONF:P` |
| **`RVA 0x1170` VA-ját tároló adat-slotok** | **43** | `CONF:P` |
| közvetlen `call rel32` a `0x1170`-re | 2 függvény: `0x10F0` és `0x29B0` | `CONF:P` |
| vtable-slot, amely a `0x1170`-re mutat | a `0x2C65060` végleges vtable `0x2C65080` slotja | `CONF:P` |

- **Független újraszámolás:** a `.rdata`/`.data`/`.tls`/`.rsrc`/`.reloc` szekciókban `8` bájtos lépésközzel kerestem a `0x180001170` értéket. **43 találat** jött ki, köztük a `0x2C1E948`, `0x2C1E950`, `0x2C5E820`, `0x2C60038` — vagyis pontosan az `apc_sites.csv` által felsorolt négy példa. Ugyanezzel a módszerrel az első owning függvény `RVA 0x1F90720` belépési VA-ját **1** slot tárolja, a `0x2D89678` — pontosabban, ahogy a `fn` oszlop mondja.
- **Az `apc_sites.csv` `target` oszlopa mostantól helyesen nevezi meg a 43 slotot.** A sor szövege: „43 data slots store the pointer VA 0x180001170 of RVA 0x1170 (RVA 0x2C1E948, RVA 0x2C1E950, RVA 0x2C5E820, RVA 0x2C60038 and 39 more)", és hozzáteszi: „the entry VA of the enclosing function is a different address and the slots that store it are counted in the fn column". A `12. fejezet` 8. sora ezért ma már a `06`/`07` dokumentumra vonatkozik, nem az evidence-ra. `CONF:P`.
- **Következmény:** hét, különböző owning függvényben ugyanaz az `RVA 0x1170` a cél, és ez a cél egyben a komponens végleges vtable-ének egyik sora is. A `QueueUserAPC` hívások tehát **szál-ébresztésre** szolgálnak egy `ret`-re mutatva, nem kódinjektálásra. A `12` §6.7 vtable-megállapítása itt független megerősítést kap, és a `06` §6 „nem mutat APC-shellcode-ra" megállapítása megerősítve és megerősíthetően zárt. `CONF:P`.

```text
BRef = [RVA:0x1170 | RAW:0x570 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x2C65080 | RAW:0x2C63A80 | CONF:P | STATUS:OBSERVED]
```

### 8.3 A kapcsoló

| Tulajdonság | Érték |
|---|---|
| kapcsoló RVA / RAW | `0x3254270` / `0x3252C70` |
| szekció | `.data`, characteristics `0xC0000040` |
| fájlbeli érték | `00 00 00 00` |
| base relocation a sloton | nincs |
| kép-szintű olvasók | 7 — pontosan a hét callhely |
| kép-szintű írók | **0** |
| RIP-relatív tárolás a képben | 0 |
| abszolút immediate tárolás | 0 |
| VA-as-imm64 / VA-low-as-imm32 / RVA-as-imm32 | 0 / 0 / 0 |
| ág-szelektor | `eax == 0` a betöltő `mov` után, `test eax, eax` + `je` a callhelyre |
| másik ág | `TerminateThread` (`RCX` = a helyi `rdx`, `RDX = 0`), majd `WaitForSingleObject(handle, INFINITE)` |

- **A `0` érték jelentése.** A fájl képén a kapcsoló nulla, ezért a `QueueUserAPC` ág a **statikusan kiválasztott** ág. Az `apc_sites.csv` `activation status` oszlopa ezt szó szerint kimondja: „static-live … a `QueueUserAPC` ág a szelektor statikusan kiválasztott ága". `CONF:P`.
- **A kapcsoló írója nincs a képben.** Ez a `06` §6 állításának pontosítás: nem „a globális értéke 0", hanem „a globális fájlban nulla, és a képben nincs hozzá író". A `0` tehát **fájl-inicializált alapérték**, nem konfigurált érték; egy regiszter-számítású tárolás, egy futásidejű képmódosítás vagy egy képkívüli író nincs kizárva. `CONF:L`.
- **A szomszédság-scan eredménye és korlátja.** A `±0x100` RVA ablakban 22 hivatkozás található, 11 írással, a `0x3254360`, `0x3254364`, `0x3254368`, `0x3254370` címekre; **egyik sem a `0x3254270`-re**. Ez a négy dword `0xF0` bájttal van a kapcsoló **után**, tehát nem szomszédos, hanem ugyanabban a `0x100` bájtos ablakban. Mind az négy nulla a fájlban. Egy velük összefüggő állapotblokk **valószínű**, de sem a kapcsoló írója, sem a kapcsolat nem bizonyított. Az `apc_sites.csv` maga is kimondja a korlátot: „a store through a register-computed address, a runtime image modification or a writer outside this image is not excluded by these scans". `CONF:U`.
- **A `QueueUserAPC` visszatérési értéke mind a hét helyen eldobva.** `CONF:P`.
- **A hét callhely őrzőfeltételei futásidejűek:** `[rsi+0xA8] != 0`, `rdi != 0`, `[rcx+0xA8] != 0`, `rdi != 0`, `rsi != 0` és `rcx != 0`, `edx == 0` és `[rcx+0x60] != 0`, `rdi != 0` és `rcx != 0`. Ezek a blokkok szerkezetileg elérhetők, a feltételek nem zárhatók le statikusan. `CONF:L`.
- **A `TerminateThread` alternatív ág `RDX = 0`** mind a hét helyen, tehát kilépési kód `0`. Ez az ág `exit code 0`-val terminates, nem hibakóddal. `CONF:P`.

```text
BRef = [RVA:0x3254270 | RAW:0x3252C70 | CONF:U | STATUS:OPEN]   # fájlban 0, 7 olvasó, 0 író
BRef = [RVA:0x3254360 | RAW:0x3252D60 | CONF:U | STATUS:OPEN]   # a 11 írási referencia ide céloz
```

### 8.4 A handle eredete és a módszertani korlát

A hét helyen a `RDX` argumentum mindegyike egy thread-object-szerkezet `+0x8` mezője. A mező **írója** a `0x1F90CC5` utasítás, amely a `_beginthreadex` `0x1F90CBF` hívásának visszatérési értékét tárolja; a `_beginthreadex` callhely közvetlen hívói: `0x1F8E09E`, `0x206619D`, `0x2067EDB`, `0x20C002E`. A mező írását vizsgáló sor kimondja: **„producer calls `SuspendThread`: no"**, vagyis az APC-ág nem egy felfüggesztett szálhoz queues-el. `CONF:P`.

- **A `GetQueuedCompletionStatus` jelenléte** csak az első owning függvényben, a `0x1F908DB`-nél; a másik hatban nincs. Ez kontextusként hasznos, nem a mechanizmus része. `CONF:P`.
- **A `WaitForSingleObject(handle, INFINITE)` minden hét ág után** ugyanazt a mintát követi: a handle újraolvasása a `+0x8` mezőből, `mov edx, 0xFFFFFFFF`, majd a várakozás. Ez tehát **soros kivárás**, nem aszinkron jelzés. `CONF:P`.
- **A módszertani korlát, amit az `apc_sites.csv` maga rögzít:** az argumentum-provenancia a **lineáris backward walk utolsó definíciója** az enclosing `IMAGE_RUNTIME_FUNCTION`-ön belül; a walk átlép az oda nem értő ágakon, és a volatilis regisztereket callnál leállítja. Ez tehát **pre-image, nem dominátor-bizonyíték**. A `RDX` szerinti handle-származtatás ezért `CONF:L`. A `lea rcx` argumentum ezzel szemben közvetlen utasításból jön, tehát az `RVA 0x1170` cél `CONF:P`.
- **Következmény a patch-komponensre:** a hét `QueueUserAPC` hívás az egyetlen vizsgált hívási forma, amelynek **nincs** belépési problémája. A `0x1E360` és a három segéd statikaira nincs közvetlen hívó, de a hét APC-blokk egy regisztrált függvény belső ágcélja, tehát a kódút statikailag létezik. A hívó(k) azonban szintén ismeretlen: a hét owning függvény belépési pontjainak a callerje nincs lezárva. `CONF:L`.

```text
BRef = [RVA:0x1F90CC5 | RAW:0x1F900C5 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x1F90CBF | RAW:0x1F900BF | CONF:P | STATUS:OBSERVED]
```

---

## 9. `target_expr` / caller / activation táblázat

Minden `target_expr` szimbolikus leírás, nem előállítási előírás; egyetlen konkrét írási bájtérték nem szerepel benne.

### 9.1 A fő mechanizmusok

| Mechanizmus | `target_expr` (szimbolikus) | Közvetlen caller | Aktiválási feltétel | `STATUS` | `CONF` |
|---|---|---|---|---|---|
| rel32 patch, `5` bájtos variáns | `rec + 0x00 − 5·(rec[0x20] & 1)`, ahol `rec[0x20] & 1 == 0`; destination `rec + 0x08` | `0x1E425` (tömeg), `0x1E4FD` (egy rekord) — mindkettő a `0x1E360`-ban | manager elérhető; heap-publikálva; `count > 0`; skip bit tiszta; az első `VirtualProtect` sikeres | `OBSERVED` / `OPEN` | `P` / `U` |
| rel32 patch, `7` bájtos variáns | `rec + 0x00 − 5`, ahol `rec[0x20] & 1 == 1`; `5` bájt a patch-site-en, `2` bájt a `rec + 0x00`-on | ugyanaz | ugyanaz, **plusz** a `0x01` flagbit beállítva | `OBSERVED` / `OPEN` | `P` / `U` |
| relatív diszlokáció tárolása | `patch_site + 1`, `4` bájt | a patcher belső | a patcher sikeres ága | `OBSERVED` | `P` |
| flag-komitt | `rec + 0x20 \|= 0x06` | a patcher belső, `0x1E336` | védelem-visszaállítás és cache-öblítés **után**, az eredményüktől függetlenül | `OBSERVED` | `P` |
| RIP redirect | `rec + 0x00 + rec[0x28][i] == CONTEXT.Rip` → `rec + 0x10 + rec[0x30][i]` | `0x1E400` (tömeg), `0x1E4F6` (egy rekord) | saját processzben futó, megnyitható szál; a `0x02` bit tiszta; `(rec[0x24] & 0xF) != 0`; a rekonstruált cél nem nulla; a kezdőindex a limit alatt | `OBSERVED` / `OPEN` | `P` / `U` |
| context alkalmazás | a `CONTEXT.Rip` mező, `CONTEXT_CONTROL` maszk `0x100001` | a redirect belső, `0x1E214` | pontos illesztés és nem nulla cél; az eredmény nincs tesztelve | `OBSERVED` | `P` |
| szál resume | nincs írható cél; egy azonosító, újra megnyitott handle | a manager, `0x1E484` és `0x1E537` | a gyűjtött listában van azonosító, és a `OpenThread` sikeres | `OBSERVED` | `P` |
| Toolhelp stub telepítése | `*(qword *)(0x317E398)`, `0x10` bájtos ablak, `0x40` védelem | **nincs** | TEB-őr átmegy; a `0x317E3A0` gate nem `0xFFFFFFFF`; sikeres modul- és exportfeloldás; a `0x317E398` nem nulla | `OBSERVED` / `OPEN` | `P` / `U` |
| Toolhelp export visszaírása | a `GetProcAddress` friss eredménye, `0x10` bájtos ablak | **nincs** | sikeres modul- és exportfeloldás; a `+0x10` mező érvényes védelem | `OBSERVED` / `OPEN` | `P` / `U` |
| NOP kitöltés | `cím`, ahol `0x140000000 ≤ cím ≤ 0x146000000` esetén `cím + *(qword *)(0x3227D40)`, egyébként `cím` változatlan; `hossz` bájt | **nincs** | a hossz nem nulla; a `VirtualProtect` sikeres (nem ellenőrzött) | `OBSERVED` / `OPEN` | `P` / `U` |
| `QueueUserAPC` | **nincs írható cél**; a meghívott rutin `RVA 0x1170` | a hét owning függvény | `*(dword *)(0x3254270) == 0` a fájlon; a blokk őrzőfeltételei; érvényes, alertálható szál | `OBSERVED` szerkezet / `U` végrehajtás | `P` / `U` |
| `TerminateThread` alternatíva | **nincs írható cél**; a hívott cél a `TerminateThread` IAT | ugyanaz a hét hely | `*(dword *)(0x3254270) != 0` | `OBSERVED` | `P` |

### 9.2 A rekordot előállítók

| Szerep | `target_expr` | Közvetlen caller | Aktiválási feltétel | `CONF` |
|---|---|---|---|---|
| `registrar` `0x1DCF0` | nincs; a `0x38` bájtos rekordot tölti fel | **nincs** | ismeretlen; a `0x1E590` list buildert hívja, az a `0x1D550` decodert | `P` szerkezet / `U` aktiválás |
| `list_builder` `0x1E590` | `rec[0x28][i]` és `rec[0x30][i]` értékeit állítja elő | `0x1DCF0` | a `0x8` elem- és a `0x32` bájtablak-plafon nem túllépve | `P` |
| `decoder` `0x1D550` | utasításhosszakat számít a list buildernek | `0x1E590` | ismeretlen; a CFG-e `96 %`-ban ért el, lásd a 11.2-t | `P` szerkezet / `L` megbízhatóság |
| `arena` `0x1D280` | futtató `VirtualAlloc` blokkokat ad a `rec + 0x10` mezőnek | `0x1DCF0` | `GetSystemInfo`, `VirtualQuery`, `VirtualAlloc` | `P` |
| `init` `0x1DC80` | nincs; a `0x1830D44F0` heap-handle-t publikálja | **nincs** | a zár megszerzése; a handle még nulla | `P` szerkezet / `U` aktiválás |

### 9.3 A `CONF:U` tételek felsorolása ebben a dokumentumban

| Tétel | Hol | Miért `U` |
|---|---|---|
| a patch-komponens futásidejű elérhetetlensége | 2.1, 5.6, 12.2 | a statikus adatlánc zárt, de a közvetett és képkívüli hívás nem zárható ki |
| a rekord-példányok tartalma | 3.2, 13.2 | a tábla slot fájlban nulla és nincs képbeli inicializáló |
| a Toolhelp célcím | 6.1 | a `0x317E398` cache futásidejű állapot |
| a `QueueUserAPC` kapcsoló írója | 8.3 | nulla statikus író, nulla képbeli initializáló |
| a `0x140000000`–`0x146000000` ablak célja | 7.1 | a `0x3227D40` bázis fájlban nulla; a szándék nem vezethető le |
| a `rec + 0x10` nullapublikálhatósága | 4.4 | a rekordelrendezésből nem dönthető el |
| a `0x20` flag 3–7. bitjeinek jelentése | 3.4 | a merge megőrzi, de egyetlen olvasója sincs |
| a felszabadítatlan `original_bytes` mező szándéka | 3.2 | nincs olvasója az elemzett halmazban |

---

## 10. `VirtualProtect` és `FlushInstructionCache` globális leltár

### 10.1 A nyolc védelmi hívási hely

A `patch_mechanisms_helpers.csv` `writer_protection_call_inventory` sora a képet felszólítja: **8 védelmi hívási hely, 6 funkció**, plusz **1 tail-jump thunk** a `0xC8F4B3`-on. Az alábbi táblázat a `CONF:P` szerkezeti adatokat foglalja össze, a `return_value_checked` oszlop a `writer_protection_result_checked` sorból származik.

| # | RVA | Funkciótartomány | Védelem argumentum | Méret argumentum | Eredmény tesztelve | `target_kind` | Statikus elérhetőség |
|---:|---|---|---|---|---|---|---|
| 1 | `0x1E2D1` | `0x1E270–0x1E357` (patcher) | `0x40` immediate | `5`/`7` számított | **igen** | `caller_argument` | a `0x1E360`-ból, `0x1E425`/`0x1E4FD` |
| 2 | `0x1E31B` | `0x1E270–0x1E357` (patcher) | `rsp+0x24` (mentett) | `5`/`7` | nem | `caller_argument` | ugyanaz |
| 3 | `0xC8CEF4` | `0xC8CE70–0xC8CF24` (telepítő) | `0x40` immediate | `0x10` immediate | nem | `import_iat_slot` | **nincs közvetlen hívó** |
| 4 | `0x1754577` | `0x1754520–0x17545BB` (NOP fill) | `0x40` immediate | incoming (`rdx`) | nem | `caller_argument` | **nincs közvetlen hívó** |
| 5 | `0x17545A0` | `0x1754520–0x17545BB` (NOP fill) | `rsp+0x2C` (mentett) | `rdi` = az incoming hossz | nem | `caller_argument` | **nincs közvetlen hívó** |
| 6 | `0x2921505` | `0x29213D0–0x2921575` | `0x4` immediate | `0x8` immediate | nem | `import_iat_slot` | **nincs közvetlen hívó** |
| 7 | `0x2921526` | `0x29213D0–0x2921575` | `rsp+0x3C` (mentett) | `0x8` immediate | nem | `import_iat_slot` | **nincs közvetlen hívó** |
| 8 | `0x2BEB8FB` | `0x2BEB88C–0x2BEB91A` | `rcx` regiszter | `rsp+0x40` | **igen** | `import_iat_slot` | statikusan elérhető: `0x2BEB98D`, `0x2BEBA27` |
| +1 | `0xC8F4B3` | `0xC8F470–0xC8F4BA` (restore) | `rsi+0x10` (mentett) | `0x10` immediate | nem, tail-jump | `import_iat_slot` | **nincs közvetlen hívó** |

A `writer_protection_call_inventory` sor `0x1E2D1;0x1E31B;0xC8CEF4;0x1754577;0x17545A0;0x2921505;0x2921526;0x2BEB8FB` sorrendben adja a nyolc hívási helyet, vagyis a `8` **a `0x2BEB8FB`-val együtt teljes**, és a kilencedik elem a `writer_import_tail_thunk_inventory` sorban külön kezelt `0xC8F4B3` protection tail-jump (`tail-jump import thunks: 1 in total; 1 for the protection entry`). A táblázat `#` oszlopa ezt a sorrendet követi.

- **A táblázat két ellentmondásra figyelmeztet, hogy ne félreértsük a „8" számot:**
  1. **A `8` nem `8` patch-útvonal.** Az 1–2 a `0x1E270` két hívása, 3 a Toolhelp-telepítő, 4–5 a NOP-fill, 6–7 egy **teljesen más** `0x29213D0` funkció két hívása `0x8` bájtos területre és `PAGE_READWRITE` védelemre, 8 pedig az `0x2BEB88C` funkció hívása, ez statikusan elérhető (`comparator_entry_0x2BEB88C`: `statically reachable`, `direct callers=0x2BEB98D;0x2BEBA27`). A Toolhelp **visszaállító** fele csak a `+1` sorban jelenik meg, mert ő `jmp`, nem `call`.
  2. **Csak `2` a `8`-ból eredmény-ellenőrzött** (`0x1E2D1` és `0x2BEB8FB`); a `writer_protection_result_checked` sor a fennmaradó hatot felsorolja teszteletlenként. A `06` §8.2 állítása, hogy a patcher az első hibát `0x0A`-val adja vissza, pontos; a `06` §8.2 azon állítása, hogy `0x1754520` „egyik eredményét sem ellenőrzi", szintén pontos (`fill_helper_protect_result_check_0x1754577` és `…_0x17545a0` mindkettő `ABSENT`); a Toolhelp-párhoz tartozó állítás ugyanígy.
- **A `0x2921505` és `0x2921526` leltárhoz tartozó három `cmovae` ág** (`0x292143B`, `0x292144B`, `0x29214C0`, `0x29214D0`) mind `0x1A`-val hasonlít, és a célcímet választja. Ez a `0x29213D0` funkció saját szerkezete, nem a patch-komponens része, de a védelmi hívás célcímét befolyásolja, ezért a leltárban meg kell maradnia. `CONF:P` a jelenléte, `CONF:U` a jelentősége.
- **A `0x2BEB8FB` gate:** a `0x330B730` `.data:uninitialised-tail` dwordját `0`-val hasonlítja, tehát egy fájlban nem inicializált kapu őrzi. `CONF:P`.

```text
BRef = [RVA:0x1E2D1 | RAW:0x1D6D1 | CONF:P | STATUS:OBSERVED]   # 1 / 8, eredmény tesztelve
BRef = [RVA:0x2BEB8FB | RAW:0x2BEACFB | CONF:P | STATUS:OBSERVED] # 2 / 8, eredmény tesztelve
BRef = [RVA:0x2921505 | RAW:0x2920905 | CONF:U | STATUS:OPEN]    # 0x8 bájt, PAGE_READWRITE, másik komponens
BRef = [RVA:0x2E4D630 | RAW:0x2E4C030 | CONF:P | STATUS:OBSERVED]  # IAT mind a 8 helyen
```

### 10.2 Az egyetlen öblítési hely

| # | RVA | Funkciótartomány | Szimbólum | IAT RVA | Argumentumok | Eredmény |
|---:|---|---|---|---|---|---|
| 1 | `0x1E330` | `0x1E270–0x1E357` | `KERNEL32.dll!FlushInstructionCache` | `0x2E4D2E8` | `GetCurrentProcess()` eredménye, `patch_site`, `5`/`7` | **nem tesztelve** |

- A `writer_cache_flush_inventory` sor szó szerint: „1 instruction-cache flush call sites in the image, in `0x1E270-0x1E357`". Ez kép-szintű, teljes leltár. `CONF:P`.
- **Következmény a Toolhelp-párra és a NOP-fillre:** egyik sem öblít. A Toolhelp-pár 16 bájtot ír egy másik modul export-előtagjába, a NOP-fill `hossz` bájtot ír egy általában idegen címre, és egyik sem öblíti az utasítás-cache-t. Ez a `06` §12 „Hook célfeloldás" és §8.2 megállapításainak közös pontja, és a `07` §6.2 azonos állítása. `CONF:P`.
- **Következmény a patcherre:** a patcher az egyetlen, amely **öblít**, tehát a `0x1E270` a teljes kép legjobban kezelt kódírási útvonala. Ez nem értékítés, hanem a negatív findingok dokumentált határa. `CONF:P`.

```text
BRef = [RVA:0x1E330 | RAW:0x1D730 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x2E4D2E8 | RAW:0x2E4BCE8 | CONF:P | STATUS:OBSERVED]
```

### 10.3 Az `xref_edges.csv`-szel való számlálás-egyeztetés

| Szimbólum | `xref_edges.csv` sorok | Magyarázat |
|---|---:|---|
| `VirtualProtect` | 10 | 8 hívási/jump hely + 1 `iat_jmp_thunk_stub` (`0xC8F4B4`) + 1 `iat_slot_symbol_binding` |
| `FlushInstructionCache` | 2 | 1 hívási hely + 1 `iat_slot_symbol_binding` |

- **Könyvelési eltérés, nem ellentmondás:** a `xref_edges.csv` a `0xC8F4B3` `jmp` utasítást a `0xC8F4B4` RVA-val rögzíti, mert a referenciarekord a diszlokáció bájtpozícióját azonosítja; a `patch_mechanisms_helpers.csv` az utasítás kezdő RVA-ját, `0xC8F4B3`-at adja meg. Egy bájtos eltérés, két termelő, eltérő konvenció. `CONF:P`.
- Az egyetlen `FlushInstructionCache`-hívás a `0x1E330`, és **nincs hozzá thunk** — a patcher közvetlenül az IAT-n hív, szemben a `0x1E029`-es `CreateToolhelp32Snapshot`-szal, amely a `0x2BED400` thunkon keresztül megy. `CONF:P`.

---

## 11. Kereszt-evidencia megfelelés és módszertani határok

### 11.1 Az `xref_edges.csv` szándékos scope-ja

Ez a pont azért szükséges, hogy két evidence-fájl ellentmondását ne olvassuk konfliktusnak.

A `xref_build.py` saját scope-határa szövegesen: a `direct_call` és `direct_jmp` élek **csak olyan közvetlen relatív ágra** kerülnek ki, amelynek célja *katalógált csomópont* — vagyis import-thunk, vagy egy író/olvasható kódpointer-slot kódcélja. „A korlátlan kép-intráns közvetlen call-gráf nincs a scope-on belül; a népességét korlátolt negatívumként jelentik, nem hallgatják el csendben."

**Következmény:** a `0x1E400 → 0x1DFF0`, `0x1E425 → 0x1E270`, `0x1E4F6 → 0x1DFF0`, `0x1E4FD → 0x1E270` **négy intra-komponens éle szándékosan hiányzik** a `xref_edges.csv`-ből, mert a `0x1DFF0` és a `0x1E270` nem import-thunk és nem kódpointer-slot cél. Továbbá a teljes fájlt végigellenőrizve a `0x1D280`, `0x1D550`, `0x1DC80`, `0x1DCF0`, `0x1DFF0`, `0x1E270`, `0x1E360`, `0x1E590`, `0xC8CE70`, `0xC8F470`, `0x1754520` egyikének sincs egyetlen `direct_call`, `thunk`, `iat`, `vtable` vagy `global_fnptr` éle sem `src`, sem `dst` oldalon. **Ez nem cáfolat, hanem a scope következménye.** `CONF:P`.

- **A keresztellenőrzés forrása ehelyett a `cfg_functions.csv` `cross_function_targets` oszlopa**, amely a teljes dekódolt CFG-ből számolja a közvetlen rel32 célokat. Ebből jött ki a 2.1. táblázat, és ez az egyetlen forrás, amelyet a négy patcher-hívási hely és a zárt komponens bizonyítékául használni lehet.
- Aki a két fájlt keresztiellenőrzi, annak ezt a korlátot ismernie kell, különben a `direct_call` ések hiányát hibás negatívumnak veszi. `CONF:P`.

### 11.2 A feloldatlan régiók a vizsgált tartományban

A `unresolved_regions.json` a vizsgált nyolc funkcióból **hétet** érint:

| `region_id` | Tartomány | `family` | `triage` | `reached_ratio` | `undecoded_bytes` | `priority` | `CONF` |
|---|---|---|---|---:|---:|---|---|
| `UR-000066` | `0x1D280–0x1D546` (arena) | `multi_entry` | `classified` | 1.0 | 0 | P0 | `P` |
| `UR-001588` | `0x1D550–0x1DC79` (decoder) | `switch_unvalidated` | `unresolved` | **0.96** | 0 | P2 | `P` |
| `UR-001589` | `0x1D550–0x1DC79` | `boundary_cross` | `unresolved` | 0.96 | 0 | P2 | `P` |
| `UR-001590` | `0x1D550–0x1DC79` | `linear_only_blocks` | `unresolved` | 0.96 | 0 | P2 | `MEDIUM` → `L` |
| `UR-001591` | `0x1D550–0x1DC79` | `multi_entry` | `classified` | 0.96 | 0 | P2 | `P` |
| `UR-000067` | `0x1DFF0–0x1E26A` (redirect) | `multi_entry` | `classified` | 1.0 | 0 | P0 | `P` |
| `UR-000068` | `0x1E270–0x1E357` (patcher) | `multi_entry` | `classified` | 1.0 | 0 | P0 | `P` |
| `UR-000069` | `0x1E590–0x1E9D0` (list builder) | `multi_entry` | `classified` | 1.0 | 0 | P0 | `P` |

A `0x1DC80` `init`, a `0x1DCF0` registrar, a `0x1E360` manager, a `0xC8CE70` és `0xC8F470` Toolhelp-pár, valamint a `0x1754520` NOP-fill **egyetlen feloldatlan régiót sem kapott**. `CONF:P`.

- **A `multi_entry` jelző olvasata a négy „tiszta" esetben benignus.** Az `evidence` mezőjük `entry_points=2; ext_calls=1; int_entries=44` (arena), illetve `int_entries=10` (patcher), `int_entries=61` (list builder), `int_entries=44` (redirect) értékeket tartalmaz, `overlap_role=sole; overlap_partners=0`, `switch_reject_reasons=none`, `decode_status=ok`. Vagyis a jelző **a saját `.pdata` belépési pont plusz az egy külső közvetlen hívást** jelenti, nem feloldatlan vezérlési folyamatot. A négy függvény `reached_ratio` 1.0 és `undecoded_bytes` 0. `CONF:P`. **Ezt a jelzőt nem szabad feloldatlan kockázatként olvasni.**
- **A `0x1D550` decoder viszont valóban a komponens leggyengébben lezárt eleme.** Négy egymásra halmozott jelzőt kap, `reached_ratio` **0.96**, `triage: unresolved`, `ok: false`, és az `evidence` mezője a következőket tartalmazza: `jmp_direct:42`, `jmp_indirect:3`, `range_end:1`, `exit_range_end:1`, `switch_reject_reasons=NO_BOUND=2`. Vagyis **el nem fogadott jump-tábla** és **három feloldatlan közvetett ugrás** van benne. Mivel a `0x28` és `0x30` bájltlista tartalma a `0x1E590` list builderben a `0x1D550` decoderből származó utasításhosszakra épül, ez a lista pontos értékének megbízhatóságát korlátozza. `CONF:L` a listák pontos tartalmára, `CONF:P` a korlát magára.
- **Ez a korlát nem az itt dokumentált szerkezeti megállapításokat érinti.** A `patcher` `reached_ratio` 1.0, `0` feloldatlan bájt, `term=call:7, jmp_direct:1, jmp_indirect:0`, `switch_reject_reasons=none`; a `redirect` `term=call:17, jmp_direct:2, jmp_indirect:0`. A 3. és 4. fejezet minden állítása ezekben a két teljesen lezárt tartományban van. `CONF:P`.

### 11.3 A sweep-lefedettség általános korlátja

A `counters` blokk szerint: a kivételkönyvtárban `142 004` rekord van, `141 899` teljesen dekódolva, összesen `9 331 019` dekódolt utasítás, és a dekódolás által nem fedett bájtok száma `0x448`. A `counters.redecoded_functions` mező hozzáteszi: **105 függvénytest és `0x448` bájt nem dekódolódik teljesen**, és az azokon belüli findingokra ez az audit nem terjed ki. `CONF:P`.

> **Forráspontosítás `[P]`:** a korábbi szöveg ezt a `method_sweep_coverage` és `method_decode_shortfall` sorokhoz rendelte. **A jelenlegi `unresolved_regions.json` `method` blokkjában ilyen sor nincs** – a `method` kulcsai: `join_key`, `family_order`, `families`, `kind_rules`, `ok_rules`, `confidence_rules`, `switch_reject_severity`, `priority_order`, `priority_levels`, `priority_sources`, `thresholds`, `row_order`, `determinism`, `limitations`. A három szám ma a `counters.redecoded_functions` (105), a `families.undecoded_range` (`regions` 247, `bytes` 1 096 = `0x448`) és a `cfg_functions.csv` `instructions` oszlopösszege (9 331 019) mezőkből reprodukálható. A `102`-es `?` nem érintett: a specimen azonos.

- A `0x1D550` decoder `undecoded_bytes` értéke `0`, tehát nem tartozik a `105`-be; a `0.96` reached_ratio külön, a `switch_unvalidated` jelző miatt van. A kettőt nem szabad összekeverni. `CONF:P`.
- A vizsgált **tizenegy** tárgyként egyik sem szerepel a `105` között a `0x1D550` eldöntöttjei alapján. `CONF:L`, mert a 105-ös lista nem szerepel külön mezőként a `unresolved_regions.json`-ban, hanem a `counters` és a `totals` aggregátumokban olvasható.

### 11.4 Egy konzisztenciamegjegyzés az unwind-bejegyzésekről

A `patch_record_table.json` nyolc `producers`/`consumers` bejegyzése `unwind_info_rva` értékei: hét a `0x300880C`–`0x300BCF8` sávban van (`0x1E270` patcher `0x300880C`; `0x1E360` manager `0x3009AF8`; `0x1D280` arena `0x300BCA0`; `0x1D550` decoder `0x300BCB4`; `0x1DCF0` registrar `0x300BCCC`; `0x1DFF0` redirect `0x300BCE0`; `0x1E590` builder `0x300BCF8`), a `0x1DC80` `init` unwind-bejegyzése viszont `0x2FFE954`, vagyis közel `0x9D000` bájttal alacsonyabban. A sávon belüli sorrend sem RVA-sorrend, tehát ez önmagában nem ad semmilyen viselkedési következményt. A `0x2FFE954` kilógó pozíció **rekordolva** van, de a fájlból nem értelmezhető: lehet a linker kiadási sorrendjének, objektumfájl-kötések vagy későbbi kézi bejegyzés-módosítás lenne. `CONF:U`, `STATUS:OPEN`.

---

## 12. Korrekciók a korábbi dokumentumokhoz

A táblázat minden pontja a friss, statikusan újraszámolt bizonyítékra hivatkozik. A `hol` oszlop a hivatkozott helyet, a `javítás` oszlop az új, pontosabb állítást adja.

| # | `hol` | Korábbi állítás | Javítás és bizonyíték | `CONF` |
|---:|---|---|---|---|
| 1 | `06` és `11` hallgatólagos processz-heap feltételezése; a korábbi `patch_record_table.json` `table.globals[heap_handle].purpose` és `table.capacity_model.allocator` szövege | „process heap handle", „a publikált processz-heapon" | A globális egy `HeapCreate(0, 0, 0)` eredménye. A `0x1DCBE` `HeapCreate` hívás közvetlenül a `0x1DCC4` `mov [0x1830D44F0], rax` tárolást előzi; IAT `0x2E4D418`. A `GetProcessHeap` a képben `7` helyről hívódik, `0` a komponensen belül. A `0x1DC80` `init` `9`-et ad vissza, ha a `HeapCreate` nullát ad. **Az evidence szövege ezt a sor írása óta maga is javítva van** (`heap.is_process_heap: false`, `heap.kind: private_heap`), tehát a korrekció ma már a `06`/`11` dokumentumra vonatkozik. | `P` |
| 2 | `06` §5.2, §10.1; `11` §7.2; `12` §5 „Hooks / patch" sor és §9/7. pont | A `0x1E270` és a `0x1DFF0` „observed" képesség, a patchernek van közvetlen hívója | A négy közvetlen hívás **intra-komponens**. A teljes `0x1D280`–`0x1E9D0` rendszer zárt: a `0x1DC80` `init`-nek és a `0x1DCF0` registrarnak **nincs** közvetlen hívója, így a komponensnek nincs belépési pontja. A `0x1E3A4` heap-kaput egyetlen utasítás írja, az `init` belsője, tehát a kapu a dekódolt CFG-ben teljesíthetetlen, és a manager `2`-vel tér vissza, mielőtt bármelyik callhelyhez érne. | `P` a gráf, `L` a futásidejű elérhetetlenség |
| 3 | `thread_context_map.json` `activation.ordering_matrix` 5. lépése és `callers[].preconditions`; `patch_mechanisms_1dff0.csv` `caller_lock_discipline`; `06` §5.3 „egyszeri" | „hand rolled interlocked once flag", „releases the once flag", „a hand rolled once flag" | Nem egyszeri flag, hanem kézzel írt spin-zár: mindhárom használó a megszerzés után **újraellenőrzi a saját feltételét**. Új tény: a versenypálya **korlátlan** (`inc rsi`/`inc rdi` stop nélkül), a `Sleep` argumentuma `0\|1` millisecond, timeout és attempt cap nincs. **A `patch_record_table.json` szövege ezt a sor írása óta maga is javítva van** (`lock.kind: hand_rolled_interlocked_spin_lock`, `attempt_cap: null`, `timeout: null`, `retry_counter_bounded: false`); a fennmaradó „once flag" megfogalmazás a felsorolt három evidence-helyen él. | `P` |
| 4 | a korábbi `patch_record_table.json` `address_model.second_store.note` és a `06`/`07` vonatkozó állítása | „a tárolt érték az egyetlen visszareferencia a terület alsó öt bájtjára", különálló `rec + 0x00` célcímmel | Fordítva. A `0x1E306` kétbájtos írás célcíme a `rec + 0x00`, azaz **az anchor**, és a hét bájtos terület `anchor − 5` kezdetű, tehát a `+0x00` a terület **felső** szélén van. Mivel `patch_site + 5 = anchor`, a két írás szomszédos, és a `7` bájtos védelmi ablakot együtt fedik: `5` bájt a `patch_site`-en, `2` bájt a `patch_site + 5`-en. Nem egyetlen folytonos írás. **Az evidence ma már ezt mondja**: `lands_on: the anchor, which is patch site + 5, the upper edge of the seven byte window`, `single_contiguous_store: false`, `write_group_count: 2`. | `P` |
| 5 | `patch_record_table.json` — nincs említve | A `spin_lock` leadás konzisztenciája nincs dokumentálva | Az orchestrator összes kilépési útja a `0x1E560`-re convergeál, ahol `xor eax, eax` majd `xchg [0x1830D44E8], eax` történik. A zár **egyszer**, minden úton elengedésre kerül, a `2`, `4`, `5`, `0x0A` hibakódokat is beleértve. A `0x1E575` `mov eax, esi` állítja vissza a return értéket, tehát az elengedés nem befolyásolja. | `P` |
| 6 | `thread_context_map.json` `activation.heap_gate`; `06` §5.3 | A `2`-es kód a heap-handle hiánya | A `2`-es kód helyes, de a kapu a komponensen belül **teljesíthetetlen**, mert az egyetlen írója, a `0x1DC80` `init`, hívatlan. Ezt a dokumentum 5.6 rögzíti. | `L` |
| 7 | `06` §5.2 | `SuspendThread`, `SetThreadContext` és `ResumeThread` eredménye nincs ellenőrizve | Pontosítás: a tömegúton a patcher **nem nulla** kódja megállítja a ciklust, tehát egy patchhiba részleges állapotot hagy hátra; az egy-rekord úton viszont a patcher kódja közvetlenül a manager státusza. A `0` a tömegúton **siker és no-op között nem megkülönböztethető**. | `P` |
| 8 | a korábbi `apc_sites.csv` `target` oszlop mondata; `06`/`07` vonatkozó állítása | „43 data slots store the entry VA `0x1F90720`" | A 43 slot az `RVA 0x1170` placeholder VA-ját tárolja. Független, `8` bájtos lépésközű szkennelés a `.rdata`/`.data`/`.tls`/`.rsrc`/`.reloc` szekciókban 43 találatot ad, köztük a felsorolt négy példát; a `0x1F90720`-hoz **egy** slot tartozik, a `0x2D89678`. Az érvelés végeredménye helyes, a benne szereplő cím téves volt. **Az `apc_sites.csv` szövege ezt a sor írása óta maga is javítva van**, és külön kimondja, hogy az owning függvény belépési VA-ja más cím, akit a `fn` oszlop számol. | `P` |
| 9 | `06` §6 | „a globális `0x183254270` értéke `0`, akkor APC" | Pontosítás: a kapcsoló **fájlban nulla és a képben nincs írója** — 7 olvasó, 0 író, nincs relocation, nincs képbeli initializáló. A `0` tehát fájl-inicializált alapérték. A `±0x100` RVA szomszékság-scan 11 írási referenciája a `0x3254360`–`0x3254370` négy dwordra céloz, `0xF0` bájttal a kapcsoló **után**, nem magára a kapcsolóra. | `P` a számokra, `U` a kapcsoló írójára |
| 10 | `patch_mechanisms_helpers.csv` `comparator_slot_write_0x1E2F7` | A `0x1E2F7` írás `base origin=immediate:0xA` | Az argumentumkövető lineáris backward pre-image, nem dominátor-bizonyíték; a `0x0A` a `0x1E2DB`-nél kerül `esi`-be, a tárolás célja nem az. A kurált modell: a `4` bájtos diszlokáció a `patch_site + 1`-en van. A sor maga deklarálja a korlátot a `method_structural_heuristics` mezőben. | `L` |
| 11 | `patch_mechanisms_helpers.csv` `toolhelp_install_inline_materialisation_0xc8cf07` | `store widths=8,16` | A szűk konstans-tárolás-futam a `0xC8CF07`–`0xC8CF17` tartományban `2`/`1`/`4`/`1` bájt szélességeket használ, összesen `8` bájtot. A `8,16` pár feltehetően a `0xC8CF01`/`0xC8CF04` `movups` mozgásra utal, nem a szűk futamra. | `P` |
| 12 | `06` §7.2, `07` §6.1; `patch_mechanisms_helpers.csv` `symmetry_*` | „a célcím ASLR/runtime-feloldás miatt nem statikus" | A pontosabb állítás: a telepítő írási ága a **`0x317E398` írható cache globálist** olvassa, nem a `GetProcAddress` friss eredményét. A feloldási ág kihagyásakor a cache a fájl képén nulla, és az írás a nullcímre menne. A visszaállító viszont **saját maga** oldja fel, és a cache-t nem használja — ez az `ASYMMETRIC` minősítés mechanizmusa. | `P` |
| 13 | `06` §10.2 | „a normál user-mode címtartományban az első argumentumot használja célcímként" | A függvény a `0x140000000`–`0x146000000` ablakon belül a `.data` `0x3227D40` bázissal **újrabázeli** az első argumentumot; a fájlbeli képén a bázis nulla, tehát a rebase no-op. A `0x8` elem- és `0x32` bájtablak-plafon a builderben. | `P` |
| 14 | `06` §7.2, `07` §6.2 | A Toolhelp-pár „symmetrikus", a méret azonos | A `symmetry_size_argument` sor valóban `identical=True`-t ad (`0x10` mindkét oldalon), de a `symmetry_target_source` `ASYMMETRIC`, és a `symmetry_protection_restore_path` szerint a szimmetria csak **azonos rekord újrahasznosításakor** áll fenn. A `symmetry_image_inventory` `matching spans` mezője a két fél tartományát nevezi meg — `0xC8CE70-0xC8CF24, 0xC8F470-0xC8F4BA` —, de a két fél két **önálló függvény**, és a `06`/`07` „szimmetrikus" minősítése a cache-elt, illetve frissen feloldott célcím miatt nem áll. **A korábbi „`matching spans: 0`" olvasat a jelen evidence-val nem egyeztethető össze.** | `P` |
| 15 | `06` §8.2, `07` §6 | A Toolhelp-pár nem őrzi meg a régi védelmet | Pontosítás: a **telepítő** nem őrzi meg közvetlenül, de a `VirtualProtect` kimeneti paraméterével a hívó rekordjának `+0x10` mezőjébe **átadja**. A visszaállító ugyanebből a mezőből olvas. A `06` §7.2 ezt már helyesen írja le; a `07` §6.1 „nem állítja vissza az oldalvédelmet" mondata a telepítőre igaz, a párra nem. | `P` |
| 16 | `06` §5.2, `§10.1` | A patchcél és a célmodul „futáskor a dinamikus rekordtáblából származik" | Pontosítás: a tábla nem „dinamikus" abban az értelemben, hogy futásidőben bármikor újraépülne; a statikus adatlánc szerint kizárólag a hívatlan `0x1DCF0` registrar írja, a hívatlan `0x1E590` builderrel és a hívatlan `0x1D280` arenával. A slot fájlban nulla, és nincs képbeli inicializáló. | `P` a kiírási pontokra, `L` a fogalom pontosítására |
| 17 | `06` §5.3 | „a `0x1DFF0` context-módosító ágban nincs közvetlen `ResumeThread`; ebből nem következik biztos szállefagyás" | A `thread_context_map.json` `caller_resume_in_caller` sora lezárja: a manager `0x1E484` és `0x1E537` helyen **két** duplikált resume-ciklust tartalmaz, azonosítónként egy `OpenThread` + `ResumeThread` + `CloseHandle` sorrenddel, tehát **egy felfüggesztés és egy folytatás** van azonosítónként. A számláló nem torzul. A `0x1DFF0` maga valóban nem folytat. | `P` |
| 18 | `06` §13 „Szállista allokáció" | „Sikertelen heap-allokáció esetén a lista üres marad, majd a snapshot lezáródik" | Pontosítás: sikertelen allokációnál a `0x1E0AE` a snapshot-handle-t lezárja és a függvény **visszatér**, tehát az out blokk nem publikálódik; a manager a `0x1E451`-nél a nulla pointert látja, és **kipedi a resume- és a free-ágat** is. A `null array` az egyetlen eset, ahol a `HeapFree` kimarad. | `P` |
| 19 | `06` §10.1 hibaágak | „a rekord a cache-hívás után akkor is `0x06` jelre áll, ha a restore sikertelen" | Megerősítve és pontosítva: a `0x06` írás a `0x1E336`-nál, a restore `0x1E31B` és az öblítés `0x1E330` **után** történik, és egyik eredmény sincs tesztelve. A `0x0A` hibakód kizárólag az első `VirtualProtect` hibájára létezik; a restore és az öblítés hibája nincs képviselve a visszatérési értékben. | `P` |
| 20 | `06` §14/3. és §14/4. nyitott kérdés | „Melyik `RVA 0x1E270` patch-rekordok aktiválódnak ténylegesen", „Ki vagy mi hívja közvetetten az `RVA 0x1754520` NOP-patch segédet" | Mindkettő lezárható **statikus adatlánnyal** a negatív oldalon: a `0x1E270` rekordjait a hívatlan `0x1DCF0` registrar hozza létre, tehát a teljes lánc statikusan halott; a `0x1754520`-nak pedig nincs közvetlen hívója, nincs mutatója és egyetlen `rva32` előfordulása a kivételkönyvtár bejegyzése. Amit ezek **nem** zárnak le: a közvetett, futásidejű vagy képkívüli hívás lehetősége. | `P` a negatív oldalon, `U` a lezáratlan oldalon |

### 12.1 Megerősített, nem javított állítások

A következő korábbi állításokat a friss bizonyék **megerősíti**, nem módosítja:

| `hol` | Állítás | Megerősítő bizonyíték | `CONF` |
|---|---|---|---|
| `06` §6, `11` §7.2, `12` §5 | A hét `QueueUserAPC` cél `RVA 0x1170`, egyetlen `ret`; nem shellcode | Független szkennelés: 43 adat-slot tárolja a `0x1170` VA-ját, 2 közvetlen hívó függvény, egy vtable-slot is rá mutat, `IMAGE_RUNTIME_FUNCTION` bejegyzése nincs | `P` |
| `06` §7.2 | A Toolhelp telepítő a `CreateToolhelp32Snapshot` első 16 bájtját menti és 8 bájtos `0xFFFFFFFF`-et visszaadó stubbal írja felül | A `0xC8CEE9` `0x10` immediate, a `0xC8CEEE` `0x40` immediate, a `0xC8CF01`/`0xC8CF04` `movups` pár, a `0xC8CF07`–`0xC8CF17` nyolcbájtos futam | `P` |
| `06` §7.2 | A visszaállító a `0xC8F4B3`-on tail-jumppal adja át a `VirtualProtect`-nak a hívást | `jmp [0x2E4D630]` a függvény utolsó utasítása, `add rsp, 0x20` és `pop rsi` után | `P` |
| `06` §8.2 | Az egyetlen közvetlen `FlushInstructionCache` a `0x1E330` | Kép-szintű leltár: 1 hely, a `0x1E270`–`0x1E357` tartományban | `P` |
| `06` §5.1 | A `0x1DFF0` a saját processz szálait választja ki, és kizárja az aktuális szálat | `0x1E063` `GetCurrentProcessId`, `0x1E075` `GetCurrentThreadId`, `0x1E07D` kilépési ág | `P` |
| `06` §5.2 | Az `OpenThread` `0x5A`-t kér | `0x1E0ED` `mov ecx, 0x5a`, `0x1E0F2` `xor edx, edx` | `P` |
| `07` §6.1 | A telepítő és a visszaállító nem hív `FlushInstructionCache`-t | Mindkét tartományban `ABSENT` | `P` |
| `11` §7.3 | A `0xC8CE70`, `0xC8F470`, `0x1754520` segédekhez nincs közvetlen hívó | `cfg_functions.csv` `cross_function_targets`: mindhárom 0; a `patch_mechanisms_helpers.csv` `*_address_literals` soraiban `rva32=1, va64=0, exception-directory=1` | `P` |

### 12.2 Felülírt állítások regisztere

A `12` fejezet korrekciós soraival azonos mintát követve ez a regiszter **minden felülírt korábbi állítást** egy helyen felsorol: a korábbi állítás és annak eredeti helye, az új hitelesített állítás, a bizonyító artifact, és a bizonyosság. A `12` fejezet `1`–`20` sora a `06`/`07`/`11`/`12` dokumentumok állításait írja felül; a `FA-01`…`FA-20` sorok a **16 dokumentum saját, a `16.x` és `16.y` újraellenőrzésekben felülírt** állításait, a `FA-21` sor a dokumentumcsaládon belül feltárt, a `14` és a `16` közötti konfliktust. A `16.0.2` táblázata a `FA-01`…`FA-16` tételek nyers változata, a `16.y.2/1` a `FA-17`, a `16.y.1` 14.–16. és 23. sora a `FA-18`/`FA-19`, a `16.y.3/A` a `FA-20` forrása; ahol mindkettő ugyanazt a tételt írja le, a regiszter a kanonikus alak.

| # | Korábbi állítás (hely) | Felülírt állítás | Bizonyító artifact | `CONF` |
|---:|---|---|---|---|
| FA-01 | a `patch_record_table.json` a `0x1E270` patch-táblát `94` invarianctal írja le (`1.2`) | A fájl `summary.anchor_count: 118`, `summary.anchor_failures: 0`, azaz `118` invariant, `0` hiba. A `94` érték semmilyen mezőből nem olvasatható, ezért supercedált | `patch_record_table.json` `summary`; lásd még a `16.y.1` 2. sora és a `1.6` `H-1` sora | `P` |
| FA-02 | a `patch_mechanisms_1e270.csv` `51` soros táblázat (`1.2`) | `50` adatsor; a `51` a fejlécet is beleszámítja | `patch_mechanisms_1e270.csv` fejléc + `50` adatsor; `1.6` `H-2` | `P` |
| FA-03 | `GetProcessHeap` a képben `8` helyről hívódik (`2.2`, `5.6`) | `7` helyről: `0x16B3`, `0x1843`, `0x8A529C`, `0x8A8F15`, `0x955AB4`, `0x959DD2`, `0xB70391`; `get_process_heap.call_sites_in_component: []`, `call_sites_in_component_count: 0` | `patch_record_table.json` `heap.why_not_the_process_heap[2]`, `heap.get_process_heap`; `patch_mechanisms_1e270.csv` `global.heap_handle` | `P` |
| FA-04 | a `patch_record_table.json` `address_model.second_store` megjegyzése félrevezető, és a `12/4` korrekció az evidence-ra vonatkozik (`3.3`) | Az evidence **maga is javítva van**: `lands_on: the anchor, which is patch site + 5, the upper edge of the seven byte window`; `region.single_contiguous_store: false`; `region.write_group_count: 2` két `write_groups` bejegyzéssel; a `note` szerint a tárolás a terület felső szélén van. A megmaradt ellentmondás a `06`/`07` dokumentumra vonatkozik | `patch_record_table.json` `address_model.second_store`, `address_model.region`; `patch_mechanisms_1e270.csv` `expr.second_store`, `expr.region` | `P` |
| FA-05 | a `SuspendThread` eredményének hiánya `CONF:L` (`4.4`, `BRef 0x1E109`) | A negatív finding `OBSERVED` / `HIGH`, tehát `CONF:P`; csak a **verseny-következmény** marad `CONF:L`. A `BRef` `CONF:P` / `STATUS:OBSERVED` | `patch_mechanisms_1dff0.csv` `thread_suspend`, `suspend_result_unchecked`; `thread_context_map.json` `api_surface.thread_lifecycle[suspend].result_checked: false` | `P` a hiányra, `L` a következményre |
| FA-06 | a `spin_lock` „egyszeri flag", és ezt a `patch_record_table.json` írja (`5.1`) | A `patch_record_table.json` **maga is spin-zár értelmezést ad** (`lock.kind: hand_rolled_interlocked_spin_lock`, `attempt_cap: null`, `timeout: null`, mindhárom holder `retry_counter_bounded: false`, `holder_count: 3`). A „once flag” megfogalmazás innentől három helyen marad fenn | `patch_record_table.json` `table.globals[spin_lock].purpose`, `lock`; `thread_context_map.json` `activation.ordering_matrix[5]`, `callers[].preconditions`; `patch_mechanisms_1dff0.csv` `caller_lock_discipline`; `patch_mechanisms_1e270.csv` `global.spin_lock` | `P` |
| FA-07 | a registrar újraellenőrzése a `0x1DD3F`-nél van (`5.1`) | A `cmp` utasítás RVA-ja `0x1DD3D`; a `0x1DD3F` ugyanazon utasítás RIP-diszlokáció-mezőjének pozíciója, és a heap-handle reader-listában is szerepel. Az 5.1 minden más sora utasítás-RVA-t használ, ezért `0x1DD3D` | `patch_record_table.json` `lock.holders[registrar].recheck_site_rva`, `table.globals[heap_handle].references[2]` | `P` |
| FA-08 | a `patch_record_table.json` `heap_handle.purpose` és `capacity_model.allocator` tévesen processz-heapot ír (`5.6`) | Az evidence javítva: `heap.is_process_heap: false`, `heap.kind: private_heap`; a globális egy `HeapCreate(0, 0, 0)` eredménye a hívatlan `init` belsőjéből. A `HeapFree` IAT `0x2E4D420`, egyetlen hívási hely `0x1E55A` | `patch_record_table.json` `heap`, `table`; `patch_mechanisms_1e270.csv` `global.heap_handle` | `P` |
| FA-09 | a heap-gate teljesíthetetlensége a `16` saját újraszámolása (`5.6`) | Az evidence szintén kimondja: `activation.reachable_inside_decoded_cfg: false`, `static_chain_confidence: "H"`, `runtime_reachability_confidence: "L"`, `gated_call_sites: ["0x1E425","0x1E4FD"]`, `gated_call_site_count: 2`, `init_direct_call_site_count: 0`, `handle_writer_count: 1`; a `0x1DCC6` mezőpozíció, az utasítás `0x1DCC4` | `patch_record_table.json` `activation`, `heap.writers_in_file`, `unresolved.orchestrator_caller`; `patch_mechanisms_1e270.csv` `caller.0x1E425`, `caller.0x1E4FD`, `open.orchestrator_caller` | `P` az adatláncon, `L` a futásidejű elérhetetlenségen |
| FA-10 | a `symmetry_image_inventory` sora `matching spans: 0`-t ad (`6.3`) | A mező értéke `0xC8CE70-0xC8CF24,0xC8F470-0xC8F4BA`: a leltár a két **közös tulajdonság** alapján nevezi meg a párt. A `symmetry_target_source` továbbra is `ASYMMETRIC`, a szimmetria csak azonos rekord újrahasznosításakor áll fenn, tehát a részleges szimmetria következtetése változatlan | `patch_mechanisms_helpers.csv` `symmetry_image_inventory`, `symmetry_target_source`, `symmetry_protection_restore_path`, `symmetry_save_restore_shape`, `symmetry_size_argument` | `P` |
| FA-11 | a `0x2AB27B0` és a `0x2AB2864` megosztott segédnek `161` függvényszintű célzója van (`6.4`) | Kép-szintű statikus hívási hely: `0x2AB27B0` = `1 438`, `0x2AB2864` = `1 433`, `0x2AB3500` = `2 408`; mindhárom `target_expr` mezője „utility behaviour, not a subject-specific activation path" | `patch_mechanisms_helpers.csv` `activation_shared_helper_0x2AB27B0`, `…_0x2AB2864`, `…_0x2AB3500` | `P` |
| FA-12 | a cookie-ellenőrzés két helyen van: `0x1E282`, `0x1E344` és `0x1E570` (`7.2`) | A `0x2AB3500` cookie-ellenőrző **hat** helyről hívódik: `0x1DFCB` (registrar), `0x1E250` (redirect), `0x1E344` (patcher), `0x1E570` (manager), `0x1E9B5` (list builder), `0x17545AE` (NOP-fill). A `0x1E282` nem `0x2AB3500` hívási hely; a redirect cookie-betöltése `0x1E00A` | `patch_mechanisms_helpers.csv` `activation_shared_helper_0x2AB3500` call-site lista, `fill_helper_global_ref_0x1754526`; `thread_context_map.json` `api_surface.stack_guard` | `P` |
| FA-13 | az `apc_sites.csv` `target` oszlopa hibásan a `0x1F90720` owning függvény VA-ját nevezi meg a `43` slotban (`8.2`) | Az evidence javítva: „43 data slots store the pointer VA 0x180001170 of RVA 0x1170", és külön hozzáteszi, hogy az owning függvény belépési VA-ja más cím, akit a `fn` oszlop számol. A független `8` bájtos lépésközű szkennelés továbbra is `43` találatot ad | `apc_sites.csv` `target` oszlop mind a hét sorban; `patch_mechanisms_1e270.csv` `open.record_instances` | `P` |
| FA-14 | az `RVA 0x1170` tartalma: egyetlen `ret`, utána `15` bájt `0xCC` kitöltés (`8.2`) | Pontosítás: `1` utasítás (`c3`), utána `15` bájt `0xCC`, majd egy `0x55`. A kitöltés hossza változatlan, a záró `0x55` korábban nem volt megemlítve | `apc_sites.csv` `target` oszlop mind a hét sorban | `P` |
| FA-15 | a `8` védelmi hívási hely a `0xC8F4B3` tail-jumpot tartalmazza, és a `0x2BEB8FB` „a kilencedik" (`10.1`) | A `writer_protection_call_inventory` `0x1E2D1;0x1E31B;0xC8CEF4;0x1754577;0x17545A0;0x2921505;0x2921526;0x2BEB8FB` – vagyis a `0x2BEB8FB` a **nyolcadik**, és a `0xC8F4B3` a kilencedik, külön sorban számolt protection tail-jump (`writer_import_tail_thunk_inventory`: 1 db) | `patch_mechanisms_helpers.csv` `writer_protection_call_inventory`, `writer_import_tail_thunk_inventory`, `writer_protection_result_checked`, `comparator_entry_0x2BEB88C`, `comparator_protect_0x2BEB8FB` | `P` |
| FA-16 | a `12/1` korrekció célpontja a `patch_record_table.json` két szövegmezője | Az evidence ma már a helyes állítást tartalmazza; a korrekció célpontja a `06` és `11` dokumentum hallgatólagos processz-heap feltételezése | `patch_record_table.json` `heap`, `table`; `patch_mechanisms_1e270.csv` `global.heap_handle` | `P` |
| FA-17 | a sweep-lefedettség számai `method_sweep_coverage` / `method_decode_shortfall` JSON-útvonalakról származnak, és a `method` blokk kulcsa (`11.3`, `14.2`) | `141 921` → **141 899** teljesen dekódolt függvény; `9 331 016` → **9 331 019** dekódolt utasítás; `0x449` (1 097) → **`0x448`** (1 096) nem dekódolt bájt; `83` → **105** függvénytest. A számok ma a `counters.redecoded_functions`, a `families.undecoded_range` és a `cfg_functions.csv` `instructions`/`undecoded_bytes` mezőkből olvashatók; a `method` blokkban **nincs** `method_sweep_coverage` és **nincs** `method_decode_shortfall` kulcs | `cfg_functions.csv` (`instructions`, `undecoded_bytes` összeg), `cfg_clusters.csv` (`functions_with_undecoded` összeg = 105), `unresolved_regions.json` (`counters`, `method` kulcslista, `families.undecoded_range`) | `P` |
| FA-18 | a `11.2`–`11.3` fejezet `unresolved_regions.json`-ra épülő sorszámai ellenőrzetlennek minősülnek (`16.0.4`) | Az `UR-000066`–`UR-000069` és `UR-001588`–`UR-001591` `region_id`, `family`, `triage`, `reached_ratio`, `undecoded_bytes`, `priority`, `confidence` attribútumai egyeznek a `11.2` táblázatával; a `105 = 142 004 − 141 899` és `1 096 = 0x448` kötések belsőleg konzisztensek. A `16.0.4` „ellenőrizetlen" minősítése ezekre a sorszámokra már nem áll; a `11.3` levezetési forráspontja változott, a `16.y.2/1` szerint | `unresolved_regions.json` `UR-000066`–`UR-000069`, `UR-001588`–`UR-001591`; `cfg_functions.csv`; `cfg_clusters.csv`; lásd a `16.y.1` 14.–16. és 17. sora | `P` |
| FA-19 | a `10.3` fejezet `xref_edges.csv` sorszámai ellenőrizetlenek (`16.0.4`) | Ellenőrizve: `xref_edges.csv` `57 101` sor, mind a `6` kategória átszúmolva, és a patch-komponens `11` megadott RVA-ja egyik `direct_call` / `thunk` / `iat` / `vtable` / `global_fnptr` élkéntben sem szerepel `src` vagy `dst` oldalon. Az `11.1` negatívuma bitre reprodukálható, és a `16.0.4` „ellenőrizetlenül marad" minősítése e sorszám ellenőrzött állapotát nem tükrözi | `xref_edges.csv` (`57 101` sor, `6` kategória, `22` oszlop); lásd a `16.y.1` 23. sora | `P` |
| FA-20 | az `E8` `inputs.patch_cross_references` a `patch_mechanisms_1e270.csv` aktuális digestjét rögzíti | Az `E8` elavult input-digestet tartalmaz: `66c8e9bc…` a lemezen `ffc2234d…` (`1.6` `H-2`, `14 895` bájt, `50` adatsor, `21` nemüres `site_rva`). Az `E8` `rva_count: 35` értéke a jelenlegi CSV-ből nem reprodukálható; ez az `E8` belső stale állapota, nem a `16` állítása, és a `14.2` a `P2` régiók számát nem használja | `unresolved_regions.json` `inputs.patch_cross_references` vs a lemez; lásd a `16.y.3/A` és a `16.y.1` 19. sora | `P` az eltérésre, `L` a hatására |
| FA-21 | **a `14` dokumentum §16.3 bekezdése a `patch_record_table.json` rekordtábláját `anchor_count = 94` értékkel nevezi meg** | A `patch_record_table.json` `summary.anchor_count` értéke **118** (`anchor_failures: 0`); a `94` semmilyen mezőből nem olvasatható, ezért supercedált. A `patch_mechanisms_1e270.csv` **nem tartalmaz `anchor_count` mezőt** (`0` előfordulás, `16` oszlopos fejléc, `50` adatsor), így a lapos CSV-ből anchor-aggregátum egyáltalán nem vezethető le. A `14` szövege a `118` értékre javítva, forrásként a `patch_record_table.json#summary` megnevezésével | `patch_record_table.json` `summary.anchor_count: 118`; `patch_mechanisms_1e270.csv` fejléc és teljes tartalom; a javított `14` §16.3 és `Újraellenőrzés/Ú.1` blokkja; lásd a `1.6` `H-1`/`H-2` sora és a `16.y.1` 26.–28. sora | `P` |

**A regiszter határa:** a fenti `FA-01`…`FA-21` tételek mind dokumentum-, mező- vagy sorszám-javítások. Egyik sem ír le végrehajtási, előállítási vagy kerülési eljárást, és egyik sem bocsát ki konkrét patch-bájtot, diszlokációértéket vagy írási receptet; a dokumentum szimbolikus kifejezései (`rec + 0x00`, `patch_site`, `rec[0x28][i]`) továbbra is leírójelölések az 1.1. pont szerint.

---

## 13. Nyitott kérdések

### 13.0 A Toolhelp telepítő caller-e és aktiválása — OPEN

Ez a kérdés a `06` §14/5. és a `07` §6.1/§6.2 nyitott kérdésének pontosított formája, és a jelen dokumentum egyik fő fejezete.

| Szegmens | Lezáratlan rész | Bizonyosság |
|---|---|---|
| **caller** | Ki hívja a `0xC8CE70`-et? A teljes képben nincs közvetlen `call rel32`, nincs abszolút mutató, nincs RIP-relatív hivatkozás, nincs függvénypointer-slot. A `patch_mechanisms_helpers.csv` `activation_subject_reachability` sora kimondja: „no static activation path is derivable for any audited subject" | a hiány `P`, a „nem fut" következtetés `L` |
| **aktiválás** | A két őr (`gs:[0x58]`-alapú TLS-slot-őr a `0xC8CE91`-nél, és a `0x317E3A0` gate `0xFFFFFFFF` összehasonlítása a `0xC8CEA5`-nél) futásidejű értékeken dönt. A gate fájlban `0`, tehát a feloldási ág fegyverben van; a `0x33070EC` TLS-index és a `gs:[0x58]` slot `+0x44` mezője futásidjű | `U` |
| **célcím** | A `0x317E398` cache tartalma. Fájlban nulla. A modul és az export feloldása a `GetModuleHandleA("kernel32.dll")` és a `GetProcAddress` eredményétől függ | `U` |
| **időzítés** | Mikor történik a telepítés a folyamat életciklusában? Sem a `CreateComponent` export, sem a TLS callbackek, sem a `DoGameLoad` slot nem mutat rá | `U` |
| **pár legitimitása** | Csak akkor értelmes, ha a `0xC8F470` ugyanazt a rekordot kapja vissza, és az export címe nem változott. Semmilyen statikus bizonyíték nem köti össze a két hívást | `U` |
| **hatás, ha lefut** | A `0x1DFF0` snapshot és a `0x2BD0FBE`–`0x2BD133E` modulkeresők `INVALID_HANDLE_VALUE`-et kapnának, tehát a mechanizmusok csendben kikapcsolnának, nem kivételeznének | `L` |

- **Nincs új állítás, hogy a telepítő lefut-e.** A `07` §6 megállapítása — „a kód erős anti-enumerációs képességet bizonyít, de nem azt, hogy a pár a vizsgált host folyamatban telepítve van" — továbbra is a helyes pozicionálás. `CONF:L`.

### 13.1 Az orchestrator caller-e

- Ki vagy mi hívja a `0x1E360`-at? A teljes dekódolt CFG-ben nincs közvetlen hívója, és nincs rá mutató mutató, `rva32`/`va64` literál vagy RIP-relatív hivatkozás. `CONF:P` a hiányra, `CONF:U` a lezáratlanságra.
- Melyik komponens lifecycle-hook, ha egyáltalán, hívja? A `12` §9/7. pontja ezt a kérdést P1 prioritással listázza, és a válasz továbbra is nincs. `U`.
- **Amit a zárt komponens bizonyít:** ha a `0x1E360` elérhető lenne, az `init` akkor sem futna hozzá, mert annak sincs hívója, tehát a `2`-es kód lenne az eredmény. A két hiány egymástól **független**; bármelyik önmagában is elég lenne a lezáráshoz. `CONF:L`.

### 13.2 A rekord-példányok

- Mely rekordok vannak futásidőben, és melyik modult és exportot célozza mindegyik anchor? A tábla slot fájlban nulla, nincs képbeli inicializáló, és az egyetlen író a hívatlan registrar. Statikusan egyetlen példány sem enumerálható. `CONF:U`.
- A `patch_record_table.json` négy nyitott kérdése ebből a blokkból származik: `record_instances`, `registrar_caller`, `orchestrator_caller`, `upper_flag_bits`. Mind `LOW`, azaz `U`.

### 13.3 A flag bitek 3–7

- Mit jelentenek a `rec + 0x20` 3–7. bitjei, és mely kód állítja őket? A registrar `0x1DF53`-nál `and r9, 0xF8`-zal megőrzi őket a merge-ben, de az elemzett három fogyasztóban egyetlen olvasó és egyetlen másik író sincs. `CONF:U`.
- **A `0x01` bit forrása is nyitott részben:** a `0x1E974` a list builderben állítja, ha az anchor előtt van egy `5` bájtos azonos filler-futtam. Ez a futam felismerésének pontos algoritmusa a fájlból nem írható le teljesen; a `patch_record_table.json` csak a jelentését adja meg. `CONF:L`.

### 13.4 A `rec + 0x10` nullapublikálhatósága

- Publikálhat-e a registrar nulla értéket az `image_base` mezőbe? A mezőt az arena blokkjából veszi, és a `0x1D280` CFG-je teljesen lezárt (`reached_ratio` 1.0, `undecoded_bytes` 0), de a blokk visszaadási ágai között a nullát nem aknáztatom. `CONF:U`.
- Ha igen, akkor a redirect `0x1E202` kapuja átmegy nulla kép-alappal és nem nulla célbájttal, és egy igen kis érték kerül a `RIP`-be. A `06` §13 és a `11` §7 ezt nem tárgyalja. `CONF:L`.

### 13.5 A hálózati/provenancia-korlát, ami ide tartozik

- A `0x1830D44F8` slot, a `0x1830D44F0` heap és a `0x1830D44E8` zár a `.data` nem inicializált farkában vannak, és a `0x30B7A00`–`0x3305A00` nyers tartományban a `11` §9 szerint több nagy, legalább `4096` bájtos nulla-részlet is van. Ezek a `patch_record_table.json` szerint a nem inicializált `.data` szokásos részei. A patch-komponens globálisai nem mutatnak titkosított vagy előre kitöltött mintát, tehát **nincs** pozitív jel arra, hogy a rekordok tartalma a fájlban el lenne rejtve. `CONF:P`.
- A hitelesítési munkamenet része, hogy a `0x317E398`, `0x317E3A0`, `0x3227D40`, `0x3254270`, `0x33070EC` és a `0x1DC80` `init` kilépési értékei mind `U` státuszúak, nem futásidejű adatok.

### 13.6 Prioritizált nyitott kérdések, a `12` §9 alapján kontextusba helyezve

| `12` §9 kérdés | A jelen dokumentum hozzáadott része |
|---|---|
| P0/7. „Van-e statikusan lezárható hook/patch cél és aktiválási út?" | A cél **szimbolikusan** lezárható (3.3, 4.3, 6.1, 7.1, 9.1). Az aktiválási út **nem**, és a kimaradó ok most már nem csak a nyitott kérdés: a teljes `0x1D280`–`0x1E9D0` komponens belépés nélküli (2.1), és a `0xC8CE70`/`0xC8F470`/`0x1754520` hármasnak sinc hívója (13.0). A konkrét patch-célmodul és a hívó továbbra is `U` |
| P1/6. „Teljes, validált syscall-inventory" | A patch-komponensben **nincs** `syscall` utasítás. A `UR-000066`–`UR-000069` és a `UR-001588`–`UR-001591` `evidence` mezői mind `syscall_sites:0`-t mutatnak a nyolc vizsgált funkcióban. A `0xC8CE70`, `0xC8F470` és `0x1754520` sem tartalmaz `syscall`-ot |
| P2/13. „Mely buildváltozások korrelálnak" | A patch-komponens nyolc funkciójának mindegyike `P0` patch-prioritású a `unresolved_regions.json` `priority.patch` oszlopában, vagyis a triage ezt a tartományt prioritásos patch-területnek tekinti. Ez a **saját** prioritizálás, nem a malware-minősítés |

---

## 14. Korlát és felülvizsgálat

### 14.1 Amit ez a dokumentum nem állít

- Nem állítja, hogy a vizsgált mechanizmusok futásidőben lefutnak. Minden aktiválási kérdés `OPEN`.
- Nem nevez meg konkrét patch-címet, patch-bájtot, diszlokációértéket vagy írási sorrendet, amelyből a patch előállítható lenne. A szimbolikus kifejezések leírójelölések.
- Nem ad bypass-, kikapcsolási vagy hook-javítási eljárást a Toolhelp-párhoz, a NOP-fillhez vagy a `0x06` flaghoz.
- Nem ad visszafordíthatatlan vagy romboló hatású mintát, és nem hajtott végre semmilyen műveletet a példányon.
- Nem minősíti sem a DLL-t, sem annak fejlesztőjét, és nem állít malware-, incidens- vagy jogi minősítést.
- Nem zárja ki a közvetett hívást, a függvénypointert, a futásidejű kódgenerálást, a `call [reg]` útvonalakat, a képkívüli írót és a külső modulok viselkedését. Ezekre az alábbi korlátok érvényesek.

### 14.2 Módszertani korlátok, amelyeket az evidence maga rögzít

| Korlát | Forrás | Hatás |
|---|---|---|
| a `direct_call` élek csak katalógált csomópontokra mennek | `xref_build.py` scope | a négy intra-komponens patcher-hívás hiányzik a `xref_edges.csv`-ből; nem ellentmondás (11.1) |
| az argumentumkövető lineáris scan, basic-block elérhetőség nélkül | `patch_mechanisms_helpers.csv` `method_structural_heuristics` | a `base origin=…` mezők szerkezeti, nem adatárami bizonyítékok (12/10) |
| a szűk-tárolás, konstans-kitöltés, slot-írás és bitmaszk detektorok szerkezetilek | ugyanott | egy találat csak a mintát mutatja, önmagában nem bizonyít futtatható kódírási mechanizmust |
| a patchcél moduljának oldalvédelme futásidőben dől el | ugyanott, `method_target_module_permissions` | ez az audit csak a **kért** védelmi argumentumokat látja, soha a céloldal tényleges állapotát |
| 105 függvénytest és `0x448` bájt nem teljesen dekódolt | `unresolved_regions.json` `counters.redecoded_functions`, `families.undecoded_range` | az azokon belüli findingok nem tartoznak ebbe az auditba (11.3) |
| a `0x1D550` decoder CFG-e `96 %`-ban ért el, `NO_BOUND` jump-táblával és 3 feloldatlan közvetett ugrással | `UR-001588`–`UR-001591` | a `0x28`/`0x30` lista pontos értéke `L` (11.2) |
| a `QueueUserAPC` argumentum-provenancia pre-image, nem dominátor | `apc_sites.csv` | a `RDX` handle-származtatás `L` (8.4) |
| a `getcontext`-szerű betöltések és a 256 bájtos kontextusmásolat ellenőrzött szerkezetű | `thread_context_map.json` `context_buffer` | a `CONTEXT` mezőelrendezése dokumentált, a kernel-viselkedés nem |
| az `apc_sites.csv` `+0x100` RVA szomszékság-scan korlátja ki van mondva | `apc_sites.csv` | a kapcsoló írója lehet regiszter-számítású tárolás vagy képkívüli (8.3) |

### 14.3 Reprodukálhatóság

A dokumentum reprodukálhatósága a fájl és a statikus lekérdezések szintjén értendő:

- a specimen SHA-256 újraellenőrzése `91cc0aa006d7315cb042c8fa8dca6c1e074a307bba7dcc9eb5509c8a7b81934e`;
- a felsorolt RVA-k disasszemblálása az image base `0x180000000` mellett;
- a `0xDC00`, illetve `0x1600` szekciónkénti RVA→RAW eltolás ellenőrzése;
- a `0x1DC80`–`0x1DCE7` és a `0xC8CE70`–`0xC8CF24` tartomány kézi disasszemblálása a heap- és cache-megállapításokhoz;
- a `cfg_functions.csv` `cross_function_targets` oszlopának újraszámolása a tizenegy tárgyként;
- a RIP-relatív globális-írási űrlapszken és a `0x180001170` nyolcbájtos szkennelés újra-futtatása.

Ez **nem** reprodukálja a DLL futásidejű viselkedését, és nem szolgáltat semmilyen invokációs, patch-, bypass- vagy credential-recovery eljárást.

### 14.4 Verzió és felülvizsgálat

| Elem | Érték |
|---|---|
| dokumentum | `reverse/adhesive-16-patch-mechanisms-targets-activation.md` |
| tárgy specimen | `reverse/adhesive.dll`, SHA-256 `91cc0aa006d7315cb042c8fa8dca6c1e074a307bba7dcc9eb5509c8a7b81934e` |
| image base | `0x180000000` |
| elsődleges evidence | `patch_record_table.json`, `patch_mechanisms_1e270.csv`, `patch_mechanisms_1dff0.csv`, `patch_mechanisms_helpers.csv`, `apc_sites.csv`, `thread_context_map.json`, `xref_edges.csv`, `unresolved_regions.json` |
| keresztellenőrzött evidence | `cfg_functions.csv`, `pdata_functions.csv` |
| konfliktusforrás | `adhesive-06`, `adhesive-07`, `adhesive-11`, `adhesive-12` |
| kódolás | UTF-8 BOM nélkül, LF sortörés |
| felülvizsgálat szükséges | a specimen hashének, a patch-komponens belépési pontjának, vagy a `0x1170` placeholder vtable-slotjának változásakor |
| kapcsolódó dokumentumok | `adhesive-00-index.md` navigáció, `adhesive-12-risk-methodology-open-questions.md` prioritizált nyitott kérdések |

### 14.5 Végső pozicionálás

A vizsgált patch-felület **négy, egymástól független írási mechanizmust** mutat:

1. egy **táblavezérelt, 5/7 bájtos relatív jump patch**et, amely egy futásidőben feltöltött `0x38` bájtos rekordtáblából dolgozik és a saját folyamat kódterületét írja;
2. egy **szál-szintű vezérlésáthelyezést**, amely saját folyamatbeli szálakat függeszt le, és a `CONTEXT.Rip` mezőt írja át egy újraépített kép megfelelő pozíciójára;
3. egy **idegen modul export-előtagjának inline stubolását**, `16` bájtos, nem írható lapot feltörő védelemváltással, cache-öblítés nélkül;
4. egy ** konstansbájtos NOP-kitöltést** feltételes célcím-újrabázeléssel, szintén cache-öblítés nélkül.

Mindegyikhez létezik egy **védelmi és cache-helyességi réteg**, és mindegyikből **egy-egy réteg hiányzik**: a patcher nem ellenőrzi a restore-t és az öblítést; a redirect nem teszteli a felfüggesztés és a context-alkalmazás eredményét; a Toolhelp-pár egyik fele sem öblít, és egyik sem őriz null-ellenőrzést; a NOP-fill nem menti el az eredeti bájtokat és nem ad státuszt.

**Egyik mechanizmus sincs igazoltan elérhető** a dekódolt CFG-ből: a patch-komponens zárt és belépés nélküli, a három segédnek nincs hívója. A `QueueUserAPC` hét ága az egyetlen írásmentes forma, amelynek a kódútja statikailag létezik, de a futásidejű eredménye és a hívója szintén nyitott.

A pontos célcímek, a hívók, az időzítés, a szándék és a rekordok futásidejű tartalma **statikusan nem dönthető el**, és a felsorolt negatívumok a dokumentált keresési scope-ra érvényesek. Dinamikus betöltés, futtatás, patch, bypass és credential-recovery nem része ennek a módszertannak.

---

## 16.x Evidence-újraellenőrzés

Ez a blokk a dokumentum minden BRef-állítását újraellenőrizte a friss evidence-készlettel, kizárólag statikus fájl- és mezőolvasással. A DLL-t nem futtattam, nem töltöttem be és nem patcheltem; új evidence-fájl nem készült. Az alábbi táblázat **minden** eltérést felsorol: régi állítás, új állítás, forrásfájl, confidence. A `P` / `L` / `U` jelölés az 1.3. pont skálája szerinti dokumentum-jelölés.

### 16.0.1 A felhasznált evidence-készlet és a nem található fájlok

| Kért fájl | Állapot |
|---|---|
| `reverse/evidence/patch_record_table.json` | megvan, felhasználva |
| `reverse/evidence/patch_mechanisms_1e270.csv` | megvan, `50` adatsor |
| `reverse/evidence/patch_audit_1dff0.json` | **nem található** az `evidence` könyvtárban |
| `reverse/evidence/patch_audit_1dff0.csv` | **nem található** az `evidence` könyvtárban |
| `reverse/evidence/patch_mechanisms_1dff0.csv` | megvan, `51` adatsor; ez a `patch_audit_1dff0` szerepét betöltő fájl |
| `reverse/evidence/patch_mechanisms_helpers.json` | **nem található** az `evidence` könyvtárban |
| `reverse/evidence/patch_mechanisms_helpers.csv` | megvan, `119` adatsor; ez a `…helpers.json` szerepét betöltő fájl |
| `reverse/evidence/apc_sites.csv` | megvan, `7` adatsor |
| `reverse/evidence/thread_context_map.json` | megvan, `145` anchor, `anchor_failures: 0` |
| `reverse/evidence/audit_handle_flow.json` | megvan, de a `target_document` mezője az `adhesive-14-c856c0-handle-producer-dataflow.md`; a hét `contested` tétel (`CF-01`…`CF-07`) egyike sem érinti ezt a komponenst vagy a három segédet, ezért itt nincs hozzá korrekció |

A két `patch_audit_1dff0` és a `patch_mechanisms_helpers.json` hiánya **nem** lett pótolva: az utasítás szerint nem írható új evidence-fájl. A tartalmi ellenőrzést a ténylegesen meglevő, azonos szerepű fájlokon végeztem el, és a fenti táblázat ezt rögzíti.

### 16.0.2 Eltérések

| # | Hely | Régi állítás | Új állítás | Forrásfájl | `CONF` |
|---:|---|---|---|---|---|
| 1 | 1.2 | `patch_record_table.json` … „a 94 invariant" | `118` invariant, `anchor_failures: 0`, `summary.anchor_count: 118` | `patch_record_table.json` | `P` |
| 2 | 1.2 | `patch_mechanisms_1e270.csv` „51 soros táblázat" | `50` adatsor (51 sor a fejlécet is beleszámítva) | `patch_mechanisms_1e270.csv` | `P` |
| 3 | 2.2/5.6 | A `GetProcessHeap` a képben `8` helyről hívódik | `7` helyről: `0x16B3`, `0x1843`, `0x8A529C`, `0x8A8F15`, `0x955AB4`, `0x959DD2`, `0xB70391`; `get_process_heap.call_sites_in_component: []` | `patch_record_table.json` `heap.why_not_the_process_heap[2]`, `heap.get_process_heap`; `patch_mechanisms_1e270.csv` `global.heap_handle` | `P` |
| 4 | 3.3, 12/4 | A `patch_record_table.json` `second_store` megjegyzése félrevezető, és a korrekció az evidence-ra vonatkozik | Az evidence **maga is javítva van**: `lands_on: the anchor, which is patch site + 5, the upper edge of the seven byte window`; `region.single_contiguous_store: false`; `region.write_group_count: 2` két `write_groups` bejegyzéssel (`patch_site .. patch_site + 5`, 2 store; `patch_site + 5 .. patch_site + 7`, 1 store); a `note` szerint „the store lands on the upper edge of the region, not below it". A megmaradt ellentmondás a `06`/`07` dokumentumra vonatkozik | `patch_record_table.json` `address_model.second_store`, `address_model.region`; `patch_mechanisms_1e270.csv` `expr.second_store`, `expr.region` | `P` |
| 5 | 4.4 | `SuspendThread` eredményének hiánya `CONF:L` (`BRef 0x1E109`) | A negatív finding `OBSERVED` / `HIGH`, tehát `CONF:P`; a **verseny-következmény** marad `CONF:L`. A `BRef` `CONF:P` / `STATUS:OBSERVED` lett | `patch_mechanisms_1dff0.csv` `thread_suspend` (`result not examined`), `suspend_result_unchecked` (`OBSERVED,HIGH`); `thread_context_map.json` `api_surface.thread_lifecycle[suspend].result_checked: false` | `P` a hiányra, `L` a következményre |
| 6 | 5.1 | A `spin_lock` „egyszeri flag", és ezt a `patch_record_table.json` írja | A `patch_record_table.json` **maga is a spin-zár értelmezést adja** (`lock.kind: hand_rolled_interlocked_spin_lock`, `attempt_cap: null`, `timeout: null`, mindhárom holder `retry_counter_bounded: false`). A „once flag” megfogalmazás innentől a `thread_context_map.json` `activation.ordering_matrix[5]` („releases the once flag"), `thread_context_map.json` `callers[].preconditions` („the once flag at 0x1830D44E8 is taken") és `patch_mechanisms_1dff0.csv` `caller_lock_discipline` („a hand rolled once flag”) helyén marad | `patch_record_table.json` `table.globals[spin_lock].purpose`, `lock`; `thread_context_map.json` `activation`, `callers`; `patch_mechanisms_1dff0.csv` `caller_lock_discipline`; `patch_mechanisms_1e270.csv` `global.spin_lock` | `P` |
| 7 | 5.1 | A registrar újraellenőrzése a `0x1DD3F`-nél | A `cmp` utasítás RVA-ja `0x1DD3D`; a `0x1DD3F` a RIP-diszlokáció mezőpozíciója ugyanazon utasításban, és a `0x1DD3F` a heap-handle reader-listában szerepel. A §5.1 többi sora utasítás-RVA-t használ, ezért a konzisztencia kedvéért `0x1DD3D` | `patch_record_table.json` `lock.holders[registrar].recheck_site_rva`, `table.globals[heap_handle].references[2]` | `P` |
| 8 | 5.6 | A `patch_record_table.json` `heap_handle.purpose` és `capacity_model.allocator` tévesen processz-heapot ír | Az evidence javítva: `heap.is_process_heap: false`, `heap.kind: private_heap`, `heap_handle.purpose` = „private KERNEL32!HeapCreate(0, 0, 0) handle, zero in the file and published by its only writer, the init that itself has no direct caller", `capacity_model.allocator` = „KERNEL32!HeapAlloc and KERNEL32!HeapReAlloc on the private heap published at 0x1830D44F0". A `HeapFree` IAT `0x2E4D420`, egyetlen hívási hely `0x1E55A` | `patch_record_table.json` `heap`, `table`; `patch_mechanisms_1e270.csv` `global.heap_handle` | `P` |
| 9 | 5.6 | A heap-gate teljesíthetetlensége a dokumentum saját újraszámolása | Az evidence szintén kimondja: `activation.reachable_inside_decoded_cfg: false`, `static_chain_confidence: "H"`, `runtime_reachability_confidence: "L"`, `gated_call_sites: ["0x1E425","0x1E4FD"]`, `gated_call_site_count: 2`, `init_direct_call_site_count: 0`, `handle_writer_count: 1`. A `0x1DCC6` a RIP-diszlokáció mezőpozíciója, az utasítás `0x1DCC4` | `patch_record_table.json` `activation`, `heap.writers_in_file`, `unresolved.orchestrator_caller`; `patch_mechanisms_1e270.csv` `caller.0x1E425`, `caller.0x1E4FD`, `open.orchestrator_caller` | `P` az adatláncon, `L` a futásidejű elérhetetlenségen |
| 10 | 6.3, 12/14 | A `symmetry_image_inventory` sora `matching spans: 0`-t ad, tehát a két fél nem illeszkedik | A mező értéke `0xC8CE70-0xC8CF24,0xC8F470-0xC8F4BA`: a leltár a két **közös tulajdonság** (védelmi hívás + nem igazított másolás) alapján nevezi meg a párt. A `symmetry_target_source` továbbra is `ASYMMETRIC`, a `symmetry_protection_restore_path` szerint a szimmetria csak azonos rekord újrahasznosításakor áll fenn, tehát a részleges szimmetria következtetése változatlanul érvényes | `patch_mechanisms_helpers.csv` `symmetry_image_inventory`, `symmetry_target_source`, `symmetry_protection_restore_path`, `symmetry_save_restore_shape`, `symmetry_size_argument` | `P` |
| 11 | 6.4 | A `0x2AB27B0` és a `0x2AB2864` megosztott segédnek `161` függvény-szintű célzója van (`cfg_functions.csv` alapján) | Kép-szintű statikus hívási hely: `0x2AB27B0` = `1 438`, `0x2AB2864` = `1 433`, `0x2AB3500` = `2 408`; mindhárom `target_expr` mezője „utility behaviour, not a subject-specific activation path" | `patch_mechanisms_helpers.csv` `activation_shared_helper_0x2AB27B0`, `…_0x2AB2864`, `…_0x2AB3500` | `P` |
| 12 | 7.2 | A cookie-ellenőrzés a `0x1E270` patcherben (`0x1E282`, `0x1E344`) és a `0x1E360` managerben (`0x1E570`) van, azaz két helyen | A `0x2AB3500` cookie-ellenőrző **hat** helyről hívódik a vizsgált tartományokban: `0x1DFCB` (registrar), `0x1E250` (redirect), `0x1E344` (patcher), `0x1E570` (manager), `0x1E9B5` (list builder), `0x17545AE` (NOP-fill). A `0x1E282` nem `0x2AB3500` hívási hely; a redirect cookie-betöltése a `thread_context_map.json` szerint `0x1E00A` | `patch_mechanisms_helpers.csv` `activation_shared_helper_0x2AB3500` call-site lista, `fill_helper_global_ref_0x1754526`; `thread_context_map.json` `api_surface.stack_guard` | `P` |
| 13 | 8.2, 12/8 | Az `apc_sites.csv` `target` oszlopa hibásan a `0x1F90720` owning függvény VA-ját nevezi meg a 43 slotban | Az evidence javítva: „43 data slots store the pointer VA 0x180001170 of RVA 0x1170 (RVA 0x2C1E948, RVA 0x2C1E950, RVA 0x2C5E820, RVA 0x2C60038 and 39 more)", és külön hozzáteszi, hogy az owning függvény belépési VA-ja más cím, akit a `fn` oszlop számol. A független `8` bájtos lépésközű szkennelés továbbra is `43` találatot ad | `apc_sites.csv` `target` oszlop mind a hét sorban; `patch_mechanisms_1e270.csv` `open.record_instances` | `P` |
| 14 | 8.2 | Az `RVA 0x1170` tartalma: egyetlen `ret`, utána `15` bájt `0xCC` kitöltés | Pontosítás: `1` utasítás (`c3`), utána `15` bájt `0xCC`, majd egy `0x55`. A kitöltés hossza változatlan, a záró `0x55` korábban nem volt megemlítve | `apc_sites.csv` `target` oszlop mind a hét sorban | `P` |
| 15 | 10.1 | A `8` védelmi hívási hely a `0xC8F4B3` tail-jumpot tartalmazza, és a `0x2BEB8FB` „a kilencedik" | A `writer_protection_call_inventory` `0x1E2D1;0x1E31B;0xC8CEF4;0x1754577;0x17545A0;0x2921505;0x2921526;0x2BEB8FB` — vagyis a `0x2BEB8FB` a **nyolcadik**, és a `0xC8F4B3` a kilencedik, külön sorban számolt protection tail-jump (`writer_import_tail_thunk_inventory`: 1 db). A táblázat `#` oszlopa átrendezve | `patch_mechanisms_helpers.csv` `writer_protection_call_inventory`, `writer_import_tail_thunk_inventory`, `writer_protection_result_checked`, `comparator_entry_0x2BEB88C`, `comparator_protect_0x2BEB8FB` | `P` |
| 16 | 12/1 | A korrekció célpontja a `patch_record_table.json` két szövegmezője | Az evidence ma már a helyes állítást tartalmazza; a korrekció célpontja a `06` és `11` dokumentum processz-heap feltételezése | `patch_record_table.json` `heap`, `table`; `patch_mechanisms_1e270.csv` `global.heap_handle` | `P` |

### 16.0.3 Megerősítve, eltérés nélkül

A hét kiemelt ellenőrzési pont mind megmaradt, a friss evidence pontosan alátámasztja őket:

| Ellenőrzési pont | Megerősítő mezők | `CONF` |
|---|---|---|
| privát `HeapCreate` heap, nem processz-heap | `heap.is_process_heap: false`; `heap.creation` (`0x1DCBE`, IAT `0x2E4D418`, három nulla argumentum, `0x1DCC4` store); `heap.why_not_the_process_heap` négy pontja; `get_process_heap.call_sites_in_component_count: 0`; `HeapFree` egyetlen helyen, `0x1E55A` | `P` |
| korlátlan spin-zár, három használó, újraellenőrzés | `lock.contention_path.attempt_cap: null`, `timeout: null`, `threshold: 0x20`; `retry_counter_bounded: false` mindhárom holderre; `not_a_once_flag` szöveg; `holder_count: 3` | `P` |
| a két diszpatches kapu static úton teljesíthetetlen | `activation.reachable_inside_decoded_cfg: false`; `gated_call_sites` = `0x1E425`, `0x1E4FD`; `handle_writer_count: 1`; `init_direct_call_site_count: 0`; `open.orchestrator_caller` | `P` az adatláncon, `L` a futásidejű elérhetetlenségen |
| a `7` bájtos patch két írásból (`5` patch_site + `2` anchor = patch_site + 5) | `address_model.region.write_group_count: 2`; `single_contiguous_store: false`; `second_store.lands_on`; `expr.region` = `patch_site .. patch_site + 5 + 2 * (rec[0x20] & 1)`; a store-ok `0x1E2EA` (1 bájt), `0x1E2F7` (4 bájt, group-offset 1), `0x1E306` (2 bájt), RVA-sorrendben felsorolva — ez szélesség- és csoport-leírás, nem írási sorrend | `P` |
| `0x1754520` újrabázelés | `activation_fill_helper_target_window`: az érték a `0x3227D40` bázisra újrabázelődik a fix ablakon belül, ablakhatárok `0x140000000` és `0x146000000` (a `0x175453C`-nél összegezve); `fill_helper_global_ref_0x175454d` (`0x3227D40`, fájlban nulla); `fill_helper_constant_fill_loop_0x1754584` | `P` |
| `0x3254270`: `7` olvasó, `0` író | `apc_sites.csv` mind a hét sorában: „image-wide references to the switch address: 7 read / 0 write"; `0` RIP-relatív store, `0` abszolút-immediate store, nincs base relocation, fájlbeli érték `0x0`; szomszédság-scan `±0x100` RVA: `22` hivatkozás, `11` írás, egyik sem a kapcsolóra | `P` a számokra, `U` a kapcsoló írójára |
| `43` adat-slot a `RVA 0x1170` VA-jára | `apc_sites.csv` mind a hét sorában: „43 data slots store the pointer VA 0x180001170 of RVA 0x1170"; `59` kép-szintű RIP-relatív hivatkozás, `1` építi az adott call argumentumát; `IMAGE_RUNTIME_FUNCTION` bejegyzése nincs | `P` |

### 16.0.4 Amit az újraellenőrzés nem zárt le

- A `0x1DD3F` / `0x1DCC6` típusú mezőpozíciók és az azonos utasításhoz tartozó utasítás-RVA-k (`0x1DD3D`, `0x1DCC4`) közötti eltérés **konvenciókülönbség, nem ellentmondás**: ugyanaz az egy utasítás két mérőpontja. A dokumentum a továbbiakban is az utasítás kezdő RVA-ját használja, a `3.1` táblázata megtartja az evidence listaértékeit.
- A `thread_context_map.json` `activation.caller_lock.contended_path` továbbra is azt sugallja, hogy a zár „at most once concurrently" futtat — ez a `patch_record_table.json` `holder_count: 3` és `retry_counter_bounded: false` állításával nem ütközik, csak a zár szemantikájának másik olvasata.
- A `0x3254270` írója, a `0x317E398` cache tartalma, a `0x3227D40` bázis, a `0x33070EC` TLS-index és a `0x1DC80` `init` kilépési értékei továbbra is `U` / `STATUS:OPEN` státuszúak; az újraellenőrzés egyiket sem zárta le és egyiket sem cáfolta.
- A `11.2`–`11.3` fejezet `unresolved_regions.json`-ra épülő számai (`UR-000066`–`UR-000069`, `UR-001588`–`UR-001591`, `142 004` rekord, `105` függvénytest, `0x448` bájt) az itteni újraellenőrzésben **nem** szerepeltek, ezért akkor ellenőrizetlennek és változatlannak minősültek. Ezt a minősítést a későbbi `16.y` blokk **felülírta**: a `16.y.1` 14.–17. és 21. sora ezeket ellenőrzöttnek és egyezőnek találta, a `16.y.2/1` pedig a `11.3` levezetési forráspontját javította. A kanonikus felülírt állítás a `12.2` regiszter `FA-17` és `FA-18` sora.
- A `10.3` fejezet `xref_edges.csv` sorszámaihoz kötött könyvelés az itteni újraellenőrzésben szintén nem szerepelt. A `16.y.1` 23. sora viszont átszámolta (`57 101` sor, `6` kategória, `22` oszlop, a `11` RVA egyik élként sem), tehát ez a sorszám is ellenőrzött; a kanonikus felülírt állítás a `12.2` regiszter `FA-19` sora.

### 16.0.5 Metodológiai határ

Ez az újraellenőrzés kizárólag a fenti mezők olvasása volt: nincs patch-bájt, nincs előállítási recept, nincs bypass- vagy kikapcsolási útmutató, és a dokumentum szimbolikus kifejezései (`rec + 0x00`, `patch_site`, `rec[0x28][i]`) továbbra is leírójelölések. A specimen SHA-256 értéke változatlan: `91cc0aa006d7315cb042c8fa8dca6c1e074a307bba7dcc9eb5509c8a7b81934e`, méret `53 575 264` bájt. A kódolás és a sortörés a dokumentum 14.4. pontjának megfelelő: UTF-8 BOM nélkül, LF.

---

## 16.y Hash- és arány-újraellenőzés (közvetlen kereszt-audit, 2026-09-26 01:45:59)

> **Scope:** kizárólag állomány- és mezőolvasás a `reverse/evidence/` készletén és a `reverse/scripts/` leltárán. A DLL-t nem futtattam, nem töltöttem be, nem mappeltem, nem hookoltam és nem patcheltem; új evidence-fájl nem készült, és a `reverse/scripts/` és `reverse/evidence/` állományához nem nyultam. A dokumentum szimbolikus kifejezései (`rec + 0x00`, `patch_site`, `rec[0x28][i]`) továbbra is leírójelölések; egyetlen konkrét patch-bájt, eljárást vagy bypass-úpot nem ad ez a blokk sem.

### 16.y.1 Ellenőrzösi mátrix

| # | Ellenőrzött tétel | Forrás | Eredmény | Állapot |
|---:|---|---|---|---|
| 1 | Specimen sha256 + méret | lemez | `91cc0aa0…` / 53 575 264 | **egyezik** |
| 2 | `patch_record_table.json` anchor-szám + `anchor_failures` | lemez | `anchor_count` 118, `anchor_failures` 0 – a 1.2 fejezet állítása | **egyezik** |
| 3 | `patch_record_table.json` egyéb `summary` tételei | lemez | `patcher_direct_call_sites` 2, `gated_call_sites` 2, `record_array_static_instances` 0, `heap_kind` `private_heap`, `lock_kind` `hand_rolled_interlocked_spin_lock`, `patch_region_write_groups` 2, `overall_confidence` `L` | **egyezik** |
| 4 | `patch_mechanisms_1e270.csv` adatsorszám | lemez | 50 adatsor (51 sor a fejléccel) – az 1.2 és 16.0.1 fejezet állítása | **egyezik** |
| 5 | `patch_mechanisms_1dff0.csv` adatsorszám | lemez | 51 adatsor – az 1.2 és 16.0.1 fejezet állítása | **egyezik** |
| 6 | `patch_mechanisms_helpers.csv` adatsorszám | lemez | 119 adatsor – a 16.0.1 fejezet állítása | **egyezik** |
| 7 | `apc_sites.csv` adatsorszám | lemez | 7 adatsor – az 1.2 és 16.0.1 fejezet állítása | **egyezik** |
| 8 | `thread_context_map.json` anchor-szám + `anchor_failures` | lemez | `anchor_count` 145, `anchor_failures` 0, `mechanism_rows` 51, `api_imports_in_range` 13, `direct_call_sites` 2, `overall_confidence` `HIGH` | **egyezik** |
| 9 | `audit_handle_flow.json` `target_document` és `contested` hatóköre | lemez | `target_document` = `reverse/adhesive-14…md`; a hét `CF-01`…`CF-07` tétel egyike sem érinti az itt tárgyalt komponenst – az 1.2 és 16.0.1 fejezet állítása | **egyezik** |
| 10 | `cfg_functions.csv` + `pdata_functions.csv` rekorddarabszám | lemez | 142 004 + 142 004 – az 1.2 fejezet állítása | **egyezik** |
| 11 | A `cross_function_targets` alapján vett hívószám (2.1 táblázat) | `cfg_functions.csv` `func_index` × `cross_function_targets` | `0x1D280`→`0x1DCF0` 1, `0x1D550`→`0x1E590` 1, `0x1DC80` 0, `0x1DCF0` 0, `0x1E590`→`0x1DCF0` 1, `0x1DFF0`→`0x1E360` 1, `0x1E270`→`0x1E360` 1, `0x1E360` 0 | **egyezik** |
| 12 | A patcher `0x1E270` CFG-adatai | E3 `func_index` a `0x1E270` kezdőcímen | `reached_ratio` 1.0, `undecoded_bytes` 0, `term=call:7, jmp_direct:1, jmp_indirect:0`, `switch_reject_reasons=none` – a 11.2 fejezet állítása | **egyezik** |
| 13 | A redirect `0x1DFF0` CFG-adatai | E3 `func_index` a `0x1DFF0` kezdőcímen | `term=call:17, jmp_direct:2, jmp_indirect:0` – a 11.2 fejezet állítása | **egyezik** |
| 14 | A 8 `unresolved_regions` sorszám és teljes attribútum-része | E7 `UR-000066`–`UR-000069`, `UR-001588`–`UR-001591` | mind a 8 `region_id`, `family`, `triage`, `reached_ratio`, `undecoded_bytes`, `priority` és `confidence` egyezik a 11.2 táblázatával; a CSV sor sorszáma = `region_id` + 1 | **egyezik** |
| 15 | A `0x1D550` decoder `evidence` mezője | E7 `UR-001588`–`UR-001591` `evidence` oszlop | `jmp_direct:42`, `jmp_indirect:3`, `range_end:1`, `exit_range_end:1`, `switch_reject_reasons=NO_BOUND=2` – a 11.2 fejezet állítása | **egyezik** |
| 16 | A négy `multi_entry` `int_entries` értéke | E7 `UR-000066/67/68/69` `evidence` | 44 (arena), 44 (redirect), 10 (patcher), 61 (list builder) – a 11.2 fejezet állítása | **egyezik** |
| 17 | **Sweep-lefedettség állítása** (11.3) | E3 `instructions` összeg; E3/E4 `undecoded_bytes`; E8 `counters` | a dokumentum `9 331 016` / `0x449` / `83 függvénytest` / `141 921 teljesen dekódolt` értékeitől a lemez **9 331 019** / `0x448` (1 096) / **105** / **141 899** ad | **javítva** (lásd 16.y.2/1) |
| 18 | E8 `method` blokk kulcslistája | lemez | `join_key`, `family_order`, `families`, `kind_rules`, `ok_rules`, `confidence_rules`, `switch_reject_severity`, `priority_order`, `priority_levels`, `priority_sources`, `thresholds`, `row_order`, `determinism`, `limitations` – a `method_sweep_coverage` és `method_decode_shortfall` sor **nem létezik** | **javítva** (lásd 16.y.2/1) |
| 19 | E8 `inputs` által a `P2` patch-régiók levezetése | E8 `inputs.patch_cross_references` vs lemez | az E8 `patch_mechanisms_1e270.csv`-ra `66c8e9bc…`-ot rögzít (rva_count 35), a lemezen `ffc2234d…` (14 895 B, 21 nemüres `site_rva`) | **eltérés, nem javított** (lásd 16.y.3/A) |
| 20 | E8 `inputs` a `cfg_functions.csv` / `pdata_functions.csv` digestjeire | E8 `inputs` vs lemez | `041d2365…` / 40 180 030 és `65ab914c…` / 29 634 365 – egyezik | **egyezik** |
| 21 | E8 `families` / `totals` összegzés | E8 | 146 005 régió, 59 839 466 bájt; a `linear_only_blocks` család 1 524 régió / 24 358 005 bájt | **egyezik** |
| 22 | E8 `baseline.lifecycle_entry_points` | E8 | `AddressOfEntryPoint` `0x2AB2770`, export `0x101F80`, TLS `0x10D0` / `0x2AB28D0` / `0x2AB2948` | **egyezik** |
| 23 | `xref_edges.csv` és a patch-komponens 11 megadott RVA-ja | E5 57 101 sor, mind a 6 kategória átszúmolva | egyik RVA sem szerepel `src` vagy `dst` oldali `direct_call` / `thunk` / `iat` / `vtable` / `global_fnptr` élként – a 11.1 fejezet negatívuma | **egyezik** |
| 24 | E9 `audit_infra.json` állapota (a `13`/`15` dokumentum cross-checkje) | lemez | 632 check / 0 hiba / `verdict=pass`; a `13` Gate D és a `15` E9-sora erre utal | **egyezik** |
| 25 | A `patch_audit_1dff0.json` / `patch_audit_1dff0.csv` / `patch_mechanisms_helpers.json` hiánya | `reverse/evidence/` leltár | mind a három fájl valóban hiányzik – a 16.0.1 fejezet állítása továbbra is helyes | **egyezik** |
| 26 | **A `1.6` `H-1`…`H-7` evidence hash-pin** mind a hét sora | lemez | `patch_record_table.json` `89a52016…` / 79 401; `patch_mechanisms_1e270.csv` `ffc2234d…` / 14 895; `patch_mechanisms_1dff0.csv` `2a71a42b…` / 17 044; `patch_mechanisms_helpers.csv` `49cb7ee8…` / 81 295; `apc_sites.csv` `09bb810c…` / 26 664; `thread_context_map.json` `ee54b448…` / 82 548; `adhesive.dll` `91cc0aa0…` / 53 575 264 | **egyezik** |
| 27 | A `patch_record_table.json` `summary.anchor_count` aktuális értéke | `1.6` számláló táblázat + lemez | `118`, `anchor_failures: 0` – az 1.2, a 16.0.1/16.y.1 2. és a `12.2` `FA-01` soraival egyezik | **egyezik** |
| 28 | A `patch_mechanisms_1e270.csv` `anchor_count` mezőjének létezése | `1.6` számláló táblázat + teljes fájltartalom | a mező **nem létezik**: 16 oszlopos fejléc, `anchor_count` előfordulás `0`, `50` adatsor. A 2. sor „51 sor" javítása továbbra is csak az adatszámra vonatkozik, számozott anchor-aggregátum a CSV-ből nem vezethető le | **egyezik** |
| 29 | A `14` dokumentum `anchor_count` állítása és a `16`-kal való konfliktusa | `adhesive-14…md` §16.3 (a javítás után) vs lemez + `12.2` `FA-21` | a `14` `anchor_count = 118`-at ír, `anchor_failures: 0`-lal, forrásként a `patch_record_table.json#summary`-t megnevezve; a korábbi `94` semmilyen mezőből nem olvasatható, és a `14` szövegéből eltűnt | **javítva** (lásd 16.y.2/2) |
| 30 | A `12.2` felülírt állítások regiszterének teljes lefedettsége | `12.2` `FA-01`…`FA-21` vs `16.0.2` 1–16. és `16.y.2/1`, `16.y.3/A` | mind a `16.0.2` 16 sora, a `16.y.2/1` javítás, a `16.y.3/A` eltérés és a `14`-konfliktus pontosan egy regisztersorba van képezve; nincs felülírt állítás regiszter nélkül | **egyezik** |

### 16.y.2 Eltérések — javított, minimális diff

**1. 11.3 és 14.2 – a sweep-lefedettség számai és forráspontja**

- **Eltérés:** a dokumentum `141 921` teljesen dekódolt függvényt, `9 331 016` dekódolt utasítást, `0x449` (1 097) nem dekódolt bájtot és `83` függvénytestet rögzített, a `method_sweep_coverage` és `method_decode_shortfall` JSON-utakhoz rendelve.
- **Új érték:** `141 921` → **141 899**; `9 331 016` → **9 331 019**; `0x449` → **`0x448`** (1 096); `83` → **105**. A forrás értékek átírása: a számok ma a `counters.redecoded_functions` (105), a `families.undecoded_range` (247 régió / 1 096 bájt) és a `cfg_functions.csv` `instructions` összege (9 331 019) mezőkből olvashatók; a `method` blokkban nincs `method_sweep_coverage` és nincs `method_decode_shortfall` kulcs. A 14.2 fejezet sorszáma és a 16.0.4 fejezet számlistaazonosítása ugyanezekre az értékekre frissült.
- **Forrásfájl:** `reverse/evidence/cfg_functions.csv` (`instructions` összeg, `undecoded_bytes` összeg, `basic_blocks` `= 0` esetények száma), `reverse/evidence/cfg_clusters.csv` (`functions_with_undecoded` összeg = 105), `reverse/evidence/unresolved_regions.json` (`counters`, `method` kulcslista, `families.undecoded_range`).
- **Confidence: `P`** (OBSERVED — a `105 = 142 004 − 141 899` és az `1 096 = 0x448` köt érték belsőleg konzisztens, és megegyezik a `13` dokumentum F-13 és F-19 állításával).

**2. A `14` dokumentum `anchor_count` állítása – a dokumentumcsaládon belüli konfliktus**

- **Eltérés:** a `14` dokumentum §16.3 záró bekezdése a `patch_record_table.json` rekordtábláját `anchor_count = 94` értékkel nevezte meg, mező- vagy fájlhivatkozás nélkül, tehát nem volt reprodukálható. A `16` §1.2 már `118`-at állított, és a `16.0.2` 1. sora ezt a konfliktust csak a `16` saját §1.2 sorára vonatkoztatta. A két dokumentum így egymással ellentétes számot hordozott ugyanarról az evidence-mezőről.
- **Új érték:** `patch_record_table.json` `summary.anchor_count` = **118**, `summary.anchor_failures` = **0**; az `invariants` tömb `118` eleme. A `14` §16.3 bekezdéséből a `94` kikerült, helyette `118`, `anchor_failures: 0` áll, a forrásként megnevezett `patch_record_table.json#summary` blokkal.
- **A `patch_mechanisms_1e270.csv` nem alternatív forrás:** a fájl **nem tartalmaz `anchor_count` mezőt** – 16 oszlopos fejléc (`id, component, kind, site_rva, site_va, record_offset, field, access, width_expr, value_expr, target_expr, readers, writers, confidence, status, note`), `anchor_count` előfordulás `0`, `50` adatsor. A lapos, soronkénti séma nem hordoz anchor-aggregátumot, ezért a `94` nem innen sem származhatott, és a `118` sem vezethető le belőle. Az egyetlen olvasható anchor darabszám a `patch_record_table.json` és a `thread_context_map.json` `summary` blokkjából áll (`118`, illetve `145`); ezt az `1.6` számláló táblázata rögzíti. A kanonikus felülírt állítás a `12.2` regiszter `FA-21` sora.
- **Forrásfájl:** `reverse/evidence/patch_record_table.json` `summary.anchor_count` / `summary.anchor_failures`; `reverse/evidence/patch_mechanisms_1e270.csv` fejléc és teljes tartalom; `reverse/adhesive-14-c856c0-handle-producer-dataflow.md` §16.3 (javított állapot).
- **Confidence: `P`** (OBSERVED); a `14` szövegének konfliktusos mondata supercedált, nem értelmezendő eltérésként.

### 16.y.3 Eltérések — megfigyelve, a dokumentum számát nem módosítva

**A. E8 `inputs.patch_cross_references` elavult input-digest**

- **Eltérés:** a `unresolved_regions.json` `inputs.patch_cross_references["patch_mechanisms_1e270.csv"].sha256` értéke `66c8e9bcaf5ab7f0ab9cafc6d08f839e34cceb8d324f56aff1199f7763241cb6`, a lemezen lévő fájl digestje `ffc2234d4b620c49420e6751bb1d4db9c3d1e2fd07a7833a9f1452f4fd678090` (14 895 bájt). A CSV mtime-je `2026-09-26 01:27:09`, az E8é `2026-09-25 21:58:36` – a CSV az E8 **után** újragenerálódott. A `patch_mechanisms_helpers.csv` digestje (`49cb7ee8…`) egyezik.
- **Következmény erre a dokumentumra:** nincs. A `16` az `1e270` CSV-t a 3. és 8. fejezetben a `rec + 0x00` / `patch_site` szerkezeti leírásra használja, nem a `P2` prioritás régiók számára; az `E8` `rva_count = 35` értékét a jelenlegi CSV 21 nemüres `site_rva` értékével nem lehet reprodukálni, de ez az `E8` belső stale állapota, nem a `16` állítása. A `14.2` fejezet a `P2` régiók számát nem használja.
- **Forrásfájl:** `reverse/evidence/unresolved_regions.json` `inputs.patch_cross_references` vs a `reverse/evidence/patch_mechanisms_1e270.csv` lemezi állapot.
- **Confidence: `P`** (OBSERVED az eltérésre), **`L`** (INFERRED a `P2` levezetés hatására); `affects_decoded_counts = false`.

### 16.y.4 Amit a kereszt-audit nem módosított

- **A patch-mechanizmusra vonatkozó minden BRef-állítás változatlan.** A 2.1 térszerkezeti táblázat, az 5. fejezet három mechanizmusmodellje, a 8. fejezet `QueueUserAPC`-ágai, a 10. fejezet NOP-fill és a 12. fejezet korrekciósorai a `patch_record_table.json`, a `patch_mechanisms_*.csv`, az `apc_sites.csv` és a `thread_context_map.json` jelenlegi állapotáből bitre reprodukálható.
- **A három `H` / `HIGH` open pont továbbra is `U` / `STATUS:OPEN`:** a `0x3254270` írója, a `0x317E398` cache tartalma, a `0x3227D40` bázis, a `0x33070EC` TLS-index és a `0x1DC80` `init` kilépési értékei.
- **A zárók és a `UNRESOLVED` státuszok változatlanok:** a `record_instances_status` és `activation_status` továbbra is `OPEN`, és a 8 patch-mechanizmus `record_fields_written` értéke továbbra is `0`.
- **BOM és sortörés:** a fájl UTF-8 BOM nélküli, `cr = 0`, `crlf = 0`, záró sortöréssel – a 14.4 fejezet állítása ezt továbbra is jóvá teszi.
- **A `13` és a `15` dokumentum E9-sora a `16`-hoz kötődően ugyanazt a 632/0 állapotot rögzíti.**
- **A hash-pin és a számláló mezők az `1.6` blokkban rögzítettek, és a fenti 26.–28. sorok igazolják őket.** A `H-1`…`H-7` érték a pin időpontjában érvényes; ha bármelyik artifact regenerálódik, a pin elavul, és ez az `16.y.3/A`-hoz hasonló külön eltérésként kezelendő, nem a dokumentum élő állításaként.
- **A `14`-felé kimutatott konfliktus a `16` mechanizmusállításaira nem hatott:** a `12.2` `FA-21` sora kizárólag a `14` §16.3 szövegállítását írja felül, a `2.1`–`14.5` tartalmát nem.

---

## 16.z Konzisztencia-javítás a `3.4` pont írási csoport-leírásában

Ez a blokk a `3.4` pontot hozza összhangba a dokumentum `1.1`, `9` és `14.1` pontjának „nem ad írási receptet" deklarációjával. A DLL-t nem futtattam, nem töltöttem be, nem hookoltam és nem patcheltem; új statikus mérés, disasszemblálás vagy feloldás nem készült. Minden megadott szám, RVA, BRef és `STATUS` változatlanul a `1.6` pinnen és a `16.y.1` mátrixban rögzített lemezállapotból származik.

**Mi változott a `3.4` pontban**

| Elem | Régi alak | Új alak | Indoklás |
|---|---|---|---|
| címsor és bevezető | „A két írás"; a `0x1E2E2`–`0x1E30B` szakasz `feladata` | „A két írási csoport"; a szakasz a `patch_record_table.json` `address_model.region` két `write_groups` bejegyzéséhez igazodik | a szakasz két írási csoportot ír le, három tárolással, nem egy lépésekből álló folyamatot |
| a szakasz első táblázata | kilenc sor `Lépés` / `RVA` / `Ugyanaz a bizonyíték` fejléccel, ahol a sorok sorrendje a tárolások sorrendjét adja | két sor `Írási csoport` / `Bizonyíték-hely` / `Az ablakban érintett bájtok` / `Tárolások száma` / `Tárolások szélessége` / `A cél származási helye` / `A csoport statikus jellemzője` fejléccel, és explicit mondat arról, hogy a sorok sorrendje nem kivitelezési sorrend | a cél az egyes csoportok statikus jellemzője; a patch-számítás és a szélességek változatlanul szerepelnek |
| a sorrendről szóló bullet | a három tárolás és a `bit 0` újratesztelésének sorrendét rögzítette | negatív állítás: a dokumentum végrehajtási sorrendet nem ad | a `3.4` állítása szembement az `1.1` és a `14.1` pont tilalmával |
| `16.0.3` sorszámai táblázat, a `7` bájtos patch sora | a három store RVA-ja felsorolva | ugyanaz a felsorolás, `(RVA-sorrendben felsorolva — ez szélesség- és csoport-leírás, nem írási sorrend)` jelöléssel | a tanúsító sor ne lasson kivitelezési sorrendet |

**Mi került ki a `3.4` első táblázatából**

- a `destination` olvasás, majd a relatív különbség és a `−5` korrekció **egymás utáni mikrolépésként**, `0x1E2F2` és `0x1E2F4` RVA-val: ez eltolási konstans receptje lett volna;
- a `+0x20` eltolás és a `bit 0` újratesztelése mint *lépés*. Az `0x1E2E2`–`0x1E2E6` címszámítás, a `0x1E2ED` `4` bájtos olvasás és a `0x1E2FA` flagolvasás továbbra is szerepel, a nem író megfigyelések között, `CONF:P`.

**Mi maradt változatlanul**

- a patch-számítás szimbolikus alakja: `rec + 0x00 − 5 · (rec[0x20] & 1)` a `3.3`-ban, `rec + 0x08 − patch_site − 5` a `3.4`-ben, `expr.region` = `patch_site .. patch_site + 5 + 2 · (rec[0x20] & 1)`;
- minden írási szélesség és célhely: `1` bájt a `patch_site`-en, `4` bájt a `patch_site + 1`-en (csoport-eltolás `1`), `2` bájt a `rec + 0x00`-on;
- a két csoport `5 + 2` bájtos, szomszédos lefedése, a `+0x00` pozíció az ablak felső szélén, `single_contiguous_store: false`, `write_group_count: 2`, a `lands_on` idézet, a `0x40` védelem és az `5`/`7` méret;
- a `0x06` flag bit-táblázata, a három kiemelt tulajdonság, a `0x0A` hibakód, a `comparator_slot_write_0x1E2F7` kontextus-korrekció és az összes BRef;
- a `2`–`16.y` fejezetek minden findingje, száma, táblázata és státusza, ideértve a `12.2` `FA-01`–`FA-21` regisztert és a `16.0.2` 1–16. sorát.

**Írási bájtérték:** a blokk és a `3.4` sem ad konkrét írási bájtértéket, NOP-kitöltő bájtot vagy DLL-betöltési, hookolási és injektálási utasítást; a tárolt értékek továbbra is a `…` jelöléssel maszkoltak, ahogyan a `3.4` táblázata előtt is.

**Formátum:** UTF-8 BOM nélkül, LF sortöréssel, záró sortöréssel; a `14.4` pont kódolási sora változatlan.
