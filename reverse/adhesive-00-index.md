# `adhesive.dll` – statikus reverse-engineering index

> **Vizsgálati elv:** kizárólag a `reverse/adhesive.dll` fájl statikus elemzése. Nem történt DLL-betöltés, futtatás, dinamikus traceelés, hálózati megfigyelés, patchelés, bypass vagy exploit-próba. A dokumentum az alábbi statikus bizonyítékok navigációs és módszertani belépési pontja.

## 1. Specimen azonosítás

| Tulajdonság | Statikus érték | Jelölés |
|---|---|---|
| Specimen | `C:\Users\Admin\Desktop\Dumper - AllInOne\reverse\adhesive.dll` | P |
| Méret | `53 575 264` bájt (`51,09335 MiB`, fájlhex: `0x3317E60`) | P |
| SHA-256 | `91CC0AA006D7315CB042C8FA8DCA6C1E074A307BBA7DCC9EB5509C8A7B81934E` | P |
| PE-típus | `PE32+` (`Magic=0x020B`), `pei-x86-64` / AMD64, `DLL`, Windows GUI subsystem; `Characteristics=0x2022` | P |
| PE biztonsági zászlók | `DllCharacteristics=0x0160`: `HIGH_ENTROPY_VA`, `DYNAMIC_BASE`, `NX_COMPAT` | P |
| Verzió | `FileVersion=1.0.0.36109`; `ProductVersion=1.0.0.36109`; `ProductName=CitizenFX`; `FileDescription=adhesive for FiveM` | P |
| Azonosító mezők | `OriginalFilename=adhesive.dll`; `InternalName=adhesive`; `CompanyName=Cfx.re`; jogi megjegyzés: `(C) 2015- CitizenFX Collective` | P |
| Export/erőforrás azonosító | egyetlen export: `CreateComponent` (`RVA 0x101F80`); erőforrás-nev: `FXCOMPONENT` | P |
| COFF-időbélyeg | `2026-09-11 15:06:18 UTC` a PE-fejlében; ez forrásmetaadat, nem önállóan bizonyított build-idő | P |
| Build-út | PDB-út: `C:\gl\builds\cfx-fivem-0\.build-cache\bin\five\release\dbg\adhesive.pdb` | P |
| Aláíró | Authenticode állapot: `Valid`; signer: `CN="Rockstar Games, Inc.", O="Rockstar Games, Inc.", L=New York, S=New York, C=US` | P |
| Aláíró kibocsátó | `CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1, O="DigiCert, Inc.", C=US` | P |
| Aláíró tanúsítvány | SHA-1 thumbprint: `FF0EE06434B1695115A35FB077DE538FD1F66D9C`; UTC érvény: `2026-07-21 00:00:00`–`2027-09-05 23:59:59` | P |
| Időbélyeg-tanúsítvány | `CN=DigiCert SHA256 RSA4096 Timestamp Responder 2026 1`; issuer: `DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1`; thumbprint: `51D9ABDA034973D84F4266ACA48248E6B369C439` | P |

A fenti azonosítóadatok a megadott specimenre, nem egy általános „FiveM DLL” mintára vonatkoznak. A pontos build-, csatorna- és eredetviszonyítás a dokumentumok `01`, `02` és `12` célpontja.

## 2. Rövid végkövetkeztetés

A specimen a `CitizenFX`/FiveM környezethez tartozó, 64 bites `adhesive` komponens-DLL-nek látszik: ezt az erőforrás- és metadatmezők, a `CreateComponent` export, a FiveM build-út és a kapcsolódó modulimportok statikusan erősítik `[P/L]`. A kriptográfiai, hálózati, VFS/resource-, folyamat- és integritási felületek statikusan jelen vannak `[P]`. A process-query, process-memory, patch- és feltételes debugger-útvonalak közvetlen, `.pdata`-határon belüli utasításszintű bizonyítékot kaptak `[P]`, de a pontos Nt-szolgáltatások, caller-ek, célok, adatfolyamok és felhasználói szándék még nyitott `[U]`.

Az Authenticode-ellenőrzés az ellenőrzés dátumán érvényes `[P]`. A statikus jelek önmagukban nem bizonyítják a rosszindulatú működést, a perzisztenciát, az anti-debug megkerülését vagy bármilyen exploit-alkalmazhatóságot; az ilyen állítások nem része ennek a vizsgálatnak.

## 3. A teljes vizsgálat scope-ja

### Bele tartozik

- A specimen pontos azonosítása: méret, SHA-256, filesystem-metaadatok, verzió és aláírási lánc.
- PE/COFF-fejlécek, Optional Header, Characteristics, entry point, image base, szekciók, adatkönyvtárak, TLS, erőforrások, debug/PDB-metaadatok és Authenticode security directory.
- Importtáblázat, IAT, delay-importok, exportok, moduláris függőségek és a statikus hívási/xref-lehetségek.
- ASCII- és UTF-16-stringek, JSON/INI- és konfigurációs nyomok, buildútvonalak, cache- és összeomlás-artifactumok.
- Process-, thread-, memória-, betöltő-, hook- és hibakeresési felületek statikus azonosítása.
- **A teljes `.pdata` function-map, CFG-lefedettség és unresolved-régió réteg:** `IMAGE_RUNTIME_FUNCTION`-rekordok, `UNWIND_INFO`/`CHAININFO` dekódolás, rekordonkénti CFG-mérőszámok, RVA-klaszterek, xref/indirect index és a lefedetlen vagy feloldatlan régiók osztályozása; ez a `13` dokumentum teljes subjectumja (`13:93`, `13:97`).
- **A validált `syscall`-inventory és a szolgáltatás-mapping fázis:** a nyers `0F 05` találatok utasításstart-szűrése és felbontása, a hat argumentumpozíció osztályosítása, valamint a service-szám producer-láncának kiértékelése; ez a `15` dokumentum subjectumja (`15:105`, `15:136`).
- **A patch-mechanizmusok szerkezete, célai és aktiválási határai:** a rekordtábla, a szál-szintű vezérlésáthelyezés, az idegen modul stubja és a feltételes NOP-kitöltés, a védelmi és cache-rétegekkel együtt; ez a `16` dokumentum subjectumja (`16:17`, `16:1148`).
- Kriptográfiai és bizalmi felületek: tanúsítványkezelés, `WinVerifyTrust`, DPAPI, OpenSSL/Botan, hash/HMAC/auth- és TLS/curl jelek, valamint a plaintext JWT/credential negatív keresések.
- Hálózati és IPC-felületek: socket, `libuv`, HTTP/WS, konfigurált vagy literálként látható végpontok, cache- és eseményhivatkozások.
- Filesystem-, VFS-, registry-, telemetry- és perzisztencia-jelek, kizárólag statikus bizonyítékként.
- Entropia-, szekció-, import-sűrűség-, overlay- és negatív Findings-elemzés a packing/obfuscation kérdéséhez.
- Kockázati besorolási módszer, confidence-jelölés, BRef-ek, korlátok és nyitott kérdések.

### Kívül marad

- A DLL betöltése, futtatása, shellelése vagy a gazdaprocesshez való kapcsolódás.
- Dinamikus API-, hálózati-, fájl- és registry-megfigyelés.
- Process injection, hookolás, debugger-alapú tesztelés, anti-debug próba.
- Exploit-, bypass- vagy patch-recept, illetve bármilyen kézi ellenőrző kód.
- A statikus jelekből nem következő jogi, szerzői vagy fenyegetési minősítés.

Minden tényleges findingnak a saját dokumentumban kell viselnie a `[P]`, `[L]` vagy `[U]` jelölést és a megfelelő BRef-eket. Az itt felsorolt API-k és stringek keresési ankorok, nem végrehajtási utasítások.

## 4. Teljes navigáció – 17 dokumentum

A teljes halmaz 17 elemből áll: a jelen `00`-as indexből és a 16 elemzési dokumentumból. A `13`–`16` dokumentum a function-map/CFG, a `0xC856C0` handle-flow, a syscall-inventory és a patch-mechanizmus réteget fedi le, és mindegyik ugyanahhoz a specimenhez tartozik (`15:937` ezt a navigációt a `00` 4. fejezetéről mint 17 elemes listát rögzíti; az itteni lista az érvényes).

1. [adhesive-00-index.md](adhesive-00-index.md) – jelen index, specimen-katalógus és navigáció
2. [adhesive-01-identity-build-signature.md](adhesive-01-identity-build-signature.md) – identitás, build- és aláírási vizsgálat
3. [adhesive-02-pe-layout-security.md](adhesive-02-pe-layout-security.md) – PE-elrendezés, szekciók és biztonsági jellemzők
4. [adhesive-03-imports-exports.md](adhesive-03-imports-exports.md) – importok, exportok és moduláris függőségek
5. [adhesive-04-component-vtables.md](adhesive-04-component-vtables.md) – komponenshatárok, vtable- és RTTI-nyomok
6. [adhesive-05-strings-config-artifacts.md](adhesive-05-strings-config-artifacts.md) – stringek, konfigurációk és helyi artifactumok
7. [adhesive-06-process-memory-hooks.md](adhesive-06-process-memory-hooks.md) – process-, memory-, thread- és loader-felületek
8. [adhesive-07-anti-debug-integrity.md](adhesive-07-anti-debug-integrity.md) – debugger-, integritási és kivételkezelési jelek
9. [adhesive-08-crypto-trust.md](adhesive-08-crypto-trust.md) – kriptográfia, tanúsítványok és trust-határok
10. [adhesive-09-network-ipc.md](adhesive-09-network-ipc.md) – hálózat, WebSocket/HTTP és IPC
11. [adhesive-10-filesystem-persistence-telemetry.md](adhesive-10-filesystem-persistence-telemetry.md) – filesystem, perzisztencia és telemetry
12. [adhesive-11-packing-negative-findings.md](adhesive-11-packing-negative-findings.md) – packing/obfuscation és negatív Findings
13. [adhesive-12-risk-methodology-open-questions.md](adhesive-12-risk-methodology-open-questions.md) – kockázati módszer, korlátok és nyitott kérdések
14. [adhesive-13-pdata-function-map-cfg.md](adhesive-13-pdata-function-map-cfg.md) – `.pdata` function-map, CFG-lefedettség, unresolved-régiók, xref/indirect index
15. [adhesive-14-c856c0-handle-producer-dataflow.md](adhesive-14-c856c0-handle-producer-dataflow.md) – `0xC856C0` handle-adatfolyam, kétlépéses diszperziós dispatch és hívóklózóra
16. [adhesive-15-syscall-inventory-service-mapping.md](adhesive-15-syscall-inventory-service-mapping.md) – syscall-inventory és szolgáltatás-mapping a 3 627 valid `0F 05` helyen
17. [adhesive-16-patch-mechanisms-targets-activation.md](adhesive-16-patch-mechanisms-targets-activation.md) – patch-mechanizmusok: rekord, redirect, stub, caller és aktiválás

### 4.1 `reverse/evidence/` és `reverse/scripts/` leltár

A két könyvtár hordozza a teljes statikus mérést: a `reverse/evidence/` 28, a `reverse/scripts/` 19 `*.py` producer fájlt tartalmaz. Az alábbi táblázatok a navigációhoz szükséges **fő** artifactokat adják, nem a teljes állományt; a méret- és hash-pinning teljes körűen a `13:23`–`13:34` (E1–E12), a `15:32`–`15:41` (E1–E10) és a `16:75`–`16:81` táblázatokban van. A méret oszlop a **2026-09-26-i lemezállapotot** adja; a sorhivatkozások `dokumentum:sor` alakúak (például `13:23` = `adhesive-13-pdata-function-map-cfg.md` 23. sora).

**12 alap-artifact – a közös mérőrétegek**

| # | Fájl (`reverse/evidence/`) | Méret (bájt) | Szerep | Hivatkozás |
|---:|---|---:|---|---|
| 1 | `pdata_functions.csv` | 29 634 365 | `IMAGE_RUNTIME_FUNCTION`-rekordok a dekódolt `UNWIND_INFO`-val; 43 oszlop, 142 004 sor | `13:23` |
| 2 | `pdata_stats.json` | 18 329 | `.pdata`-statisztika és 37 pontos önellenőrzés (Gate A) | `13:24`, `13:719` |
| 3 | `cfg_functions.csv` | 40 180 030 | rekordonkénti CFG, entry-, terminátor- és IAT-mérőszámok; 80 oszlop, 142 004 sor | `13:25` |
| 4 | `cfg_clusters.csv` | 127 104 | a 233 RVA-klaszter aggregátumai; 65 oszlop | `13:26` |
| 5 | `xref_edges.csv` | 11 126 183 | él- és kategória-típusú hívási/xref-index; 22 oszlop, 57 101 sor | `13:27` |
| 6 | `indirect_sites.csv` | 27 390 456 | közvetett hívási és ugrási helyek; 28 oszlop, 157 153 sor | `13:28` |
| 7 | `unresolved_regions.csv` | 57 583 948 | teljes régiótábla (lefedetlen + feloldatlan); 37 oszlop, 146 005 sor | `13:29` |
| 8 | `unresolved_regions.json` | 12 253 941 | módszertan, családosztályok, 9 900 beágyazott régió; 116 ellenőrzés (Gate B) | `13:30`, `13:723` |
| 9 | `baseline.json` | 36 512 | a dokumentált `.pdata`-állítások referenciája, amit a Gate A 13 mezőre egyeztet | `13:33`, `13:719` |
| 10 | `syscall_candidates_raw.csv` | 920 267 | a `P0/S6` nyers `0F 05` találatok boundary- és sweep-verdikttel; 3 881 sor, 33 oszlop | `15:32` |
| 11 | `syscall_arg_inventory.csv` | 4 468 093 | a hat argumentumpozíció osztályai; 3 627 sor, 100 oszlop | `15:33` |
| 12 | `syscall_arg_classes.json` | 56 745 | osztálykiírás, cenzus, ablakgeometria; 20 ellenőrzés, mind átment | `15:34` |

**4 audit / attestációs artifact**

| # | Fájl (`reverse/evidence/`) | Méret (bájt) | Szerep | Hivatkozás |
|---:|---|---:|---|---|
| 13 | `audit_infra.json` | 170 001 | független statikus infra-audit: 632 ellenőrzés, 0 hiba, verdict `pass`, a négy finding mind `closed` (Gate D); a `632 / 0 / pass` érték a payload `summary` blokkjából közvetlenül ellenőrizhető, és az itt közölt check-szám a jelenlegi audit-futtatásé | `13:31`, `13:732` |
| 14 | `audit_syscall_candidates.json` | 1 765 141 | a `syscall`-korpusz független boundary- és control-flow-audita; 31 ellenőrzés (Gate C) | `13:32`, `13:728` |
| 15 | `audit_handle_flow.json` | 106 955 | a 12 validált wrapper, a 21 `wrapper_forwarding` site és a `0xC856C0` számlálások újraszámítása; 163 ellenőrzés, 0 hiba, `target_document` = a `14` dokumentum | `15:41`, `14:1004` |
| 16 | `toolchain.json` | 27 150 | producer-leltár és digest-attestáció: 19 scriptbejegyzés, `missing_from_inventory` és `drifted_entries` egyaránt üres (`D-002`) | `13:34`, `13:639` |

**4 új kanonikus artifact – a `13`–`16` fázis kimenete**

| # | Fájl (`reverse/evidence/`) | Méret (bájt) | Szerep | Hivatkozás |
|---:|---|---:|---|---|
| 17 | `c856c0_forward.json` | 694 730 | a `0xC856C0` előrehaladó passza: 37 elérhető cél, 12 wrapper, stage- és consume-halmaz; testvére a `c856c0_dataflow.json` és a `c856c0_callers.csv` | `14:1002`–`14:1003` |
| 18 | `syscall_inventory.csv` | 5 993 935 | a kanonikus inventory: 3 627 sor, 106 oszlop (100 megőrzött + 6 új + 1 felülírt) | `15:35`, `15:124` |
| 19 | `syscall_service_map.json` | 19 589 | service-osztályok, naming-gate és korlátok; 28 ellenőrzés, mind átment | `15:36` |
| 20 | `patch_record_table.json` | 79 401 | a patch-rekordtábla: a `0x38` bájtos rekord, a hat globális, a flagbitek, a patcher-modell és a 118 anchor; `anchor_failures: 0` | `16:17`, `16:87` |

**A fenti 20 tagon kívüli evidence-fájlok (8):** a `14` fázis `c856c0_dataflow.json` és `c856c0_callers.csv` testvérei; a `16` fázis lapos táblázatai és kontextustérképei (`patch_mechanisms_1e270.csv`, `patch_mechanisms_1dff0.csv`, `patch_mechanisms_helpers.csv`, `apc_sites.csv`, `thread_context_map.json`); továbbá a `pdb_correlation.json` (83 426 bájt), amelyet a `pdb_correlate.py` ír és amelynek öt mezőjét (`pdb_debug_id`, `pdb_match_key`, `authenticode_image_sha256`, `section_content_key`, `correlation_vector_sha256`) a `12:383` már hivatkozza. A `16:1232`–`16:1236` rögzíti, hogy a `patch_audit_1dff0.csv`, a `patch_audit_1dff0.json` és a `patch_mechanisms_helpers.json` nem létezik, és helyettük az azonos szerepű `patch_mechanisms_1dff0.csv` és `patch_mechanisms_helpers.csv` szolgál.

**Producer-scriptek (19, a `toolchain.json` `scripts[]` tömbje egyezik a lemezen mért 19 `*.py`-val)**

| Réteg | Scriptek (`reverse/scripts/`) | Szerep |
|---|---|---|
| function-map | `pdata_map.py`, `cfg_build.py`, `xref_build.py`, `unresolved_regions.py` | a `pdata`, CFG/klaszter, xref/indirect és régió rétegek írója (E1–E8) |
| syscall | `syscall_scan.py`, `syscall_args.py`, `syscall_service_map.py` | nyers találat, argumentumosztályok, service-map (E1–E5 a `15`-ben) |
| patch | `patch_record_1e270.py`, `patch_audit_1dff0.py`, `patch_audit_helpers.py`, `apc_audit.py` | a `16` patch-rekord-, mechanizmus- és APC-artifactjai |
| handle-flow | `c856c0_callers.py`, `defuse_slice.py` | a `14` caller- és forward-halmaz, illetve a diszperziós szelet |
| audit | `audit_infra.py`, `audit_syscall_candidates.py`, `audit_handle_flow.py` | Gate C, Gate D és a `14` számlálás-auditja |
| toolchain | `common.py`, `refresh_toolchain.py`, `pdb_correlate.py` | közös konstansok, a 19 tagú producer-leltár, PDB-korreláció |

> **Snapshot-megjegyzés `[P]`:** a méreteket és a `toolchain.json` 19 bejegyzését 2026-09-26-án lemezről ellenőriztem, és a pin-készletet az aznapi lemezállapothoz igazítottam. A frissítés négy artifactot érintett: az `audit_infra.json` (`169 558` → `170 001` bájt, `97134043…` → `251b79e7…`), a `toolchain.json` (`26 638` → `27 150` bájt, `6f3dd634…` → `72a1eed0…`), az `audit_handle_flow.json` (`105 880` → `106 955` bájt, `9279ee8e…` → `c1636fcd…`) és a `syscall_arg_classes.json` (`56 745` bájt változatlan, `058e2c58…` → `9133ad84…`) méret- és digest-pinje; a többi 16 artifact pinje bitre változatlan. A `13`/`15` által korábban rögzített pin után a méret változatlanul, de a tartalom változva driftelt egy artifact az `unresolved_regions.json` (`12 253 941` bájt, lemezen `0092fef1…`, amit a `13:30` így pinel; a `b9b6498a…` elődöt a `13:17` és a `13:724` dokumentálja). Az `audit_handle_flow.json` esetében a lemezmérés egyetlen eredménye `106 955` bájt és `c1636fcd…` digest, és ezt az egy értéket idézik a `15:41` (E10 evidence-sor), a `15:959` (a `19.1` kereszt-audit 10. sora) és a `14:1004` (a `21.1` kereszt-audit 6. sora) – egyetlen mérés, amelyet a dokumentumok ugyanazként idéznek, nem három független mérés; mindegyik `163` ellenőrzést és `0` hibát ír mellé. Nincs olyan dokumentumsorszám, amely az `audit_handle_flow.json`-ra `105 928` bájtos, `f96a9f44…` digestű pinnét rögzítene. Külön kell választani az evidence-fájlok pinjét a dokumentumok saját digestjétől: a `16:71` szerint a pin egyirányú, az evidence-fájlokat pineli, nem a dokumentumot, és a `14` dokumentum szerkesztéskor önmagában változik, így saját digestje minden íráskor elavul, ezért az ilyen pin soha nem a dokumentum hashére, hanem mindig az adott artifact lemezállapotára vonatkozik. Az `audit_handle_flow.json` tartalmi állításai változatlanul érvényesek: `id = AFH-2026-09-26`, `163` ellenőrzés, `0` hiba.

### 4.2 Felülírt korábbi állítások: hol van az új változat

A `06`, `07` és `11` dokumentum érintett részei nem érvénytelenítik azokat a dokumentumokat; a szám- és szerkezetállításaik felülírását a `13`–`16` dokumentumok friss statikus újraszámítása rögzíti. Ahol eltérés van, az alábbi sorok az érvényesek, a korábbi szöveghelyek történeti állításként maradnak olvashatók.

| Korábbi hely | Felülírt tartalom | Hol van most | Hivatkozás |
|---|---|---|---|
| `06` §5.2, §5.3, §6, §7.2, §8.2, §10.1, §10.2, §13, §14/3–4.; `11` §7.2 | processz-heap feltételezés, a patcher hívója és elérhetősége, a Toolhelp-pár „szimmetriája", az `apc_sites` célcím, a szállista-allokáció hibaága, az APC-kapcsoló írója, a patch-cél „dinamikus" jellege | a `16` 12. fejezetének 20 számozott korrekciója (`#` 1–20); a `PCH-01`–`PCH-03` tételek nem a `16`-ban, hanem a `12` §12.4 bekezdésében vannak | `16:1030`, `12:503`–`12:505` |
| `06` §9.1–§9.5 és §13 „Távoli írás" sora; `07` §7.1 `0xC856C0` sora; `12` §6.1–§6.3 | a `0xC856C0` darabszámai: **2 tábla és 16 slot**, 16 közvetlen `syscall` + 16 wrapper-hívás, **12** wrapper, **28** syscall-hely, 2 handle-olvasás, 32 fogyasztó | a `14` teljes terjedelmében, a „Javított számlálások" blokkal; a `06`/`07`/`12` ankorhelyeinek gépi visszapontjai a `13` `doc_anchors` táblájában | `14:13`–`14:26`, `14:1010`, `13:301` |
| `06` §5.2/§10.1 „observed" patch-képesség; `12` §5 és §9/7. | a négy közvetlen hívás intra-komponens, a `0x1D280`–`0x1E9D0` rendszernek nincs belépési pontja, a heap-gate a komponensen belül teljesíthetetlen | `16` §2.1 és §5.6; `12` §12.4 `PCH-03`, státusz `bounded_open` | `16:106`, `16:608`, `12:505` |
| `06`/`07` széles „nincs validált syscall" negatívuma; `11` `PAGE_READWRITE` sora; `07` `GetModuleHandleA` resolver-típus konfliktusa | a `0xD7B0AE`/`0xD7B4B9`/`0xD7C0AC` valódi `0F 05`; a `0x0C874E9` `PAGE_EXECUTE_READWRITE`; mindkét CoreRT callsite `GetModuleHandleW`; a nyers találatok `3 627 + 209 + 45 = 3 881` felbontása, plusz 30 a CSV scope-on kívül | `12` §11 konfliktusnapló; a `15` §4 teljes felbontása és a `P0/S6` audit Gate C-je | `12:437`–`12:439`, `15:143`, `13:727` |
| minden `blocks_reached` / `reached_ratio` olvasat a `06`, `07`, `11` és a korábbi `12` dokumentumokban; a `54` wrapper-hívó | a két elérhetőségi bizonyítéknyom egy mérőszámba keveredik; a 12 wrapper distinct hívója 37, a 54 csak a forward sinkre érvényes | `13` §7 és §12 `D-009`; `14` `CF-01`; `12` §12.7 `SWEEP-02` | `13:327`, `13:684`–`13:708`, `14:32`, `12:524` |

## 5. Témák szerinti keresési térkép

A térkép az első statikus keresési pontokat adja meg; a `P/L/U` itt a várható bizonyíték kezdeti erősségét jelöli, nem a már lezárt findingot.

| Téma | Elsődleges dokumentum | Statikus keresési kulcsok és ankorok | Kezdő jelölés |
|---|---|---|---|
| Identitás, build, aláírás | 01 | `FileVersion`, `ProductVersion`, `CreateComponent`, `FXCOMPONENT`, PDB-út, COFF `Time/Date`, `Security Directory`, Authenticode-tanúsítványok | P |
| PE-layout és biztonság | 02 | `MZ`, `PE\0\0`, `PE32+`, `DllCharacteristics=0x0160`, `HIGH_ENTROPY_VA`, `DYNAMIC_BASE`, `NX_COMPAT`, `.text`, `.rdata`, `.data`, `.tls`, `.rsrc`, `.reloc`, `IMAGE_DIRECTORY_ENTRY_*` | P |
| Importok és exportok | 03 | `DLL Name`, IAT, delay-import, `CreateComponent`, `GetProcAddress`, `LoadLibrary*`, `KERNEL32.dll`, `CRYPT32.dll`, `WS2_32.dll`, FiveM-modulok | P |
| Komponensek, vtable-ok, RTTI | 04 | `ComponentLoader`, `CoreGetComponentRegistry`, `CoreIsDebuggerPresent`, MSVC RTTI-/vtable-stringek, konstruktor-/destruktor-nyomok, `citizen-resources-*`, `gta-core-five.dll`, `scripting-gta.dll` | L |
| Stringek, config és artifactumok | 05 | ASCII/UTF-16 scan, `CitizenFX.ini`, `CFX_*`, `CitizenFX_SDK_Guest`, `CitizenFX_ToolMode`, `data\cache\crashometry`, `server-cache-priv%s`, `CitizenFX_SubProcess_%s.bin`, JSON-kulcsok, PDB-nevek | P |
| Process, memória és hookok | 06 | `OpenProcess`, `GetThreadContext`, `SetThreadContext`, `SuspendThread`, `ResumeThread`, `QueueUserAPC`, `VirtualAlloc`, `VirtualProtect`, `FlushInstructionCache`, `CreateToolhelp32Snapshot`, közvetlen `syscall`; a `WriteProcessMemory`/`CreateRemoteThread` nevek nem importáltak | P |
| Anti-debug és integritás | 07 | `IsDebuggerPresent`, `CoreIsDebuggerPresent`, `ProcessBasicInformation`, `ProcessDebugPort=7`, `ProcessDebugObjectHandle=0x1E`, `ProcessDebugFlags=0x1F`, `NtSetInformationProcess` class `0x28`, `RDTSC; AND EAX,0xF`, `Toolhelp` stub/restore | P |
| Kriptográfia és trust | 08 | `CryptUnprotectData`, `Cert*`, `WINTRUST.dll`, `BCryptGenRandom`, beágyazott `OpenSSL 1.1.1t`, `Botan`, `AES`, `ChaCha20`, `SHA256`, `HMAC`, `Authorization`; plaintext JWT/private-key negatívum | P |
| Hálózat és IPC | 09 | `WS2_32.dll`, `WSA*`, `libuv.dll`, `net-*`, `HttpClient`, `cpr`, curl, WebSocket, HTTP/2, `http://clients2.google.com/time/1/current`, `compcache:/`, `privcache:/`, event- és pipe-nevek | P/L |
| Filesystem, perzisztencia, telemetry | 10 | `CreateFileW`, `DeleteFileW`, `MoveFileExW`, VFS/`vfs-core.dll`, `CitizenFX.ini`, cache- és crash-útvonalak, `RegGetValueW`, event-log API-k, `CFXGame`, `ServerInfoFile` | P/L |
| Packing és negatív Findings | 11 | szekcióentropia, `.text`/`.rdata` arány, import-sűrűség, overlay, TLS/resource, packer-jelző stringek, keresési scope-hoz kötött hiányok | L/U |
| Function-map, CFG és unresolved-régiók | 13 | `IMAGE_RUNTIME_FUNCTION`, `.pdata`, `UNWIND_INFO`, `CHAININFO`, `pdata_functions.csv`, `pdata_stats.json`, `cfg_functions.csv`, `cfg_clusters.csv`, `xref_edges.csv`, `indirect_sites.csv`, `unresolved_regions.*`, `doc_anchors`, `blocks_reached` vs `blocks_linear_only`, `reached_ratio`, `F-31`, `D-009`, Gate A–D | P |
| `0xC856C0` handle-flow és dispatch | 14 | `0xC856C0`, `0xC85650`, `0xC85681`, `0xC856F3`, `0xC86440`, `0x2CFB1F8`/`0x2CFB238`, `RDTSC; AND EAX,0xF`, 32 slot, `c856c0_dataflow.json`, `c856c0_forward.json`, `c856c0_callers.csv`, `audit_handle_flow.json`, `CF-01`–`CF-07`, `U-01`–`U-08` | P/U |
| Syscall-inventory és service-mapping | 15 | `0F 05`, `syscall_candidates_raw.csv`, `syscall_arg_inventory.csv`, `syscall_arg_classes.json`, `syscall_inventory.csv`, `syscall_service_map.json`, `nt_service=UNRESOLVED`, `static_constant`, `A6_SELF_HANDLE`, `A7_REG_INDIRECT`, `wrapper_forwarding`, `fallthrough_proven` / `sweep_hypothesis`, 3 881 → 3 627 felbontás | P/U |
| Patch-mechanizmusok, célok és aktiválás | 16 | `0x1E270`, `0x1DFF0`, `0x1E360`, `0xC8CE70`/`0xC8F470`, `0x1754520`, `rec + 0x00`, `0x06` flag, `CONTEXT.Rip`, `patch_record_table.json`, `patch_mechanisms_*.csv`, `apc_sites.csv`, `thread_context_map.json`, `QueueUserAPC`, `RVA 0x1170`; a korrekciós tételek a `12` §12.4 `PCH-01`–`PCH-03` (`12:503`–`12:505`) | P/L/U |
| Kockázat és módszertan | 12 | BRef-ek, confidence, `STATUS`, hívási út bizonyítéka, negatív findingok, korlátok és lezáratlan kérdések | U |

A `13`–`16` sorok anchorjai keresési és azonosítási pontok. A `16` sor szimbolikus kifejezései (`rec + 0x00`, `rec[0x28][i]`, `0x06` flag, `CONTEXT.Rip`) leírójelölések: a `16` dokumentum szándékosan nem ad patch-bájtot, diszlokációértéket, írási sorrendet vagy kikapcsolási eljárást (`16:5`–`16:11`, `16:1096`, `16:1159`).

## 6. Confidence-jelölés

- **`P=proven`:** a fájlban, metaadatban, PE-struktúrában, import/export-listában vagy statikus byte/string-bizonyítékban közvetlenül megfigyelhető. A `P` nem jelent jogi vagy fenyegetési minősítést.
- **`L=likely`:** több statikus jelből erős, de nem közvetlen következtetés; jellemzően szerep-, cél- vagy viselkedésazonosítás.
- **`U=unknown`:** a jelen fájlos vizsgálatból nem dönthető el, futásidőfüggő, konfigurációfüggő, rejtett vagy még nem visszafejtett.

## 7. BRef-formátum

A BRef mezői: **RVA/RAW/CONF/STATUS**. A táblázatokban és a kapcsolódó dokumentumokban az alábbi kanonikus forma használatos:

```text
BRef = [RVA:<hex|N/A> | RAW:<hex|N/A> | CONF:<P|L|U> | STATUS:<OBSERVED|INFERRED|NEGATIVE|OPEN>]
```

- **RVA:** a PE-image-ben értelmezett relatív virtuális cím; hexadecimális, `0x` előtaggal. Nem azonos a fájloffsettel.
- **RAW:** a specimen fájlban mért offset a fájl kezdetétől; hexadecimális, `0x` előtaggal.
- **CONF:** a globális `P/L/U` confidence-jelölés.
- **STATUS:** `OBSERVED` = közvetlenül megfigyelt; `INFERRED` = statikus adatfolyamból valószínű; `NEGATIVE` = megadott scope-on belül nem találtunk; `OPEN` = lezáratlan.

Példák a jelen specimenhez:

```text
BRef = [RVA:0x2AB2770 | RAW:N/A | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x101F80 | RAW:N/A | CONF:P | STATUS:OBSERVED]
BRef = [RVA:N/A | RAW:0x3315600 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:N/A | RAW:N/A | CONF:U | STATUS:OPEN]
```

Több helyet érintő findinghoz több BRef szükséges. `NEGATIVE` findinghez mindig dokumentálni kell a keresett mintát, encodingset, szekciókat és time-windowot; a „nem láttuk” nem azonos azzal, hogy „nincs”.

## 8. Legfontosabb nyitott kérdések

1. **Komponens-életciklus `[U]`:** pontosan milyen belépési pontból hívja a `CreateComponent` az egyes alrendszereket, és melyek érhetők el valójában a `citizen-resources-*`, `gta-core-five.dll`, `net-*` és `scripting-gta.dll` modulokon keresztül?
2. **Process- és thread-útvonalak célja `[U]`:** a közvetlen process-basic-information, process-memory, context-, APC- és patch-utasítások statikusan igazoltnak látszanak, de melyik runtime caller, handle, célprocessz, adat és szolgáltatás kapcsolódik hozzájuk, továbbá milyen védelmi vagy kompatibilitási szerepet töltenek be?
3. **Debugger-szemantika és caller `[U]`:** a `ProcessDebugPort=7`, `ProcessDebugObjectHandle=0x1E`, `ProcessDebugFlags=0x1F`, `NtSetInformationProcess` class `0x28`, valamint a `CoreIsDebuggerPresent` + `INT3` szerkezet közvetlen statikus képességek; nyitott a top-level callerlista, az aktiválási feltétel, a pontos szolgáltatásnév és az anti-debug szándék.
4. **Hálózati adatfolyam `[U]`:** a statikusan látható HTTP/WebSocket/socket stack milyen tényleges végpontokat, protokollváltozatokat, hitelesítési adatokat és kimenő sémákat használ; a `clients2.google.com` time-URL használata valós alkalmazási út-e?
5. **Helyi artifactumok és megőrzés `[U]`:** milyen szerepe van a `CitizenFX.ini`, `data\cache\crashometry`, `server-cache-priv%s`, `CitizenFX_SubProcess_%s.bin` és kapcsolódó cache/log-útvonalaknak; keletkezik-e rendszerindítás utáni vagy felhasználói fiókhoz kötött állapot?
6. **Trust- és hibakezelés `[U]`:** hogyan kapcsolódnak a Windows certificate store, a közvetlen PKCS#7/CMS-útvonal, a beágyazott OpenSSL/Botan és a HMAC/auth-sztringek; mi az indokolt szerepe a `WinVerifyTrust` és DPAPI import/thunk látható, de közvetlen call graph nélküli felületének?
7. **Packing/obfuscation `[L/U]`:** a normál szekciónevek, a közepes `.text`-entropia, a látható importok és a tisztán megmagyarázható `0x2860` bájtos security-directory farok elegendő-e a „nem látható csomagolás” kizárásához, vagy vannak-e csak lokálisan dekódolt adatok?
8. **Build- és release-megfeleltetés `[L/U]`:** a `1.0.0.36109`, a COFF-időbélyeg, a PDB-út és a Rockstar- CitizenFX-aláírás hogyan illeszkedik egy konkrét FiveM buildhez vagy csatornához; a statikus specimen önmagában nem igazolja az eredetváltozatot.

A `13`–`16` fázisok hat további lezáratlan tételt rögzítettek. A 9–11. pont a `12:534` mérlegében felsorolt négy valóban nyitott téma közül hármat pontosít; a 12–14. pont módszertani, payload- és korrelációs hiány. A sorrend a módszertani hatot követi, nem a kockázat szerinti rangsort.

9. **A `0xC856C0` handle producer továbbra is `OPEN` `[U]`:** a belépési határ (`0xC85650`) a hat enumerált statikus élformán üres, a `0`/`1`/`2` szintű lezárási séta 444 sor (`14`/`429`/`1`), a frontier üres és a séta kimerült, tehát a negatív oldal lezárt. A `[descriptor+0]` mezőt író kód és a belépő függvény hívója nem azonosított; a `0xD7B86E` `OpenProcess(0x1000, …)` jog (`PROCESS_QUERY_LIMITED_INFORMATION`) a 6- és 5 pozíciós sémához nem elég, és a patch-rekordtáblával sincs statikus él. A `12:530` `P-01` tétel státusza `open`. (`14:858`–`14:897`, `14:907`, `12:526`–`12:530`)
10. **A 3 627 valid `syscall`-hely Nt/Zw szolgáltatásneve `UNRESOLVED` `[U]`:** a mapping fázis a teljes korpuszon lefutott és **0** nevet nevezett meg; mind a 3 627 sor `nt_service = UNRESOLVED`, `nt_confidence = none`, `status = unresolved_symbolic_service_number`, a `svc_kind` census `static_constant` értéke `0`, tehát a naming gate egyetlen soron sem értékelődött ki. A `0xC856C0` 28 tárgyhelye és a 21 `wrapper_forwarding` site szintén 0 nevet kapott; a 21 nem a 12 wrapper censusza. A szolgáltatásszám mindenütt futásidejű keverésből képződik. (`15:618`, `15:752`, `15:769`, `12:517`)
11. **A patch-mechanizmusok aktiválása `OPEN` `[U]`:** a négy írási mechanizmus egyike sincs igazoltan elérhető a dekódolt CFG-ből. A patch-komponens zárt és belépés nélküli (a négy közvetlen hívás intra-komponens), a heap-gate a komponensen belül teljesíthetetlen, és a `0xC8CE70`/`0xC8F470`/`0x1754520` hármasnak nincs közvetlen hívója, mutatója vagy cím-literálja. A `0x317E398` cache tartalma fájlban nulla, a `0x317E3A0` gate `0`, a `0x33070EC` TLS-index futásidejű. A negatív oldal `[P]`, a lezáratlanság `[U]`; a `12:505` `PCH-03` státusza `bounded_open`. (`16:1034`, `16:1066`, `16:1110`–`16:1111`, `16:1158`)
12. **A lineáris sweep elérhetőségi korlátja (`D-009`) nyitott `[L/U]`:** a `cfg_functions.csv` `blocks_reached` (503 338 blokk) rekurzív leszállást, a `blocks_linear_only` (614 473 blokk, 24 358 005 bájt) sweep-hipotézist mér, és a `reached_ratio` a kettőt egyetlen számba sűríti, ezért soha nem használható kizárólagos elérési bizonyítékként. Ugyanez a korlát a `syscall` opkódon: 3 627-ből 243 descent-bizonyított (6,70 %) és 3 384 csak sweep-hipotézis. A javításhoz három dolog kellene: blokkonkénti `proof_level` oszlop, a `linear_only_blocks` család tartomány-szintű újradekódolása a `redecode_max_size=0x10000` korlát megemelésével, és egy keresztfájl check. A `12:524` `SWEEP-02` státusza `open`. (`13:684`–`13:708`, `13:321`, `12:519`–`12:524`)
13. **A 275 közvetett ugrás eltérés (`F-31`) nyitott `[U]`:** az E3 `indirect_jumps` összeg 86 559, az E6 `jmp_reg + jmp_mem_rip + jmp_mem_base` 86 834. A definíciók eltérnek (a függvényeken belül dekódolt helyek kontra minden annotált utasítássor, 355 stub-bal), de az E9 `xref.edges` 33 és `indirect.sites` 19 ellenőrzése egyike sem hasonlítja össze a kettőt, így a finding a Gate D `pass` verdiktje ellenére is nyitva marad. (`13:497`–`13:499`, `13:990`, `13:791`)
14. **A PDB-lehetőség korrelációja `[L/U]`:** a beágyazott CodeView-blokk PDB GUID-je `CB927E36-3F3D-8D77-4C4C-44205044422E`, age `1`, a PDB-út `C:\gl\builds\cfx-fivem-0\.build-cache\bin\five\release\dbg\adhesive.pdb`; maga a PDB nincs a specimenben és a projektben sincs ilyen nevű PDB, tehát nincs mit korrelálni. A Rich header bizonyítottan hiányzik, így a fájlból compiler- vagy product-tuple nem olvasható. A `reverse/evidence/pdb_correlation.json` (83 426 bájt, `pdb_correlate.py`) megvan, és öt mezőjét (`pdb_debug_id`, `pdb_match_key`, `authenticode_image_sha256`, `section_content_key`, `correlation_vector_sha256`) a `12:383` már hivatkozza; a hivatalos `1.0.0.36109` builddel való korreláció a `12` 9. fejezetének build-korrelációs kérdése változatlanul nyitott. (`01:185`–`01:196`, `01:196`, `12:410`, `15:871`)

## 9. Változási és ellenőrzési dátum

- **Index változási dátuma:** `2026-09-26`. A frissítés a `13`, `14`, `15` és `16` dokumentumot, valamint a `reverse/evidence/` és `reverse/scripts/` aktuális állományát vette fel; a specimenhoz nem nyúlt.
- **Specimen azonosításának, PE-fejléceinek, verzió- és aláírásadatainak statikus ellenőrzése:** `2026-09-25`; ez az 1. fejezet táblázatának ellenőrzési dátuma. A `13`–`16` dokumentumok 2026-09-26-i snapshotja ugyanazt a specimen-hashot pineli (`13:13`, `14:984`, `15:935`, `16:7`), de nem újraellenőrizte az 1. fejezet azonosító táblázatát.
- **Specimen filesystem módosítási ideje:** `2026-09-13T14:17:25.1851835Z`; ez a kapott fájl metadataértéke, nem a fordítás vagy a release ideje.
- **Következő felülvizsgálat:** a specimen SHA-256ának, verziójának vagy aláírásának változásakor, illetve a kapcsolódó dokumentumok frissülésekor az indexet is újra kell ellenőrizni.

---

## 10. Pin-konformancia-javítás (2026-09-26)

> **Scope:** kizárólag szövegszerkesztés az `adhesive-00-index.md`, `adhesive-12`, `adhesive-13`, `adhesive-14` és `adhesive-15` fájlokban. A DLL-t nem futtattam, nem töltöttem be, nem mappeltem és nem patcheltem; új evidence-fájl nem készült, és a `reverse/evidence/` vagy a `reverse/scripts/` állományhoz nem nyúltam. A méret- és `sha256`-pinok a `2026-09-26`-i lemezállapothoz lettek igazítva.

### 10.1 Az indexben frissített pin-ek (3 artifact, 4 hely)

| Hely | Artifact | Régi érték | Új érték |
|---|---|---|---|
| 4.1 fejezet, „4 audit / attestációs artifact" 13. sora | `audit_infra.json` méret | `169 558` bájt | **`170 001` bájt** |
| 4.1 fejezet, „4 audit / attestációs artifact" 15. sora | `audit_handle_flow.json` méret | `105 880` bájt | **`106 955` bájt** |
| 4.1 fejezet, „4 audit / attestációs artifact" 16. sora | `toolchain.json` méret | `26 638` bájt | **`27 150` bájt** |
| 4.1 fejezet, Snapshot-megjegyzés | `audit_handle_flow.json` méret + digest | `105 880` bájt, `9279ee8e…` | **`106 955` bájt, `c1636fcd…`** |

Az index a méreteket oszlopként, digestet nem tartalmaz; a `syscall_arg_classes.json` méret-pinje (`56 745`) már egyezett a lemezzel, digestje viszont más dokumentumokban pinelt. Az `audit_infra.json`, a `toolchain.json` és a `syscall_arg_classes.json` digest-pinje a `13`, illetve a `15` dokumentumban frissült, a fenti értékekkel azonosan.

### 10.2 Amit a javítás nem módosított

- **Nem változott semmilyen finding, státusz vagy confidence érték, és a 20 felsorolt artifact közül 17 pinje változatlan:** a `pdata_functions.csv`, `pdata_stats.json`, `cfg_functions.csv`, `cfg_clusters.csv`, `xref_edges.csv`, `indirect_sites.csv`, `unresolved_regions.csv`, `unresolved_regions.json`, `baseline.json`, `syscall_candidates_raw.csv`, `syscall_arg_inventory.csv`, `audit_syscall_candidates.json`, `c856c0_forward.json`, `syscall_inventory.csv`, `syscall_service_map.json` és `patch_record_table.json` méret- és digest-pinje bitre változatlan; a `syscall_arg_classes.json` méret-pinje (`56 745`) szintén változatlan, csak a digestje frissült.
- **A 632 / 0 / `verdict=pass` értékek változatlanok és ellenőrizhetők:** az `audit_infra.json` `summary` blokkja `check_count = 632`, `failed_count = 0`, `verdict = pass`, `discrepancy_count = 4`, `discrepancy_open_count = 0`, `failed_checks = []` értékeket ad; a 4.1 fejezet 13. sora ehhez hozzáfűzte, hogy ez a jelenlegi audit-futtatás check-száma.
- **A 163 / 0 értékek változatlanok:** az `audit_handle_flow.json` `validation` blokkja `check_count = 163`, `failed_count = 0`.
- **A 19 scriptbejegyzés és a `missing_from_inventory` / `drifted_entries` üres állapota változatlan** a `toolchain.json` nagyobbodása ellenére is.
- **A 8. fejezet 12. pontjának `6,70 %`-os és `3 384`-es aránya változatlan**, és egyezik a `12:524` frissített `93,30 %`-ával.
- **Kódolás és sortörés:** a fájl UTF-8 BOM nélküli, LF sortöréssel, záró sortöréssel; `cr = 0`.
