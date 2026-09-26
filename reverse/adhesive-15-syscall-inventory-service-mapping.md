# `adhesive.dll` – syscall-inventory és szolgáltatás-mapping: a 3 627 valid `0F 05` hely lezáratlan mappinggel

> **Vizsgálati elv:** kizárólag a `reverse/adhesive.dll` fájl statikus elemzése. Nem történt DLL-betöltés, image-mapping végrehajtás célra, futtatás, shellelés, dinamikus traceelés, patchelés, debugger-hozzáférés, hálózati vagy fájlrendszer-megfigyelés. A dokumentum **nem tartalmaz** exploit-, bypass- vagy patch-receptet, kézi ellenőrző kódot, runtime-caller-klózát vagy szolgáltatásnév-feloldást.
>
> **A fő eredmény negatív és legitim:** a `P0/S8` fázis a service mappinget **nem zárta le**. Mind a **3 627** sor `nt_service = UNRESOLVED`, `nt_confidence = none`, `status = unresolved_symbolic_service_number`. Egyetlen Nt/Zw szolgáltatásnév sem került beírásra. Ez a fázis tervezett kimenete, nem hiányosság: a naming gate soha nem érte el a névágat. A dokumentum ezt a kimenetet méri, nem megkerüli.

**Confidence-jelölés (az `adhesive-00-index.md` 6. fejezete szerint):** `P=proven`, `L=likely`, `U=unknown`.
**BRef-formátum:** `BRef = [RVA:<hex|N/A> | RAW:<hex|N/A> | CONF:<P|L|U> | STATUS:<OBSERVED|INFERRED|NEGATIVE|OPEN>]`.
**Egyéb státuszok:** `OBSERVED` = közvetlenül mért; `INFERRED` = statikus adatfolyamból valószínű; `NEGATIVE` = a megadott scope-on belül nem találtunk; `OPEN` = lezáratlan.
**Nagy CSV-fájlokból sorokat nem másolunk be:** minden állítás `hit_index` / `rva_hex` / számlált mezőnév hivatkozással azonosított. A `hit_index` 1-alapú CSV-sorszám.

---

## 1. Vizsgálati hatókör

| Tulajdonság | Statikus érték | Jelölés |
|---|---|---|
| Specimen | `C:\Users\Admin\Desktop\Dumper - AllInOne\reverse\adhesive.dll` | P |
| Méret | `53 575 264` bájt (`0x3317E60`) | P |
| SHA-256 | `91cc0aa006d7315cb042c8fa8dca6c1e074a307bba7dcc9eb5509c8a7b81934e` | P |
| MD5 / SHA-1 | `2e24179cc01167e50190fdd3bcf6939a` / `ae5627c6aab786095a816fc43f0e4ce04cee8829` | P |
| PE-típus | `PE32+` / AMD64, `DllCharacteristics=0x0160` | P |
| Preferált image base | `0x180000000` | P |
| Szórás | minden alább hivatkozott RVA a PE képbeli relatív virtuális cím; fálloffset a szekcióból: `.text` → `RAW = RVA − 0xC00`, `.rdata`/`.data` → `RAW = RVA − 0x1600` | P |
| Eszközök | Python `3.14.7`, Capstone `5.0.7` (`5.0.1280`), GNU objdump `2.47.20260726` (Binutils for MinGW-W64) | P |
| Irány | kizárólag statikus fájl-parse; a `syscall_scan.py`, az `audit_syscall_candidates.py`, az `audit_infra.py` és az `audit_handle_flow.py` auditált script **egyik sem futott**, az auditált CSV-k és JSON-ok nem íródtak újra | P |

### 1.1 Evidence-készlet

| # | Fájl | Méret (bájt) | SHA-256 | Sor / oszlop | Tartalom |
|---|---|---|---|---|---|
| E1 | `reverse/evidence/syscall_candidates_raw.csv` | 920 267 | `7c99950c48c6320487a28bdde1cba5914a8d620b4ef2049ae3f2118a2fcc3e8a` | 3 881 sor / 33 oszlop | `P0/S6` nyers `0F 05` találatok, boundary- és sweep-verdikt |
| E2 | `reverse/evidence/syscall_arg_inventory.csv` | 4 468 093 | `5dd86ec3ff41969567c1630628dff1d3f1146a9994b9fa5109e02733edab1500` | 3 627 sor / 100 oszlop | `P0/S7` hat argumentumpozíció osztályai |
| E3 | `reverse/evidence/syscall_arg_classes.json` | 56 745 | `9133ad84946bbcfb84cad38ce11a288fd7d88e893a7557a51bf07c85bbdd38a1` | 20 ellenőrzés / mind átment | `P0/S7` osztálylétra, cenzus, korlátok |
| E4 | `reverse/evidence/syscall_inventory.csv` | 5 993 935 | `bb1879aa251407b5ee753ababe088af3644250d80e3171c83d12a40eac07ed76` | 3 627 sor / 106 oszlop | `P0/S8` inventory: 100 megőrzött `S7` oszlop + 6 új + 1 felülírt |
| E5 | `reverse/evidence/syscall_service_map.json` | 19 589 | `25e29583be2f90d9902c984b880799ed25971e13e0547d7344d685b2bae481bb` | 28 ellenőrzés / mind átment | `P0/S8` módszertan, service-osztályok, gate, korlátok |
| E6 | `reverse/evidence/audit_syscall_candidates.json` | 1 765 141 | `e8cd41f2a27779b4b6265019d167b3c18a4ac32a6220395e7440cb07c26561be` | 31 ellenőrzés / mind átment | `P0/S6` független boundary- és control-flow-audit |
| E7 | `reverse/evidence/cfg_functions.csv` | 40 180 030 | `041d2365e3be008fbacbcb6f957fbd10fe0ae08c52ee1cbc9090e04bb64df788` | 142 004 sor | runtime-function és CFG-illesztés |
| E8 | `reverse/evidence/xref_edges.csv` | 11 126 183 | `fc744f611f4b94caf3c619a874dbead3b57123ded4e5df55ba128d748334270a` | 57 101 sor | `P0/S7` entry-parameter csatorna, 3 761 IAT callsite |
| E9 | `reverse/evidence/audit_infra.json` | 170 001 | `251b79e722620af61824b793ced1ade1ffe9b375608a429e109880aaa8b8b1dc` | 632 ellenőrzés / 0 hiba | toolchain-leltár független újraszámítása a producer byte-okból |
| E10 | `reverse/evidence/audit_handle_flow.json` | 106 955 | `c1636fcd6315a1bf679bc02e57cd3498a06a67b1a96252b8900f90b5b5b5f72c` | 163 ellenőrzés / mind átment | a 12 validált wrapper és a 21 `wrapper_forwarding` site független keresztmérése |

> **E9 méret- és hash-megjegyzés `[P]`:** a fenti `170 001` bájt és `251b79e7…` digest a `2026-09-26`-i lemezállapot. A `632` / `0` érték a payload `summary` blokkjából közvetlenül ellenőrizhető: `check_count = 632`, `failed_count = 0`, `verdict = pass`, `discrepancy_count = 4`, `discrepancy_open_count = 0`, `failed_checks = []`. **A dokumentum által közölt check-szám a jelenlegi audit-futtatásé**, nem egy korábbi payloadé; a `22` csoportos bontás ugyanannak a `summary.by_group` blokknak a `632`-es összegét adja.

**Producer-lánc és script-digestek `[P]`:**

| Réteg | Script | Lemezen mért SHA-256 (2026-09-26) | Rögzítve a payloadban |
|---|---|---|---|
| E1 | `reverse/scripts/syscall_scan.py` (636 sor) | `1710dd90b8e7bad04b29d9101f900c3a0040d83a16b8d35446556ed4b210cfc8` | E6 `inputs.audited_script.sha256` – egyezik |
| E2/E3 | `reverse/scripts/syscall_args.py` | `a5c58df7020d8440a40a097833a95fc3bd136b695820d7aff75273992a9836b3` | E3 `generated_by.sha256` – egyezik |
| E4/E5 | `reverse/scripts/syscall_service_map.py` (89 433 bájt, 2 133 sor) | `5e303021696ca6ac6061e1fa3e31914062661345e70f1e9ff75b27f5c26e60b6` | E12 `toolchain.json` `scripts[]` – egyezik; a 19 bejegyzéses leltárban már benne van |
| E6 | `reverse/scripts/audit_syscall_candidates.py` | `dfd90442d93cd591bcbacf2999a85fe50f514f2796136f741c1c94c69114b7a5` | E6 `producer.script_sha256` – egyezik |
| – | `reverse/scripts/common.py` | `4aa2ceec1af88b9cd72e64274b779f4fadf6b62d491fead2c865c3fa99eca750` | E12 `toolchain.json` – egyezik |

**F-01 — A `P0/S8` producer már stabil pinelve van a toolchain-leltárban; a saját payloadja továbbra sem önpinez és nem hasheli a kimenetét. `[P]`**

*A finding a jelenlegi lemezállapothoz korrigálva. Az eredeti első sor – „a `toolchain.json` `scripts[]` 17 bejegyzés, és a `syscall_service_map.py` nincs közöttük, tehát a producer a leltár rögzítése után jelent meg" – a mai állapothoz képest elavult, és a `13` dokumentum ugyanezen, ott `D-002`-ként kezelt megfigyelését az `E9` `closed` státuszban zárja le.*

| Hely | Tartalom | Állapot |
|---|---|---|
| `reverse/evidence/toolchain.json` `scripts[]` | **19** bejegyzés; a `syscall_service_map.py` **benne van** | **lezárva** – az eredeti „17 bejegyzés, nincs benne" állítás elavult |
| a `syscall_service_map.py` bejegyzés mezői | `size 89 433`, `sha256 5e303021696ca6ac6061e1fa3e31914062661345e70f1e9ff75b27f5c26e60b6`, `utf8_bom false`, `crlf_line_count 0`, `lf_line_count 2 133`, `third_party_imports ["capstone"]` | egyezik a lemezen mért értékkel |
| `E9` `audit_infra.json` `toolchain.scripts` / `toolchain.inventory` | az audit a script byte-okból újraszámolja: `syscall_service_map.py.sha256` `expected = actual = 5e303021…` (`ok true`), `inventory_names` 19 = 19, `entry_count` 19 = 19 | **lezárva**, független megerősítés |
| `E9` `audit_infra.json` `summary` | 632 ellenőrzés, **0 hiba**, `verdict=pass`; a `toolchain.scripts`, `toolchain.package_versions` és `toolchain.digests` csoport mind zöld, tehát a producer-leltárra **és** a digest-bevitelre sincs hiba | **lezárva**, a korábbi 5 CSV-attestálási hiba is megszűnt |
| `syscall_service_map.json` `generated_by` | scriptnév + Python-verzió, **nincs** `script_sha256` | **nyitott** – a payload nem önpinez |
| `syscall_service_map.json` | az **output** `syscall_inventory.csv` (E4, `bb1879aa…`) saját hashét **nem** tartalmazza | **nyitott** – a kimeneti fájl nincs payloadból ellenőrizhető |
| `syscall_service_map.json` `inputs` | 3 input hash (E1, E2, E7) | rendben |

**A jelenlegi toolchain-bevitel sha256-ja: `5e303021696ca6ac6061e1fa3e31914062661345e70f1e9ff75b27f5c26e60b6`** – a `reverse/evidence/toolchain.json` `scripts[]` `syscall_service_map.py` bejegyzéséből, függetlenül megerősítve az `E9` `toolchain.scripts` ellenőrzéseiben. A `toolchain.json` payload saját fázldigesztje, amit az `E9` `provenance.digests` és az `E9` `files` rögzít: `72a1eed07d4d8a83df62cce8bd175a56cbba0da22982b34278fb537b15de0e6b` (27 150 bájt).

A megkötés fennmaradó része reprodukciós határ, nem mérési hiba: mind a 28 `E5`-ellenőrzés a lemezen lévő adatfájlokon futott le, és azok hashét itt rögzítjük. `CONF:P`, `STATUS:OBSERVED`.

### 1.2 Amit a dokumentum nem tesz

- nem futtatja a DLL-t és nem mappeli végrehajtásra;
- nem ír szolgáltatásnevet egyetlen sorba sem;
- nem ad exploit-, bypass-, patch- vagy hooking-receptet;
- nem minősíti malware-, incidens- vagy jogi kockázatra a specimen;
- a negatív findingokat kifejezetten a megadott statikus scope-ra korlátozza.

---

## 2. Rövid összegzés

| Terület | Statikus megállapítás | Konf. | BRef |
|---|---|---|---|
| Nyers találat | `.text` szekcióban **3 881** nyers `0F 05` bájppár; minden szekcióban **3 911** | P | `[RVA:N/A \| RAW:0x400 \| CONF:P \| STATUS:OBSERVED]` |
| Valid felbontás | **3 881 → 3 627 valid + 209 covered_by_instruction + 45 pdata-gap**; a 3 627 mellett **+30 non-code** a scope-on kívül | P | `[RVA:N/A \| RAW:0x400 \| CONF:P \| STATUS:OBSERVED]` |
| Reprodukálhatóság | a négy szám független sweep-ből és objdump-pal is reprodukálódik, 0 eltérés | P | `[RVA:N/A \| RAW:0x0 \| CONF:P \| STATUS:OBSERVED]` |
| Control-flow korlát | **3 384** site csak lineáris sweep-hipotézis; **243** fallthrough-bizonyított | P | `[RVA:N/A \| RAW:0x0 \| CONF:P \| STATUS:OBSERVED]` |
| Argumentumok | **21 762** = 3 627 site × 6 pozíció, 8 osztály, `A3_INOUT_BUF` = 0 | P | `[RVA:0x3D50BA \| RAW:0x3D44BA \| CONF:P \| STATUS:OBSERVED]` |
| Anchor-csoportok | **9** anchor, 1:1 a `service_class` oszlop 7 osztályával; a 9 anchor összege 3 627 | P | `[RVA:N/A \| RAW:0x0 \| CONF:P \| STATUS:OBSERVED]` |
| Producer-kind cenzus | `memory_indirect` **1 957**, `kuser_shared_data` **961**, `peb` **367**, `code_address` **342**; `static_constant` **0** | P | `[RVA:0x3D5091 \| RAW:0x3D4491 \| CONF:P \| STATUS:OBSERVED]` |
| Service mapping | **3 627 / 3 627 `UNRESOLVED`**; `nt_confidence` mind `none`; név **0** | P | `[RVA:N/A \| RAW:0x0 \| CONF:P \| STATUS:NEGATIVE]` |
| `allocation_to_write` | **0** argumentum / **0** site; `allocation_origins.by_symbol` üres; 1 534 buffer-sort a rétegközi jelölést kapta | P | `[RVA:0xD7B0AE \| RAW:0xD7A4AE \| CONF:P \| STATUS:OBSERVED]` |
| `wrapper_forwarding` | **21** sor / **7** owning function; a predikátum csak az 1–4. pozíciót fogja; a 12 validált `0xC856C0` wrapper egyik site-ja sem tartozik bele | P | `[RVA:0x291C08F \| RAW:0x291B48F \| CONF:P \| STATUS:OBSERVED]` |
| Nt/Zw szolgáltatásnév | **OPEN**; a 3 627 hely egyikére sem zárható statikus service mapping | U | `[RVA:N/A \| RAW:N/A \| CONF:U \| STATUS:OPEN]` |

A statikus szerkezet teljesen lezárt és sorszinten auditált. Az egyetlen nyitott tárgy a szolgáltatás azonosítása – és az ismert okból nem zárható le ebből a fájlból.

---

## 3. A fázislánc és a 100 → 106 oszlop-szerződés

| Fázis | Script | Kimenet | Feladat |
|---|---|---|---|
| `P0/S6` | `syscall_scan.py` | E1 | a nyers `0F 05` census és a boundary-verdikt |
| `P0/S7` | `syscall_args.py` | E2, E3 | a hat argumentumpozíció osztálya 40 bájtos ablakban |
| `P0/S8` | `syscall_service_map.py` | E4, E5 | a service mapping gate és az anchor-csoportok |
| audit | `audit_syscall_candidates.py` | E6 | a `P0/S6` verdikt független reprodukciója és control-flow-mérése |

Az `S8` az `S7` 100 oszlopát változatlan sorrendben megőrzi, és hét oszlop a tulajdonosa:

| Oszlop | Sors |
|---|---|
| `svc_producer_rva` | új |
| `producer_chain` | új |
| `nt_confidence` | új |
| `mapping_basis` | új |
| `service_class` | új |
| `status` | új |
| `nt_service` | **felülírt**: a `S7`-ben is létező oszlop ugyanabba a pozícióba írja az `S8` verdiktet, hogy egy csv-olvasó ne vonjon össze két azonos nevű oszlopot |

Így `100 + 6 = 106` oszlop, 7 `S8`-hoz kötött oszloppal. A felülírt `nt_service` `S7`-es állítását az `nt_service_status` megőrzi: mind a 3 627 sorban `UNRESOLVED_NOT_ATTEMPTED`, vagyis az `S7` nem is próbált szolgáltatásnevet feloldani.

**Ellenőrzött tény `[P]`:** az `S8` payload az `E2` fájlt `5dd86ec3…` digeszttel rögzíti, és a lemezen lévő `E2` pontosan ezt a digestet adja. Az `S8` tehát nem módosította az `S7` argumentum-inventoryt; a felülírás csak az `E4` fájl `nt_service` oszlopára vonatkozik.

---

## 4. A 3 881 → 3 627 felbontás

### 4.1 A négyirányú partíció

A nyers `0F 05` bájppár **nem** önmagában szolgáltatásazonosítás. A `P0/S6` három csatornán keresztül szűri, és mindhárom csatorna a fájlból reprodukálható:

| Sors | Darab | A scope része | Döntő csatorna |
|---|---:|---|---|
| `instruction_start` – valid candidate | **3 627** | igen | valódi utasításstart a saját runtime function lineáris sweep-jében |
| `covered_by_instruction` | **209** | igen | a bájppár az előző utasítás belső byte-ja |
| `no_pdata_function` | **45** | igen | egyetlen `IMAGE_RUNTIME_FUNCTION` sem fedi le az RVA-t |
| nem végrehajtható szekció | **30** | **nem** | a szekció sem `MEM_EXECUTE`, sem `CNT_CODE` flaget nem hordoz |

Ellenőrzés: `3 627 + 209 + 45 = 3 881`, és a 30 külön rétegben, a CSV scope-on kívül számolódik.

### 4.2 A 30 nem végrehajtható találat

A `P0/S6` audit saját bájtcenzusa **minden** nyers-backed szekciót végigsweepelt, nem csak a `.text`-et:

| Szekció | `0F 05` találat | Szekció characteristics |
|---|---:|---|
| `.text` | 3 881 | `0x60000020` (RX, code) |
| `.rdata` | 27 | `0x40000040` (R, inicializált adat) – sem `MEM_EXECUTE`, sem `CNT_CODE` |
| `.data` | 3 | `0xC0000040` (RW, inicializált adat) – sem `MEM_EXECUTE`, sem `CNT_CODE` |
| `.retplne` | 0 | `0x0` |
| `.rsrc` | 0 | R |
| `.tls` | 0 | RW |
| `.reloc` | 0 | R, relocations |
| **összes** | **3 911** | |

A 30 találat mindegyikénél a saját runtime function lefedettség is `false`. A `.rdata`/`.data` bájppár tehát sem szekcióflag szerint, sem lefedettség szerint nem lehet utasítás: a 3 881 a végrehajtható szekció teljes census-e, a 3 911 az összes nyers-backed szekcióé. A 30 nem szerepel az E1 fájlban, mert annak scope-ja szándékosan a végrehajtható szekció; a szám ugyanabból a nyers bájtcenzusból származik, nem egy második instrumentumból.

Rámtartozó körülmény: ez a 30 találat nem cáfolja a `.rdata` kriptográfiai adatszigetéről szóló `11` dokumentumi findingot sem – egy `0F 05` bájppár egy adatblobban nem `syscall` utasítás, hanem adat.

### 4.3 A 209 `covered_by_instruction`

A bájppár az előző utasítás belsejébe esik, így azt az utasítás opcode-ként, diszplácensként vagy immediátként fogyasztja el, és sosem dekódolódik:

| Az elnyelő utasítás mnemonikája | Darab |
|---|---:|
| `call` | 112 |
| `lea` | 33 |
| `movabs` | 21 |
| `mov` | 19 |
| `movzx` | 11 |
| `xor` | 8 |
| `add` | 1 |
| `cmp` | 1 |
| `je` | 1 |
| `jmp` | 1 |
| `jne` | 1 |
| **összes** | **209** |

Példa (`hit_index` a nyers fájlban): `rva 0x3E754` a `0x3E751`-es `movzx edx, byte ptr [rdi + rcx + 5]` 3. belső bájtja; `rva 0xCDD5D` a `0xCDD5C`-es `call 0xCE270` 1. belső bájtja. Mind a 209 esetben `objdump_instruction_start = false`, vagyis a második dekóder is ugyanazt a verdiktet adja.

### 4.4 A 45 `no_pdata_function` – pdata-rés

| `gap_kind` | Darab |
|---|---:|
| `inter_function_alignment_gap` | 25 |
| `inter_function_code_island` | 20 |
| **összes** | **45** |

| Mérőszám | Érték |
|---|---|
| `gap_size` minimum / maximum / összeg | 19 / 175 312 / 579 013 bájt |
| `distance_to_nearest_gap_edge` minimum / maximum | 5 / 50 795 bájt |
| `recursive_descent_reached = false` | 45 / 45 |
| `inside_another_instruction = true` | 13 / 45 |

Ezekre a bitekre nem állítható utasításstart, mert nincs dekódolási kontextusuk: egyiket sem fedi le runtime function. A rekurzív leszállás sem éri el őket, tehát nincs olyan futásidejű belépési pont, ahonnan `syscall`-ként dekódálhatnának. A 13 `inside_another_instruction = true` eset ráadásul egy másik utasítás része is.

### 4.5 A reprodukció

| Csatorna | Eredmény |
|---|---|
| Független lineáris sweep (saját Capstone-sweep, minden owning functionre) | 3 627 / 209 / 45 – egyezik |
| GNU objdump `2.47.20260726` mint független második dekóder | 549 tartomány; 3 627 utasításstart megerősítve; 3 627 `syscall` mnemonika; **0** vita; **0** más mnemonika |
| Sweep-leállás a candidate előtt | **0** |
| Az owning function végéig nem fogyott sweep | **0** |
| Az E1 CSV sorszámonkénti egyezése a független halmazzal | 0 eltérés |

A 228 objdump-tartomány `ranges_with_undecoded_tail` listája nem hiba: ezek a tartományok végén maradt néhány bájt, amit a második dekóder nem bontott utasításszá, és egyik érintett tartományban sincs candidate a farokban.

### 4.6 Amit a felbontás nem állít

A `3 627` **érvényes utasításstartokat** jelent, nem elérhető vagy végrehajtott kódot. Az elérhetőségi szintet az 5. fejezet adja meg, a szolgáltatásazonosítást a 10. fejezet. A 209 + 45 + 30 elutasítás kizárólag a boundary-csatornára vonatkozik.

---

## 5. A 3 384 lineáris sweep-hipotézis korlát

### 5.1 A három bizonyítékszint

A `P0/S6` egyetlen dekódolási csatornája a saját runtime function lineáris sweep-je. Ebből három szint adódik:

| Szint | Definíció | Site |
|---|---|---:|
| `fallthrough_proven` | megszakítatlan fallthrough-láncon a owning function belépőjétől, tehát az utasításstart csak a belépőből következik | **243** |
| `branch_proven` | nincs a fallthrough-láncon, de a rekurzív leszállásban a szülő függvény egy feloldható direkt ága eléri | **0** |
| `sweep_hypothesis` | csak a lineáris sweep éri el, vagyis a dekódolásnak egy olyan vezérlőátadáson keresztül kell folytatódnia, amit a sweep figyelmen kívül hagy | **3 384** |

A rekurzív leszállás 243-at megerősít és 3 384-at nem. A kettő kizárja egymást és összege 3 627.

### 5.2 Miért 3 384 – az ignorált vezérlőátadás csatornája

| Az utolsó ignorált vezérlőátadás típusa | Site |
|---|---:|
| `indirect_jump` | 2 786 |
| `direct_jump` | 575 |
| `terminator` | 23 |
| **összes** | **3 384** |

Az `indirect_jump` dominanciája a `RDTSC`-alapú diszperzióval és a jump-táblákkal konzisztens: az ilyen átadás célcímét csak futásidőben lehet eldönteni.

### 5.3 A rekurzív leszállás eredménye

| Mérőszám | Érték |
|---|---|
| Magok | a kivételkönyvtár **mindegyik** runtime function belépője |
| Elért utasításstart | 3 964 288 |
| `.text` RVA tartomány | `0x1000` – `0x2BEE600` (46 061 056 bájt) |
| Direkt ágcel egy másik utasítás belsejébe | 24 cím |
| `any_candidate_affected` | **false** |

### 5.4 A négy megkötés

1. Egyetlen owning function sem igényelt leállított sweepet, tehát nincs candidate, amelyet a saját runtime functionjén belüli nem dekódolható bájt hagyna döntés nélkül.
2. Egyetlen direkt ágcél sem esik egy másik utasítás belsejébe, tehát nincs középutas átadással belépett candidate.
3. A pdata-rés bejegyzések a leszállás hozzáadásával már nemambigusak: egyik sem érhető el egyetlen runtime function belépőből sem.
4. A csak sweep-hipotézises bejegyzés **nem az auditált script hibája**, amelynek docstringje a lineáris sweepet nevezi meg dekódolási csatornának; ez az evidence-fájl önmagában bizonyítható korlátja.

### 5.5 Mi örökli ezt a korlátot

A `P0/S7` és a `P0/S8` a `P0/S6` 3 627 soros készletét dolgozza fel, így mind a 21 762 argumentumosztály és mind a 3 627 service-verdikt ugyanazokon a site-okon áll, amelyek 93,30 %-a csak sweep-hipotézis. Ez nem az argumentum- vagy mapping-módszertan hibája, hanem a control-flow-bizonyítottság szintje, amelyet a `P0/S6` örökített tovább. `CONF:P`, `STATUS:OBSERVED`.

```text
BRef = [RVA:0x293D4DE | RAW:0x293C8DE | CONF:P | STATUS:OBSERVED]
BRef = [RVA:N/A | RAW:0x0 | CONF:P | STATUS:NEGATIVE]   # 3 384 nem control-flow-bizonyított
```

---

## 6. A 21 762 argumentumosztály

### 6.1 A pozíciók

| Pozíció | Forrás | Hely |
|---:|---|---|
| 1 | register | `R10` |
| 2 | register | `RDX` |
| 3 | register | `R8` |
| 4 | register | `R9` |
| 5 | stack slot | `[RSP+0x28]` |
| 6 | stack slot | `[RSP+0x30]` |

`3 627 × 6 = 21 762` argumentum. A `[RSP+0x28]` anchor a call útján elért stubra igaz: `[RSP]` a return address, alatta 32 bájt callee shadow space. Hívás nélkül belépett stubnál nincs return address, és az első stack argumentum egy slottal lejjebb ül – ez a korlát változatlanul öröklődik az `S8`-ba.

### 6.2 Az osztálylétra

A legkisebb sorszámú rangú egyező szabály nyer (1 = legerősebb), precedencia: legközelebbi határozott definíció → legközelebbi feltételes definíció → ablakon belüli feloldatlan.

| Rang | Kód | Szabály |
|---:|---|---|
| 1 | `A1_PSEUDO_HANDLE` | a pseudo-handle ablakon belüli feloldott konstans |
| 2 | `A3_INOUT_BUF` | feloldott adatcílem az ablakban megfigyelt olvasás/írás párral |
| 3 | `A3_OUT_BUF` | feloldott adatcílem ilyen pár nélkül |
| 4 | `A4_LEN` | legfeljebb 1 MiB feloldott konstans közvetlenül egy buffer pozíció után |
| 5 | `A2_OBJ_CLASS` | minden más feloldott, nemnegatív konstans literál |
| 6 | `A6_SELF_HANDLE` | az értéklánc a owning függvény entry paraméterénél végződik |
| 7 | `A5_STACK_SLOT` | stack argumentum slot, amelynek tárolt értéke nincs feloldva |
| 8 | `A7_REG_INDIRECT` | register argumentum, amelyet az ablak nem redukál konstansra vagy címre |
| 9 | `A8_UNKNOWN` | nincs definíció az ablakban, vagy a definíció nem értelmezett |

Két ablak-határ működik: egy volatile regiszter definíciója a window utolsó `call`-ja előtt nem az élő érték, és egy feltételes definíció (`cmov` és társai) csak egy élen definiál, ezért a feltételes definíció eredménye `conditional_merge`.

### 6.3 A cenzus

| Osztály | Argumentum | Site | `R10` | `RDX` | `R8` | `R9` | `[RSP+0x28]` | `[RSP+0x30]` |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `A5_STACK_SLOT` | 5 256 (24,15 %) | 3 106 | – | – | – | – | 2 238 | 3 018 |
| `A8_UNKNOWN` | 4 650 (21,37 %) | 1 769 | 529 | 1 118 | 1 364 | 1 639 | – | – |
| `A7_REG_INDIRECT` | 2 820 (12,96 %) | 2 192 | 977 | 767 | 716 | 360 | – | – |
| `A3_OUT_BUF` | 2 794 (12,84 %) | 1 534 | 40 | 1 031 | 730 | 418 | 514 | 61 |
| `A2_OBJ_CLASS` | 2 698 (12,40 %) | 1 728 | 96 | 374 | 577 | 597 | 514 | 540 |
| `A1_PSEUDO_HANDLE` | 1 602 (7,36 %) | 1 602 | 1 602 | – | – | – | – | – |
| `A6_SELF_HANDLE` | 1 108 (5,09 %) | 676 | 383 | 321 | 201 | 195 | – | 8 |
| `A4_LEN` | 834 (3,83 %) | 834 | – | 16 | 39 | 418 | 361 | – |
| `A3_INOUT_BUF` | **0** (0,00 %) | 0 | – | – | – | – | – | – |
| **összes** | **21 762** | – | 3 627 | 3 627 | 3 627 | 3 627 | 3 627 | 3 627 |

A pseudo-handle ablak `0xFFFFFFFFFFFFFF00`–`0xFFFFFFFFFFFFFFFF`; a 1 602 névhez kötött értékből 1 586 `current_process` (`-1`) és 16 `current_thread` (`-2`). Az `A1_PSEUDO_HANDLE` kizárólag az 1. pozícióban fordul elő, ami konzisztens a handle-szemantikával.

A 21 762 argumentum 448 owning functionre oszlik el, mind a 3 627 site CFG-illesztett és a dekódolás sikeres (`window_decoded = 3627`, `cfg_bounds_match = 3627`).

### 6.4 Az ablak geometriája

| `window_bytes` | 31 | 32 | 33 | 34 | 35 | 36 | 37 | 38 | 39 | 40 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| site | 1 | 44 | 21 | 110 | 110 | 427 | 416 | 660 | 765 | 1 073 |

| `window_instruction_count` | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| site | 68 | 126 | 605 | 750 | 939 | 592 | 366 | 157 | 22 | 2 |

| `window_stack_delta` | −96 | −80 | −64 | −48 | −40 | 0 |
|---|---:|---:|---:|---:|---:|---:|
| site | 58 | 68 | 636 | 1 280 | 1 261 | 324 |

A paraméterként dokumentált `20..40` bájtos tartomány alsó fele nem fordult elő: a tényleges megfigyelt tartomány **31–40 bájt**, 4–13 utasítással. Az ablak minden site-on a candidate-t megelőző utasításokból áll, és a saját owning function határánál soha nem lép túl. A `stack_delta` 324 site-on `0`, tehát az esetek 8,9 %-ában a `syscall` változatlan stack-ponttal érkezik; a többségben a `push`/`sub rsp` nemnulla eltolást okoz.

### 6.5 A 129 class signature

A `site_signature` oszlopban 129 különböző hatosztályos aláírás szerepel. A leggyakoribb négy:

| Aláírás | Site |
|---|---:|
| `A7_REG_INDIRECT + A8_UNKNOWN + A8_UNKNOWN + A8_UNKNOWN + A5_STACK_SLOT + A5_STACK_SLOT` | 539 |
| `A8_UNKNOWN + A8_UNKNOWN + A8_UNKNOWN + A8_UNKNOWN + A5_STACK_SLOT + A5_STACK_SLOT` | 351 |
| `A1_PSEUDO_HANDLE + A7_REG_INDIRECT + A7_REG_INDIRECT + A2_OBJ_CLASS + A5_STACK_SLOT + A5_STACK_SLOT` | 262 |
| `A1_PSEUDO_HANDLE + A3_OUT_BUF + A2_OBJ_CLASS + A3_OUT_BUF + A4_LEN + A2_OBJ_CLASS` | 248 |

A 129 aláírás közül 39 `A1_PSEUDO_HANDLE`-lel kezdődik, vagyis a saját processz pseudo-handle a first argumentum 1 602 site-on, de csak 39 különböző teljes alakban. A 129 alak közül 72 végződik `A5_STACK_SLOT + A5_STACK_SLOT`-on, ami a 6. pozíció feloldhatatlanságának közvetlen következménye: a második stack argumentum a korpusz 83,21 %-ában (3 018 site) feloldatlan marad.

### 6.6 Miért nulla az `A3_INOUT_BUF`, ha van 7 read/write pár

Ez a rész a 7. fejezethez vezet, de itt érdemes lezárni: a `rw_pair` jel 7 argumentumon igaz, és mind a hetedik az **5. pozícióban**, azaz a `[RSP+0x28]` slotban van. Mindegyik feloldott értéke a konstans `0`, és a `reason` `const_literal_zero_stack_slot_store`, tehát a pár **nem** egy feloldott adatcímre vonatkozik:

```text
hit 929  rva 0xD7B0AE  arg5_evidence = rw frame:rsp:40; read mov rbp, qword ptr [rsp + 0x58]@0xD7B093;
                              write mov qword ptr [rsp + 0x28], 0@0xD7B0A5; chain [rsp+0x28]<-0@0xD7B0A5
```

Az olvasott slot (`0x58`) és az írt slot (`0x28`) különbözik; az ablakon belüli megfigyelés egy konstans nulla tárolása. Az `A3_INOUT_BUF` 2. rangú szabálya *feloldott adatcímet* kér, tehát a 7 jel a 3. rangú `A2_OBJ_CLASS`-ba és nem az `A3_INOUT_BUF`-ba esik. Az `A3_INOUT_BUF = 0` aritmetikailag következetes, nem hiányzó megfigyelés. A 7 jelből 6 a `0xD7A400` owning functionben van, 1 a `0x2951DD0`-ben.

---

## 7. A nulla `allocation_to_write` rétegközi magyarázat

### 7.1 A két szám különböző mennyiség

| Jel | Jelentés | Leckezett hatókör |
|---|---|---|
| `A3_OUT_BUF` / `A3_INOUT_BUF` | a service-nek átadott **cím** a syscall boundary-n | 40 bájtos ablak |
| `allocation_to_write` | egy **allokátor visszatérési értéke** az értékláncban **ÉS** egy megfigyelt írás ugyanezen a mutatón | 40 bájtos ablak |

Ez nem ellentmondás, hanem két külön mennyiség. A korpusz 1 534 site-ot osztályoz buffer-pozíciót hordozónak, ugyanakkor az `allocation_to_write` mindenütt 0.

### 7.2 Miért kényszerül a nulla

Két egymástól független tény szorítja nullára:

| Tény | Forrás | Érték |
|---|---|---|
| Az allokátor-hívás csatorna üres | `allocation_calls` oszlop, mind a 3 627 sorban | üres string |
| Egyetlen argumentum sem ér véget allokátor-visszatérésnél | `allocation_origins.by_symbol` | `{}` (üres objektum) |
| `allocation_write_arguments` | oszlop, mind a 3 627 sorban | `0` |

Mivel a korpuszban egyetlen allokátor-szimbólum sincs, amelyhez bármelyik argumentum értékláncra kapcsolódna, a „buffer osztály **és** allokátor-eredet" konjunkció **számtanilag nulla**, nem pedig egy elmulasott megfigyelés. A `P0/S7` 19 allokátor-szimbólumot sorol fel (`VirtualAlloc`, `NtAllocateVirtualMemory`, `malloc`, …) – egyik sem jelenik meg egyetlen 40 bájtos ablakban sem.

### 7.3 A rétegközi magyarázat

Ahol egy ilyen buffert valóban egy allokátor termel, az írás **másik rétegben** történik. A lehetséges rétegek, mindegyik a statikus adatfolyamból ellenőrizhető:

1. az allokáló hívás a 40 bájtos ablakon **kívül** van;
2. az allokáló hívás a **hívó frame-jében** van (wrapperes átadás);
3. a mutató a stubhoz egy `A6_SELF_HANDLE` entry paraméteren, egy prologue spillen vagy egy wrapperből lemásolt értéken **átadódik**;
4. az írás egy ágra kerül, amelyet a lineáris sweep nem jár be.

Az ilyen továbbítás a write-et kihúzza az ablakból anélkül, hogy hamissá tenné. A `P0/S8` ezt **különbségként, nem ütközésként** rögzíti, és a `mapping_basis`-ban két nem ledobható tokent ír be minden érintett sorra: `alloc_write_scope=window` és `alloc_write=forwarded_or_cross_layer`.

### 7.4 A soronkénti jelölés és a validációs szabály

| Mérőszám | Érték |
|---|---:|
| Buffer osztályt hordozó sor | 1 534 |
| Buffer osztályt hordozó **és** `allocation_write_arguments = 0` sor | 1 534 |
| Megfigyelt allokációs írással rendelkező sor | **0** |
| Allokátor-eredetű argumentum | **0** |
| `alloc_write_scope=window` tokent hordozó sor | 1 534 |
| `alloc_write=forwarded_or_cross_layer` tokent hordozó sor | 1 534 |
| `alloc_write=observed_in_window` tokent hordozó sor | **0** |

A `P0/S8` validáció explicit szabálya: **egyetlen ellenőrzés sem tekinti hibának**, ha egy buffer osztály `allocation_write_arguments = 0`-val együtt szerepel. A `no_allocation_write_is_claimed_without_observation` ellenőrzés várható értéke 0, tényleges értéke 0.

### 7.5 Amit ez nem állít

A nulla nem azt mondja, hogy a specimen nem ír allokált bufferbe. Azt mondja, hogy **ebben a 40 bájtos ablakban, ebben a 448 owning functionben** nem volt egyetlen olyan megfigyelt írás sem, amelynek pointerét egy allokátor-visszatéréshez lehetne kötni. `CONF:P` a számokra, `CONF:U` bármely végrehajtási következtetésre.

```text
BRef = [RVA:0xD7B0AE | RAW:0xD7A4AE | CONF:P | STATUS:OBSERVED]   # 7 rw_pair, 0 alloc_write
BRef = [RVA:0xD7A5F3 | RAW:0xD799F3 | CONF:P | STATUS:OBSERVED]   # 7 rw_pair, 0 alloc_write
BRef = [RVA:0x2952474 | RAW:0x2951874 | CONF:P | STATUS:OBSERVED]  # 7 rw_pair, 0 alloc_write
BRef = [RVA:N/A | RAW:0x0 | CONF:P | STATUS:NEGATIVE]              # allocation_calls üres 3 627/3 627
```

---

## 8. Az anchor-csoportok

### 8.1 A rendezett predikátum

A `service_class` oszlop egy determinisztikus függvénye a `P0/S7` celláknak. A csoportok **rendezett sorrendben** értékelődnek, és **az első, amelyik tüzel, dönt**:

| # | Anchor | `service_class` | Szabály | Site |
|---:|---|---|---|---:|
| 1 | `information_class_0x00` | `process_information_basic` | a 2. argumentum statikusan feloldott konstans `0x00`, és a 3. vagy 4. argumentum az osztályhoz szükséges buffert vagy hosszt hordoz | 78 |
| 2 | `information_class_0x07` | `process_information_debug` | a 2. argumentum `0x07` (`ProcessDebugPort`), buffer vagy hossz kíséri | 8 |
| 3 | `information_class_0x1E` | `process_information_debug` | a 2. argumentum `0x1E` (`ProcessDebugObjectHandle`), buffer vagy hossz kíséri | 8 |
| 4 | `information_class_0x1F` | `process_information_debug` | a 2. argumentum `0x1F` (`ProcessDebugFlags`), buffer vagy hossz kíséri | 8 |
| 5 | `information_class_0x28` | `process_information_instrumentation_callback` | a 2. argumentum `0x28` (`ProcessInstrumentationCallback`), buffer vagy hossz kíséri | 8 |
| 6 | `constants_0x1000_and_0x40` | `allocation_0x1000_0x40` | az argumentumhalmaz a hat pozícióban hordozza a `0x1000` típust **és** a `0x40` oldalvédelmet | 16 |
| 7 | `five_resolved_buffer_and_length` | `transfer_5arg` | mind az 5 pozíció feloldott osztályú, legalább egy buffer és legalább egy hossz | 633 |
| 8 | `four_entry_parameters_forwarded` | `wrapper_forwarding` | mind a 4 register pozíció `A6_SELF_HANDLE` | 21 |
| 9 | `no_anchor` | `other` | egyik fenti sem tüzel | 2 847 |
| | | | **összes** | **3 627** |

Az anchor → `service_class` leképezés **1:1** (9 anchor, 7 osztály: a három debug anchor ugyanazt az osztályt hordozza, a `0x00` és a `0x28` külön osztály). A partíció teljes, átfedés nélküli, és összege 3 627.

### 8.2 Az information-class anchor két kemény feltétele

A `information_class` predikátum egyszerre **négy** feltételt vizsgál:

1. a 2. pozíció osztálya pontosan `A2_OBJ_CLASS` (nem pusztán egy konstans);
2. a konstans nem `None`, és `0 ≤ érték < 0x80`;
3. az 1. pozíció osztálya handle-osztály (`A1_PSEUDO_HANDLE`, `A6_SELF_HANDLE` vagy `A7_REG_INDIRECT`);
4. a 3. **vagy** a 4. pozíció osztálya buffer vagy `A4_LEN`.

A 4. feltétel nélkül a `0x00`, `0x07`, `0x1E`, `0x1F` és `0x28` érték önmagában nem elég. Ez magyarázza a következő három megfigyelést.

### 8.3 A dokumentált 64 anchor site és az `S8` osztályok kereszttáblája

A `P0/S6` audit a `06`, `07` és `12` dokumentumban említett **64** egyedi syscall helyet ellenőrizte, és mind a 64 a valid 3 627-es részhalmazban van. A 64 hely `S8` osztály szerinti megoszlása, közvetlenül a `rva_hex` alapján összekapcsolva:

| A `06`/`07`/`12` dokumentum csoportja | Site | `S8` `service_class` |
|---|---:|---|
| `adhesive-07 process debug port` | 8 | `process_information_debug` |
| `adhesive-07 process debug object handle` | 8 | `process_information_debug` |
| `adhesive-07 process debug flags` | 8 | `process_information_debug` |
| `adhesive-07 process instrumentation callback direct branches` | 8 | `process_information_instrumentation_callback` |
| `adhesive-12 dispatch branch syscalls` | 8 | `allocation_0x1000_0x40` |
| `adhesive-06/12 dynamic Nt wrapper cluster` | 12 | `other` |
| `adhesive-07 process instrumentation callback helper routines` | 6 | `other` |
| `adhesive-06/12 remote buffer syscalls` | 3 | `other` |
| `adhesive-07 process basic information` | 3 | `other` |
| **összes** | **64** | 40 anchor-csoportba, 24 `other`-be |

A 24 debug + 8 instrumentation + 8 allokáció site pontosan azok a dokumentált helyek, ahol a `S7` ablak a 3. vagy a 4. argumentum pozíciót buffernek vagy `A4_LEN`-nek tudta minősíteni, vagyis a 8.2. pont 4. feltétele teljesült. A `process_information_debug` 24 sora a `06`/`07` dokumentum három top-level rutinjában van, egyenként 8: `0x293E060` (DebugFlags), `0x293EF20` (DebugPort), `0x293FDF0` (DebugObjectHandle). Az `allocation_0x1000_0x40` 16 sorából 8 a `0xC856C0` anchor 8 közvetlen allokációs ága (ez egyezik a `14` dokumentum C-01 korrekciójával), a másik 8 a `0xE48B60` függvényben.

### 8.4 Miért nincs a `process_information_basic` csoportban a `0xD7A400` funkció

Ez a dokumentum legfontosabb keresztreferencia-eltérése, ezért explicit módon kell állítani:

| Site | `arg1` | `arg2` | `arg3` | `arg4` | `S8` osztály |
|---|---|---|---|---|---|
| `0xD7B0AE` | `A1_PSEUDO_HANDLE` = `0xFFFFFFFFFFFFFFFF` | `A2_OBJ_CLASS` = `0x0` | `A7_REG_INDIRECT` | `A2_OBJ_CLASS` = `0x30` | `other` |
| `0xD7B4B9` | `A1_PSEUDO_HANDLE` = `0xFFFFFFFFFFFFFFFF` | `A2_OBJ_CLASS` = `0x0` | `A7_REG_INDIRECT` | `A2_OBJ_CLASS` = `0x30` | `other` |
| `0xD7C0AC` | `A1_PSEUDO_HANDLE` = `0xFFFFFFFFFFFFFFFF` | `A2_OBJ_CLASS` = `0x0` | `A7_REG_INDIRECT` | `A2_OBJ_CLASS` = `0x30` | `other` |

A 2. argumentum konstans `0x0`, vagyis a `ProcessBasicInformation` érték **feloldva van**. Az anchor a 4. feltételen bukik el: a 3. pozíció `A7_REG_INDIRECT` (a 40 bájtos ablakban nem volt redukálható adatcímre), és a 4. pozíció `A2_OBJ_CLASS`, nem `A4_LEN` – az `A4_LEN` a létra 4. rangú szabálya egy **buffer pozíció utáni** konstansra vonatkozik, és a 3. pozíció nem az.

A `06` és `07` dokumentum megállapítása ettől **nem változik**: a három hely valódi `0F 05` utasításstart a `0xD7A400` runtime functionben, `R10=-1`, `EDX=0`, `R9D=0x30`, `R8=rbp`, és a `buffer+0x28` → `OpenProcess(0x1000, FALSE, parentPid)` adatfolyam statikusan megvan. Az `S8` anchor-csoport **nem ezt méri**. Ugyanez a mechanizmus bontja ki a `0x28` osztály 6 segédrutin-helyét is (`0x2941AC2`–`0x29422AA`): a 3. pozíció `A6_SELF_HANDLE` vagy `A7_REG_INDIRECT`, ezért a 4. feltétel nem teljesül, és mind a 6 az `other` csoportba kerül. A 8 közvetlen ág (`0x293D4DE` és a hét testvére) `lea r8, [rsp+0x20]` miatt `A3_OUT_BUF`-ot kap, így azok tüzelnek.

Következmény a 78-as számra: a `process_information_basic` anchor-csoport 78 site-ot tartalmaz **11 owning functionben**, és ezek között **nincs** a `0xD7A400`. A 78 tehát nem a dokumentált három hely bővítése, hanem egy önálló, konstans-alapú alakcsoport. `CONF:P` a számokra, `CONF:L` a `06`/`07` és az anchor közötti alak-eltérés magyarázatára.

### 8.5 Az anchor-csoport nem azonosítás

A `parameters.information_class_constants` kulcsai a **dokumentált nyilvános `PROCESSINFOCLASS` értékek**. Csoportcímként használva egy hipotézis az alakról szól, nem az elért szolgáltatás azonosítása. A `P0/S8` korlátlistája ezt külön is kimondja: *a group label egy hipotézis egy alakról, nem az elért szolgáltatás azonosítása*.

---

## 9. A producer-kind cenzus

### 9.1 A négy kind

A sweep a `RAX`-at követi visszafelé a saját owning runtime functionben belül, és a lánc végállapotát `svc_kind` néven írja ki:

| `svc_kind` | Site | Arány | A lánc miért áll meg itt |
|---|---:|---:|---|
| `memory_indirect` | **1 957** | 53,96 % | regiszter-indirekt operand; a célcím futásidőben dől el |
| `kuser_shared_data` | **961** | 26,50 % | a `0x7FFE0000`–`0x7FFF0000` ablakba eső abszolút operand; a fájlban nincs értéke |
| `peb` | **367** | 10,12 % | `gs` szegmens operand, illetve minden olyan memóriaoperandum, amelynek bázisregisztere a PEB-re oldódik |
| `code_address` | **342** | 9,43 % | `lea`-vel előállított kód- vagy adatcím, illetve ilyen értéket hordozó image slot |
| `static_constant` | **0** | 0,00 % | foldolható konstans utasításszintű operand – **egyetlen site-on sem** |
| `register_undefined` / `conditional_merge` / `opaque_instruction` / `sweep_unreached` | 0 | 0,00 % | a gate korábbi ágaihoz sem jutott egyetlen site sem |

A `memory_indirect` + `kuser_shared_data` + `peb` együtt **1 328** site (36,61 %), amely szimbolikusan ismeretlen operand miatt áll meg; a `code_address` **342** site azért, mert a `symbolic_unknown` szabály a `lea`-vel előállított kód- vagy adatcímet is tiltólistára teszi. Együtt **1 670** site áll meg olyan operandon, amely szabály szerint nem nevezhető meg szolgáltatásszámnak – ez a 3 627 **46,04 %**-a.

### 9.2 A `symbolic_operand` megoszlása

| `symbolic_operand` | Site | `svc_kind` |
|---|---:|---|
| `kuser_shared_data_0x7FFE0330` | 451 | `kuser_shared_data` |
| `peb_gs_disp_0x30` | 445 | 367 `peb` + 78 `kuser_shared_data` |
| `kuser_shared_data_0x7FFE0260` | 286 | `kuser_shared_data` |
| `kuser_shared_data_0x7FFE0270` | 137 | `kuser_shared_data` |
| `kuser_shared_data_0x7FFE026C` | 9 | `kuser_shared_data` |
| *(nincs token)* | 2 299 | 342 `code_address` + 1 957 `memory_indirect` |

A négy KUSER_SHARED_DATA-cím a `12` §6.3-ban felsorolt négy cím halmaza. A `peb_gs_disp_0x30` token 445 sorban jelenik meg, miközben a `peb` kind csak 367 sorban: a `symbolic_operand` a lánc **első** szimbolikus bejegyzése, nem feltétlenül a döntő kind. A 78 olyan `kuser_shared_data` site, amelynek láncában a PEB-load érkezik előbb, és a KUSER_SHARED_DATA-olvasás dönt később. Ez a `symbolic_origin` mező definíciójából következik, nem adatokonzisztenciahiba.

### 9.3 A `svc_kind` × `service_class` mátrix

| `service_class` | `memory_indirect` | `kuser_shared_data` | `peb` | `code_address` | összes |
|---|---:|---:|---:|---:|---:|
| `other` | 1 630 | 757 | 286 | 174 | 2 847 |
| `transfer_5arg` | 253 | 156 | 70 | 154 | 633 |
| `process_information_basic` | 39 | 29 | 9 | 1 | 78 |
| `process_information_debug` | 15 | 6 | 0 | 3 | 24 |
| `allocation_0x1000_0x40` | 4 | 4 | 0 | 8 | 16 |
| `process_information_instrumentation_callback` | 5 | 3 | 0 | 0 | 8 |
| `wrapper_forwarding` | 11 | 6 | 2 | 2 | 21 |
| **összes** | **1 957** | **961** | **367** | **342** | **3 627** |

Egyetlen anchor-csoport nem kind-koncentrált: a szolgáltatás- és az argumentumalak-csoport egymástól független szelet, és a négy producer-kind minden osztályban jelen van. Ez további bizonyíték arra, hogy a producer-kind és az argumentum-alak két külön mérés, amelyeket sem a service mapping, sem a mapping-elégtelenség nem dönt el.

### 9.4 A lánc utolsó bejegyzése

A `producer_chain` cella a séma szerint a 320 karakteres limit eléréséig `...`-lal végződik. **873** sor (24,06 %) ilyen, ezért az alábbi táblázat csak a 2 754 nem csonkolt sorra teljes:

| `svc_kind` | `address:lea` | `image_slot` | `register_indirect` | `kuser_shared_data` | `peb` | `no_live_def` | egyéb foldolható | csonkolt cella |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `memory_indirect` | 106 | 42 | 1 267 | – | – | 11 | 292 | 239 |
| `kuser_shared_data` | 13 | 3 | 51 | 178 | 101 | – | 60 | 555 |
| `code_address` | 220 | 88 | – | – | – | – | 16 | 18 |
| `peb` | – | 4 | – | – | 252 | – | 50 | 61 |
| **összes** | **339** | **137** | **1 318** | **178** | **353** | **11** | **418** | **873** |
| **ellenőrzés** | | | | | | | | 2 754 nem csonkolt + 873 csonkolt = **3 627** |

A `code_address` 342 sora esetén 220 `address:lea`, 88 `image_slot`, 18 csonkolt cella és 16 foldolható `mov`/`xor` bejegyzés a lánc utolsó eleme. A `peb` 367 sora nem mutat `address:lea`-t és nem mutat regiszter-indirekt gyökért: 252 `peb`, 50 egyéb foldolható, 4 `image_slot` és 61 csonkolt. A 11 `no_live_def` gyökér és a 418 egyéb foldolható gyökér nyitott vagy határon megálló láncvéget jelez, nem nevesített szolgáltatást.

### 9.5 A foldolható opkódok és a négy ablak-határ

A konstans-foldolás **21** mnemonikát ismer: `adc`, `add`, `and`, `bswap`, `dec`, `imul`, `inc`, `neg`, `not`, `or`, `rol`, `ror`, `sal`, `sar`, `sbb`, `shl`, `shld`, `shr`, `shrld`, `sub`, `xor` – és a producer külön kiegészítő halmazként kezeli az `shld`/`shrld` kettőt és a `not`/`neg`/`inc`/`dec`/`bswap` unary ötöt. A 3 627 `producer_text` token 10 különböző mnemonikára esik: `xor` 2 233, `mov` 465, `imul` 208, `not` 201, `shr` 192, `sub` 130, `add` 86, `lea` 82, `bswap` 28, `or` 2.

Négy határ szabályozza, mi számít élő definíciónak:

1. egy `call` után a volatile regiszterek definiálatlanok, ezért a window utolsó `call`-ja előtti `RAX`-definíció nem az élő érték;
2. egy feltétel nélküli jump vagy egy `ret` lezárja a lineáris utat, ezért az utolsó ilyen előtti definíció nincs a candidate útján;
3. egy read-modify-write szigorúan a saját utasítása előtt olvassa az akkumulátort, tehát a lánc nem záródik önmagára;
4. egy `cmov` és társai csak egy élen definiálnak, ezért a legközelebbi határozott definíció dönt, a feltételes pedig `conditional_merge`.

A lánc lineáris és korlátos. A `CHAIN_MAX_DEPTH = 10` a **regiszter-másolási** ugrásokra vonatkozik, nem a lánc hosszára. **374** sor tartalmaz `depth_limit:` tokent a láncban; ezek közül 53-ban ez az utolsó *látható* token, de mind az 53 csonkolt, 320 karakteres cella, ezért a valódi gyökér-token a vágás miatt nem különíthető el. A 2 754 teljesen látható lánc között **nulla** `depth_limit` gyökér van, és 2 sorban szerepel a token nem gyökérként. A windowon kívüli ágon távozó definíció és a 10 ugrásnál mélyebb másolási lánc `register_undefined` kindként beszámolódik, és nem állítható teljesnek.

### 9.6 A két hisztogram 16 vödörös kivágása

A payload két hisztogramot publikál, mindkettőt a producer saját `_histogram(values, limit=16)` segédje vágja a **16 legkisebb** kulcsra:

| Hisztogram | Publikált vödörök lefedett site | Hiányzó |
|---|---:|---|
| `chain_length_histogram` (láncbejegyzések száma) | **2 238** (1–16 hossz) | **1 389** site 17 vagy hosszabb lánccal, nem publikált |
| `sweep_depth_instructions_64_buckets` | **1 149** (0–960 utasítás) | **2 478** site legalább 1 024 elsweepelt utasítással, nem publikált |

A `chain_length_histogram` a **nyers** `len(item.chain)` értéket számolja, míg a CSV `producer_chain` cellája a séma szerint **de-duplikálja** a látogatási sorrendet; ezért a cellából visszaszámolt látható hop-szám nem azonos a hisztogram értékével. A 320 karakteres cellakorlát 873 sort csonkolt, tehát a 2 754 teljes cella sem ad pontos lánchosszat. A rekurzív séma önmagában **egyetlen** `+N_more` tokent sem írt ki, tehát a 24 bejegyzésos sémakorlát egyszer sem volt döntő.

A `sweep_depth` magyarázata a payloadban: ez a candidate előtt elsweepelt utasítások száma 64-es blokkokra kerekítve, 4 096-ig kerekítve. **Ez a bizonyíték arra, hogy a producer-lánc nem fér a `P0/S7` 20–40 bájtos argumentumablakába**, ezért az `S8` a teljes owning pdata/CFG ablakot járja végig. A sweep-mélység leképezése valójában egy `bisect`-tel kiszámolt owning function-előtag, tehát a 4 096 csak a vödörözés korlátja, nem elemzési költségvetés.

**A 16 vödörös vágás újraszámolva `[P]`:** a finding a jelenlegi forrásból és a lemezen lévő `E5` payloadból változatlanul igazolódik, a számok nem módosultak.

| Ellenőrzés | Forrás | Érték |
|---|---|---|
| A vágó segéd definíciója | `syscall_service_map.py:1645` – `_histogram(values, limit=16)` a `sorted(values)[:limit]` kulcsokon vág, tehát a 16 legkisebbet tartja meg | 16 kulcs |
| A lánchossz forrása | `syscall_service_map.py:1697` – `Counter(len(item.chain) …)`, a nyers lánchossz, nem a cellában csonkolt érték | nyers |
| A sweep-vödör képlete | `syscall_service_map.py:1698` – `min(item.sweep_instructions // 64 * 64, 4096)` | 64-es blokk, 4 096-es korlát |
| `chain_length_histogram` 16 kulcsának összege | E5 | **2 238** |
| A lánchossz-bontás teljes | `2 238 + 1 389` | **3 627** |
| `sweep_depth_instructions_64_buckets` 16 kulcsának összege | E5 | **1 149** |
| A sweep-mélység-bontás teljes | `1 149 + 2 478` | **3 627** |
| A nem publikált sweep-vödörök mind `≥ 1 024` | a 17. kulcs a `1024` blokk, onnan a `4096` korlátig | 2 478 site |
| A 320 karakteres cellakorlát által csonkolt `producer_chain` cella | E4 `producer_chain` | 873 |
| `+N_more` token a láncban | E4 `producer_chain` | **0** – a 24 bejegyzéses sémakorlát egyszer sem volt döntő |

---

## 10. A 3 627 `UNRESOLVED` eredmény és miért legitim

### 10.1 A gate sorrendje

A naming gate öt kimenettel rendelkezik, és **sorrendben** dönt:

| # | Feltétel | `nt_service` | `nt_confidence` | `status` |
|---:|---|---|---|---|
| 1 | a sweep nem érte el a candidate-et | `UNRESOLVED` | `none` | `unresolved_sweep_unreached` |
| 2 | `register_undefined` és nincs producer RVA | `UNRESOLVED` | `none` | `unresolved_no_producer` |
| 3 | a kind **nem** `static_constant` | `UNRESOLVED` | `none` | **`unresolved_symbolic_service_number`** |
| 4 | `static_constant`, de a csoportnak nincs sémát adó anchorja | `UNRESOLVED` | `none` | `unresolved_schema_insufficient` |
| 5 | `static_constant` **és** a sémát adó anchor | a csoport hipotézise | `static_constant_schema_sufficient` | `named` |

A 3 627 sor mind a **3. kimenetet** kapja. A gate tehát a névágat **egyetlen egyszer sem éri el**: a 4. és az 5. kimenet egyetlen site-on sem értékelődött ki.

### 10.2 Miért nincs `static_constant`

A `RAX` lánc 3 627 site-on mindig vagy szimbolikus operandon, vagy tiltott operandtípuson áll meg, vagy határon. A `static_constant` kindhez foldolható konstans utasításszintű operand kellene minden köztes értéken. Ez a specimen kódkeverése mellett nem következik be egyetlen helyen sem: a szolgáltatásszám `KUSER_SHARED_DATA`-ból, PEB-ből, `gs:[0x30]`-ból, titkosított image slotokból és `RDTSC`-diszperzióból képződik.

### 10.3 A nulla eredmény tíz független megerősítése

| Ellenőrzés | Forrás | Érték |
|---|---|---|
| `static_service_numbers` | E5 `service_number` | `{}` – üres |
| `static_service_number_sites` | E5 `service_number` | `0` |
| `naming_gate.named_rows` | E5 | `0` |
| `naming_gate.by_nt_service` | E5 | `{"UNRESOLVED": 3627}` |
| `naming_gate.by_status` | E5 | `{"unresolved_symbolic_service_number": 3627}` |
| `naming_gate.by_nt_confidence` | E5 | `{"none": 3627}` |
| `service_number=0x…` tokent hordozó sor | E4 `mapping_basis` | **0** |
| `nt_service != UNRESOLVED` sor | E4 | **0** |
| `nt_confidence != none` sor | E4 | **0** |
| `nt_service_status` | E4 | mind `UNRESOLVED_NOT_ATTEMPTED` |

A `named_rows_have_a_static_service_number`, `named_rows_have_a_sufficient_schema`, `no_sufficient_static_row_left_unnamed` és `named_count_agrees_with_the_rows` ellenőrzés mind `expected 0 / actual 0 / ok true`. Vagyis a gate **nem hagyott le** névra alkalmas sort: nincs olyan sor, amelynek statikus szolgáltatásszáma és sémája lett volna, és mégis névtelen maradt.

### 10.4 A producer hipotézistáblája elérhetetlen

A producer `SERVICE_HYPOTHESIS` térképe a payloadban `service_hypothesis_by_class` néven publikálva van, és három information-class csoporthoz rendel egy-egy szolgáltatásnevet. Ez a táblázat **konfiguráció, nem kimenet**:

- a gate 3. kimenete az 5. előtt fut le, tehát a táblázat egyetlen eleme sem kerül kiértékelésre;
- egyetlen sor sem viseli ezeket a neveket;
- az `S8` saját korlátlistája a nevet szolgáltatásszám-fold nélkül nem adható.

A dokumentum ezt a konfigurációt azért említi, hogy a `12` 9. fejezete 3. pontjának open questionje (`Mely Nt/Zw szolgáltatások a 12 validált wrapperhez tartoznak?`) láthatóan **a megfelelő fázisban** lett feltevés, és a válasz `0 név` lett. A szolgáltatásnevek itt **nem** kerülnek azonosításként használatra. `CONF:U`, `STATUS:OPEN`.

### 10.5 Az audit service-provenance osztályai – miért nem ellentmondás

A `P0/S6` audit külön, 8 utasításos **korlátolt visszafelé** ablakban vizsgálta a service-szám eredetét, és egy három osztályból álló osztályozást adott. Ez **nem** adatfolyam-bizonyítás, hanem egy oldhatósági jel:

| Provenance osztály | Valid halmaz (3 627) | A 64 dokumentált anchor (64) |
|---|---:|---:|
| `constant_immediate_in_window` | 1 439 | 37 |
| `register_or_memory_derived_in_window` | 1 210 | 25 |
| `no_eax_definition_in_window` | 978 | 2 |
| **összes** | **3 627** | **64** |

A `constant_immediate_in_window` 1 439 site **nem** nevezhető meg service-nek, mert:

1. más csatorna: a 8 utasításos ablak a candidate közvetlen környezete, az `S8` viszont a teljes owning function prefixét járja;
2. más cél: a konstans az `RAX` környezetében van, nem egy service-számként felismerhető utasításszintű töredékben;
3. a nyitott kérdés explicit: **a konstansok stabil service-számok-e, vagy csak build-seedek** – ezt statikusan nem lehet eldönteni.

A 2. osztály (1 210) esetén a keverési lánc a `KUSER_SHARED_DATA`-t, a PEB-et és a globális konstansokat olvassa, vagyis pontosan azok a csatornák, amelyeket az `S8` szabály szerint szimbolikus ismeretlennek tekint. A 3. osztály (978) esetén nincs `RAX`-definíció a 8 utasításban, tehát a szám magasabban vagy más úton képződik.

Az audit lezáró mondata: **minden site unresolved; ez az audit nem állít service-nevet, és a provenance osztály oldhatósági jel, nem mapping**.

### 10.6 A payload öt nyitott kérdése a service mappingre szűkítve

1. melyik Nt/Zw szolgáltatáshoz tartozik az `R10`/`EDX`/`R8`/`R9` argumentumkészlet;
2. a konstans provenance osztály immediátjai stabil service-számok-e, vagy csak build-seedek;
3. a derived osztályok hogyan számítják a számot – ehhez a `KUSER_SHARED_DATA`-t, a PEB-et és a globális konstansokat olvassó keverési lánc kellene;
4. a valid bejegyzések közül melyik érhető el egyáltalán – ezt a proof level split nyitva hagyja a 3 384 sweep-only bejegyzésre;
5. az a tíz dokumentált site, amely ugyanazzal a runtime functionnel osztozik egy dokumentált parent PID olvasással, ugyanaz-e a service, mint a process memory site-ok.

### 10.7 A sorszintű mapping-ellenőrzések

| Ellenőrzés | Várható | Tényleges | OK |
|---|---:|---:|---|
| `row_count` | 3 627 | 3 627 | true |
| `s7_columns_preserved` | 100 | 100 | true |
| `column_count_at_least_s7` | 100 | 106 | true |
| `no_duplicate_columns` | 106 | 106 | true |
| `rows_in_raw_offset_order` | true | true | true |
| `hit_index_is_a_permutation` | 3 627 | 3 627 | true |
| `sweep_reached_every_site` | 3 627 | 3 627 | true |
| `raw_hit_rows` | 3 881 | 3 881 | true |
| `valid_candidate_rows` | 3 627 | 3 627 | true |
| `cfg_function_rows` / `runtime_functions` | 142 004 | 142 004 | true |
| `kuser_shared_data_and_peb_rows_stay_unresolved` | 0 | 0 | true |
| `no_symbolic_operand_without_a_symbolic_kind` | 0 | 0 | true |
| `symbolic_kinds_name_their_operand` | 0 | 0 | true |
| `buffer_rows_carry_the_reconciliation_marks` | 1 534 | 1 534 | true |
| `allocation_write_never_exceeds_buffer_positions` | 0 | 0 | true |
| `all_checks_passed` | true | true | true |

---

## 11. A 21 `wrapper_forwarding` predikátum scope-korlátja

### 11.1 A pontos predikátum

```text
all(argument_class(row, position) == A6_SELF_HANDLE for position in 1..4)
```

azaz `arg1_class`, `arg2_class`, `arg3_class` és `arg4_class` mind `A6_SELF_HANDLE`. A `service_class` függvényben ez a **8.** szabály, tehát a kilencedik (`no_anchor`) előtt értékelődik, és csak a korábbi hét anchor után megmaradó maradékot jelöli.

### 11.2 A négy scope-korlát

**(1) Csak az 1–4. pozíciót fogja.** A predikátum a `range(1, 5)`-öt nézi, vagyis a négy regiszterpozíciót (`R10`, `RDX`, `R8`, `R9`). Az 5. és 6. pozíció – `[RSP+0x28]` és `[RSP+0x30]` – **nincs** a predikátumban, és teljesen független marad. A 21 sor kétféle sémát mutat:

| Kompakt séma | Site | 5. pozíció | 6. pozíció |
|---|---:|---|---|
| `A6+A6+A6+A6+A3+A5` | 16 | `A3_OUT_BUF` | `A5_STACK_SLOT` |
| `A6+A6+A6+A6+A5+A5` | 5 | `A5_STACK_SLOT` | `A5_STACK_SLOT` |

Egyik esetben sem az 5. vagy 6. pozíció állítja a csoporttagságot; a négy regiszter pozíció egyedül is elegendő volt. A 16 sorban az 5. pozíció ráadásul egy feloldott adatcím, tehát a teljes hat pozíciós alak egy része ténylegesen feloldott – de ezt a predikátum nem értékeli, és a 6. pozíció mindkét sémában feloldatlan marad.

**(2) Maradék, nem elsőbbségi szabály.** Az `information_class`, az `allocation` és a `transfer_5arg` anchor előbb értékelődik. Mivel az `A6_SELF_HANDLE` beletartozik a `RESOLVED_ARGUMENT_CLASSES` halmazba, egy olyan site, amelynek első öt pozíciója mind feloldott, legalább egy bufferes és legalább egy `A4_LEN`-es, `transfer_5arg` névre kap, **nem** `wrapper_forwarding`, még ha a négy regisztere forwarding is. A 21 így a korábbi anchorok után megmaradó maradék, nem egy önálló census.

**(3) Alak-állítás, nem feloldás.** Az `A6_SELF_HANDLE` azt mondja, hogy az értéklánc a owning függvény entry paraméterénél végződik. A predikátum ezzel a kérdést **átadja** a hívó rétegének: a sémát a hívó tulajdonolja. A sor nem nevez meg hívót, nem nevez meg szolgáltatást, és nem állítja, hogy a stub maga végrehajtja a szolgáltatást. Ezért a csoportleírás szövege is így fogalmaz: *az argumentumséma a hívó rétegéhez tartozik*.

**(4) A 21 nem forwarding stub census.** A 21 sor 7 owning functionben van:

| Owning function | Site |
|---|---:|
| `0x291BE60` | 8 |
| `0x291CAC0` | 8 |
| `0x2950CD0` | 1 |
| `0x2950E50` | 1 |
| `0x2951000` | 1 |
| `0x29511B0` | 1 |
| `0x2951310` | 1 |

Argumentumszinten viszont a corpus **1 108** `A6_SELF_HANDLE` argumentumot tartalmaz **676** site-on, vagyis **32-szor** nagyobb a populáció. A 21 tehát sem a forwarding-jelű site-ok, sem a forwarding-jelű argumentumok száma; kizárólag azoké a site-oké, ahol mind a négy regiszter pozíció `A6`.

### 11.3 A közvetlen ellenőrzés

Ezt a dokumentum a fájlon újraszámolta, nem a payloadra hagyatkozik: a `syscall_inventory.csv`-ban azok a site-ok száma, ahol `arg1_class`, `arg2_class`, `arg3_class` **és** `arg4_class` mind `A6_SELF_HANDLE`, azaz **21** – pontosan a `service_class = wrapper_forwarding` oszlop értéke. A 676 site-on legalább egy `A6` van a hat pozíció bármelyikében; a pozíciónkénti `A6` darabszám 383 / 321 / 201 / 195 / 0 / 8. `CONF:P`.

```text
BRef = [RVA:0x291C08F | RAW:0x291B48F | CONF:P | STATUS:OBSERVED]   # A6 x4 + A3 + A5
BRef = [RVA:0x2950E2E | RAW:0x295022E | CONF:P | STATUS:OBSERVED]   # A6 x4 + A5 + A5
BRef = [RVA:N/A | RAW:0x0 | CONF:U | STATUS:OPEN]                   # melyik hívó birtokolja a sémát
```

### 11.4 A 12 validált `0xC856C0` wrapperrel való konzisztencia

A független `E10` `audit_handle_flow.json` a 21-es csoportot külön is újraszámolja, és kimondja, hogy a `0xC856C0` 12 validált wrapperének **egyik site-ja sem** a 21-ben van. A két megállapítás nem mond ellent egymásnak; a diszjunktság oka a 11.2. pont (1) alattjának közvetlen következménye, és a `E4` korpuszán ezen a dokumentumban is újramérhető:

| Ellenőrzés | Forrás | Érték |
|---|---|---:|
| A 12 wrapper site-ja a 3 627-es korpuszban van | E4 `hit_index` 92–97 és 890–895 | 12 / 12 |
| A 4. pozíció osztálya | E4 `arg4_class` | `A7_REG_INDIRECT` 12 / 12 |
| Az 1. pozíció osztálya | E4 `arg1_class` | `A6_SELF_HANDLE` 10, `A8_UNKNOWN` 2 |
| A 2. és 3. pozíció osztálya | E4 `arg2_class`, `arg3_class` | `A6_SELF_HANDLE` 12 / 12 |
| Az 5. és 6. pozíció osztálya | E4 `arg5_class`, `arg6_class` | `A5_STACK_SLOT` 12 / 12 |
| A tüzelő anchor | E4 `mapping_basis` | `no_anchor` 12 / 12 |
| A service-osztály | E4 `service_class` | `other` 12 / 12 |
| A státusz | E4 `status` | `unresolved_symbolic_service_number` 12 / 12 |
| A 21 és a 12 owning function halmazának metszete | E4 `cfg_function_begin_rva_hex` | **0** |
| A 21 és a 12 site halmazának metszete | E4 `rva_hex` | **0** |

A 12 wrapper a 4. pozíción bukik el, és az `A7_REG_INDIRECT` a fázis saját szabálya szerint szimbolikus ismeretlen; az 1. pozíció ráadásul 2 wrappernél maga is elbukik (`0x51D84C` és `0x51DFC5`, `A8_UNKNOWN`). Ezért mind a 12 a `no_anchor` maradékba, azaz az `other` osztályba kerül, és egyik sem kerülhet a 21-be. A `P0/S8` saját osztályrendje is ezt teszi lehetővé: a `transfer_5arg` anchor az ötödik pozícióig néz, tehát a két `A5_STACK_SLOT` miatt eleve nem tüzelhet.

A 21 tehát sem a 12 wrapper, sem a 16 inline allokációs/átviteli site censusének nem része; az `E10` a 21-et a 12 wrappertől, a 16 inline sitetól és a `0xC85000`–`0xC88000` kódklasztertől is diszjunktnak mondja. A `14` §9.1 szerinti forwarding-elve – a hívó argumentum `n` a syscall argumentum `n-1`-re csomagolódik – rétegek között továbbra is érvényes, de a 21-re nem ad számszerű állítást. `CONF:P` a számokra, `CONF:U` arra, hogy a 12 wrapper melyik hívója birtokolja a sémát.

---

## 12. A service mapping sikertelen lezárása legitim eredmény

### 12.1 Miért eredmény és nem hiányosság

| Szempont | Értékelés |
|---|---|
| A gate sorrendje | mind a 3 627 sor a 3. kimeneten áll meg, tehát az 5. kimenet (a névágat) sosem fut le: nincs névra alkalmas sor, amit elmulasztottunk |
| Ellenőrző invariáns | `no_sufficient_static_row_left_unnamed = 0` – a gate nem hagyott önkényesen névtelen sort |
| Önkényes név tiltása | a naming gate csak `static_constant` foldot és dokumentált információs osztály konstansot fogad el |
| Payload-szintű korlátok | a `static_constant` fold feltétele, a 21 foldolható opkód és az 5 szimbolikus tiltás mind explicit |
| Reprodukálhatóság | mind a 28 `S8` ellenőrzés átment; az 5 gate-kimenetből 4 statisztikailag 0, egyedül a 3. az aktív |

Egy service mapping, amelyet a specimen kódkeverése miatt nem lehet lezárni, **helyes kimenet**. A hiba az lenne, ha 0 helyett név lenne a cellákban.

### 12.2 Mi változatlan marad a 06, 07 és 12 dokumentumokból

| Megállapítás | Forrás | Státusz a `P0/S8` után |
|---|---|---|
| A `0xD7A400` három `0F 05` helye valódi utasításstart a `.pdata` határon belül | `06` §4.1, `07` §3.1 | **érvényes** – mindhárom a valid 3 627-ben |
| `R10=-1`, `EDX=0`, `R9D=0x30`, 5. argumentum nulla | `06` §4.1, `07` §3.1 | **érvényes** – az `S7` cellái ezt az értéket adják |
| `buffer+0x28` → `OpenProcess(0x1000, FALSE, parentPid)` | `06` §4.2, `07` §3.2 | **érvényes** – a service mapping nem érinti |
| A `0x293D370` 8 közvetlen class `0x28` ága + 6 segédrutin | `07` §3.4 | **érvényes** – az anchor-csoport pontosan a 8 közvetlen ágat azonosítja |
| A `ProcessDebugPort/DebugObjectHandle/DebugFlags` 8+8+8 ág | `07` §3.3 | **érvényes** – mind a 24 az anchor-csoportban van |
| A `0xC856C0` 16 inline syscall és 12 wrapper | `14` §C-01 | **érvényes** – a 8 allokációs ág az `allocation_0x1000_0x40` csoportban |
| A service number futásidőben, `KUSER_SHARED_DATA`/PEB/konstans keverésből képződik | `06` §9.2, `11` §4.6, `12` §6.3 | **megerősítve** – mind a 3 627 helyen tiltott operandon álló lánc: 1 957 regiszter-indirekt + 1 328 szimbolikus ismeretlen + 342 `code_address` |
| A 3 881 nyers találat nem szolgál utasításlistaként | `12` 8. fejezete 5. pontja | **érvényes és pontosított** – a felbontás 3 627 / 209 / 45 a CSV scope-on, +30 a scope-on kívül |

### 12.3 Amit ez a fázlsor hozzáadott

1. a nyers `3 881` találat teljes, reprodukált felbontása valid utasításstartokra;
2. a 3 627 site mindegyikéhez hat argumentumosztály, 21 762 argumentum;
3. a service-szám producer-láncának strukturált feltevése minden site-on, `svc_producer_rva`-val és lánccel;
4. a négy producer-kind cenzusa és az 1 328 szimbolikusan ismeretlen operand;
5. a 9 anchor-csoport teljes, átfedés nélküli partíciója;
6. a 0 `allocation_to_write` rétegközi, számtanilag kikényszerített magyarázata és a 1 534 sor jelölése;
7. a 3 627 `UNRESOLVED` sor **gatespecifikus** oka, nem pusztán egy hiányzó lépés.

### 12.4 Amihez további fázis kellene – és nem tartozik ide

Egy Nt/Zw service mapping lezárásához a `KUSER_SHARED_DATA` és PEB értékek futásidejű ismerete, a `CHAIN_MAX_DEPTH`on túlmenő keverési lánc, vagy a 3 384 sweep-only site control-flow-bizonyítása szükséges. Ezek bármelyike a jelen fázis scope-ján kívül esik, és egyik sem alapozható meg a `Dumper - AllInOne` projekt statikus eszközláncával ebben a fázisban. A `14` §17 és a `12` 9. fejezete 3. pontjának open questionje változatlanul **open**.

---

## 13. A `syscall_service_map.py` korlátai, változatlanul

A payload `limitations` listájából, csoportosítva:

**Vizsgálati határ**

1. A specimen csak fájlként parse-olt: semmi nem betöltve, végrehajtásra nem mapolva, nem patch-ölve és nem futtatva; egyetlen megfigyelés sem futásidejű megfigyelés.
2. A fázis nem ad exploitot, bypass-t és patch-receptet, és egyetlen evidence-cella sem ilyen.

**A szolgáltatásszám csatorna korlátai**

3. A service szám **csak** a `RAX` producer-láncból olvasódik. Ha egy dispatcher callee-ben számolja ki és visszaadja a számot, vagy futásidőben épített táblát indexel, az nem követődik; az így kapott szám unresolved marad.
4. A `KUSER_SHARED_DATA` és PEB olvasás szabály szerint szimbolikus ismeretlen. Fájbeli értékük nincs, ezért az ezekből levezetett szám nem statikus tény, és nincs hozzá név.
5. A frame- vagy stack-relatív operand, a regiszter-indirekt operand és a `lea`-vel előállított kódcím mind külön kind, és mindegyik blokkolja a nevet. A site által a saját hívójától átadott buffer ezért a hívó rétegének sémájával leírt, amit az anchor-csoportok jelölnek, nem oldják.
6. A láncmenet lineáris és korlátos. Az ablakon kívüli ágon távozó definíció, illetve a `CHAIN_MAX_DEPTH`on túlmenő lánc `register_undefined` vagy `opaque_instruction` kindként beszámolódik, és nem állítható teljesnek.
7. Az első stack argumentum `[RSP+0x28]` anchorja a **callhely** `P0/S7` tulajdonsága, nem a candidate-é, és az argumentumablak `P0/S7` korlátai változatlanul öröklődnek az innen olvasott sémára.

**Szemantikai és modellkorlátok**

8. Az anchor-csoportokat kulcsoló információs osztály értékek a dokumentált nyilvános `PROCESSINFOCLASS` értékek. Csoportosítási konstansként használódnak, és a csoportcímke alakról szóló hipotézis, nem az elért szolgáltatás azonosítása.
9. Egy global slot fájlbeli értéke a relokációs tábla `DIR64` fixupjaival korrigált érték, vagyis a preferált bázison történő betöltést modellezi. Egy másik modul vagy egy runtime inicializáló betöltés után felülírt slot nincs látva.

---

## 14. Bounded negatív findingok

| # | Finding | Scope | Módszer | Conf. | False-negative korlát | BRef |
|---|---|---|---|---|---|---|
| N-01 | **Nincs statikus service mapping** a 3 627 site egyikére sem | A 3 627 valid candidate, a teljes owning pdata/CFG ablak, `RAX` producer-lánc | 21 foldolható opkód, 5 szimbolikus tiltás, 5 kimenetes gate | P a számra, U a szolgáltatásra | Külső táblázat, callee-ben számolt és visszaadott szám, futásidőben kevert konstans, másik modul keverése | `[RVA:N/A \| RAW:0x0 \| CONF:P \| STATUS:NEGATIVE]` |
| N-02 | **Nincs `static_constant` service szám** | Ugyanaz | `svc_kind` cenzus | P | Egy 10 másolási ugrásnál sekélyebb, tisztán foldolható lánc, amely éppen nem ebben a 3 627 halmazban van | `[RVA:0x3D5091 \| RAW:0x3D4491 \| CONF:P \| STATUS:NEGATIVE]` |
| N-03 | **Nincs allokátor-hívás** a 3 627 ablakban | 3 627 site × 40 bájt, 448 owning function | `allocation_calls` oszlop és `allocation_origins.by_symbol` | P | Allokáció a hívó frame-jében, wrapperen át, vagy a 40 bájton kívül | `[RVA:N/A \| RAW:0x0 \| CONF:P \| STATUS:NEGATIVE]` |
| N-04 | **Nincs `A3_INOUT_BUF`** | 21 762 argumentum | 9 rangú osztálylétra, 7 ablakon belüli rw pár | P | Egy külső call által kitöltött buffer, amelynek pointerje az ablakon kívül keletkezik | `[RVA:0xD7B0AE \| RAW:0xD7A4AE \| CONF:P \| STATUS:NEGATIVE]` |
| N-05 | **Nem futtatható szekcióban nincs `syscall` utasítás** | Mind a 7 szekció, mind a 3 911 nyers találat | Szekció characteristics és runtime function lefedettség | P | Bármilyen későbbi betöltési szakasz, amely a statikus szekcióhatárokat felülírja | `[RVA:0x2C065E4 \| RAW:0x2C04FE4 \| CONF:P \| STATUS:NEGATIVE]` |
| N-06 | **Nem futtattuk a specimen** | A teljes fájl | A scope explicit: csak statikus parse | P | Semmi – ez a fázis korlátja, nem megfigyelés | `[RVA:N/A \| RAW:N/A \| CONF:P \| STATUS:NEGATIVE]` |

---

## 15. Nyitott kérdések

Prioritás szerint, a `12` §9 prioritizálását követve.

**P0 – a service mapping lezárásához**

1. **Lezárható-e a 12 validált wrapper és a `0xC856C0` 32 ágának service szintje?** Ehhez a `KUSER_SHARED_DATA` és PEB értékek szimbolikus kezelése és a keverőlépések offline kiértékelése kellene. A jelen fázis 1 670 site-on tiltott operandon áll meg; a maradék 1 957 `memory_indirect` site lezárásához a mutatócél futásidejű feloldása kellene, ami ebből a fájlból nem elérhető.
2. **A `constant_immediate_in_window` 1 439 site immediate-jei stabil service-számok vagy build-seedek?** Ez a `P0/S6` audit első osztálya, és a `P0/S8` nem tudta lezárni, mert más csatornát és más célt használt.
3. **A 3 384 sweep-only site melyike érhető el?** Ehhez a `0x293D*` / `0x51D*` / `0xC8F*` szerkezetű diszperziós ágak vezérlőátadás-feloldása kellene. A bizonyított 243 site a 3 627 **6,70 %**-a, vagyis az elérhetőségi arányra ez egy **alsó korlát**, nem becslés. A 64 dokumentált helyből 20 fallthrough-bizonyított és 44 csak sweep-hipotézis, tehát a dokumentált helyek 68,75 %-a is a nem bizonyított 93,30 %-ból kerül ki.

**P1 – a scope-korlátok szűkítésére**

4. **A 21 `wrapper_forwarding` site melyik hívója birtokolja a sémát?** A predikátum 4 pozíciót fog, és a hívó rétegét nevezi meg tulajdonosként anélkül, hogy megnevezné. A 676 site-os `A6` argumentumpopuláció 32-szor nagyobb, mint a 21; a forwarding-jelű site-ok teljes censuséhez az entry paraméter csatornát caller-irányban kellene folytatni.
5. **A `0xE48B60` 8 site a `0xC856C0` allokációs klaszter második halmaza?** A `constants_0x1000_and_0x40` anchor 16 site-ból áll, és 8 a `0xC856C0` ismert 8 közvetlen allokációs ága, 8 pedig egy külön függvényben. Az anchor a konstanspárra kulcsol, nem a függvényre, ezért a klaszter-határ nincs lezárva.
6. **A `process_information_basic` 78 site bármelyike kapcsolódik-e a `0xD7A400` három helyhez?** A 78 site 11 owning functionben van, és a `0xD7A400` egyikben sincs. A három hely jelenleg azért marad `other`, mert a 3. pozíció `A7_REG_INDIRECT`; ha egy későbbi ablakfejlesztés azt `A3_OUT_BUF`-nak feloldaná, a 4. feltétel teljesülne, és a három hely a `process_information_basic` csoportba kerülne.

**P2 – kontextuális megerősítés**

7. **Korrelálható-e a PDB egy hivatalos `1.0.0.36109` builddel?** Változatlanul a `12` 9. fejezete 5. pontjának kérdése; a syscall-inventory nem ad hozzá új bizonyítékot.
8. **A `14` §17 szerinti nyolc nyitott kérdés változatlanul open**, köztük a handle producer, a 16-ágú dispatch szolgáltatás-egyenértékűsége és a hook/patch cél-aktiválás.

---

## 16. BRef-katalógus

A katalógus a `00` index 7. fejezete szerinti kanonikus `[RVA | RAW | CONF | STATUS]` mezőket használja. Nagy CSV-fájlokból nem másolunk sort; minden hivatkozás `hit_index`-szel együtt olvasható.

| ID | Finding | BRef |
|---|---|---|
| **B15-01** | Nyers `0F 05` census: `.text` 3 881, összes szekció 3 911 | `[RVA:0x1000 \| RAW:0x400 \| CONF:P \| STATUS:OBSERVED]` |
| **B15-02** | Valid felbontás 3 627 / 209 / 45 a `.text` scope-on | `[RVA:N/A \| RAW:0x0 \| CONF:P \| STATUS:OBSERVED]` |
| **B15-03** | 30 nem végrehajtható szekcióbeli találat (27 `.rdata`, 3 `.data`) | `[RVA:0x2C065E4 \| RAW:0x2C04FE4 \| CONF:P \| STATUS:OBSERVED]`; `[RVA:0x315E092 \| RAW:0x315CA92 \| CONF:P \| STATUS:OBSERVED]` |
| **B15-04** | `covered_by_instruction` 209, 12 mnemonika szerinti bontásban | `[RVA:0x3E754 \| RAW:0x3DB54 \| CONF:P \| STATUS:OBSERVED]`; `[RVA:0xCDD5D \| RAW:0xCD15D \| CONF:P \| STATUS:OBSERVED]` |
| **B15-05** | `no_pdata_function` 45: 25 alignment gap, 20 code island | `[RVA:0xA091C8 \| RAW:0xA085C8 \| CONF:P \| STATUS:OBSERVED]`; `[RVA:0x1128895 \| RAW:0x1127C95 \| CONF:P \| STATUS:OBSERVED]` |
| **B15-06** | Proof level: 243 fallthrough-bizonyított, 3 384 sweep-hipotézis | `[RVA:0xD7B0AE \| RAW:0xD7A4AE \| CONF:P \| STATUS:OBSERVED]`; `[RVA:N/A \| RAW:0x0 \| CONF:P \| STATUS:NEGATIVE]` |
| **B15-07** | Sweep-hipotézis kiváltója: 2 786 indirekt jump, 575 direkt jump, 23 terminátor | `[RVA:N/A \| RAW:0x0 \| CONF:P \| STATUS:OBSERVED]` |
| **B15-08** | 21 762 argumentumosztály, 8 osztály, `A3_INOUT_BUF = 0` | `[RVA:0x3D50BA \| RAW:0x3D44BA \| CONF:P \| STATUS:OBSERVED]` |
| **B15-09** | `A1_PSEUDO_HANDLE` 1 602, ebből 1 586 `current_process` | `[RVA:0x3D7B6B \| RAW:0x3D6F6B \| CONF:P \| STATUS:OBSERVED]` |
| **B15-10** | `A6_SELF_HANDLE` 1 108 argumentum 676 site-on | `[RVA:0x3D8F4C \| RAW:0x3D834C \| CONF:P \| STATUS:OBSERVED]` |
| **B15-11** | Ablakgeometria: 31–40 bájt, 4–13 utasítás; a 20 bájtos határ nem fordult elő | `[RVA:N/A \| RAW:0x0 \| CONF:P \| STATUS:OBSERVED]` |
| **B15-12** | A 7 `rw_pair` argumentum mind az 5. pozícióban, konstans `0` értékkel | `[RVA:0xD7A5F3 \| RAW:0xD799F3 \| CONF:P \| STATUS:OBSERVED]`; `[RVA:0xD7CBEE \| RAW:0xD7BFEE \| CONF:P \| STATUS:OBSERVED]` |
| **B15-13** | `allocation_to_write` 0, `allocation_origins.by_symbol` üres, 1 534 sor jelölve | `[RVA:N/A \| RAW:0x0 \| CONF:P \| STATUS:NEGATIVE]` |
| **B15-14** | 9 anchor-csoport, 1:1 a 7 `service_class` osztállyal, összeg 3 627 | `[RVA:N/A \| RAW:0x0 \| CONF:P \| STATUS:OBSERVED]` |
| **B15-15** | `process_information_debug` 24 sor a három top-level rutinban | `[RVA:0x293E263 \| RAW:0x293D663 \| CONF:P \| STATUS:OBSERVED]`; `[RVA:0x293F124 \| RAW:0x293E524 \| CONF:P \| STATUS:OBSERVED]`; `[RVA:0x293FFF4 \| RAW:0x293F3F4 \| CONF:P \| STATUS:OBSERVED]` |
| **B15-16** | `process_information_instrumentation_callback` 8 sor a 8 közvetlen ágon | `[RVA:0x293D4DE \| RAW:0x293C8DE \| CONF:P \| STATUS:OBSERVED]`; `[RVA:0x293E030 \| RAW:0x293D430 \| CONF:P \| STATUS:OBSERVED]` |
| **B15-17** | A `0xD7A400` három hely az `other` csoportban, a 4. feltétel miatt | `[RVA:0xD7B0AE \| RAW:0xD7A4AE \| CONF:P \| STATUS:OBSERVED]`; `[RVA:0xD7B4B9 \| RAW:0xD7A8B9 \| CONF:P \| STATUS:OBSERVED]`; `[RVA:0xD7C0AC \| RAW:0xD7B4AC \| CONF:P \| STATUS:OBSERVED]` |
| **B15-18** | A 6 class `0x28` segédrutin-hely az `other` csoportban | `[RVA:0x2941AC2 \| RAW:0x2940EC2 \| CONF:P \| STATUS:OBSERVED]`; `[RVA:0x29422AA \| RAW:0x29416AA \| CONF:P \| STATUS:OBSERVED]` |
| **B15-19** | `allocation_0x1000_0x40` 16 sor: 8 a `0xC856C0`-ban, 8 a `0xE48B60`-ban | `[RVA:0xC858E0 \| RAW:0xC84CE0 \| CONF:P \| STATUS:OBSERVED]`; `[RVA:0xC86420 \| RAW:0xC85820 \| CONF:P \| STATUS:OBSERVED]`; `[RVA:0xE491B6 \| RAW:0xE485B6 \| CONF:P \| STATUS:OBSERVED]` |
| **B15-20** | `wrapper_forwarding` 21 sor 7 owning functionben, négy regiszter pozícióra szűkítve | `[RVA:0x291C08F \| RAW:0x291B48F \| CONF:P \| STATUS:OBSERVED]`; `[RVA:0x2950E2E \| RAW:0x295022E \| CONF:P \| STATUS:OBSERVED]` |
| **B15-21** | Producer-kind cenzus: 1 957 / 961 / 367 / 342, `static_constant` 0 | `[RVA:0x3D5091 \| RAW:0x3D4491 \| CONF:P \| STATUS:OBSERVED]` |
| **B15-22** | 1 328 szimbolikus operand; négy KUSER_SHARED_DATA-cím + `peb_gs_disp_0x30` | `[RVA:0x3D836C \| RAW:0x3D776C \| CONF:P \| STATUS:OBSERVED]` |
| **B15-23** | Mind a 3 627 sor `UNRESOLVED` / `none` / `unresolved_symbolic_service_number` | `[RVA:N/A \| RAW:0x0 \| CONF:P \| STATUS:NEGATIVE]` |
| **B15-24** | A service-provenance három osztálya: 1 439 / 1 210 / 978 | `[RVA:N/A \| RAW:0x0 \| CONF:P \| STATUS:OBSERVED]` |
| **B15-25** | A Nt/Zw szolgáltatásnév egyetlen site-ra sem zárható | `[RVA:N/A \| RAW:N/A \| CONF:U \| STATUS:OPEN]` |
| **B15-26** | A `P0/S8` producer a 19 bejegyzéses toolchain-leltárban pinelve van (`5e303021…`), de a saját payloadja nem önpinez és nem hasheli a kimenetét | `[RVA:N/A \| RAW:N/A \| CONF:P \| STATUS:OBSERVED]` |
| **B15-27** | Az `S8` nem módosította az `S7` argumentum-inventoryt | `[RVA:N/A \| RAW:0x0 \| CONF:P \| STATUS:OBSERVED]` |
| **B15-28** | A 12 validált `0xC856C0` wrapper site-ja mind `other` / `no_anchor`; a 21 `wrapper_forwarding` csoporttól diszjunkt | `[RVA:0x51D84C \| RAW:0x51CC4C \| CONF:P \| STATUS:OBSERVED]`; `[RVA:N/A \| RAW:0x0 \| CONF:P \| STATUS:NEGATIVE]` |

---

## 17. Korlátok és reprodukciós határ

1. **Nincs dinamikus bizonyíték.** Nem futott a specimen; egyetlen itt idézett jel sem futásidejű megfigyelés.
2. **A 3 627 valid ≠ elérhető.** 3 384 site csak lineáris sweep-hipotézis. Az elérhetőségi arány nem 100 %.
3. **A 9 anchor-csoport ≠ service azonosítás.** A csoportcímke alakról szóló hipotézis; a szolgáltatásnév gate-je nem tűzelt.
4. **Az argumentumséma ablak-helyi.** A 40 bájtos ablakból kilépő definíció nem látszik, ezért a séma az adott ablakon belüli állítás.
5. **A globális slotértékek a preferált bázison modellezettek.** `DIR64` fixupokkal korrigált fájlértékek; betöltés utáni felülírat nincs látva.
6. **A fold 21 opkódra korlátolt.** Bármely más utasítás `opaque_instruction` kindként jön vissza.
7. **A `syscall_service_map.py` stabil pinelve van**, a `toolchain.json` 19 bejegyzéses leltárában `5e303021…` digesttel, és az `E9` ezt a script byte-okból újraszámolja. A nyitott rész az, hogy a payload nem ömpinez és a saját kimenetét sem hasheli – lásd F-01.
8. **A két hisztogram 16 vödörre van vágva**, így a `chain_length_histogram` 2 238 és a `sweep_depth_instructions_64_buckets` 1 149 site-ot ír le a 3 627-ből; a maradék nem publikált.
9. **A `producer_chain` cella 320 karaktérre csonkolt 873 sorban**, és de-duplikált látogatási sorrendet ír ki, nem a nyers lánchosszt.
10. **A `13` dokumentum F-01 driftje lezárva:** a `syscall_service_map.py` ma már benne van a `toolchain.json` **19** bejegyzéses leltárában – a `13` által látott 17 helyett –, és a hozzá tartozó `D-002` eltérés az `E9` `audit_infra.json`-ban `closed` státuszú. Az `E9` teljes egészében **632 ellenőrzés / 0 hiba / `verdict=pass`** eredményt ad, vagyis a producer-leltárra és a digest-bevitelre sincs nyitott hiba. A `P0/S8` által bevett inputok mind a `13` által pinelt fájlok, tehát a syscall számok érintetlenek.

**Reprodukciós határ:** azonos SHA-256 újraellenőrzése; a felsorolt input- és output-hash-ek újraszámítása; a 3 627 soros cenzusok újraolvasása a négy `svc_kind` / `mapping_basis` / `service_class` / `status` oszlopból; a 209 + 45 + 30 felbontás újraolvasása a `capstone_candidate_disposition` és a `valid_candidate` oszlopokból; a 9 anchor összegének és az anchor → osztály 1:1 leképezésnek az újraellenőrzése. **Ez nem reprodukálja a DLL runtime viselkedését, és nem zárja le egyetlen Nt/Zw szolgáltatásnevet sem.**

---

## 18. Változási dátum és kapcsolódó dokumentumok

- **Dokumentum keletkezése:** 2026-09-26.
- **Evidence-pillanék:** minden hash a fenti fájlok 2026-09-26-i lemezállapota; a specimen hash változatlan `91cc0aa0…`.
- **Kapcsolódó dokumentumok:** `adhesive-00-index.md` (BRef/confidence), `adhesive-06-process-memory-hooks.md` (process-memory, §4.1, §9.2, §9.3), `adhesive-07-anti-debug-integrity.md` (process-debug, §3.1–§3.4), `adhesive-11-packing-negative-findings.md` (B15, §4.6, §8.1), `adhesive-12-risk-methodology-open-questions.md` (§6.3, a 8. fejezet 5. pontja, a 9. fejezet 3. pontja, a 10. fejezet 3. pontja), `adhesive-13-pdata-function-map-cfg.md` (E1–E12 leltár, F-01), `adhesive-14-c856c0-handle-producer-dataflow.md` (C-01/C-05 korrekciók, 32 ág, 12 wrapper).
- **A `00` index 4. fejezetében a teljes navigáció 17 elemet sorol fel** – a `00` indexet és a 16 elemzési dokumentumot –, és a `13`–`16` navigáció már része a listának: a `13` a function-map/CFG, a `14` a `0xC856C0` handle-flow, a `15` a syscall-inventory és a `16` a patch-mechanizmus réteget fedi le. A jelen dokumentum a `13`, `14` és `16` után készült, és az index 4. fejezetének frissítése a `00` oldalán megtörtént.
- **Felülírás:** ez a dokumentum felülírja a `12` 8. fejezete 5. pontjának azon mondatát, hogy a nyers `3 881` találat „nem szolgál utasításlistaként" – ez továbbra is igaz, de a felbontás mostantól számszerűen megadott (3 627 / 209 / 45 a CSV scope-on, +30 a scope-on kívül). A `12` 9. fejezete 3. pontjának kérdése („Mely Nt/Zw szolgáltatások a 12 validált wrapperhez tartoznak?") nyitott marad, és a `P0/S8` erre **0 nevet** adott.

---

## 19. Hash- és arány-újraellenőzés (közvetlen kereszt-audit, 2026-09-26 01:45:59)

> **Scope:** kizárólag állomány- és mezőolvasás a `reverse/evidence/` készletén és a `reverse/scripts/` leltárán. A DLL-t nem futtattam, nem töltöttem be, nem mappeltem, nem patcheltem; új evidence-fájl nem készült, és a `reverse/scripts/` és `reverse/evidence/` állományához nem nyultam.

### 19.1 Ellenőrzösi mátrix

| # | Ellenőrzött tétel | Forrás | Eredmény | Állapot |
|---:|---|---|---|---|
| 1 | E1 `syscall_candidates_raw.csv` sha256 + méret + 3 881 sor / 33 oszlop | lemez | `7c99950c…` / 920 267 / 3 881 / 33 | **egyezik** |
| 2 | E2 `syscall_arg_inventory.csv` sha256 + méret + 3 627 sor / 100 oszlop | lemez | `5dd86ec3…` / 4 468 093 / 3 627 / 100 | **egyezik** |
| 3 | E3 `syscall_arg_classes.json` sha256 + méret + 20 ellenőrzés | lemez | `9133ad84…` / 56 745 / 20 | **javítva** (a `2026-09-26` záró pin-konformancia-javításban: `058e2c58…`; a méret változatlan) |
| 4 | E4 `syscall_inventory.csv` sha256 + méret + 3 627 sor / 106 oszlop | lemez | `bb1879aa…` / 5 993 935 / 3 627 / 106 | **egyezik** |
| 5 | E5 `syscall_service_map.json` sha256 + méret + 28 ellenőrzés | lemez | `25e29583…` / 19 589 / 28 | **egyezik** |
| 6 | E6 `audit_syscall_candidates.json` sha256 + méret + 31 check | lemez | `e8cd41f2…` / 1 765 141 / 31 | **egyezik** |
| 7 | E7 `cfg_functions.csv` sha256 + méret + 142 004 sor | lemez | `041d2365…` / 40 180 030 / 142 004 | **egyezik** |
| 8 | E8 `xref_edges.csv` sha256 + méret + 57 101 sor | lemez | `fc744f61…` / 11 126 183 / 57 101 | **egyezik** |
| 9 | E9 `audit_infra.json` sha256 + méret + check-/hibaszám | lemez | `251b79e7…` / 170 001 / 632 / 0 | **javítva** (a `2026-09-26` záró pin-konformancia-javításban: 169 558 / `97134043…`; a még régebbi érték 165 149 / `cce51a63…` / 628 / 5) |
| 10 | E10 `audit_handle_flow.json` sha256 + méret + 163 ellenőrzés / 0 hiba | lemez | `c1636fcd…` / 106 955 / 163 / 0 | **javítva** (a `2026-09-26` záró pin-konformancia-javításban: `9279ee8e…` / 105 880; a 163 / 0 változatlan) |
| 11 | Specimen sha256 + méret | lemez | `91cc0aa0…` / 53 575 264 | **egyezik** |
| 12 | `syscall_scan.py` digest (636 sor) | lemez + E12 | `1710dd90…`, 24 266 B, 636 sor – egyezik az E6 `inputs.audited_script` és az E12 `scripts[]` bejegyzésével | **egyezik** |
| 13 | `syscall_args.py` digest | lemez + E12 | `a5c58df7…`, 113 239 B – egyezik | **egyezik** |
| 14 | `syscall_service_map.py` digest + méret + sor | lemez + E12 | `5e303021…`, 89 433 B, 2 133 sor – egyezik | **egyezik** |
| 15 | `audit_syscall_candidates.py` digest | lemez + E6/E12 | `dfd90442…`, 69 878 B – egyezik | **egyezik** |
| 16 | `common.py` digest | lemez + E2/E8/E12 | `4aa2ceec…`, 46 556 B – egyezik | **egyezik** |
| 17 | `toolchain.json` fájldigest | lemez + E9 `provenance.digests` / `files` | `72a1eed0…` / 27 150 B | **javítva** (a `2026-09-26` záró pin-konformancia-javításban: `6f3dd634…` / 26 638 B; a még régebbi érték `46d8d871…`) |
| 18 | `audit_infra.py` digest | lemez + E9 `audit.script_sha256` | `ebf7f4f4…` / 151 067 B – egyezik | **egyezik** |
| 19 | **Nyers `0F 05` felbontás** 3 911 → 3 881 → 3 627 + 209 + 45; +30 non-code | E1 `capstone_candidate_disposition`, `valid_candidate`; E6 `raw_census` | 3 881 `.text` találat, 3 627 valid, 209 `covered_by_instruction`, 45 `no_pdata_function`, 30 `rdata`/`data` | **egyezik** |
| 20 | **Argumentum-cenzus** 21 762 = 3 627 × 6 pozíció, 8 osztály, `A3_INOUT_BUF` = 0 | E2 oszlopkösszeg, E3 `census` | 3 627 × 6 = 21 762; `A3_INOUT_BUF` 0 | **egyezik** |
| 21 | **Anchor-csoportok** 9 anchor, 1:1 a 7 `service_class`-szal, összeg 3 627 | E4 `mapping_basis` `anchor=` × 3 627 | 9 anchor: `no_anchor`2 847, `five_resolved_buffer_and_length`633, `information_class_0x00`78, `four_entry_parameters_forwarded`21, `constants_0x1000_and_0x40`16, `information_class_0x28`8, `information_class_0x1F`8, `information_class_0x07`8, `information_class_0x1E`8; összeg **3 627** | **egyezik** |
| 22 | **Producer-kind cenzus** `memory_indirect` 1 957, `kuser_shared_data` 961, `peb` 367, `code_address` 342, `static_constant` 0 | E4 `mapping_basis` `svc_kind=` × 3 627 | 1 957 / 961 / 367 / 342, `static_constant` 0 | **egyezik** |
| 23 | **Service mapping** 3 627 / 3 627 `UNRESOLVED`, `nt_confidence` mind `none`, név 0 | E4 `nt_service`, `nt_confidence`, `status`, `nt_service_status` | `UNRESOLVED`:3 627, `none`:3 627, `unresolved_symbolic_service_number`:3 627, `UNRESOLVED_NOT_ATTEMPTED`:3 627 | **egyezik** |
| 24 | `service_class` teljes bontása | E4 `service_class` × 3 627 | `other`2 847, `transfer_5arg`633, `process_information_basic`78, `wrapper_forwarding`21, `allocation_0x1000_0x40`16, `process_information_debug`24, `process_information_instrumentation_callback`8 | **egyezik** |
| 25 | `allocation_to_write` 0 argumentum / 0 site; `allocation_origins.by_symbol` üres | E4 oszlopok, E3 `allocation_origins` | 0 | **egyezik** |
| 26 | `wrapper_forwarding` 21 sor / 7 owning function | E4 `service_class`, E10 `inventory.forwarding_owner_count` | 21 sor; `forwarding_owner_count` = 7 | **egyezik** |
| 27 | E6 mind az 5 verdict-boolean `true` | E6 `verdict` | `ratios_reproduce`, `instruction_start_confirmed`, `anchors_in_subset`, `control_flow_claims_consistent`, `all_checks_passed` mind `true`; `checks_run = 31` | **egyezik** |
| 28 | E3/E5 validációs check-számok | E3 `validation`, E5 `validation` | E3 20, E5 28 – a dokumentumban rögzítve egyezik | **egyezik** |
| 29 | E5 `inputs` (E1, E2, E7) digest | E5 `inputs` vs lemez | a három digest a lemezen lévő fájlokkal egyezik | **egyezik** |
| 30 | E10 `wrapper_forwarding` diszjunktság a 12 `0xC856C0` wrapperrel és a 28 tárgykörhellyel | E10 `inventory.forwarding_*` checkek | `forwarding_disjoint_from_wrappers` = `true`, `forwarding_disjoint_from_inline_sites` = `true`, `no_subject_site_is_wrapper_forwarding` = 0 | **egyezik** |
| 31 | A `14` dokumentum saját digestjének kezelése az `E10` payloadban | `reverse/evidence/audit_handle_flow.json` `observation.audited_document` vs lemez | az `E10` a `14` dokumentumot `eebcd7c7…` / 101 147 B értéken figyeli meg az `observation` blokkban, `is_attestation: false` és `carries_a_verdict: false` jelöléssel, és a hét tanúsított `inputs` bejegyzés között nincs dokumentum; a `14` **saját, önreferenciás** pinje tehát **nem attestation**, és a `14` bármely szerkesztésére – a jelen pin-javítást is beleértve – elavul | **megfigyelés, nem eltérés** (lásd 19.3/A) |

### 19.2 Eltérések — javított, minimális diff

**1. E9 `audit_infra.json` sorszáma, mérete és check-száma (az 1.1 fejezet E9-sora)**

- **Eltérés:** a dokumentum `165 149` bájt / `cce51a6396de4402ff8e15cb23f8d1ff02d5e5c27d43fd6f65253083ef09a1fa` értéket és `628 ellenőrzés / 5 hiba` állapotot rögzített. A jelenlegi `audit_infra.json`: **170 001** bájt, `251b79e722620af61824b793ced1ade1ffe9b375608a429e109880aaa8b8b1dc`, `check_count = 632`, `failed_count = 0`, `verdict = pass`, `failed_checks = []`. (Közbeeső érték: `169 558` bájt / `97134043e684931b9b8cb1e12c75d4c1f9b7ee0e2681bd9ee41e811137c6ce02`; a méret- és digest-pin a `2026-09-26` záró konformancia-javításban frissült erre.)
- **A 3 korábbi hiba sorsa:** mind az 5 a `toolchain.digests` `digest_attested[…]` checkjeire esett (`cfg_functions.csv`, `cfg_clusters.csv`, `xref_edges.csv`, `indirect_sites.csv`, `syscall_candidates_raw.csv`). A `digests` blokk ma már mind az öt `entries` értéket tartalmazza, a `toolchain.digests` csoport **21 check / 0 hiba**, és a D-004 `unattested = []`-t ad.
- **Új érték:** `165 149` → **170 001**, `cce51a63…` → **`251b79e7…`**, `628 / 5` → **`632` / `0`**, `verdict=fail` → **`verdict=pass`**.
- **Forrásfájl:** `reverse/evidence/audit_infra.json` (`summary`, `summary.by_group`, `failed_checks`, `discrepancies[D-004].bounded`).
- **Confidence: `P`** (OBSERVED).

**2. F-01 sorszáma – az `E9 summary` sor**

- **Eltérés:** a sor `628 ellenőrzés, 5 hiba; mind az 5 a toolchain.digests 5 CSV-attestálására esik…` állítást adott.
- **Új érték:** `632 ellenőrzés, 0 hiba, verdict=pass; a toolchain.scripts, toolchain.package_versions és toolchain.digests csoport mind zöld` — vagyis a producer-leltár mellett a digest-bevitel sincs nyitva.
- **Forrásfájl:** `reverse/evidence/audit_infra.json` `summary` és `summary.by_group`.
- **Confidence: `P`** (OBSERVED).

**3. F-01 záró – a `toolchain.json` fájldigest**

- **Eltérés:** a dokumentum `46d8d871e3a4383a04c4ac4fcd79ba443ca9ce989bb76d8054451280787c5d41` értéket adott. A lemezen lévő `toolchain.json` és az `E9` `provenance.digests` / `files` blokkja egyaránt **`72a1eed07d4d8a83df62cce8bd175a56cbba0da22982b34278fb537b15de0e6b`** (27 150 bájt). (Közbeeső érték: `6f3dd634…` / 26 638 bájt.)
- **Új érték:** a záró szöveg a jelenlegi digestre és méretre frissült.
- **Forrásfájl:** `reverse/evidence/toolchain.json` és `reverse/evidence/audit_infra.json` `provenance.digests`, `files`.
- **Confidence: `P`** (OBSERVED).

**4. 17. fejezet 10. pontja — az `E9` állapotása**

- **Eltérés:** a pont még `0 hibával a producer-leltárra` szököst adott, ami az `E9` teljes állapotánál többet állított, mint a valóság.
- **Új érték:** a pont immán `632 ellenőrzés / 0 hiba / verdict=pass` eredményt idéz, és hozzáteszi, hogy a `toolchain.digests` csoport is zöld.
- **Forrásfájl:** `reverse/evidence/audit_infra.json` `summary`.
- **Confidence: `P`** (OBSERVED).

### 19.3 Eltérések — megfigyelve, a dokumentum számát nem módosítva

**A. A `14` dokumentum digestje az `E10` payloadban nem-attesztáló megfigyelés, nem tanúsított input**

- **Megfigyelés:** a `reverse/evidence/audit_handle_flow.json` a `14` dokumentumot az `observation.audited_document` mezőben `eebcd7c7af63a694b547c6723e45c563ffd1f8608e3d12fd9e1c33dad676017b` / `101 147` bájt értéken figyeli meg. A payload ezt explicit jelöli: `observation.is_attestation = false`, `observation.carries_a_verdict = false`, és az `observation.why_not_attested` blokk a ciklust nevezi meg – az `E10`-t magát a `14` digesteli. A hét `inputs` bejegyzés kizárólag evidence-artifact (`inputs_note`), dokumentum nincs köztük. A korábban idézett `audit.audited_document_sha256` = `1875fe26…` / 94 338 B mező és a `1875fe26…`/`ed31dff5…`/`100 418 B` értéktriplet az `E10` és a `14` korábbi revízióira vonatkozott, és elavult.
- **Státusz:** **nem attestation**, és **szerkesztésre elavuló megfigyelés**. Az `E10` a saját futásakor olvasott `14`-byte-okat jegyzi be; a `14` jelen pin-konformancia-javítása maga is módosítja a fájlt, tehát a bejegyzés már nem friss. Csak történeti, nem-attesztáló megfigyelésként olvasható.
- **Következmény erre a dokumentumra:** nincs. Az `E10` `target_document` mezője az `adhesive-14…md`, nem a jelen fájl, és a `14` a saját «Javított számlálások» blokkjában közli az `AFH-2026-09-26` auditot. A `15` az `E10`-ot csak a `wrapper_forwarding` 21-es scope-állítására használja, és az **változatlanul reprodukálható** a jelenlegi `syscall_inventory.csv`-ből (19.1/26. sor).
- **Forrásfájl:** `reverse/evidence/audit_handle_flow.json` `observation.audited_document`, `observation.is_attestation`, `observation.why_not_attested`, `inputs`, `inputs_note` vs `reverse/adhesive-14-c856c0-handle-producer-dataflow.md` lemezi állapot.
- **Confidence: `P`** (OBSERVED).

**B. Az `E12` leltár csak pillanatnyi konzisztencia — mért korlát, nem készlethiba**

- **Megfigyelés:** az `E12` `digests.entries` nyolc bejegyzése ma mind reprodukálható vagy a `pdata_stats.json` által, vagy a `digests` blokkból, ezért a D-004 `unattested = []`-t ad. A leltár azonban nem kötés szabvány: minden producer-változás újra elavulttá teszi. A `P0/S8` mérőszámait ez nem érinti, mert az `E4`/`E5` a saját `inputs` által tanúsítja át.
- **Forrásfájl:** `reverse/evidence/toolchain.json` `digests.entries_cover`; `reverse/evidence/audit_infra.json` `discrepancies[D-004].bounded`; `reverse/evidence/syscall_service_map.json` `inputs`.
- **Confidence: `P`** (OBSERVED).

### 19.4 Amit a kereszt-audit nem módosított

- **A `15` dokumentum minden mérőszáma változatlan.** A 3–17. fejezet valamennyi darabszáma, aránya és oszlopszáma a jelenlegi E1–E8, E10 CSV-kből és JSON-okból űszámban reprodukálható (19.1/19–30. sor). Külön értékes: a 3 881 → 3 627 felbontás, a 21 762 argumentumpozíció, a 9 anchor × 3 627 összeg, a négy `svc_kind` cenzus, a 3 627/3 627 `UNRESOLVED` negatív eredmény és a 21 `wrapper_forwarding` hely.
- **A fő eredmény változatlanul negatív:** egyetlen Nt/Zw szolgáltatásnév nincs beírva, `nt_confidence` mind `none`; a naming gate ma sem érte el a nevágat.
- **A nyitott kérdések változatlanok:** a szolgáltatás azonosítása, a `producer_chain` 320 karakteres csonkolása és a 16 vödörre vágtott hisztogramok továbbra is `STATUS:OPEN`.
- **A `13` és a `16` dokumentumhoz fűződő állítások érvényesek:** a `13` E1–E8, E10–E11 pinje bitre változatlan; a `13` E9/E12 sorszámát és a `D-002`/`D-004` státuszát a `13` dokumentumban javítva lett.
- **BOM és sortörés:** a fájl UTF-8 BOM nélküli, `cr = 0`, `crlf = 0`, záró sortöréssel.

---

## 20. Pin-konformancia-javítás (2026-09-26)

> **Scope:** kizárólag szövegszerkesztés a `reverse/adhesive-00-index.md`, `adhesive-12`, `adhesive-13`, `adhesive-14` és `adhesive-15` fájlokban. A DLL-t nem futtattam, nem töltöttem be, nem mappeltem és nem patcheltem; új evidence-fájl nem készült, és a `reverse/evidence/` vagy a `reverse/scripts/` állományhoz nem nyúltam. A méret- és `sha256`-pinok a `2026-09-26`-i lemezállapothoz lettek igazítva.

### 20.1 A `15` dokumentumban frissített pin-ek (4 artifact, 7 pinérték, 11 cited hely)

| Hely | Artifact | Régi érték | Új érték |
|---|---|---|---|
| 1.1 fejezet, E3-sor | `syscall_arg_classes.json` digest | `058e2c584f62cb56958c78b52fff7605a52c78db835c8cd46bce9a4e8b8d8ff0` | **`9133ad84946bbcfb84cad38ce11a288fd7d88e893a7557a51bf07c85bbdd38a1`** (méret `56 745` változatlan) |
| 1.1 fejezet, E9-sor | `audit_infra.json` méret + digest | `169 558` bájt, `97134043e684931b9b8cb1e12c75d4c1f9b7ee0e2681bd9ee41e811137c6ce02` | **`170 001` bájt, `251b79e722620af61824b793ced1ade1ffe9b375608a429e109880aaa8b8b1dc`** |
| 1.1 fejezet, E10-sor | `audit_handle_flow.json` méret + digest | `105 880` bájt, `9279ee8ea232a5b36d272b2ac0adea5cbea073eee8d161d4567783955b06ffd4` | **`106 955` bájt, `c1636fcd6315a1bf679bc02e57cd3498a06a67b1a96252b8900f90b5b5b5f72c`** |
| F-01 záró bekezdés (a 19.1/17. sor forrása) | `toolchain.json` méret + digest | `26 638` bájt, `6f3dd634c494b2dea837cd1da2dd452a82311ce2faa6e5686507fddd5497074d` | **`27 150` bájt, `72a1eed07d4d8a83df62cce8bd175a56cbba0da22982b34278fb537b15de0e6b`** |
| 19.1 fejezet, 3. sor | `syscall_arg_classes.json` digest | `058e2c58…` / 56 745 / 20 | **`9133ad84…` / 56 745 / 20** |
| 19.1 fejezet, 9. sor | `audit_infra.json` méret + digest | `97134043…` / 169 558 | **`251b79e7…` / 170 001** |
| 19.1 fejezet, 10. sor | `audit_handle_flow.json` méret + digest | `9279ee8e…` / 105 880 | **`c1636fcd…` / 106 955** |
| 19.1 fejezet, 17. sor | `toolchain.json` méret + digest | `6f3dd634…` / 26 638 B | **`72a1eed0…` / 27 150 B** |
| 19.2 fejezet, 1. alpont | `audit_infra.json` méret + digest | `169 558` bájt, `97134043e684931b9b8cb1e12c75d4c1f9b7ee0e2681bd9ee41e811137c6ce02` | **`170 001` bájt, `251b79e722620af61824b793ced1ade1ffe9b375608a429e109880aaa8b8b1dc`** |
| 19.2 fejezet, 1. alpont „Új érték" sora | `audit_infra.json` méret + digest | `165 149` → `169 558`, `cce51a63…` → `97134043…` | **`165 149` → `170 001`, `cce51a63…` → `251b79e7…`** (közbenső: `169 558` / `97134043…`) |
| 19.2 fejezet, 3. alpont | `toolchain.json` méret + digest | `46d8d871…` → `6f3dd634c494b2dea837cd1da2dd452a82311ce2faa6e5686507fddd5497074d` (26 638 B) | **`46d8d871…` → `72a1eed07d4d8a83df62cce8bd175a56cbba0da22982b34278fb537b15de0e6b`** (27 150 bájt) |

### 20.2 Az önreferenciás digest annotációja

- **A `14` dokumentum saját magára hivatkozó digestje nem attestation.** Az `audit_handle_flow.json` a `14` digestjét az `observation.audited_document` mezőben figyeli meg (`eebcd7c7…` / 101 147 B), `observation.is_attestation = false` és `carries_a_verdict = false` jelöléssel, és a hét tanúsított `inputs` bejegyzés között nincs dokumentum; az `observation.why_not_attested` a kört nevezi meg.
- **Ez szerkesztésre elavuló megfigyelés:** az `E10` a saját futásakor olvasott `14`-byte-okat jegyzi be, és a jelen pin-konformancia-javítás is módosítja a `14` fájlját, tehát a bejegyzés már nem friss. Csak történeti, nem-attesztáló megfigyelésként olvasható.
- **A `15` nem pinel saját magára hivatkozó digestet:** egyetlen payload sem – az `E9`, az `E10` és az `E6` sem – rögzíti az `adhesive-15…md` fájl méretét vagy digestjét, így a `15` nem tartalmaz ilyen, önmagára visszautaló pin-t. Az `E10` `target_document` mezője az `adhesive-14…md`-re mutat, nem a jelen fájlra.
- **A `15` mérőszámaira nincs hatása:** a 3 881 → 3 627 / 209 / 45 felbontás, +30 a CSV scope-on kívül, a 21 762 argumentumpozíció, a 9 anchor-csoport, a négy `svc_kind` cenzus, a 3 627/3 627 `UNRESOLVED` negatív eredmény és a 21 `wrapper_forwarding` hely változatlan.

### 20.3 Amit a javítás nem módosított

- **Nem változott semmilyen statisztikai szám, finding, státusz vagy confidence érték:** a 3 627 sor / 106 oszlop, a 20 (E2/E3) és 28 (E5) ellenőrzés, a 31 (E6) check, a `632 / 0 / pass` (E9) és a `163 / 0` (E10) érték, a `SVC-01` `bounded_open` státusza és a service-nevek `UNRESOLVED` eredménye változatlan.
- **A `632` / `0` / `verdict=pass` érték ellenőrizhető és a jelenlegi audit-futtatásé:** az `E9` `summary` blokkja `check_count = 632`, `failed_count = 0`, `verdict = pass`, `discrepancy_count = 4`, `discrepancy_open_count = 0`, `failed_checks = []`; a `22` csoportos bontás összege `632`.
- **A `163` / `0` érték ellenőrizhető:** az `E10` `validation` blokkja `check_count = 163`, `failed_count = 0`; `audit.id = AFH-2026-09-26`.
- **A `toolchain.json` 19 bejegyzése, `missing_from_inventory = []` és `drifted_entries = {}` változatlan**, és a `syscall_service_map.py` bejegyzés továbbra is `5e303021…` / 89 433 B / 2 133 sor.
- **A `syscall_service_map.json` `inputs` három digestje változatlanul egyezik** a lemezen lévő `syscall_candidates_raw.csv`, `syscall_arg_inventory.csv` és `cfg_functions.csv` fájlokkal.
- **A `13:374`, a `15:264` és a `15:863` `93,30 %`-os aránya változatlan**, és egyezik a `12:524` frissített értékével; a `3 384 / 3 627` arány másik dokumentumban nem igazítandó.
- **Kódolás és sortörés:** a fájl UTF-8 BOM nélküli, LF sortöréssel, záró sortöréssel; `cr = 0` / `crlf = 0`.
