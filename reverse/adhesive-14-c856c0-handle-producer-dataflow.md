# `adhesive.dll` – `0xC856C0` handle-adatfolyam, kétlépéses diszperziós dispatch és kimerülő hívóklóza

> **Vizsgálati elv:** kizárólag a `reverse/adhesive.dll` fájl statikus elemzése. Nem történt DLL-betöltés, futtatás, dinamikus traceelés, hálózati vagy fájl-figyelés, patchelés, bypass vagy exploit-próba. A dokumentum kódstruktúrát, argumentumsémát és tulajdonosi viszonyokat ír le; nem tartalmaz végrehajtási, módosítási vagy kerülési útmutatást.
>
> **Státusz:** ez a dokumentum felülírja a `06`, `07` és `12` dokumentum `0xC856C0`-ra vonatkozó darabszám- és szerkezetállításait. Ahol ellentmond, a `14` dokumentum az érvényes; a korábbi szöveghelyek a [3. fejezet](#3-felülírt-korábbi-állítások) korrekciós táblájában supercedált jelölést kaptak, és nem értelmezendők ellenkező állításként.
>
> **Javítási réteg:** a független `AFH-2026-09-26` újraszámítás a nyolc mérőszámot változatlanul megerősítette, viszont hét, a dokumentumban szereplő állítást nem reprodukálta. Ezek javítva a [Javított számlálások](#javított-számlálások) blokkban és az érintett szekciókban szerepelnek.

## Javított számlálások

Ez a blokk a [3. fejezet](#3-felülírt-korábbi-állítások) táblájának testvére, de más korrekcióforrást kezel. A 3. fejezet a `06`, `07` és `12` dokumentumok ellentmondó darabszámait írja felül; ez a blokk a jelen dokumentum saját állításait javítja a `reverse/evidence/audit_handle_flow.json` (`AFH-2026-09-26`, 163 ellenőrzés, 0 hiba) újraszámítása alapján. A hét vitatott tétel (`CF-01`…`CF-07`) a rájuk hivatkozó szekciókban alkalmazva van; az alábbi két táblázat a végleges számlálásokat és a tételek diffjét foglalja össze.

### Végleges számlálások

| # | Mennyiség | Végleges érték | Audit tétel | Konf. | BRef |
|---:|---|---|---|---|---|
| 1 | dispatch táblák és slotjaik | **2 tábla × 16 slot** (32 slot, 4 bájtos lépés, szomszédos) | `D-01`, `D-02`, `D-03` | P | `[RVA:0x2CFB1F8 \| RAW:0x2CF9BF8 \| CONF:P \| STATUS:OBSERVED]` |
| 2 | közvetlen `syscall` ágak | **16** (8 allokációs + 8 transzfer) | `B-01` | P | `[RVA:0xC858E0 \| RAW:0xC84CE0 \| CONF:P \| STATUS:OBSERVED]` |
| 3 | wrapper-hívás ágak | **16** (8 allokációs + 8 transzfer) | `B-02` | P | `[RVA:0xC85737 \| RAW:0xC84B37 \| CONF:P \| STATUS:OBSERVED]` |
| 4 | wrapper függvények | **12** (6 allokációs + 6 transzfer), egyenként 1 `syscall` | `W-01` | P | `[RVA:0x51D680 \| RAW:0x51CA80 \| CONF:P \| STATUS:OBSERVED]` |
| 5 | syscall-helyek a teljes forward tárgykörben | **28** (16 inline + 12 wrapper) | `S-01` | P | `[RVA:0xC870DB \| RAW:0xC864DB \| CONF:P \| STATUS:OBSERVED]` |
| 6 | handle descriptor-mező olvasásai | **2** (`0xC856F3` `r14`, `0xC86440` `rbx`) | `H-01` | P | `[RVA:0xC86440 \| RAW:0xC85840 \| CONF:P \| STATUS:OBSERVED]` |
| 7 | handle fogyasztó élek | **32** (16 allokációs + 16 transzfer; argumentumregiszter 16 `r10` + 16 `rdx`) | `H-02` | P | `[RVA:0xC856F3 \| RAW:0xC84AF3 \| CONF:P \| STATUS:OBSERVED]` |
| 8 | handle producer | **OPEN** (a belépési határ `0xC85650`-nél a 6 enumerált élformán zárt, a producer nincs azonosítva) | `P-01` | U | `[RVA:N/A \| RAW:N/A \| CONF:U \| STATUS:OPEN]` |

A fenti nyolc érték egyikét sem változtatta meg az audit; a korrekciók kizárólag a táblázaton kívüli, a dokumentum más állításaira vonatkoznak.

### A hét vitatott tétel

| Contested ID | Súlyosság | Konf. | Régi állítás | Új állítás | Forrás |
|---|---|---|---|---|---|
| `CF-01` | high | P | §9.4: `wrapper_distinct_caller_functions` = **54**, `caller_functions_outside_the_anchor` = **54**, klaszteren belüli hívó = **0** | A 12 wrapper distinct hívója **37** (408 szint-1 sor); 36 a `0xC85000`–`0xC88000` tartományon kívül, 1 belül: maga az anchor `0xC856C0`, 16 hívóhelyről. A **54** csak a 13 forward sinkre érvényes (12 wrapper + `0x495D0`), ahol 2 hívó van a tartományban | `c856c0_forward.json#caller_closure.rows`, `c856c0_callers.csv` |
| `CF-02` | high | P | §15.4 és `NEG-15`: a forrásoldali `src_rva`-k kizárólag `0x0`–`0x9` magas nibble alá esnek, ezért a klaszterből **0** forrásoldali él | A `src_rva` oszlop **decimális**, a legnagyobb érték `0x3306F60`, így a valódi hex magas nibble kizárólag `0x0`. A klaszterből **17** forrásoldali sor van, 5 forrásfüggvényből (`0xC81EE0`, `0xC871F0`, `0xC873C0`, `0xC87830`, `0xC87900`), 6 `call_indirect_iat` + 11 `call_rel_to_code` relációval. A klaszternél a bounded negatívum megmarad: **0** `CloseHandle` és **0** `DuplicateHandle` forrásoldali sor | `xref_edges.csv#src_rva`, `xref_edges.csv#code_instruction_function_begin` |
| `CF-03` | medium | P | §14.2: a `.pdata`-lefedett **21** függvény mellett **16** olyan cél is van, amelyre nincs `RUNTIME_FUNCTION` | A 37 elérhető célból **23** `RUNTIME_FUNCTION` rekorddal rendelkezik, **14** anélkül; mind a 14 felsorolva van, a `0xCAC150` is, amely a §7.4 thunk-táblájából hiányzott | `c856c0_forward.json#forward_reachable_set.functions`, `c856c0_forward.json#forward_reachable_set.targets_outside_pdata` |
| `CF-04` | medium | P | §7.4: a `0xC8FEE4` a `0xCAC0D0` thunk második hívóhelye, és a backward passz 5 thunkja a teljes lista | A `0xC8FEE4` a **`0xCAC150`** thunk hívóhelye, a hívó a `0xC8FDE0` transzfer wrapper; a backward passz 5 thunkja változatlan, a hatodikat csak a forward passz rögzíti. Encoding és feloldott globális: `N/A` | `c856c0_forward.json#forward_reachable_set.targets_outside_pdata`, `c856c0_forward.json#wrappers[].helper_calls`, `c856c0_dataflow.json#global_address_thunks` |
| `CF-05` | medium | P | §4.2 és §9.4: a 6 transzfer wrapper `cluster_id = 85`, „tehát a klaszteren belül" | A `cluster_id = 38` és `cluster_id = 85` két `cfg_functions.csv` közelség-csoport azonosítója, nem a 16 függvényes `0xC85000`–`0xC88000` tartomány; a két azonosító nem felcserélhető. Mind a **12** wrapper a tartományon kívül van, a 6 transzfer wrapper egyike sem esik bele | `cfg_functions.csv#cluster_id`, `c856c0_dataflow.json#cluster` |
| `CF-06` | low | P | §7.1–§7.3: a wrapper-ág törzse **8–9** utasítás, az inline-ágé 41–113 | A **16** wrapper-ág törzse a forward passzban 8–9 (allokáció 9, transzfer 8), a backward passzban 9–10, minden érintett ágon −1 különbséggel; a 16 inline-ág 41–113 mindkét passzban azonos. Definíciókülönbség, nem ellentmondás | `c856c0_dataflow.json#dispatch.tables[].branches[].block_instruction_count`, `c856c0_forward.json#stages[].branches[].instruction_count` |
| `CF-07` | low | P | §12.1: a növekedési segédet a belépő függvény és a `0x176F860` hívja | A `0x495D0` növekedési segédnek **17** distinct hívója van, 20 szint-1 sorral; a `0xC85650` (a tartományon belül) és a `0x176F860` ezek közül kettő, a többi felsorolatlan | `c856c0_forward.json#caller_closure.rows`, `c856c0_callers.csv` |

### A `wrapper_forwarding` service-map predikátum scope-korlátja

A service-map `wrapper_forwarding` csoportjának publikált helyszáma **21**, és ez nem a jelen dokumentum wrapperjeinek száma, hanem egy alak-osztály száma a teljes, 3 627 helyes korpuszon. A predikátum az a helyet veszi fel, ha mind a négy argumentumregiszter-pozíciója a saját belépési paraméteréből kapott érték. A 21 hely egységes `A6_SELF_HANDLE` négyes alakot visel, a `0x291C08F`–`0x2951479` sávban, 7 runtime function alatt – a `0xC856C0` tárgykörzetétől távol.

| Korpusz | Helyszám | Osztályozás | Konf. |
|---|---:|---|---|
| Service-map `wrapper_forwarding` csoport, teljes korpusz | 21 | a 12 `0xC856C0` wrapper egyike sem tartozik bele | P |
| A 12 wrapper saját 6 pozíciós alakja | 12 | 10 hely `A6_SELF_HANDLE`×3 + `A7_REG_INDIRECT` + 2 stack slot, 2 hely `A8_UNKNOWN` + `A6_SELF_HANDLE`×2 + `A7_REG_INDIRECT` + 2 stack slot; a 4. pozíció regiszter-indirekt, ezért a konjunkció egyikükre sem teljesül | P |
| A 16 inline hely osztályozása | 8 + 8 | a 8 allokációs inline hely az `allocation_0x1000_0x40` csoportba kerül a `0x1000` és `0x40` konstans miatt, a 8 transzfer inline hely az `other` csoportba, mert a 2. pozíciójuk regiszter-indirekt | P |
| A 28 tárgykörhely `wrapper_forwarding` tagsága | **0** | a korábbi „nem ütközik" megállapítás ezt nem cáfolja, hanem pontosítja | P |

A 21 tehát a 12 wrapperrel diszjunkt halmazt alkot, és a service-map maga is így zárja: a `reconciliation.forwarding_is_not_a_conflict` mező `alloc_write_scope = window`, `alloc_write = forwarded_or_cross_layer` jelöléssel. A §9.1-ben kimondott forwarding-szabály – hívás argumentum `N` a syscall argumentum `N-1` helyére – szerkezetileg ugyanaz az elv, más corpuson és szűkebb szabálykészlet mellett; ezért a két szám nem egyeztethető össze, és a dokumentum továbbra is **12** wrappert és **28** syscall-helyet dokumentál. A szolgáltatásnév nyitottsága változatlan: a service-map a 3 627 korpuszhelyből 0-t és a 28 tárgykörhelyből 0-t nevez meg.

```text
BRef = [RVA:0x2CFB238 | RAW:0x2CF9C38 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x51D680 | RAW:0x51CA80 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0xC856C0 | RAW:0xC84AC0 | CONF:P | STATUS:NEGATIVE]
BRef = [RVA:N/A | RAW:N/A | CONF:U | STATUS:OPEN]
```

## 1. Vizsgálati hatókör

| Tulajdonság | Statikus érték | Jelölés |
|---|---|---|
| Specimen | `C:\Users\Admin\Desktop\Dumper - AllInOne\reverse\adhesive.dll` | P |
| Méret | `53 575 264` bájt | P |
| SHA-256 | `91CC0AA006D7315CB042C8FA8DCA6C1E074A307BBA7DCC9EB5509C8A7B81934E` | P |
| PE-típus | `PE32+`, AMD64, `DllCharacteristics=0x0160` (`HIGH_ENTROPY_VA`, `DYNAMIC_BASE`, `NX_COMPAT`) | P |
| Preferált image base | `0x180000000` | P |
| Anchor | RVA `0xC856C0`, raw `0xC84AC0`, VA `0x180C856C0` | P |
| Közvetlen hívó | RVA `0xC85650`, raw `0xC84A50`, call helye `0xC85681` / raw `0xC84A81` | P |
| Bemeneti payload | `reverse/evidence/c856c0_dataflow.json` (backward), `reverse/evidence/c856c0_forward.json` (forward) | P |
| Támogató input | `c856c0_callers.csv`, `xref_edges.csv`, `cfg_functions.csv`, `patch_record_table.json`, `toolchain.json` | P |
| Generáló script | `reverse/scripts/defuse_slice.py`, `sha256 5c82f21d6127545afb7c7d3b7a3f0d1bf237ad84a8815c7bbf2718d395a6d650` | P |
| Eszközök | `pefile 2024.8.26`, `capstone 5.0.7` (`5.0.1280`), Python `3.14.7` | P |
| Irány | backward a `[descriptor+0]` loadtól; forward a két loadtól és a hívóklózától felfelé | P |

A két payload maga rögzíti a korlátot: `static file parsing only; the specimen is never loaded, mapped or executed`, továbbá `the payload describes code structure only; it contains no exploit, bypass, patch or shellcode guidance`.

```text
BRef = [RVA:<hex|N/A> | RAW:<hex|N/A> | CONF:<P|L|U> | STATUS:<OBSERVED|INFERRED|NEGATIVE|OPEN>]
```

- **RVA:** a PE-image-ben értelmezett relatív virtuális cím; hexadecimális, `0x` előtaggal.
- **RAW:** a specimen fájlban mért offset; hexadecimális, `0x` előtaggal.
- **CONF:** globális `P` / `L` / `U` confidence-jelölés.
- **STATUS:** `OBSERVED` = közvetlenül megfigyelt; `INFERRED` = statikus adatfolyamból valószínű; `NEGATIVE` = megadott scope-on belül nem találtunk; `OPEN` = lezáratlan.

## 2. Rövid összegzés

| Terület | Statikus megállapítás | Konf. | BRef |
|---|---|---|---|
| Dispatch | **Két** szomszédos, egyenként 16 elemű relatív jogcím-tábla: `0x2CFB1F8` és `0x2CFB238`; mindkettőt saját `RDTSC; AND EAX,0xF` sorozat választja ki | P | `[RVA:0x2CFB1F8 \| RAW:0x2CF9BF8 \| CONF:P \| STATUS:OBSERVED]` |
| Ágak | `16 + 16 = 32` ág-törzs; fázisonként 8 közvetlen `syscall` és 8 wrapper-hívás, tehát összesen **16 inline syscall + 16 wrapper-branch** | P | `[RVA:0xC8570B \| RAW:0xC84B0B \| CONF:P \| STATUS:OBSERVED]` |
| Handle load | **Két** különálló olvasás ugyanarról a descriptor-mezőről: `0xC856F3` (`r14`) és `0xC86440` (`rbx`); mindkettő 16 ágat táplál, összesen **32 fogyasztó él** | P | `[RVA:0xC856F3 \| RAW:0xC84AF3 \| CONF:P \| STATUS:OBSERVED]` |
| Wrapper | **12** distinct wrapper (6 allokációs + 6 transzfer); mindegyik pontosan egy `syscall`-t tartalmaz, és a hívás argumentum `N+1`-et továbbítja a syscall argumentum `N` helyére | P | `[RVA:0x51D680 \| RAW:0x51CA80 \| CONF:P \| STATUS:OBSERVED]` |
| Allokációs séma | 6 pozíció, `branches_matching_schema = 16`, `diverging = 0` | P | `[RVA:0xC858E0 \| RAW:0xC84CE0 \| CONF:P \| STATUS:OBSERVED]` |
| Transzfer séma | 5 pozíció, `branches_matching_schema = 16`, `diverging = 0` | P | `[RVA:0xC865ED \| RAW:0xC859ED \| CONF:P \| STATUS:OBSERVED]` |
| `remote_base` | `[rsp+0x50]`, egyszer nullázva, mind a 16 allokációs ág írja, kétszer olvassák, `RAX`-ban visszaadva; **nincs** átadott érték felülvizsgálata | P | `[RVA:0xC856E5 \| RAW:0xC84AE5 \| CONF:P \| STATUS:OBSERVED]` |
| Kimeneti vector | `closure+0` `{begin,end,capacity}`, `2*length+2` bájtos UTF-16 puffer; a visszaadott értéket **feltétel nélkül** appendeli | P | `[RVA:0xC85695 \| RAW:0xC84A95 \| CONF:P \| STATUS:OBSERVED]` |
| Hibaág | egyetlen explicit elágazás a merge-pont `test r14, r14`; nulla `remote_base` esetén nulla visszatérés, transzferfázis nélkül | P | `[RVA:0xC8642B \| RAW:0xC8582B \| CONF:P \| STATUS:OBSERVED]` |
| Státusz | 32 ágból **egyik sem** teszteli a syscall-státuszt; a transzfer-státusz slotnak **nincs** olvasóhelye | P | `[RVA:0xC86437 \| RAW:0xC85837 \| CONF:P \| STATUS:NEGATIVE]` |
| Handle-életciklus | a provable forward halmazban **nincs** `CloseHandle` és **nincs** `DuplicateHandle` callsite; a descriptoron keresztül **nincs** store | P | `[RVA:0xC856C0 \| RAW:0xC84AC0 \| CONF:P \| STATUS:NEGATIVE]` |
| Hívóklóza | `0 → 1 → 2` szinten kimerül: szint 2-n egyetlen `no_inbound_edge_in_enumerated_forms` sor, a frontier üres | P | `[RVA:0xC85650 \| RAW:0xC84A50 \| CONF:P \| STATUS:NEGATIVE]` |
| Handle producer | **OPEN**; nincs visszafelé elérhető store, a szerző nincs azonosítva | U | `[RVA:N/A \| RAW:N/A \| CONF:U \| STATUS:OPEN]` |
| Nt szolgáltatásnevek | **OPEN**; mind a 28 syscall helyen a service szám futásidőben, `KUSER_SHARED_DATA`/PEB/konstans keverésből képződik | U | `[RVA:0xC85A9A \| RAW:0xC84E9A \| CONF:U \| STATUS:OPEN]` |

A statikus szerkezet erős és teljesen lezárt. A célzott értelmezés – mely Nt szolgáltatás, mely célprocessz, mely szerző és mely felhasználói szándék – nyitott marad.

## 3. Felülírt korábbi állítások

A `06`, `07` és `12` dokumentumok `0xC856C0`-ra vonatkozó darabszám- és szerkezetállításai az alábbiakban **supercedáltak**. Az új számok a két új payloadból származnak, és a `06`/`12` azon mondataira vonatkoznak, amelyek a `8 syscall`, `2 wrapper` vagy `1 load` alakot használták.

| # | Korábbi állítás (forrás) | Felülírt állítás | Bizonyíték |
|---|---|---|---|
| C-01 | „8 dispatch-syscallpont", „a `0xC856C0` 8 közvetlen ága" (`12` §7.2, a 8. fejezet 5. pontja és a 12. fejezet, `06` §9.2) | Az anchorban **16** közvetlen `syscall` van: 8 allokációs + 8 transzfer. A wrapper-függvényekben további **12** `syscall` van, tehát a teljes forward tárgykörben **28** syscall-hely. | `exits.anchor.syscall_site_count = 16`; `inline_syscalls` lista 16 eleme; `wrappers` 12 eleme, mind `syscall` mezővel. `[RVA:0xC870DB \| RAW:0xC864DB \| CONF:P \| STATUS:OBSERVED]` |
| C-02 | A második diszperziós tábla (`0x2CFB238`, `0xC86443` selector) nem szerepel sem a `06`, sem a `12` dispatch-listájában | Két **egymástól független** 16-águ tábla létezik, szomszédos `.rdata` címeken (`0x2CFB1F8` + 0x40 = `0x2CFB238`), külön selector-sorozattal és külön merge-ponttal (`0xC86426` / `0xC870E1`). | `dispatch.tables_are_adjacent = true`; `dispatch.selectors` két elem; `stages` két elem. `[RVA:0x2CFB238 \| RAW:0x2CF9C38 \| CONF:P \| STATUS:OBSERVED]` |
| C-03 | „2 wrapper": a `06` §9.2 a `0x51D680`/`0x51D880`, a §9.3 a `0xC8F650`/`0xC8F880` wrappereket nevezi | **12** distinct wrapper: 6 allokációs (`0x51D680`, `0x51D880`, `0x51DAB0`, `0x51DC60`, `0x51DDE0`, `0x51DFF0`) és 6 transzfer (`0xC8F650`, `0xC8F880`, `0xC8FAA0`, `0xC8FC00`, `0xC8FDE0`, `0xC8FF60`). A 16 wrapper-branch a 12 címet 4 esetben ismétli (`0x51D680` a 0. és 10., `0x51DAB0` a 3. és 13., `0xC8F650` a 0. és 10., `0xC8FAA0` a 3. és 13. ágon). | `distinct_wrapper_targets` mindkét fázisban 6 elem; `wrappers` 12 elem `called_from_branch_indexes` mezővel. `[RVA:0x51DAB0 \| RAW:0x51CEB0 \| CONF:P \| STATUS:OBSERVED]` |
| C-04 | „1 load": a `06` §9.1 szerint a wrapper „a kapott descriptor első qwordját" használja; a `12` §6.1 egyetlen `0xC856F3` loadot említ | **Két** külön olvasás: `0xC856F3` (`mov r14, qword ptr [rcx]`, 16 fogyasztó) és `0xC86440` (`mov rbx, qword ptr [rbx]`, 16 fogyasztó). A második az allokációs merge-pont **után** történik, ezért a két érték nem automatikusan azonos. | `handle.loads` két elem, `use_count = 32`; `handle_lifetime.consume_site_count = 32`. `[RVA:0xC86440 \| RAW:0xC85840 \| CONF:P \| STATUS:OBSERVED]` |
| C-05 | A `12` §6.1 pont 3: „A legtöbb ágon `R14` a közvetlen `syscall` első argumentumaként, `R10`-be kerül" | Pontosan **16** ágon megy `R10`-be (8 allokációs + 8 transzfer), a másik **16** wrapper-ágon a `RDX` a második argumentumhelyzetbe kerül. A `R14`/`RBX` tehát nem domináns, hanem **50/50** megoszlású. | `handle.use_sites` 32 eleme, `argument_register` 16 `r10` és 16 `rdx`. `[RVA:0xC85731 \| RAW:0xC84B31 \| CONF:P \| STATUS:OBSERVED]` |
| C-06 | A `12` §6.3 a `0x051D680–0x051EBB9` tartományban 12 wrapper-syscallt sorol fel | Az a tartomány **6** allokációs wrappert tartalmaz, egyenként 1 syscalllal. A másik 6 transzfer-wrapper a `0x0C8F650–0x0C90144` tartományban van. A korábbi „12 wrapper" szám a két halmaz összegére igaz, de csak az egyik halmaz RVA-ja volt megadva. | `wrappers` mind a 12 címet felsorolja szekvenciálisan: `0x51D680`–`0x51DFF0`, majd `0xC8F650`–`0xC8FF60`. `[RVA:0xC8FF3A \| RAW:0xC8F33A \| CONF:P \| STATUS:OBSERVED]` |
| C-07 | A `06` §9.2/§9.3 néhány kiválasztott ágat nevez meg (`0xC85737`, `0xC8576D`, `0xC86420`, `0xC86477`, `0xC864A0`, `0xC870DB`) | Mind a 32 ág dokumentált, egyenként a slot-, blokk-, argument-, sink- és join-címmel. A korábbi hat példa nem reprezentatív volt: a `0xC86420` az **8** allokációs inline ág egyike, a `0xC870DB` a **8** transzfer inline ág egyike. | `dispatch.tables[0].branches` és `tables[1].branches` 16–16 elem. `[RVA:0xC86305 \| RAW:0xC85705 \| CONF:P \| STATUS:OBSERVED]` |
| C-08 | A `06` §13 táblázata: „Távoli írás – Státusz nem kerül visszaadásra" | Megerősítve és pontosítva: a **16** wrapper-ág `RAX`-ban a nyers státuszt adja vissza, de az anchor ezt eldobja, és **egyetlen** ág sem teszteli; az `rsp+0x40` transzfer-státusz slotnak **nulla** olvasóhelye van. | `wrappers[*].returns_syscall_status = true`; `result_slot.lifecycle.slots[0].direct_read_site_count = 0`. `[RVA:0xC86430 \| RAW:0xC85830 \| CONF:P \| STATUS:OBSERVED]` |
| C-09 | A `07` §7.1 csak az `0xC856F6`/`0x2CFB1F8` selector-párt listázza a `0xC856C0` kontextusban | Az anchor **két** selector-párt tartalmaz; a második `0xC86443` `RDTSC` / `0xC86445` `AND EAX,0xF` / `0xC86448` `LEA` / `0xC86456` `JMP RAX`, a `0x2CFB238` táblával. | `dispatch.selectors[1]`; `exits.anchor.exits[1]`. `[RVA:0xC86445 \| RAW:0xC85845 \| CONF:P \| STATUS:OBSERVED]` |

A nem érintett `06`/`07`/`12` megállapítások – köztük a `descriptor+0` → processzhandle szerkezet, a 6 argumentumos allokációs és az 5 argumentumos írás-/olvasásséma, a `2*length+2` méret, az ismeretlen handle-eredet és a `PROCESS_QUERY_LIMITED_INFORMATION` nem-összekapcsolhatóság – változatlanul érvényesek, és a jelen dokumentum nem cáfolja őket.

## 4. Kanonikus azonosítás és kódklaszter

### 4.1 A két runtime function

| Elem | `0xC85650` (belépő) | `0xC856C0` (anchor) |
|---|---|---|
| Kezdő RVA / raw | `0xC85650` / `0xC84A50` | `0xC856C0` / `0xC84AC0` |
| Záró RVA | `0xC856C0` | `0xC87104` |
| Méret | 112 bájt | 6 724 bájt |
| Unwind RVA | `0x301407C` | `0x30640A0` |
| Cluster id (`cfg_functions.csv`) | 85 | 85 |
| Dekódolt utasítás | 30, 0 nem dekódolt | 1 486, 0 nem dekódolt |
| Alapblokkok | 8 / 8 elérve, `reached_ratio = 1.0` | 108, `blocks_reached = 1`, `reached_ratio = 0.009259` |
| Terminátorok | 4 call, 1 direkt jmp, 2 jcc, 1 ret | 69 call, 31 direkt jmp, 2 indirekt jmp, 1 jcc, 1 ret, **16 syscall** |
| Kilépés | 1 (`0xC856BF` `ret`) | 3 (`0xC85709` `jmp rax`, `0xC86456` `jmp rax`, `0xC87103` `ret`) |
| Doc anchor | `0xC85650:handle_forward_wrapper` | `0xC856C0:handle_dispatch_site` |

Az anchor `reached_ratio` értéke nem hiba, hanem a diszperziós szerkezet következménye: a 16-entry jump-táblák 32 belépési élét a `cfg_functions.csv` nem számolja elérhető alapblokként, ezért egyetlen lineáris belépésből csak egy blokk látszik elérhetőnek. A `switch_sites_validated = 0` és a `syscall_sites = 16` mezők ezt egyszerűen rögzítik.

```text
BRef = [RVA:0xC85650 | RAW:0xC84A50 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0xC856C0 | RAW:0xC84AC0 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x30640A0 | RAW:N/A | CONF:P | STATUS:OBSERVED]
```

### 4.2 A 16 függvényből álló kódklaszter

A `0xC85000–0xC88000` tartományban 16 `.pdata`-lefedett függvény van. Az anchor a hatodik. A klaszter a két dispatch-táblát nem tartalmazza: azok a `.rdata` `0x2BEF000`, 5 021 696 bájtos tartományában, a `0x2CFB1F8` és `0x2CFB238` címen vannak.

| # | Begin RVA | End RVA | Méret | Unwind RVA | Raw |
|---:|---|---|---:|---|---|
| 1 | `0xC81EE0` | `0xC8558A` | 13 994 | `0x3063F84` | `0xC812E0` |
| 2 | `0xC85590` | `0xC855AE` | 30 | `0x3063FA8` | `0xC84990` |
| 3 | `0xC855B0` | `0xC855CE` | 30 | `0x3063FC0` | `0xC849B0` |
| 4 | `0xC855D0` | `0xC8564C` | 124 | `0x3011724` | `0xC849D0` |
| 5 | `0xC85650` | `0xC856C0` | 112 | `0x301407C` | `0xC84A50` |
| 6 | `0xC856C0` | `0xC87104` | 6 724 | `0x30640A0` | `0xC84AC0` |
| 7 | `0xC87110` | `0xC871E4` | 212 | `0x2FFAC14` | `0xC86510` |
| 8 | `0xC871F0` | `0xC87347` | 343 | `0x30640B4` | `0xC865F0` |
| 9 | `0xC87350` | `0xC87381` | 49 | `0x30640D0` | `0xC86750` |
| 10 | `0xC87390` | `0xC873B8` | 40 | `0x30640E0` | `0xC86790` |
| 11 | `0xC873C0` | `0xC876B4` | 756 | `0x3064148` | `0xC867C0` |
| 12 | `0xC876C0` | `0xC876F8` | 56 | `0x306416C` | `0xC86AC0` |
| 13 | `0xC87710` | `0xC87730` | 32 | `0x2FF7034` | `0xC86B10` |
| 14 | `0xC87730` | `0xC877A2` | 114 | `0x3014FC0` | `0xC86B30` |
| 15 | `0xC87830` | `0xC878FF` | 207 | `0x2FFAC14` | `0xC86C30` |
| 16 | `0xC87900` | `0xC8CE4E` | 21 838 | `0x30641CC` | `0xC86D00` |

A 12 wrapper mind a tizenhat függvényes `0xC85000–0xC88000` tartományon **kívül** van: a 6 allokációs a `0x51D680–0x51DFF0` tartományban, a 6 transzfer a `0xC8F650–0xC8FF60` tartományban, és egyikük sem esik a fenti 16 funkció közé. A `cluster_id` ezzel szemben a `cfg_functions.csv` közelség-csoportjának azonosítója: a 6 allokációs wrapper `cluster_id = 38`, a 6 transzfer wrapper `cluster_id = 85`, akárcsak a belépő függvény és az anchor. A `cluster_id = 85` tehát **nem** azt jelenti, hogy a transzfer wrapper-ek a tizenhat függvényes tartományban vannak; a két azonosító nem felcserélhető, és a közös szám ellenére a tartományhatár megmarad.

```text
BRef = [RVA:0xC85000 | RAW:N/A | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0xC8CE4E | RAW:0xC8C24E | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x2BEF000 | RAW:0x2BEDA00 | CONF:P | STATUS:OBSERVED]
```

## 5. Objektummodell

### 5.1 A 16 bájtos closure pár

A belépő függvény `RCX`-e egy 16 bájtos szerkezet, `{qword output_vector, qword descriptor}`:

| Offset | Szerep | Bizonyíték helye | Konf. |
|---:|---|---|---|
| `+0x00` | a visszaadott címek kimeneti vektora | `0xC85664` / `0xC84A64` – `mov rsi, qword ptr [rcx]` | P |
| `+0x08` | a descriptor pointer, amit `RCX`-ként ad tovább | `0xC85667` / `0xC84A67` – `mov rcx, qword ptr [rcx + 8]` | P |

A belépő függvény két további bemenetet kezel: a string objektumot `RDX`-ben, amelynek `+0x10` mezője a hossz és `+0x18` mezője a tárolási mód; a bájszám `2 * length + 2` a `0xC8566F` / `0xC84A6F` címen képződik (`lea r8, [rax*2 + 2]`), ami UTF-16 pufferméret. A tárolási mód kiválasztása a `0xC8567C` / `0xC84A7C` címen történik.

### 5.2 A descriptor

A descriptor `+0` mezőjét olvassa az anchor, és **semmi mást**:

```text
0xC856F3  4C 8B 31   mov r14, qword ptr [rcx]
0xC86440  48 8B 1B   mov rbx, qword ptr [rbx]
```

`fields_observed = [0]`; a `size_bytes` mező `null`, mert a függvényben nincs olyan hozzáférés, amelyből a teljes méret eldönthető lenne. A descriptor `RCX`-ben megőrződik: `0xC856D3` / `0xC84AD3` – `mov rbx, rcx`, hogy a transzferfázis újraolvashassa. A `0xC856D3` nincs élként a `c856c0_dataflow.json` `edges` listájában, de a `handle` mező maga is rögzíti.

### 5.3 Nincs MSVC RTTI

A `.rdata` `0x2BEF000`, 5 021 696 bájtos tartományának átvizsgálása:

| Mutató | Eredmény | Konf. |
|---|---:|---|
| `.?A` típusleíró nevek | 0 | P |
| `signature == 1` Complete Object Locator rekordok | 0 | P |
| Összesített következtetés | a descriptor és a closure konkrét osztálya RTTI-ből nem nevezhető meg | P |

A szerkezeti leírás (`object_model`) használható; a típusnév nem. A `06` §9.5 és a `12` §6.1 azon állítása, hogy a handleeredet a visszafelé futó adatfolyam miatt nyitott, ezt nem cáfolja, hanem oklát ad: az objektumot RTTI nélkül nem lehet osztályként azonosítani.

```text
BRef = [RVA:0x2BEF000 | RAW:0x2BEDA00 | CONF:P | STATUS:NEGATIVE]
BRef = [RVA:N/A | RAW:N/A | CONF:U | STATUS:OPEN]
```

## 6. A két dispatch tábla

### 6.1 Szomszédság és formátum

| Tulajdonság | Allokációs tábla | Transzfer tábla | Konf. |
|---|---|---|---|
| Tábla RVA | `0x2CFB1F8` | `0x2CFB238` | P |
| Tábla raw | `0x2CF9BF8` | `0x2CF9C38` | P |
| Szekció | `.rdata` | `.rdata` | P |
| Elem | 16 `int32` relatív jogcím | 16 `int32` relatív jogcím | P |
| Slot lépés | 4 bájt | 4 bájt | P |
| Materializáló `LEA` | `0xC856FB` / `0xC84AFB` | `0xC86448` / `0xC85848` | P |
| Slot tartomány | `0x2CFB1F8`–`0x2CFB234` | `0x2CFB238`–`0x2CFB274` | P |
| `tables_are_adjacent` | `true` (`0x2CFB1F8` + 0x40 = `0x2CFB238`) | | P |
| Összes elem | `table_entries = 16` fázisonként, `2` tábla összesen | | P |

A szomszédság byte-szinten igazolt, szemantikai jelentése nem: mindkét tartomány saját `RDTSC & 0xF` sorozattal és saját merge-ponttal rendelkezik, így a két tábla önálló 16-águ diszperzió. A közös `.rdata` blokk valószínűleg a fordító kimenetének egyszerű térkiosztása, nem tervezett 32-águ dispatch; a kérdés a 17. fejezet `Q-05` tétele marad.

### 6.2 A két selector-sorozat

Mindkét szelektor a rá közvetlenül előző handle-load utasítás után hat utasításból áll, azonos kódhosszakkal, így a második szekvencia a `0xC86456` `JMP RAX` címen zárul, és az első transzfer blokk `0xC86458`-nál kezdődik. A `MOVSXD` és az `ADD` a fájlból olvasott `48 63 04 81` és `48 01 c8` bájtokon alapul.

```text
allokáció:
0xC856F3  4C 8B 31                     mov r14, qword ptr [rcx]      ; első handle load
0xC856F6  0F 31                         rdtsc
0xC856F8  83 E0 0F                      and eax, 0xf
0xC856FB  48 8D 0D F6 5A 07 02          lea rcx, [rip + 0x02075af6]  ; rcx = 0x2CFB1F8
0xC85702  48 63 04 81                   movsxd rax, dword ptr [rcx + rax*4]
0xC85706  48 01 C8                      add rax, rcx
0xC85709  FF E0                         jmp rax

transzfer:
0xC86440  48 8B 1B                     mov rbx, qword ptr [rbx]      ; második handle load
0xC86443  0F 31                         rdtsc
0xC86445  83 E0 0F                      and eax, 0xf
0xC86448  48 8D 0D E9 4D 07 02          lea rcx, [rip + 0x02074de9]  ; rcx = 0x2CFB238
0xC8644F  48 63 04 81                   movsxd rax, dword ptr [rcx + rax*4]
0xC86453  48 01 C8                      add rax, rcx
0xC86456  FF E0                         jmp rax
```

| Elem | Allokáció | Transzfer | Konf. |
|---|---|---|---|
| `RDTSC` RVA / raw | `0xC856F6` / `0xC84AF6` | `0xC86443` / `0xC85843` | P |
| `AND EAX,0xF` RVA / raw | `0xC856F8` / `0xC84AF8` (`83 E0 0F`) | `0xC86445` / `0xC85845` (`83 E0 0F`) | P |
| `LEA` encoding | `48 8d 0d f6 5a 07 02` | `48 8d 0d e9 4d 07 02` | P |
| `MOVSXD` / `ADD` / `JMP RAX` | `0xC85702` / `0xC85706` / `0xC85709` | `0xC8644F` / `0xC86453` / `0xC86456` | P |
| `JMP RAX` raw | `0xC84B09` | `0xC85856` | P |
| `leaves_function` | `true` | `true` | P |

A `07` §7.1 a `0xC856F6` sort disasszemblálva már dokumentálta; a `0xC86443` sor a jelen passzban került először teljes sorrendi rögzítéssel. A `RDTSC` itt ágválasztó és kódkeverő eszköz; önmagában nem delta-időzítési küszöb és nem anti-debug jel.

```text
BRef = [RVA:0xC856F6 | RAW:0xC84AF6 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0xC86443 | RAW:0xC85843 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x2CFB1F8 | RAW:0x2CF9BF8 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x2CFB238 | RAW:0x2CF9C38 | CONF:P | STATUS:OBSERVED]
```

### 6.3 Slot- és cél-táblázat

Mind a 32 slot `int32` relatív eltolást tartalmaz; a cél a slot saját RVA-je + eltolás. A `0xFDF8…` nagyságrendű eltolások a 34 MB-os `.text` mérettel konzisztens.

| Slot (allok) | Raw | `int32` | Cél RVA | Slot (transzfer) | Raw | `int32` | Cél RVA |
|---|---|---|---|---|---|---|---|
| `0x2CFB1F8` | `0x2CF9BF8` | `0xFDF8A513` | `0xC8570B` | `0x2CFB238` | `0x2CF9C38` | `0xFDF8B220` | `0xC86458` |
| `0x2CFB1FC` | `0x2CF9BFC` | `0xFDF8A549` | `0xC85741` | `0x2CFB23C` | `0x2CF9C3C` | `0xFDF8B249` | `0xC86481` |
| `0x2CFB200` | `0x2CF9C00` | `0xFDF8A57F` | `0xC85777` | `0x2CFB240` | `0x2CF9C40` | `0xFDF8B272` | `0xC864AA` |
| `0x2CFB204` | `0x2CF9C04` | `0xFDF8A6F3` | `0xC858EB` | `0x2CFB244` | `0x2CF9C44` | `0xFDF8B3C0` | `0xC865F8` |
| `0x2CFB208` | `0x2CF9C08` | `0xFDF8A729` | `0xC85921` | `0x2CFB248` | `0x2CF9C48` | `0xFDF8B3E9` | `0xC86621` |
| `0x2CFB20C` | `0x2CF9C0C` | `0xFDF8A8AD` | `0xC85AA5` | `0x2CFB24C` | `0x2CF9C4C` | `0xFDF8B50A` | `0xC86742` |
| `0x2CFB210` | `0x2CF9C10` | `0xFDF8A8E3` | `0xC85ADB` | `0x2CFB250` | `0x2CF9C50` | `0xFDF8B533` | `0xC8676B` |
| `0x2CFB214` | `0x2CF9C14` | `0xFDF8A9C3` | `0xC85BBB` | `0x2CFB254` | `0x2CF9C54` | `0xFDF8B722` | `0xC8695A` |
| `0x2CFB218` | `0x2CF9C18` | `0xFDF8A9F9` | `0xC85BF1` | `0x2CFB258` | `0x2CF9C58` | `0xFDF8B74B` | `0xC86983` |
| `0x2CFB21C` | `0x2CF9C1C` | `0xFDF8AA2F` | `0xC85C27` | `0x2CFB25C` | `0x2CF9C5C` | `0xFDF8B774` | `0xC869AC` |
| `0x2CFB220` | `0x2CF9C20` | `0xFDF8ABD6` | `0xC85DCE` | `0x2CFB260` | `0x2CF9C60` | `0xFDF8B89F` | `0xC86AD7` |
| `0x2CFB224` | `0x2CF9C24` | `0xFDF8AC0C` | `0xC85E04` | `0x2CFB264` | `0x2CF9C64` | `0xFDF8B8C8` | `0xC86B00` |
| `0x2CFB228` | `0x2CF9C28` | `0xFDF8ADDF` | `0xC85FD7` | `0x2CFB268` | `0x2CF9C68` | `0xFDF8BA8F` | `0xC86CC7` |
| `0x2CFB22C` | `0x2CF9C2C` | `0xFDF8AF53` | `0xC8614B` | `0x2CFB26C` | `0x2CF9C6C` | `0xFDF8BBDD` | `0xC86E15` |
| `0x2CFB230` | `0x2CF9C30` | `0xFDF8AF89` | `0xC86181` | `0x2CFB270` | `0x2CF9C70` | `0xFDF8BC06` | `0xC86E3E` |
| `0x2CFB234` | `0x2CF9C34` | `0xFDF8B10D` | `0xC86305` | `0x2CFB274` | `0x2CF9C74` | `0xFDF8BD27` | `0xC86F5F` |

### 6.4 A két konstanstár

| Ablak | RVA | Raw | Méret | Entropia | Nulla bájt | 8 nulla bájttal kezdődő 24 bájtos csoport |
|---|---|---|---:|---:|---:|---:|
| Allokációs konstans | `0x31261B0` | `0x3124BB0` | 160 | 5,6929 | 40 (25,0 %) | 2 / 6 |
| Transzfer konstans | `0x3189A90` | `0x3188490` | 256 | 5,4270 | 88 (34,4 %) | 5 / 10 |
| Wrapper állapotglobálisok | `0x30E35F0` | `0x30E1FF0` | 64 | 0,0 | 64 (100 %) | 2 / 2, teljesen nulla |

Az entropia és a nulla-prefix szám a nyers fájlbájtokon mért érték, ezért a „24 bájtos csoport, amelyek fele 8 nulla bájttal kezdődik" leírás ellenőrizhető, nem feltevés. Referenciaként az anchor törzse (`0xC856C0`, 6 724 bájt) 5,9970 entropiájú, 266 nulla bájttal és 0 ilyen csoporttal. A wrapper-állapot ablak teljesen nulla a fájlban, ami összhangban van azzal, hogy a wrapperek futás közbeni kontextust hordoznak benne.

```text
BRef = [RVA:0x31261B0 | RAW:0x3124BB0 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x3189A90 | RAW:0x3188490 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x30E35F0 | RAW:0x30E1FF0 | CONF:P | STATUS:OBSERVED]
```

## 7. A 16 + 16 ág

### 7.1 Allokációs fázis – 16 ág

Merge-pont: `0xC86426` / `0xC85826`. Hordozó regiszter: `r14`. `branches = 16`, `wrapper_branch_count = 8`, `inline_branch_count = 8`, `distinct_wrapper_targets = 6`.

| Ág | Slot RVA | Blokk RVA | Utasítás (forward passz) | Sink | Sink raw | Cél | Arg. hely | Arg. raw | Join |
|---:|---|---|---:|---|---|---|---:|---|---|
| 0 | `0x2CFB1F8` | `0xC8570B` | 9 | `call 0x18051D680` @ `0xC85737` | `0xC84B37` | `0x51D680` | `rdx, r14` @ `0xC85731` | `0xC84B31` | `jmp` merge |
| 1 | `0x2CFB1FC` | `0xC85741` | 9 | `call 0x18051D880` @ `0xC8576D` | `0xC84B6D` | `0x51D880` | `rdx, r14` @ `0xC85767` | `0xC84B67` | `jmp` merge |
| 2 | `0x2CFB200` | `0xC85777` | 79 | `syscall` @ `0xC858E0` | `0xC84CE0` | – | `r10, r14` @ `0xC858C4` | `0xC84CC4` | fall-through |
| 3 | `0x2CFB204` | `0xC858EB` | 9 | `call 0x18051DAB0` @ `0xC85917` | `0xC84D17` | `0x51DAB0` | `rdx, r14` @ `0xC85911` | `0xC84D11` | `jmp` merge |
| 4 | `0x2CFB208` | `0xC85921` | 87 | `syscall` @ `0xC85A9A` | `0xC84E9A` | – | `r10, r14` @ `0xC85A7E` | `0xC84E7E` | fall-through |
| 5 | `0x2CFB20C` | `0xC85AA5` | 9 | `call 0x18051DC60` @ `0xC85AD1` | `0xC84ED1` | `0x51DC60` | `rdx, r14` @ `0xC85ACB` | `0xC84ECB` | `jmp` merge |
| 6 | `0x2CFB210` | `0xC85ADB` | 41 | `syscall` @ `0xC85BB0` | `0xC84FB0` | – | `r10, r14` @ `0xC85B94` | `0xC84F94` | fall-through |
| 7 | `0x2CFB214` | `0xC85BBB` | 9 | `call 0x18051DDE0` @ `0xC85BE7` | `0xC84FE7` | `0x51DDE0` | `rdx, r14` @ `0xC85BE1` | `0xC84FE1` | `jmp` merge |
| 8 | `0x2CFB218` | `0xC85BF1` | 9 | `call 0x18051DFF0` @ `0xC85C1D` | `0xC8501D` | `0x51DFF0` | `rdx, r14` @ `0xC85C17` | `0xC85017` | `jmp` merge |
| 9 | `0x2CFB21C` | `0xC85C27` | 88 | `syscall` @ `0xC85DC3` | `0xC851C3` | – | `r10, r14` @ `0xC85DA7` | `0xC851A7` | fall-through |
| 10 | `0x2CFB220` | `0xC85DCE` | 9 | `call 0x18051D680` @ `0xC85DFA` | `0xC851FA` | `0x51D680` | `rdx, r14` @ `0xC85DF4` | `0xC851F4` | `jmp` merge |
| 11 | `0x2CFB224` | `0xC85E04` | 105 | `syscall` @ `0xC85FCC` | `0xC853CC` | – | `r10, r14` @ `0xC85FB0` | `0xC853B0` | fall-through |
| 12 | `0x2CFB228` | `0xC85FD7` | 79 | `syscall` @ `0xC86140` | `0xC85540` | – | `r10, r14` @ `0xC86124` | `0xC85524` | fall-through |
| 13 | `0x2CFB22C` | `0xC8614B` | 9 | `call 0x18051DAB0` @ `0xC86177` | `0xC85577` | `0x51DAB0` | `rdx, r14` @ `0xC86171` | `0xC85571` | `jmp` merge |
| 14 | `0x2CFB230` | `0xC86181` | 87 | `syscall` @ `0xC862FA` | `0xC856FA` | – | `r10, r14` @ `0xC862DE` | `0xC856DE` | fall-through |
| 15 | `0x2CFB234` | `0xC86305` | 61 | `syscall` @ `0xC86420` | `0xC85820` | – | `r10, r14` @ `0xC86404` | `0xC85804` | fall-through |

Mind a 16 ág `branches_matching_schema = 16` szerint illeszkedik az allokációs sémához, `branches_diverging_from_schema = 0`. Az „Utasítás (forward passz)" oszlop a `c856c0_forward.json#stages[].branches[].instruction_count` értékeit adja; a backward passz `block_instruction_count` mezője a 8 wrapper-ágon (0., 1., 3., 5., 7., 8., 10., 13.) 10, vagyis egy utasítással nagyobb, a 8 inline ágon viszont a két érték azonos (79, 87, 41, 88, 105, 79, 87, 61).

### 7.2 Transzfer fázis – 16 ág

Merge-pont: `0xC870E1` / `0xC864E1`. Hordozó regiszter: `rbx`. `branches = 16`, `wrapper_branch_count = 8`, `inline_branch_count = 8`, `distinct_wrapper_targets = 6`.

| Ág | Slot RVA | Blokk RVA | Utasítás (forward passz) | Sink | Sink raw | Cél | Arg. hely | Arg. raw | Join |
|---:|---|---|---:|---|---|---|---:|---|---|
| 0 | `0x2CFB238` | `0xC86458` | 8 | `call 0x180C8F650` @ `0xC86477` | `0xC85877` | `0xC8F650` | `rdx, rbx` @ `0xC8646E` | `0xC8586E` | `jmp` merge |
| 1 | `0x2CFB23C` | `0xC86481` | 8 | `call 0x180C8F880` @ `0xC864A0` | `0xC858A0` | `0xC8F880` | `rdx, rbx` @ `0xC86497` | `0xC85897` | `jmp` merge |
| 2 | `0x2CFB240` | `0xC864AA` | 73 | `syscall` @ `0xC865ED` | `0xC859ED` | – | `r10, rbx` @ `0xC865D8` | `0xC859D8` | fall-through |
| 3 | `0x2CFB244` | `0xC865F8` | 8 | `call 0x180C8FAA0` @ `0xC86617` | `0xC85A17` | `0xC8FAA0` | `rdx, rbx` @ `0xC8660E` | `0xC85A0E` | `jmp` merge |
| 4 | `0x2CFB248` | `0xC86621` | 59 | `syscall` @ `0xC86737` | `0xC85B37` | – | `r10, rbx` @ `0xC86722` | `0xC85B22` | fall-through |
| 5 | `0x2CFB24C` | `0xC86742` | 8 | `call 0x180C8FC00` @ `0xC86761` | `0xC85B61` | `0xC8FC00` | `rdx, rbx` @ `0xC86758` | `0xC85B58` | `jmp` merge |
| 6 | `0x2CFB250` | `0xC8676B` | 113 | `syscall` @ `0xC8694F` | `0xC85D4F` | – | `r10, rbx` @ `0xC8693A` | `0xC85D3A` | fall-through |
| 7 | `0x2CFB254` | `0xC8695A` | 8 | `call 0x180C8FDE0` @ `0xC86979` | `0xC85D79` | `0xC8FDE0` | `rdx, rbx` @ `0xC86970` | `0xC85D70` | `jmp` merge |
| 8 | `0x2CFB258` | `0xC86983` | 8 | `call 0x180C8FF60` @ `0xC869A2` | `0xC85DA2` | `0xC8FF60` | `rdx, rbx` @ `0xC86999` | `0xC85D99` | `jmp` merge |
| 9 | `0x2CFB25C` | `0xC869AC` | 65 | `syscall` @ `0xC86ACC` | `0xC85ECC` | – | `r10, rbx` @ `0xC86AB7` | `0xC85EB7` | fall-through |
| 10 | `0x2CFB260` | `0xC86AD7` | 8 | `call 0x180C8F650` @ `0xC86AF6` | `0xC85EF6` | `0xC8F650` | `rdx, rbx` @ `0xC86AED` | `0xC85EED` | `jmp` merge |
| 11 | `0x2CFB264` | `0xC86B00` | 102 | `syscall` @ `0xC86CBC` | `0xC860BC` | – | `r10, rbx` @ `0xC86CA7` | `0xC860A7` | fall-through |
| 12 | `0x2CFB268` | `0xC86CC7` | 73 | `syscall` @ `0xC86E0A` | `0xC8620A` | – | `r10, rbx` @ `0xC86DF5` | `0xC861F5` | fall-through |
| 13 | `0x2CFB26C` | `0xC86E15` | 8 | `call 0x180C8FAA0` @ `0xC86E34` | `0xC86234` | `0xC8FAA0` | `rdx, rbx` @ `0xC86E2B` | `0xC8622B` | `jmp` merge |
| 14 | `0x2CFB270` | `0xC86E3E` | 59 | `syscall` @ `0xC86F54` | `0xC86354` | – | `r10, rbx` @ `0xC86F3F` | `0xC8633F` | fall-through |
| 15 | `0x2CFB274` | `0xC86F5F` | 85 | `syscall` @ `0xC870DB` | `0xC864DB` | – | `r10, rbx` @ `0xC870C6` | `0xC864C6` | fall-through |

`branches_matching_schema = 16`, `branches_diverging_from_schema = 0`. Az „Utasítás (forward passz)" oszlop itt is a forward passz értékeit adja; a backward passz a 8 wrapper-ágon (0., 1., 3., 5., 7., 8., 10., 13.) 9-et ad, vagyis egy utasítással többet, a 8 inline ágon a két passz megegyezik (73, 59, 113, 65, 102, 73, 59, 85).

### 7.3 A két ágcsoport szerkezeti különbsége

| Jellemző | 8 wrapper-ág fázisonként | 8 inline-ág fázisonként |
|---|---|---|
| Törzs hossza, forward passz | 8–9 utasítás | 41–113 utasítás |
| Törzs hossza, backward passz | 9–10 utasítás | 41–113 utasítás, a forward passzal azonos |
| Argumentumhordozó mozgás | 1 `mov` | 1 `mov` |
| Köztes hívások | 0 | 1–7 (`other_calls`) |
| Szolgáltatás-szám keverés | a wrapperben, külön függvényben | a blokkban, a `syscall` előtt |
| Join | `unconditional_jump` a merge-re, `merge_reachability = OBSERVED` | `add rsp, 0x30` majd `jmp`, `merge_reachability = NOT_ASSERTED` |
| Státuszteszt a merge előtt | 0 | 0 |
| Indirekt callsite | 0 | 0 |
| `status_tested_after_sink` | `false` | `false` |

A `NOT_ASSERTED` jelölés nem azt jelenti, hogy a merge elérhetetlen: azt jelenti, hogy a `syscall` utáni lineáris utasításfolyam feltételes vezérlést tartalmaz, ezért az elérés lineáris dekóddal nem állítható. A `07` §8.2 és a `12` 8. fejezete 6. pontjának disassembly-korlátja ezt a határt nem szünteti meg.

A két wrapper-törzs hosszában a két passz 1 utasításban különbözik, és a különbség a 16 wrapper-ág mindegyikén `forward minus backward = -1`, azaz 9 a 10 helyett az allokációban és 8 a 9 helyett a transzferben. Ez definíciókülönbség – a backward passz 1 utasítással korábbi blokkkezdést feltételez –, nem számszerű ellentmondás; a 16 inline ág-törzsnél a két passz bitre azonos.

### 7.4 Globális cím-thunkok az ágakban

A backward passz öt olyan `lea rax, [rip + …]` thunkot rögzít az ágakban, amelyek `.data` globálisra oldanak, és egyik sem `.pdata`-lefedett. A forward passz egy hatodikat is kimutat, a `0xCAC150`-et, amelyet a `0xC8FDE0` transzfer wrapper hív a `0xC8FEE4` hívóhelyen; az encodingjét és a feloldott globálisát a rendelkezésre álló audit nem adja meg, ezért azok `N/A`:

| Thunk RVA | Thunk raw | `lea` RVA | Encoding | Feloldott globális | Szekció |
|---|---|---|---|---|---|
| `0xCAC0D0` | `0xCAB4D0` | `0xCAC0D1` | `48 8d 05 8c 90 4a 02` | `0x3155164` | `.data` |
| `0xCAC0F0` | `0xCAB4F0` | `0xCAC0F1` | `48 8d 05 04 da 4e 02` | `0x3199AFC` | `.data` |
| `0xCAC110` | `0xCAB510` | `0xCAC111` | `48 8d 05 76 9b 5b 02` | `0x3265C8E` | `.data` |
| `0xCAC130` | `0xCAB530` | `0xCAC131` | `48 8d 05 e3 2b 4e 02` | `0x318ED1B` | `.data` |
| `0xCAC150` | `0xCAB550` | `0xCAC151` | `N/A` | `N/A` | `N/A` |
| `0xCAC170` | `0xCAB570` | `0xCAC171` | `48 8d 05 42 79 4f 02` | `0x31A3ABA` | `.data` |

A hívóhelyek: `0xCAC0D0` a `0xC85B1D`-en (allok 6. ág); `0xCAC0F0` a `0xC870A4`-en (transzfer 15. ág); `0xCAC110` a `0xC87015`-en (transzfer 15. ág) és a `0xC8FCEB`-en; `0xCAC130` a `0xC868DA`-n (transzfer 6. ág); `0xCAC170` a `0xC86A52`-en (transzfer 9. ág); `0xCAC150` a `0xC8FEE4`-en, a `0xC8FDE0` transzfer wrapperből (T5), tehát nem inline ágból. Ezek `RAX`-ot állítanak be, majd az ág a syscall service-szám keverésébe vonja be őket; a szolgáltatásszám emiatt futásidejű. A `covered_by_pdata = false` jelölés nem anomália: ezek öt bájtos, két utasítással nem fedett szekvenciák, nem funkciók. A `0xCAC150` raw értéke nem szerepel a payloadokban, hanem a `.text` szakasz `0xC00`-es rva–raw eltolásából származtatott, ezért `L` jelölésű.

```text
BRef = [RVA:0xCAC0D0 | RAW:0xCAB4D0 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0xCAC150 | RAW:0xCAB550 | CONF:L | STATUS:OBSERVED]
BRef = [RVA:0x3155164 | RAW:0x3153B64 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0xC85B1D | RAW:0xC84F1D | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0xC8FEE4 | RAW:0xC8F2E4 | CONF:L | STATUS:OBSERVED]
BRef = [RVA:N/A | RAW:N/A | CONF:U | STATUS:OPEN]
```

## 8. A két handle load és a 32 fogyasztó él

### 8.1 A két olvasás

| # | RVA | Raw | VA | Utasítás | Hordozó | Fogyasztó ágak | Fázis |
|---:|---|---|---|---|---|---:|---|
| L1 | `0xC856F3` | `0xC84AF3` | `0x180C856F3` | `mov r14, qword ptr [rcx]` (`4c 8b 31`) | `r14` | 16 | allokáció |
| L2 | `0xC86440` | `0xC85840` | `0x180C86440` | `mov rbx, qword ptr [rbx]` (`48 8b 1b`) | `rbx` | 16 | transzfer |

A `loads_are_separate_reads = true`. Az `RBX` a `RCX`-ből `0xC856D3` / `0xC84AD3` – `mov rbx, rcx` – útjávan kerül ide, tehát a második olvasás ugyanarra a descriptor-mezőre mutat.

### 8.2 A 32 fogyasztó él

Az élhalmaz `use_count = 32`, `consume_site_count = 32`, `consume_sites = {alloc_stage: 16, transfer_stage: 16}`, `carriers = [r14, rbx]`. Minden él háromlépéses: tábla → hordozó → argumentumhelyzet → sink.

| Élcsoport | Forrás csomópont | Közbenső | Argumentumhely | Élek | Konf. |
|---|---|---|---|---:|---|
| `indirect_jump` | `N_TABLE_ALLOC` | – | – | 16 | P |
| `copy` | `N_R14` | – | `RDX` (wrapper) | 8 | P |
| `copy` | `N_R14` | – | `R10` (inline) | 8 | P |
| `argument_pass` | argumentum-csomópont | – | wrapper-hívás / `syscall` | 16 | P |
| `indirect_jump` | `N_TABLE_TRANSFER` | – | – | 16 | P |
| `copy` | `N_RBX` | – | `RDX` (wrapper) | 8 | P |
| `copy` | `N_RBX` | – | `R10` (inline) | 8 | P |
| `argument_pass` | argumentum-csomópont | – | wrapper-hívás / `syscall` | 16 | P |
| Összes | | | | **96 élrekord, 32 fogyasztási hely** | P |

Az argumentumhelyzet-megoszlás pontosan 16 `R10` (első syscall argumentum) és 16 `RDX` (második argumentum, mert a wrapper az első helyen egy állapotglobálist kap). Ez a `12` §6.1 pont 3 „legtöbb ágon" megfogalmazását korrigálja: az arány 50/50.

### 8.3 Olvasás, nem írás

A teljes anchor törzs capstone-dekódja alapján a descriptor-t hordozó regiszterek (`rcx`, `rbx`) egyikén sincs store:

| Mutató | Eredmény | Konf. |
|---|---:|---|
| `stores_through_a_descriptor_carrying_register` | 0 | P |
| `load_sites` | 2 | P |
| `indirekt callsite` az anchorban | 0 | P |
| `indirekt callsite` a 32 ág-törzsben | 0 | P |
| `indirekt callsite` a belépő függvényben | 0 | P |
| `indirekt callsite` a 12 wrapperben | 0 | P |

A handle tehát a teljes vizsgált tartományban csak olvasódik, és a 32 fogyasztási hely mindegyike egy-egy argumentumátadás. A `12` §6.1 pont 2–3 megállapítása ezzel megerősítve és számszerűen lezárva.

### 8.4 A két olvasás értékének azonossága: nyitott

A `handle.value_may_change_between_loads` flag `true`, indoklással: hat distinct allokációs wrapper-hívás és nyolc inline `syscall` van közöttük, a descriptor pedig futásidejű cím, ezért aliasing store sem megerősíthető, sem kizárható. Egyik hívott függvény sem kapja meg pointerként a descriptort, így a def-use lánc két független olvásként marad nyilvántartva; ez a `Q-06` nyitott kérdés.

```text
BRef = [RVA:0xC856F3 | RAW:0xC84AF3 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0xC86440 | RAW:0xC85840 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:N/A | RAW:N/A | CONF:U | STATUS:OPEN]
```

## 9. A 12 wrapper forwarding

### 9.1 Közös szerkezeti séma

Mind a 12 wrapperre igaz:

| Tulajdonság | Érték | Konf. |
|---|---|---|
| `syscall` helyek száma | pontosan 1 | P |
| Hívás argumentum `N` → syscall argumentum `N-1` | minden pozícióra | P |
| `returns_syscall_status` | `true` | P |
| Státusz-visszaadás | `mov eax, esi` a `syscall` után | P |
| `api_call_site_count` | 0 | P |
| `handle_argument_position` | 1 | P |
| `closes_handle` | `false` | P |
| `duplicates_handle` | `false` | P |
| Prologue frame | 104 bájt, kivéve `0x51D680` és `0x51DDE0`: 120 | P |
| `indirect_call_site_count` | 0 | P |

A service-map `wrapper_forwarding` predikátumának 21 helyszáma nem ezt a 12 wrappert számolja: az egy másik, 3 627 helyes korpuszon érvényes alak-osztály, és a 12 wrapper egyike sem tartozik bele. A scope-korlát részlete a [Javított számlálások](#javított-számlálások) blokkban van.

### 9.2 Allokációs wrapper-ek – 6

| # | RVA | Raw | Méret | Utasítás | `syscall` RVA | `syscall` raw | Státusz-vissza | `ret` RVA | Hívó ág(ak) | Állapotglobális |
|---:|---|---|---:|---:|---|---|---|---|---|---|
| A1 | `0x51D680` | `0x51CA80` | 501 | 132 | `0x51D84C` | `0x51CC4C` | `0x51D862` | `0x51D874` | 0, 10 | `0x30E35FB` |
| A2 | `0x51D880` | `0x51CC80` | 547 | 137 | `0x51DA7B` | `0x51CE7B` | `0x51DA91` | `0x51DAA2` | 1 | `0x30E35FB` |
| A3 | `0x51DAB0` | `0x51CEB0` | 418 | 104 | `0x51DC2A` | `0x51D02A` | `0x51DC40` | `0x51DC51` | 3, 13 | `0x30E35FB` |
| A4 | `0x51DC60` | `0x51D060` | 374 | 93 | `0x51DDAE` | `0x51D1AE` | `0x51DDC4` | `0x51DDD5` | 5 | `0x30E35FB` |
| A5 | `0x51DDE0` | `0x51D1E0` | 526 | 132 | `0x51DFC5` | `0x51D3C5` | `0x51DFDB` | `0x51DFED` | 7 | `0x30E35FB` |
| A6 | `0x51DFF0` | `0x51D3F0` | 438 | 107 | `0x51E180` | `0x51D580` | `0x51E196` | `0x51E1A5` | 8 | `0x30E35FB` |

### 9.3 Transzfer wrapper-ek – 6

| # | RVA | Raw | Méret | Utasítás | `syscall` RVA | `syscall` raw | Státusz-vissza | `ret` RVA | Hívó ág(ak) | Állapotglobális |
|---:|---|---|---:|---:|---|---|---|---|---|---|
| T1 | `0xC8F650` | `0xC8EA50` | 546 | 136 | `0xC8F84C` | `0xC8EC4C` | `0xC8F862` | `0xC8F871` | 0, 10 | `0x30E360F` |
| T2 | `0xC8F880` | `0xC8EC80` | 530 | 130 | `0xC8FA6C` | `0xC8EE6C` | `0xC8FA82` | `0xC8FA91` | 1 | `0x30E360F` |
| T3 | `0xC8FAA0` | `0xC8EEA0` | 339 | 81 | `0xC8FBCD` | `0xC8EFCD` | `0xC8FBE3` | `0xC8FBF2` | 3, 13 | `0x30E360F` |
| T4 | `0xC8FC00` | `0xC8F000` | 466 | 113 | `0xC8FDAC` | `0xC8F1AC` | `0xC8FDC2` | `0xC8FDD1` | 5 | `0x30E360F` |
| T5 | `0xC8FDE0` | `0xC8F1E0` | 384 | 95 | `0xC8FF3A` | `0xC8F33A` | `0xC8FF50` | `0xC8FF5F` | 7 | `0x30E360F` |
| T6 | `0xC8FF60` | `0xC8F360` | 484 | 117 | `0xC9011E` | `0xC8F51E` | `0xC90134` | `0xC90143` | 8 | `0x30E360F` |

A két halmazban a 7. argumentumhelyzet (`stack+0x30`, `page_protection`) eltérő scratch regisztert használ (`r11`, `r13`, `r15`, `r12`), ami a fordító regiszterallokációjának terméke, nem szemantikai eltérés. A 6. pozíció (`stack+0x28`) szintén változik. Az egyetlen közös a pozíciószám: a wrapperben a syscall 6. argumentuma (`bytes_written_out` vagy `page_protection`) a hívás 7. pozíciójából jön.

### 9.4 A wrapper-ek nem privát dispatch

| Mutató | Eredmény | Konf. |
|---|---:|---|
| `wrapper_distinct_caller_functions` (a 12 wrapperre) | 37 | P |
| `caller_functions_outside_the_anchor` (a 12 wrapperre) | 36 | P |
| A 12 wrapperből hívó függvények a `0xC85000`–`0xC88000` tartományon belül | 1 (`0xC856C0`) | P |
| Level-1 hívósor a 12 wrapperre | 408 | P |
| Hívóhelyek a 12 wrapperre az anchorból | 16 | P |
| Distinct hívó a 13 forward sinkre (12 wrapper + `0x495D0`) | 54, ebből 2 a tartományon belül | P |

A 12 wrapper megosztott futásidejű segéd, nem a `0xC856C0` privát diszperziója. A `06` 11. fejezete záró bekezdésének azon állítása, hogy a `0x51D680` és `0x51D880` távoli callhelyekről is hívódik, ezt 37 distinct caller funkcióval pontosítja; a 13 forward sinkre számított 54-es érték a wrapper-ekre nem érvényes. A 37-ből 36 hívó a `0xC85000`–`0xC88000` tartományon kívül van, és az egyetlen kivétel maga az anchor `0xC856C0`, amely 16 hívóhelyről hívja mind a 12 wrappert – a korábbi „0 a klaszteren belül" cella ezért téves volt. A `cfg_functions.csv` szerint a 6 allokációs wrapper `cluster_id = 38`, a 6 transzfer wrapper `cluster_id = 85`; ez két közelség-csoport azonosítója, nem a tizenhat függvényes `0xC85000`–`0xC88000` tartomány, így a közös `85` értékből semmi sem következik a tartományhatárra (lásd §4.2).

```text
BRef = [RVA:0x51D680 | RAW:0x51CA80 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0xC8F650 | RAW:0xC8EA50 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x30E35FB | RAW:0x30E1FFB | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x30E360F | RAW:0x30E200F | CONF:P | STATUS:OBSERVED]
```

## 10. A 6 pozíciós allokációs séma

### 10.1 Syscall-szintű séma

| Poz. | Hely | Kifejezés | Szerep | Konf. |
|---:|---|---|---|---|
| 1 | `r10` | `r14` | `process_handle` | L |
| 2 | `rdx` | `&frame+0x50` | `base_address_out` | P |
| 3 | `r8` | `0` (`xor r8d, r8d`) | `zero_bits` | P |
| 4 | `r9` | `&frame+0x48` | `region_size_out` | P |
| 5 | `stack+0x28` | `0x1000` | `allocation_type` | P |
| 6 | `stack+0x30` | `0x40` | `page_protection` | P |

A szerepnevek az argumentumpozíció nevét jelentik, nem szolgáltatásnevet; a szolgáltatásnév nyitott. A `0x1000` és `0x40` konstans `MEM_COMMIT` és `PAGE_EXECUTE_READWRITE` jelleghez illeszkedik, de a `P` jelölés a konstansra és a pozícióra vonatkozik, nem a szolgáltatásazonosításra. A `shape_confidence = HIGH`, a `role_confidence = MEDIUM`.

### 10.2 Hívásszintű séma (wrapper-ágak)

| Poz. | Hely | Kifejezés | Szerep |
|---:|---|---|---|
| 1 | `rcx` | `&.data+0x30E35FB` | `wrapper_state_global` |
| 2 | `rdx` | `r14` | `process_handle` |
| 3 | `r8` | `&frame+0x50` | `base_address_out` |
| 4 | `r9` | `0` | `zero_bits` |
| 5 | `stack+0x20` | `&frame+0x48` | `region_size_out` |
| 6 | `stack+0x28` | `0x1000` | `allocation_type` |
| 7 | `stack+0x30` | `0x40` | `page_protection` |

A hívásszintű séma 7 pozíció, mert a wrapper az első helyen egy állapotglobálist kap; a `position N → syscall position N-1` forwarding miatt a két séma ugyanazt a hat Nt-szintű argumentumot hordozza. `branches_matching_schema = 16`, `branches_diverging_from_schema = 0`.

### 10.3 A három frame-slot

| Slot | Szerep | Közvetlen írás | Címfelvevő helyek | Közvetlen olvasás |
|---|---|---:|---:|---:|
| `rsp+0x40` | `transfer_status` | 1 (`0xC86437` / `0xC85837`, `mov …, 0`) | 16 | **0** |
| `rsp+0x48` | `region_size` | 1 (`0xC856EE` / `0xC84AEE`, `mov …, r8`) | 16 | **0** |
| `rsp+0x50` | `remote_base` | 1 (`0xC856E5` / `0xC84AE5`, `mov …, 0`) | 16 | 2 |

A `rsp+0x48` slot a bejövő harmadik argumentumból (`r8`) mentett bájtszám, amit az allokációs fázis `region_size_out` pozícióként ad tovább, és amelyet az anchor később nem olvas. A `rsp+0x50` slot az egyetlen, amelynek van olvasója és amelynek értéke a visszatérés is. A `rsp+0x40` slot 16 szálon kap címfelvevést, de soha nem olvassák.

```text
BRef = [RVA:0xC858E0 | RAW:0xC84CE0 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0xC86420 | RAW:0xC85820 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0xC856EE | RAW:0xC84AEE | CONF:P | STATUS:OBSERVED]
```

## 11. Az 5 pozíciós transzfer séma

### 11.1 Syscall-szintű séma

| Poz. | Hely | Kifejezés | Szerep | Konf. |
|---:|---|---|---|---|
| 1 | `r10` | `rbx` | `process_handle` | L |
| 2 | `rdx` | `r14` | `remote_base` | P |
| 3 | `r8` | `rsi` | `buffer` | P |
| 4 | `r9` | `rdi` | `length` | P |
| 5 | `stack+0x28` | `&frame+0x40` | `bytes_written_out` | P |

A 2. argumentum minden 16 ágon változatlanul az allokációs merge-ponton beolvasott `remote_base`; ezt a `06` §9.3 és a `12` §6.1 „ötargumentumos írás-/olvasásséma" megállapítása megerősíti. A 6 pozíciós és az 5 pozíciós séma együttesen erősen `NtAllocateVirtualMemory` + `NtWriteVirtualMemory`/`NtReadVirtualMemory` kompatibilis; a szolgáltatásnév és az írás iránya nyitott marad, ahogy a `06` §9.3 és a `12` §6.1 már megfogalmazta.

### 11.2 Hívásszintű séma (wrapper-ágak)

| Poz. | Hely | Kifejezés | Szerep |
|---:|---|---|---|
| 1 | `rcx` | `&.data+0x30E360F` | `wrapper_state_global` |
| 2 | `rdx` | `rbx` | `process_handle` |
| 3 | `r8` | `r14` | `remote_base` |
| 4 | `r9` | `rsi` | `buffer` |
| 5 | `stack+0x20` | `rdi` | `length` |
| 6 | `stack+0x28` | `&frame+0x40` | `bytes_written_out` |

`branches_matching_schema = 16`, `branches_diverging_from_schema = 0`.

### 11.3 A `remote_base` életciklusa

| Lépés | RVA | Raw | Utasítás | Konf. |
|---:|---|---|---|---|
| Nullázás | `0xC856E5` | `0xC84AE5` | `mov qword ptr [rsp + 0x50], 0` | P |
| Író ágak száma | – | – | mind a 16 allokációs ág egy `lea` címet vesz fel | P |
| Olvasás a merge-nél | `0xC86426` | `0xC85826` | `mov r14, qword ptr [rsp + 0x50]` | P |
| Olvasás a visszatéréskor | `0xC870E1` | `0xC864E1` | `mov rsi, qword ptr [rsp + 0x50]` | P |
| Visszatérési regiszter | `0xC870F3` | `0xC864F3` | `mov rax, rsi` | P |
| Kilépés | `0xC87103` | `0xC86503` | `ret` | P |

A `remote_base` az egyetlen frame-slot, amelyet az anchor `RAX`-ban visszaad. Nincs olyan írás, amely értéket adna neki a 16 allokációs ágon kívül, és nincs olyan olvasás, amely a `rsp+0x40` sloton keresztül státuszt adna vissza.

```text
BRef = [RVA:0xC856E5 | RAW:0xC84AE5 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0xC870E1 | RAW:0xC864E1 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:N/A | RAW:N/A | CONF:U | STATUS:OPEN]
```

## 12. Kimeneti vector

### 12.1 A vector szerkezete

| Elem | RVA | Raw | Konf. |
|---|---|---|---|
| Elérhetés a belépő függvényben | `0xC85664` | `0xC84A64` | P |
| `end` olvasása | `0xC8568B` | `0xC84A8B` | P |
| `capacity` összehasonlítása | `0xC8568F` / `0xC85693` | `0xC84A8F` / `0xC84A93` | P |
| Helyben append (`[end] = rax`) | `0xC85695` | `0xC84A95` | P |
| `end` léptetése 8-cal | `0xC85698` | `0xC84A98` | P |
| Növekedési segéd hívása | `0xC856A7` | `0xC84AA7` | P |
| Növekedési segéd | `0x495D0` | `0x489D0` | P |

A `0x495D0` függvény `cfg_functions.csv` szerint 499 bájt, 42 alapblokk, 42/42 elérve, 6 direkt call, 1 IAT-hívóhely, `cluster_id = 1`; a dedikált `rel32`-sweep 20 szint-1 hívósort és **17** distinct hívó funkciót ad neki. Ezek közül a `0xC85650` – amely a `0xC85000`–`0xC88000` tartományon belül van – és a `0x176F860` (`0x17709FA`, `0x1770DE8`) példaként említhető, a többi 15 felsorolatlan marad. A `xref_edges.csv` ehhez a függvényhez 0 sort tartalmaz, noha a dedikált sweep 20 hívóhelyet talál, tehát a fájl nem teljes hívási inventory: az itteni nulla érték önmagában nem szerkezeti negatívum.

### 12.2 Mi kerül a vectorba

Az appendelt érték az anchor visszatérési értéke, vagyis a `remote_base` – **feltétel nélkül**. A `status_checked = false` és az `appended_value` mező egyaránt ezt rögzíti. A `06` §9.4 „a hívó az allokált címet a kapott vectorba appendeli" állítása pontos, de hozzá kell tenni, hogy **sikertelen** allokáció esetén is ugyanez történik: a nulla érték éppúgy bekerül, és a kimeneti vector nem különbözteti meg a hibát a címtől.

```text
BRef = [RVA:0xC85695 | RAW:0xC84A95 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0xC856A7 | RAW:0xC84AA7 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x495D0 | RAW:0x489D0 | CONF:P | STATUS:OBSERVED]
```

## 13. Hibaágak

### 13.1 A hat rögzített hiba- és határeset

| ID | Hely | RVA | Raw | Típus | Feltétel | Hatás | Konf. |
|---|---|---|---|---|---|---|---|
| E-PATH-01 | merge | `0xC8642B` | `0xC8582B` | `null_base_after_allocation` | `r14 == 0`, azaz az allokációs fázis nulla bázist hagyott | `esi` nullázva `0xC86430` / `0xC85830`, a függvény 0-val tér vissza, a transzferfázis nem indul | P |
| E-PATH-02 | belépő | `0xC85695` | `0xC84A95` | `unchecked_result_append` | nincs | a nulla bázis is bekerül | P |
| E-PATH-03 | belépő | `0xC85693` | `0xC84A93` | `vector_growth` | `end == capacity` | a növekedési segéd meghívódik a mentett visszatérési érték címével | P |
| E-PATH-04 | belépő | `0xC8567C` | `0xC84A7C` | `string_storage_select` | a string kapacitása 8 kódegység alatt | a heap pointer betöltése a hívás előtt, egyébként az inline buffer használata | P |
| E-PATH-05 | anchor | `0xC870EE` | `0xC864EE` | `stack_guard_check` | a frame cookie eltér a prologue-ban tárolttól | a `0x2AB3500` guard helper meghívódik; a hiba-viselkedés a lineáris dekódon kívül van | P |
| E-PATH-06 | merge | `0xC870E1` | `0xC864E1` | `unchecked_transfer_status` | nincs | az anchor akkor is visszaadja az allokációs bázist, ha a transzferfázis hibát jelez, és a belépő ezt appendeli | P |

### 13.2 Nincs feltételes kilépés és nincs rollback

| Mutató | Eredmény | Konf. |
|---|---:|---|
| Kilépések száma az anchorban | 3 | P |
| Kilépések | `0xC85709` `jmp rax`, `0xC86456` `jmp rax`, `0xC87103` `ret` | P |
| Feltételes hiba-ág a törzsben | 0 | P |
| Ág, amely a merge előtt státuszt tesztel | 0 / 32 | P |
| `transfer_status` olvasóhely | 0 | P |
| Távoli region felszabadítás sikertelen írás után | nincs | P |
| `single_exit_anchor` | `true` | P |

A `06` §9.4 „Sikertelen írás esetén nincs rollback vagy remote free" és §13 táblázatának „Távoli írás – Státusz nem kerül visszaadásra" sora a jelen passzal megerősítve és számszerűen lezárva: 32 ág, 0 teszt, 0 olvasóhely.

### 13.3 A visszatérési érték szerkezete

| Lépés | Hely | Konf. |
|---|---|---|
| A wrapper visszaadja a nyers syscall-státuszt | `mov eax, esi` mind a 12 wrapperben | P |
| Az anchor eldobja | `0xC86426` / `0xC85826` felülírja a tartalmat a `remote_base`-szel; a nulla ágon `0xC86430` / `0xC85830` – `xor esi, esi` | P |
| Visszatérés | `0xC870F3` / `0xC864F3` – `mov rax, rsi` | P |

A wrapper-státusz tehát elér a hívóhoz, de az anchor nem használja fel; a visszatérési érték kizárólag a `remote_base`. A `06` §9.4 és a `12` §6.1 ebben nem tér el.

```text
BRef = [RVA:0xC8642B | RAW:0xC8582B | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0xC870EE | RAW:0xC864EE | CONF:P | STATUS:OBSERVED]
BRef = [RVA:N/A | RAW:N/A | CONF:U | STATUS:OPEN]
```

## 14. `CloseHandle` és `DuplicateHandle` negatívum

### 14.1 Az import- és él-nézet

| Mutató | `CloseHandle` | `DuplicateHandle` | Konf. |
|---|---:|---:|---|
| `xref_edges.csv` sorok `dst_symbol` szerint | 61 | **0** | P |
| Relációk | `call_indirect_iat` 59, `iat_jmp_thunk_stub` 1, `iat_slot_symbol_binding` 1 | – | P |
| Import jelen van | igen | **nem** | P |
| Hívóhely a `0xC85000–0xC88000` klaszteren belül | 0 | 0 | P |
| Hívóhely a provable forward halmazban | 0 | 0 | P |
| Legközelebbi `CloseHandle` hívóhely | `0xC81D49` (hívóhely) a `0xC81D10` függvényben, távolság −14 711 bájt a cimkétől | – | P |
| További `CloseHandle` hívóhelyek | `0xCA8AE7` (távolság +144 423), `0x87F348` (távolság −4 219 768) | – | P |

A `0xC81D49` hívóhely argumentuma egy `.data` globálisból olvasott handle (`0x317E370` a `0xC81D3D` – `mov rcx, qword ptr [rip + 0x24fc62c]` – helyen), nem a `0xC856C0` descriptorából; a statikus adatfolyam nem köti őket össze.

### 14.2 A forward-halmaz nézet

A `0xC85650` és `0xC856C0` közvetlen hívási lezárása 37 funkciót, 4 mélységet ad (`function_count = 37`, `max_depth = 4`, `exhausted = false`):

| Mélység | Funkciók száma | Konf. |
|---:|---:|---|
| 0 | 2 (`0xC85650`, `0xC856C0`) | P |
| 1 | 22 | P |
| 2 | 6 | P |
| 3 | 5 | P |
| 4 | 2 | P |

A 37 elérhető célból 23 `RUNTIME_FUNCTION` rekorddal rendelkezik, 14 pedig anélkül: a `0xCAC0D0`, `0xCAC0F0`, `0xCAC110`, `0xCAC130`, `0xCAC150`, `0xCAC170` thunkok, továbbá a `0x5219A0`, `0x5219C0`, `0x2A98530`, `0x2AAE840`, `0x2AB2418`, `0x2BEDDF0`, `0x2BEE110`, `0x2BEE1E0` címek – 14 cél, nem 16. A korábbi „21 lefedett + 16 nemlefedett" pár nem reprodukálható: a helyes feloszlás 23 és 14, és a korábbi lista a `0xCAC150` thunkot nem tartalmazta, noha annak `0xC8FEE4` hívóhelye a forward passzból származik (lásd §7.4). E halmazban `api_call_site_count = 0` a wrappereken, a 32 ág-törzsön, a belépő függvényen és az anchorban is. Következmény:

- a `0xC856C0` **nem zárja le** a kapott handle-t;
- a `0xC856C0` **nem duplikálja** a kapott handle-t;
- egyik `Nt`-szintű argumentumséma sem tartalmaz close- vagy duplicate-jellegű pozíciót;
- a handle-ről a teljes vizsgált tartományban csak olvasódik, és a `rcx`/`rbx` descriptor-hordozókon sincs store.

### 14.3 Amit a negatívum nem állít

| Állítás | Státusz |
|---|---|
| A handle tulajdonosa ismeretlen | U, nyitott |
| A handle létrehozója ismeretlen | U, nyitott |
| A handle a klaszteren kívül nem zárható le | U, nem kizárható |
| `DuplicateHandle` a teljes image-ben sem létezik edge formában | P, negatív a publikált inventory scope-on |
| A forward halmaz `exhausted = false`, tehát 4 mélységnél megállt | P, korlát |

A két negatív finding együtt azt adják, hogy a `0xC856C0` a kapott handle-t **fogyasztja, nem kezeli**. A `06` §4.2 „nincs közvetlen `CloseHandle`" és §4.3 megállapításai a `0xD7B86E` parent-handle ágon változatlanul érvényesek, és a jelen passz nem vonja be őket a `0xC856C0` láncba.

```text
BRef = [RVA:0xC81D49 | RAW:0xC81149 | CONF:P | STATUS:NEGATIVE]
BRef = [RVA:0x317E370 | RAW:0x317CD70 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:N/A | RAW:N/A | CONF:U | STATUS:OPEN]
```

## 15. A `0 → 1 → 2` kimerülő hívóklóza

### 15.1 A felfelé menő séma

A `c856c0_callers.csv` (445 sor, 1 fejléc) és a `c856c0_forward.json#caller_closure` 444 adatsort ad, három szinten:

| Szint | Edge típus | Sorok | Leírás | Konf. |
|---:|---|---:|---|---|
| 0 | `forward_subject` | 14 | a vizsgált tárgykészlet magja: 1 anchor, 1 vektor-növekedési segéd, 6 allokációs és 6 transzfer wrapper | P |
| 1 | `direct_call` | 429 | `pdata_boundary+rel32_displacement+in_text_target` bizonyítékkal attribuált közvetlen hívóhelyek a 13 forward sinkre (12 wrapper + `0x495D0`); 54 distinct caller funkció, ebből 2 a `0xC85000`–`0xC88000` tartományon belül | P |
| 2 | `no_inbound_edge_in_enumerated_forms` | 1 | a `0xC85650` belépési határa: üres frontier | P |
| – | `uncovered_call_site_count` | 0 | a felsorolt hívóhelyek mind közvetlenek | P |
| – | `open = F-U-01` | 220 sor | a szolgáltatásnév/producer nyitottsága a sorokon | U |

A 429 sorból 408 a 12 wrapperre, 20 a növekedési segédre jut; a 12 wrapper distinct hívója ezért 37, a 13 sinkre együttesen 54, és a 37-ből egyetlen hívó – maga az anchor `0xC856C0` – van a `0xC85000`–`0xC88000` tartományon belül.

A szint-2 sor a `0xC85650` belépési határának összegzése:

```text
0xC85650 inbound edges: absolute_pointer=0 + api_target=0 + code_pointer_slot=0
                        + rel32_call=0 + rel32_jmp=0 + rip_relative_materialisation=0
```

### 15.2 A szint-0 tárgykészlet

| Tárgy | Hívóhely(ek) a clusteren | Hívó funkció | Megjegyzés |
|---|---|---|---|
| `0xC856C0` | `0xC85681` | `0xC85650` | az anchor |
| `0x495D0` | `0xC856A7` | `0xC85650` | vektor-növekedési segéd |
| `0x51D680` | `0xC85737`, `0xC85DFA` | `0xC856C0` | allokációs wrapper |
| `0x51D880` | `0xC8576D` | `0xC856C0` | allokációs wrapper |
| `0x51DAB0` | `0xC85917`, `0xC86177` | `0xC856C0` | allokációs wrapper |
| `0x51DC60` | `0xC85AD1` | `0xC856C0` | allokációs wrapper |
| `0x51DDE0` | `0xC85BE7` | `0xC856C0` | allokációs wrapper |
| `0x51DFF0` | `0xC85C1D` | `0xC856C0` | allokációs wrapper |
| `0xC8F650` | `0xC86477`, `0xC86AF6` | `0xC856C0` | transzfer wrapper |
| `0xC8F880` | `0xC864A0` | `0xC856C0` | transzfer wrapper |
| `0xC8FAA0` | `0xC86617`, `0xC86E34` | `0xC856C0` | transzfer wrapper |
| `0xC8FC00` | `0xC86761` | `0xC856C0` | transzfer wrapper |
| `0xC8FDE0` | `0xC86979` | `0xC856C0` | transzfer wrapper |
| `0xC8FF60` | `0xC869A2` | `0xC856C0` | transzfer wrapper |

### 15.3 A `0xC85650` belépési határa

| Keresett forma | Eredmény | Konf. |
|---|---:|---|
| `rel32` call (`0xE8` dekód, minden `.text` bájt, tartománykorlát nélkül) | 0 | P |
| `rel32` jmp (`0xE9` dekód) | 0 | P |
| 8 bájtos abszolút VA pointer keresése (`image_base + 0xC85650`) | 0 | P |
| RIP-relatív materializálás | 0 | P |
| Publikált `fnptr_slot_code_target` él | 0 | P |
| Publikált IAT- vagy thunk-cél | 0 | P |
| DIR64 slot a `0xC85000–0xC88000` klaszterre | 0 / 19 041 | P |
| `0xC856C0` `rel32` callhely | **1**, `0xC85681`, `e8 3a 00 00 00` | P |
| `0xC856C0` `rel32` jmphely | 0 | P |

A `0xC856C0` és `0xC85650` egyetlen előfordulása 32 bites értékként a saját `RUNTIME_FUNCTION` rekordjuk címmezője:

| Érték | Előfordulás RVA | Előfordulás raw | Rekord index | Mező |
|---|---|---|---:|---|
| `0xC85650` | `0x2EC5D38` | `0x2EC4738` | 38 549 | `begin_address` |
| `0xC856C0` | `0x2EC5D3C` | `0x2EC473C` | 38 549 | `end_address` |
| `0xC856C0` | `0x2EC5D44` | `0x2EC4744` | 38 550 | `begin_address` |

Tehát egyik cím sem szerepel függvénypointerként, táblaelemként vagy metadarecordként; kizárólag saját kivétel-directory rekordjukban. A `xref_edges.csv` 57 101 sora között **nulla** `dst_rva` a `0xC85650`-re vagy `0xC856C0`-ra mutat.

### 15.4 A `xref_edges.csv` lefedettségi korlátja

A `xref_edges.csv` `src_rva` oszlopa **decimális** számot tartalmaz, nem hexadecimálist: a 57 101 forrásoldali cím legnagyobb értéke `0x3306F60`, ezért a valódi hexadecimális magas nibble kizárólag `0x0`. A korábbi nibble-táblázat a decimális vezető számjeggyel számolt, és így hamis `0x0`–`0x9` tartományt sugallt. A javított nézet:

| Forrásoldali cím vezető számjegye, decimális alapon | Sorok |
|---|---:|
| `0` | 0 |
| `1` | 6 496 |
| `2` | 8 716 |
| `3` | 18 317 |
| `4` | 19 210 |
| `5` | 1 194 |
| `6` | 1 022 |
| `7` | 1 119 |
| `8` | 500 |
| `9` | 527 |
| Összes | 57 101 |

| Forrásoldali cím valódi hex magas nibbleje | Sorok |
|---|---:|
| `0x0` | 57 101 |
| `0x1`–`0xF` | **0** |

A `0x1`–`0xF` nulla sor tehát nem korlátot jelent, hanem a tartomány felső szélét: a legnagyobb `src_rva` `0x3306F60`, így a teljes 57 101 sor a `0x0` magas nibble alá esik, és nincs olyan érték, amely a `0xC85000`–`0xC88000` klasztert ki lehetne zárni. A klaszterből viszont **17** forrásoldali sor van, így a „nulla forrásoldali él a klaszterből" állítás nem igazolt:

| Mutató | Eredmény | Konf. |
|---|---:|---|
| Forrásoldali sor a `0xC85000`–`0xC88000` tartományból | 17 | P |
| Forrásfüggvények száma és listája | 5: `0xC81EE0`, `0xC871F0`, `0xC873C0`, `0xC87830`, `0xC87900` | P |
| Reláció szerinti megoszlás | 6 `call_indirect_iat` + 11 `call_rel_to_code` | P |
| IAT-célok a klaszterből | `KERNEL32.dll!VirtualAlloc`, `KERNEL32.dll!VirtualFree`, `KERNEL32.dll!VirtualQuery`, `api-ms-win-crt-runtime-l1-1-0.dll!_invalid_parameter_noinfo_noreturn` | P |
| Közvetlen hívás céljai a klaszterből | `0x89CF0`, `0x89FA0` | P |
| `CloseHandle` célú forrásoldali sor a klaszterből | **0** | P |
| `DuplicateHandle` célú forrásoldali sor a klaszterből | **0** | P |

Következmény: a 32 fogyasztási hely és a 429 hívósor valóban nem a publikált `xref_edges.csv`-ből, hanem a nyers `.text` `rel32`-dekódolásból és `.pdata`-attribúcióból származik, és ez a dedikált passz a szuperszet – de a klaszter lefedettségéről nem állítható, hogy nulla. A `CloseHandle`/`DuplicateHandle` negatívum érintetlen: a 17 klaszterbeli forrásoldali sor között egy sincs ilyen célú, ahogy a 61 `CloseHandle` él egyike sem a klaszterből. A negatív megállapítások ezért a dedikált passz módszerére boundedek, nem a `xref_edges.csv` hiányosságára.

```text
BRef = [RVA:0xC85650 | RAW:0xC84A50 | CONF:P | STATUS:NEGATIVE]
BRef = [RVA:0x2EC5D38 | RAW:0x2EC4738 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x2E54E3C | RAW:0x2E5383C | CONF:P | STATUS:OBSERVED]
```

## 16. A handle producer: OPEN

### 16.1 Amit a backward pass kimutatott

| Mutató | Eredmény | Konf. |
|---|---:|---|
| A `0xC856C0` egyetlen közvetlen hívója | `0xC85650` @ `0xC85681` | P |
| A `0xC85650` belépő élhelyei | 0 minden enumerált formában | P |
| A descriptor `+0` mezőjéhez visszafelé elérhető store | nincs | P |
| A producer csomópont | `kind = unknown_producer`, `rva = null`, `raw = null` | P |
| A store él | `confidence = LOW`, `status = OPEN` | U |
| `handle.producer.status` | `OPEN`, `identified = false`, `unresolved_id = U-01` | U |

### 16.2 A descriptor-adatfolyam

```text
outer argumentum (RCX a 0xC85650-ben)
  └─ [outer+0x0]  → output vector          (0xC85664)
  └─ [outer+0x8]  → descriptor             (0xC85667)
                        └─ [descriptor+0] → processzhandle  (0xC856F3, majd 0xC86440)
```

A `0xC85650` két olvasása között nincs store; a `0xC856C0` két olvasása között sincs store. A producer tehát a belépési határon kívül van, és a backward út **terminál**: a frontier üres, nem csonkolt. Ez a `06` §9.5 és a `12` §6.1 pont 5 állításának lényegi változtatás nélküli megerősítése, most már lezárt negatívummal a keresési formákra.

### 16.3 Amit ez nem jelent

| Feltevés | Státusz |
|---|---|
| A handle-t a `0xD7B86E` `OpenProcess(0x1000, …)` adja | nem kapcsolódik össze statikusan; a `0x1000` jog `PROCESS_QUERY_LIMITED_INFORMATION`, ami a 6 pozíciós és 5 pozíciós sémához nem elég |
| A handle a hoszt által futás közben épülő komponens-metódustáblából érkezik | konzisztens a megfigyeléssel, de nem bizonyított |
| A handle `DuplicateHandle` másolat | a publikált él-készletben nincs `DuplicateHandle` él |
| A handle-t a `patch_record_table.json` által leírt patch-mechanizmus állítja elő | a két mechanizmus (`0x1E270` patcher, `0xC856C0` allokáció) között nincs statikus él |

A `06` §4.3 „a query-handle nem bizonyítottan a távoli írás handleje" és a `12` §6.1 zárókövetkeztetése változatlanul érvényes, és a jelen passz nem ad hozzá új bizonyítékot a producer oldalához. A `patch_record_table.json` külön, `0x1830D44F8` globalit használó rekordtáblája (`anchor_count = 118`, `anchor_failures = 0`, `record_instances_status = OPEN`, `overall_confidence = L`) nem érinti a `0xC856C0` láncot: annak nincs DIR64-forrása és nincs hozzá `.pdata`-szintű hívója sem.

Az `anchor_count` szám egyetlen forrása a `reverse/evidence/patch_record_table.json` `summary` blokkja (`anchor_count: 118`, `anchor_failures: 0`). A `reverse/evidence/patch_mechanisms_1e270.csv` **nem tartalmaz `anchor_count` mezőt**: a fejléc 16 lapos, soronkénti oszlopot nevez meg (`id, component, kind, site_rva, site_va, record_offset, field, access, width_expr, value_expr, target_expr, readers, writers, confidence, status, note`), és a fájlban az `anchor_count` szó `0`-szor fordul elő, `50` adatsor mellett. Ehhez a lapos táblázathoz tehát semmilyen anchor-aggregátum nem rendelhető; az itt korábban szereplő `94` egyik mezőből sem származott, ezért el lett távolítva, és a `16` dokumentum `118`-ra javított állítása az érvényes. A két dokumentum ellentérése és a javítás forrása a dokumentum végén álló `Újraellenőrzés` blokkban rögzített.

```text
BRef = [RVA:N/A | RAW:N/A | CONF:U | STATUS:OPEN]
BRef = [RVA:0xC85667 | RAW:0xC84A67 | CONF:P | STATUS:OBSERVED]
BRef = [RVA:0x30D44F8 | RAW:0x30D2EF8 | CONF:P | STATUS:OBSERVED]
```

## 17. A nyolc bounded nyitott kérdés

Minden tétel lezárt keresési formákkal és explicit lezárási feltétellel rendelkezik. A nyitott kérdések `U-01`–`U-08` (backward) és `F-U-01`–`F-U-08` (forward) azonosítók; ahol ugyanazt a kérdést fedik le, egy tételbe vannak összevonva.

| # | Azonosítók | Kérdés | Miért bounded | Mi zárná le statikailag | Konf. |
|---:|---|---|---|---|---|
| Q-01 | `U-01`, `U-02`, `F-U-01`, `F-U-03` | Ki írja a `[descriptor+0]` mezőt, és mely kód hívja a `0xC85650` belépő függvényt? | A belépési határ 6 enumerált formában üres, a DIR64 klasztercenzus 0, a `record`-szintű forward nincs feloldva | a hoszt által futás közben felépített komponens-metódustábla rekonstrukciója, majd a 16 bájtos `{vector, descriptor}` pár illesztése | U |
| Q-02 | `U-04`, `F-U-02` | Mely Nt szolgáltatásszámot használja a 16 inline `syscall` és a 12 wrapper? | Mind a 28 helyen a `syscall` előtt futásidőben képződik a szám; a 16 inline ágon a közvetlen producer utasítás: `xor eax, ecx` (7 ág), `xor eax, 0x5982a5fe` (2 ág), `add eax, 0x5abf22d7`, `sub eax, ecx`, `lea eax, [rax + rcx*2]`, `mov eax, dword ptr [rsp + 0x58]` (3 ág), `mov eax, r15d`, `KUSER_SHARED_DATA`- és PEB-adatokból keverve | a keverési lánc kiértékelése szimbolikus `KUSER_SHARED_DATA`-értékekkel, futtatás nélkül, a `12` 10. fejezete 6. pontjának javaslata szerint | U |
| Q-03 | `U-03`, `U-06` | Mi a descriptor `+0` mezőn túli elrendezése, és mi a closure/descriptor konkrét osztálya? | Az anchor csak a `+0` mezőt dereferenciálja; a `.rdata` RTTI-szken 0 típusleíró és 0 Complete Object Locator | egy második belépési pont, amely ugyanazt a descriptort kapja; vagy a `object_model` szerkezeti leíráshoz való korreláció a publikált CitizenFX komponensinterfésszel, mapping-feltevés nélkül | U |
| Q-04 | `U-05`, `F-U-05` | Azonos Nt szolgáltatást hív-e a 8 inline és a 8 wrapper ág egy fázison belül, és a két fázis szolgáltatásai összetartoznak-e? | A forward pass fázisonként egy argumentumsémát állított fel (`16/16` egyezés, `0` divergencia), de a szolgáltatásszám mind a 32 ágon futásidejű | `Q-02` feloldása, majd a fázisonkénti szolgáltatásszámok összevetése | U |
| Q-05 | `U-07`, `F-U-07` | Egy 32-águ dispatch-et alkot-e a két szomszédos tábla, vagy két független 16-águ diszperziót? | A két tábla szomszédos, de mindkettőt saját `RDTSC & 0xF` sorozat választja ki, saját merge-ponttal; a forward pass a transzferfázist kizárólag a merge-ből és nem nulla bázis esetén éri el | egy hívás két szelektor-értékének egyidejű rögzítése – ez a jelen passz módszerén kívül esik | U |
| Q-06 | `U-08` | Biztosan azonos a `0xC86440`-ben újraolvasott érték a `0xC856F3`-ban betöltött értékkel? | A két olvasás között 6 distinct wrapper-hívás és 8 inline `syscall` van; a descriptor futásidejű cím, és egyik hívott függvény sem kapja meg pointerként, így aliasing store sem megerősíthető, sem kizárható | a descriptor pointer propagálása mind a 12 wrapperbe, majd az aliasing store-ok tesztelése; addig a két load két független def-use lánc | U |
| Q-07 | `F-U-04`, `F-U-06` | Az `RAX`-ban visszaadott érték valóban az a cím, amelyre a transzferfázis ír, és ellenőrzik-e a transzfer eredményét bárhol? | A `rsp+0x40` státuszslotnak 0 olvasóhelye van, a belépő feltétel nélkül appendel; az `rsp+0x48` méretout-paraméternek szintén 0 olvasója van | a `remote_base` és a `region_size` együttes rögzítése futásidőben, ami a statikus módszeren kívül esik | U |
| Q-08 | `F-U-08` | Van-e az anchorhoz exception funclet, és elérhetik-e az inline `syscall` utáni blokktörzsek a fázis-merge pontokat? | Az anchor unwind-rekordja nem dekódol standard x64 `UNWIND_INFO` kódtömbbé, és a `syscall` utáni lineáris utasításfolyam feltételes vezérlést tartalmaz (`merge_reachability = NOT_ASSERTED` mind a 16 inline ágon) | a 16 blokktörzs rekurzív vezérlésfolyam-gráfja és az unwind-rekord saját parserhez való illesztése; a lineáris módszeren kívül esik | U |

### 17.1 A nyitott kérdések priorizálása

| Prioritás | Kérdés | Miért |
|---|---|---|
| P0 | Q-01, Q-02 | a producer és a szolgáltatásnév nélkül nincs cél- vagy adatfolyam-következtetés |
| P1 | Q-04, Q-06 | a 32 fogyasztási hely szerkezeti értelmezése a szolgáltatás-egyenértékűségtől és a két load azonosságától függ |
| P2 | Q-03, Q-05, Q-07, Q-08 | szerkezeti pontosítás, nem az alapvető értelmezés blokkolója |

### 17.2 Amit a két payload nyíltan lezáratlanul hagy

| Forrás | Megfogalmazás | Konf. |
|---|---|---|
| `c856c0_dataflow.json#handle.producer` | `status: OPEN`, `identified: false` | U |
| `c856c0_forward.json#handle_lifetime.ownership` | `OPEN`, `ownership_unresolved_id: F-U-03` | U |
| `c856c0_forward.json#scope.no_actionable_output` | a payload csak kódszerkezetet ír le, exploit/bypass/patch/shellcode útmutatást nem | P |
| `c856c0_dataflow.json#scope.libraries_note` | a `toolchain.json` script-listája még nem tartalmazza ezt a scriptet | P |
| `c856c0_forward.json#forward_reachable_set.exhausted` | `false`, tehát a lezárás 4 mélységnél megállt | P |

```text
BRef = [RVA:N/A | RAW:N/A | CONF:U | STATUS:OPEN]
```

## 18. Negatív findingok bounded scope-szal

| ID | Állítás | Módszer | Eredmény | Konf. |
|---|---|---|---|---|
| NEG-01 | `0xC85650`-nek nincs közvetlen `rel32` call- vagy jmp-hivatkozása a `.text`-ben | minden `0xE8` és `0xE9` bájt előjeles 32 bites eltolásként dekódolva | 0 call, 0 jmp | P |
| NEG-02 | `0xC85650` nem szerepel 8 bájtos abszolút pointerként sehol a fájlban | `image_base + 0xC85650` keresése kicsi endian 64 bites értékként | 0 találat | P |
| NEG-03 | `0xC85650` soha nem materializálódik RIP-relatív címként | minden REX-prefixelt RIP-relatív `disp32` operandum szkennelése | 0 hely | P |
| NEG-04 | `0xC856C0`-nak pontosan egy közvetlen `rel32` callhelye van, `0xC85681`-en, a `0xC85650`-en belül | `0xE8`/`0xE9` dekód | 1 call, 0 jmp | P |
| NEG-05 | egyetlen betöltéskor relokált pointer sem `.rdata`-ban, sem `.data`-ban nem mutat a `0xC85000..0xC88000` klaszterre | minden 8 bájtra igazított DIR64 slot olvasása | 0 / 19 041; `.rdata` 16 176, `.data` 2 865; 0 nulla értékű | P |
| NEG-06 | a `0xC856C0` és `0xC85650` egyetlen 32 bites előfordulása a saját `RUNTIME_FUNCTION` rekordjaikban van | 32 bites értékre végzett bájtkeresés, majd besorolás a tartalmazó `.pdata` rekordhoz | 1 + 2 találat, mind `.pdata` címmező | P |
| NEG-07 | az image nem hordoz MSVC RTTI-t, így a típus nem nevezhető meg | `.rdata` szkennelés `.?A` névre és `signature = 1` Complete Object Locatorra | 0 és 0 találat | P |
| NEG-08 | egyetlen ág sem tesztel syscall-státuszt a merge előtt | a sink és a fázis-merge közötti utasításcenzus, a közös merge-teszt kivételével | 32 ág, 0 teszt, 0 státuszolvasó | P |
| NEG-09 | a wrapper-ek, az ág-törzsek és a belépő függvény nem hívnak regiszteren vagy import-sloton keresztül | minden hívóhely osztályozása direkt vagy indirekt szerint | 0 indirekt callsite | P |
| NEG-10 | az anchor nem ír a descriptoron keresztül | a teljes törzs dekódja, minden store célje a `rcx`/`rbx` hordozókhoz képest | 0 store, 2 load | P |
| NEG-11 | nincs `DuplicateHandle` él a publikált inventoryban | `xref_edges.csv` sorcenzus `dst_symbol` szerint | 0 sor | P |
| NEG-12 | a wrapperek megosztott futásidejű segéd, nem privát dispatch | 12 wrapper szint-1 hívócenzusa a teljes `.text`-en | 408 szint-1 sor, 37 distinct hívó funkció, ebből 36 a `0xC85000`–`0xC88000` tartományon kívül és 1 belül (`0xC856C0`); a 13 forward sinkre 54 distinct hívó adódik | P |
| NEG-13 | az anchor törzsében nincs feltételes kilépés | terminátor- és kilépéscenzus a teljes runtime functionre | 3 kilépés, mind `jmp rax` vagy `ret` | P |
| NEG-14 | a publikált él-készletben egyetlen él sem mutat a `0xC85650`-re vagy `0xC856C0`-ra | `xref_edges.csv` 57 101 sorának `dst_rva` szűrése | 0 találat | P |
| NEG-15 | a `0xC85000`–`0xC88000` klaszterből a publikált él-készletnek nincs `CloseHandle` vagy `DuplicateHandle` célú forrásoldali sora | a 57 101 forrásoldali `src_rva` decimális oszlopként olvasva, a `0xC85000`–`0xC88000` tartományra szűkítve, majd `dst_symbol` szerinti osztás | 17 klaszterbeli forrásoldali sor 5 forrásfüggvényből, ezek között 0 `CloseHandle` és 0 `DuplicateHandle` sor; a valódi hex magas nibble kizárólag `0x0`, a legnagyobb `src_rva` `0x3306F60` | P |

Minden negatívum a felsorolt keresési formára és scope-ra bounded. A „nem láttuk" nem azonos azzal, hogy „nincs": a `Q-01` nyitott kérdés épp a negatívum ellenkezőjének bizonyítása lenne.

## 19. Korlátok és reprodukciós határ

1. **Nincs dinamikus bizonyíték.** Nem láttuk, melyik ág fut ténylegesen, melyik `RDTSC` szelektorérték keletkezik, és milyen státuszt adnak a syscallok.
2. **Szolgáltatásnév nem levezethető.** A 28 syscall-hely mindegyikén futásidejű a service szám; az argumentumséma kompatibilitás nem szolgáltatásazonosítás.
3. **A két load azonossága nincs lezárva.** A `Q-06` téma statikusan nem eldönthető az aliasing kérdés miatt.
4. **A merge-elérhetőség részleges.** A 16 inline ágon `merge_reachability = NOT_ASSERTED`; a 16 wrapper-ágon `OBSERVED`.
5. **Az unwind-rekord nem dekódol standard kódtömbbé.** Exception-funclet nincs igazolva és nincs kizárva.
6. **A hívóklóza 4 mélységnél megállt** (`exhausted = false`); a felfelé menő séma viszont a `0xC85650`-nél 3 szinten, üres frontierrel lezárult.
7. **A `xref_edges.csv` lefedettsége nem egyenletes.** A `0xC85000`–`0xC88000` klaszterből 17 forrásoldali sor van, de a 32 fogyasztási hely és a 429 hívósor egyike sem innen származik: ezek a dedikált nyers-text passzból jönnek. A `0x495D0` növekedési segédhez a fájl 0 sort ad, miközben a dedikált `rel32`-sweep 20 hívóhelyet talál, tehát egy nulla érték önmagában nem szerkezeti negatívum.
8. **Nincs PDB-szimbolika.** A típusnevek, a paraméternevek és a szolgáltatásnevek nem vezethetők le szimbolumtáblából.

A reprodukálhatóság e fájl és az alábbi statikus lekérdezések szintjén értendő:

- `reverse/evidence/c856c0_dataflow.json` és `reverse/evidence/c856c0_forward.json` újratermelése a `reverse/scripts/defuse_slice.py` scripttel;
- a `c856c0_callers.csv` újratermelése a `reverse/scripts/c856c0_callers.py` scripttel;
- a felsorolt RVA-k disasszemblálása az image base `0x180000000` mellett;
- a slotok `int32` értékeinek újraolvasása a `0x2CFB1F8` és `0x2CFB238` RVA-ről;
- a `CloseHandle`/`DuplicateHandle` élcenzus a `xref_edges.csv`-en.

Ez **nem** reprodukálja a DLL runtime viselkedését, syscall-megoldását vagy bármilyen külső hatást. A dokumentum szándékosan nem tartalmaz load- vagy export-invokációt, hálózati végpontot, patchlépést, kerülési technikát vagy működő exploitot.

## 20. Változási dátum és kapcsolódó dokumentumok

- **Dokumentum keletkezése:** `2026-09-26`.
- **Specimen:** változatlan, `91CC0AA0…B81934E`.
- **Felülírt állítások:** a `06` §9.1–§9.5 darabszámai, a `06` §13 „Távoli írás" sora, a `07` §7.1 táblázatának `0xC856C0` sora, a `12` §6.1 pont 3, §6.2 és §6.3, valamint a `12` §7.2 8. és 12. pontja.
- **Érvényes maradó kapcsolódó helyek:** `adhesive-00-index.md#7` (BRef-formátum), `adhesive-06-process-memory-hooks.md#9`, `adhesive-06-process-memory-hooks.md#4.3`, `adhesive-07-anti-debug-integrity.md#7.1`, `adhesive-12-risk-methodology-open-questions.md#6.1`, `adhesive-12-risk-methodology-open-questions.md#10` (a 10. fejezet 6. pontja).
- **Következő felülvizsgálat:** a specimen SHA-256ának, verziójának vagy aláírásának változásakor, illetve ha a `Q-01` vagy `Q-02` nyitott kérdés statikusan lezárul.

---

## 21. Hash- és arány-újraellenőzés (közvetlen kereszt-audit, 2026-09-26 01:45:59)

> **Scope:** kizárólag állomány- és mezőolvasás a `reverse/evidence/` készletén és a `reverse/scripts/` leltárán. A DLL-t nem futtattam, nem töltöttem be, nem mappeltem, nem patcheltem; új evidence-fájl nem készült, és a `reverse/scripts/` és `reverse/evidence/` állományához nem nyultam.

### 21.1 Ellenőrzösi mátrix

| # | Ellenőrzött tétel | Forrás | Eredmény | Állapot |
|---:|---|---|---|---|
| 1 | Specimen sha256 + méret | lemez | `91cc0aa0…` / 53 575 264 – az 1. fejezet állítása | **egyezik** |
| 2 | `defuse_slice.py` digest (a 1. fejezet egyetlen generáló scriptje) | lemez | `5c82f21d6127545afb7c7d3b7a3f0d1bf237ad84a8815c7bbf2718d395a6d650`, 68 046 B – egyezik | **egyezik** |
| 3 | `c856c0_dataflow.json` sha256 + méret | lemez | `c39d281a…` / 255 083 – egyezik az `E10` `inputs` blokkjaival | **egyezik** |
| 4 | `c856c0_forward.json` sha256 + méret | lemez | `1b33efb7…` / 694 730 – egyezik | **egyezik** |
| 5 | `c856c0_callers.csv` sha256 + méret | lemez | `a12f3e35…` / 50 631 – egyezik | **egyezik** |
| 6 | `audit_handle_flow.json` sha256 + méret + `check_count` / `failed_count` | lemez | `c1636fcd…` / 106 955 / **163** / **0** – egyezik a dokumentum állításával | **egyezik** (a `2026-09-26` záró pin-konformancia-javításban frissítve) |
| 7 | `syscall_inventory.csv` sha256 + méret | lemez | `bb1879aa…` / 5 993 935 – egyezik | **egyezik** |
| 8 | `syscall_service_map.json` sha256 + méret | lemez | `25e29583…` / 19 589 – egyezik | **egyezik** |
| 9 | `cfg_functions.csv` és `xref_edges.csv` sha256 + méret | lemez | `041d2365…` / 40 180 030 és `fc744f61…` / 11 126 183 – egyezik | **egyezik** |
| 10 | `patch_record_table.json` digest — a 14.2 fejezet 50 RVA-ja | `E10` `inputs.patch_record_table.json` vs lemez | a `14` nem rögzít hozzá digestet; a lemez `89a52016…` / 79 401 B | **nincs rögzíve** (lásd 21.2/2) |
| 11 | `xref_edges.csv` sorszám- és oszlopszám | lemez + `E10` `xref.*` checkek | 57 101 sor / 22 oszlop – `xref.row_count` és `xref.column_count` checkje igazolja | **egyezik** |
| 12 | **A nyolc auditált számlálás** (Végleges számlálások táblázat) | `E10` `validation` checkek | 2×16 slot / 32 slot; 16 direkt `syscall` ág; 16 wrapper-hívás ág; 12 wrapper (6+6); 28 syscall-hely; 2 handle-load; 32 fogyasztó él; producer `OPEN` | **egyezik** |
| 13 | **`CF-01`** – 12 wrapper distinct hívója | `E10` `wrapper.*` | 37 distinct hívó, 408 szint-1 sor, 36 a `0xC85000`–`0xC88000` tartományon kívül, 1 belül (`0xC856C0`); 13 forward sinkre 54 distinct hívó, 2 a tartományban | **egyezik** |
| 14 | **`CF-02`** – klaszterből forrásoldali sor | `E10` `xref.*` | 17 sor, 5 forrásfüggvény, `max_src` 0x3306F60, 0 `CloseHandle` és 0 `DuplicateHandle` forrásoldali sor | **egyezik** |
| 15 | **`CF-03`** – elérhető célok `.pdata`-lefedettsége | `E10` `reachable.*` | 37 cél, 23 `RUNTIME_FUNCTION` rekorddal, 14 anélkül, `outside_pdata_is_subset = true` | **egyezik** |
| 16 | **`CF-04`** – a `0xC8FEE4` hívóhely és a 6. thunk | `E10` `forward_reachable_set.targets_outside_pdata` | a `0xCAC150` thunk hívóhelye, hívó `0xC8FDE0`; a `0xCAC150` a 14 felsorolt cél között van | **egyezik** |
| 17 | **`CF-05`** – a 6 transzfer wrapper `cluster_id` | `E10` `cluster.*` és `cfg_functions.csv#cluster_id` | `{85}` a 6 transzfer wrapperre és az anchorra/entry-re egyaránt; a 12 wrapper mind a 16 függvényes tartományon kívül | **egyezik** |
| 18 | **`CF-06`** – a wrapper-/inline-ág törzs méretei | `E10` `branch.block_count_delta_*` | 16 wrapper-ágon ∑ delta, egyenletes `{−1}`, inline törzs `[41, 113]` | **egyezik** |
| 19 | **`CF-07`** – a növekedési segéd hívói | `E10` `growth.distinct_callers` | 17 distinct hívó (`0x495D0`) | **egyezik** |
| 20 | **`wrapper_forwarding` scope-korlát** – 21 hely, 7 owning function | `E10` `inventory.forwarding_*` és a 15. fejezet service-map-táblázata | 21 sor / 7 owning function; 0 a 28 tárgykörhelyen; diszjunkt a 12 wrapperrel és a 16 inline hellyel | **egyezik** |
| 21 | A három állításosztály **dokumentum** SHA-256-ja | `E10` `observation.audited_document` vs lemez | az `E10` a `14` dokumentumot **`eebcd7c7…` / 101 147 B** értéken figyeli meg az `observation` blokkban, explicit `is_attestation: false` és `carries_a_verdict: false` jelöléssel, és a hét tanúsított input között nem szerepel; a `14` **saját, önreferenciás** pinje: **nem attestation**, a dokumentum sem tartalmát, sem számait nem tanúsítja, és a fájl bármely szerkesztése – a jelen célzott szövegjavítást is beleértve – elavítja | **eltérés, nem javítandó** (lásd 18.2/1) |
| 22 | `E10` `verdict` — a tizenhét állítás minősített | `E10` `verdict` | `agree`: `B-01`, `B-02`, `D-01`, `D-02`, `D-03`, `H-01`, `H-02`, `P-01`, `S-01`, `W-01` (10); `contested`: `[X-04, X-06]`; `contested_statements`: `CF-01`–`CF-07` (7) | **egyezik** |
| 23 | `E10` `inputs` blokkja | `E10` `inputs` vs lemez | **7** bejegyzés, mind a 7 evidence-fájl digestje egyezik a lemezzel; a dokumentum nincs a tanúsított inputok között, hanem az `observation` blokkban, nem-attesztáló megfigyelésként szerepel (21. sor) | **egyezik** |
| 24 | A 16 függvényes `0xC85000`–`0xC88000` klaszter táblázata (4.2) | `E10` `cluster.function_count_field` / `functions_listed` | 16 függvény, a 16 kezdő-/záró RVA, unwind- és raw oszlopok egyeznek | **egyezik** |
| 25 | A 32 dispatch-slot `int32` értéke és a 32 cél RVA | `E10` `dispatch.*` és `c856c0_forward.json` | 2×16 slot, 4 bájtos lépés, `tables_are_adjacent = true`; a dokumentum slot- és cél-táblázata egyezik | **egyezik** |
| 26 | A 12 wrapper RVA-listája és a 6+6 felosztás | `E10` `wrapper.allocation_rvas` / `wrapper.transfer_rvas` | `0x51D680`–`0x51DFF0` és `0xC8F650`–`0xC8FF60`, mindkettő 6 – egyezik a 3. fejezet C-03/C-06 soraival | **egyezik** |
| 27 | **Három függvény `reached_ratio`** (4.1) | `E10` `cluster.*` | anchor 108 blokk / 1 elért / `reached_ratio` 0,009259; entry 8 blokk / 8 elért; `anchor_switch_sites_validated` 0, `anchor_syscall_sites` 16 | **egyezik** |
| 28 | `argument_register` megoszlás | `E10` `handle.r10_sites` / `handle.rdx_sites` | 16 `r10` + 16 `rdx` = 32 | **egyezik** |

### 21.2 Eltérések — megfigyelve, a dokumentum számát nem módosítva

**1. Az `AFH-2026-09-26` audit a `14` dokumentum digestjét nem-attesztáló megfigyelésként rögzíti**

- **Eltérés:** a `reverse/evidence/audit_handle_flow.json` a `14` dokumentumot az `observation.audited_document` mezőben `eebcd7c7af63a694b547c6723e45c563ffd1f8608e3d12fd9e1c33dad676017b` / `101 147` bájt értéken figyeli meg. Ez **nem tanúsítás**: a payload `observation.is_attestation = false` és `observation.carries_a_verdict = false` jelölést ad, az `observation.why_not_attested` blokk pedig kimondja a ciklus okát – a `reverse/evidence/audit_handle_flow.json`-t magát a `14` dokumentum digesteli, ezért a dokumentum digestjének ilyen payloadba írása kört zárna be, hiszen bármelyik fájl szerkesztése érvényteleníti a másikban rögzített értéket. A hét `inputs` bejegyzés kizárólag evidence-artifact, dokumentum nincs köztük (`inputs_note`).
- **A `eebcd7c7…` érték státusza:** önreferenciás, snapshot-jellegű **megfigyelés, nem attestation**. A `14` saját fájl-digestje ilyen formában nem tanúsítható, és a dokumentum bármely szerkesztése – a jelen pin-konformancia-javítást is beleértve – elavítja, ezért a 21.1 fejezet 21. sora alapján csak az `E10` futásának időpontjában mért lemezi állapotról szabad olvasni. A korábbi pin (`1875fe26…` / 94 338 B, az `audit.audited_document_sha256` mezőben) és az azóta közölt `ed31dff5…` / 100 418 B lemezi érték egyaránt elavult: az első az `E10` korábbi revíziójának mezőneve, a második a `14` egy régebbi revíziójának digesztje.
- **Következmény a dokumentum számaira:** nincs. Az `E10` a nyolc számtani kérdést állítja `agree` státusszal, a hét `CF-01`…`CF-07` szöveges állítást pedig a jelenlegi `Javított számlálások` blokk már alkalmazza; a `14` fő számása, dispatch- és `syscall`-darabszámai változatlanul reprodukálhatók a `c856c0_dataflow.json`, a `c856c0_forward.json`, a `c856c0_callers.csv` és a `cfg_functions.csv` jelenlegi állapotából (21.1/12–30. sor).
- **Miért érdekesebb:** a megfigyelés egyirányú – az audit a saját időpontjában olvasott dokumentum-verziót jegyzi be, nem fordítva, és ezt a bejegyzést eleve kivonja a tanúsított inputok halmazából. Egy következő `audit_handle_flow.py` futtatás a `14` aktuális digestjét fogja megfigyelni.
- **Forrásfájl:** `reverse/evidence/audit_handle_flow.json` `observation.audited_document`, `observation.is_attestation`, `observation.why_not_attested`, `inputs`, `inputs_note` vs `reverse/adhesive-14-c856c0-handle-producer-dataflow.md` lemezi állapot.
- **Confidence: `P`** (OBSERVED).

**2. A `14` nem rögzít shát a `patch_record_table.json`-ra — a 14.2 fejezet 50 RVA-ja digest nélkül áll**

- **Megfigyelés:** a 14.2 fejezet a `reverse/evidence/patch_record_table.json` 50 adatsorát használja, de a dokumentum se méretet, se `sha256`-t nem rögzít rála. A lemezen a `patch_record_table.json` digestje `89a5201689ab0701c59ba75724825bde5ea8fdf7e96510251a21f359c5c26a5a` / 79 401 bájt, 50 adatsorral – a 14.2 fejezet állítása a sorszámra helyes. Az `ffc2234d…` / 14 895 bájt digest nem ehhez a fájlhoz, hanem a `reverse/evidence/patch_mechanisms_1e270.csv`-hoz tartozik.
- **Forrásfájl:** `reverse/evidence/patch_record_table.json` és a `14` dokumentum 14.2 fejezete.
- **Confidence: `P`** (OBSERVED).

### 21.3 Amit a kereszt-audit nem módosított

- **A `14` dokumentum minden száma változatlan és reprodukálható.** A 4–17. fejezet valamennyi darabszáma, aránya, RVA-ja és CSV/JSON-sorszáma a jelenlegi `c856c0_*.json`, `c856c0_callers.csv`, `syscall_inventory.csv`, `syscall_service_map.json`, `cfg_functions.csv` és `xref_edges.csv` állapotából üszámban visszaszármálható; a `Javított számlálások` mind a hét `CF-01`–`CF-07` tétele az `E10` `validation` blokkjával lezárt.
- **A köt nyitott pont továbbra is nyitott:** a handle producer (`P-01`, `STATUS:OPEN`) és az Nt/Zw szolgáltatásnevek (`STATUS:OPEN`) állapotása nem változott; az `E10` ezt megerősíti.
- **A `13` és a `15` dokumentumhoz fűződő állítások érvényesek:** a `13` E1–E8, E10–E11 pinje bitre változatlan; a `13` E9/E12 sorszáma és a `15` E9-sora a mostani 632/0 állapotra javítva lett.
- **BOM és sortörés:** a fájl UTF-8 BOM nélküli, `cr = 0`, `crlf = 0`, záró sortöréssel.

---

## Újraellenőrzés (célzott konfliktusjavítás)

> **Scope:** kizárólag állomány- és mezőolvasás a `reverse/evidence/` készletén, a `reverse/adhesive.dll` statikus fájl-ellenőrzésén és a `reverse/adhesive-16-patch-mechanisms-targets-activation.md` szövegén. A DLL-t nem futtattam, nem töltöttem be, nem mappeltem, nem hookoltam és nem patcheltem. A módosítás kizárólag ebben a két markdown fájlban történt; a `reverse/evidence/` és a `reverse/scripts/` állományhoz nem nyúltam, új evidence-fájl nem készült.

### Ú.1 A feloldott konfliktus

| # | Korábbi állítás (hely) | Felülírt állítás | Forrás artifact | `CONF` |
|---:|---|---|---|---|
| Ú-01 | §16.3 záróbekezdő bekezdése: a `patch_record_table.json` rekordtáblája `anchor_count = 94` értékkel | A `patch_record_table.json` `summary` blokkja `anchor_count: 118`-at és `anchor_failures: 0`-t rögzít. A §16.3 bekezdéséből a `94` kikerült, helyette `118`, `anchor_failures: 0` áll, forrásként a `patch_record_table.json#summary` megnevezésével | `reverse/evidence/patch_record_table.json` → `summary.anchor_count = 118`, `summary.anchor_failures = 0` | `P` |
| Ú-02 | a `94` számhoz nem volt megadva semmilyen mező- vagy fájlhivatkozás, tehát nem volt reprodukálható | A `reverse/evidence/patch_mechanisms_1e270.csv` **nem tartalmaz `anchor_count` mezőt**: 16 oszlopos fejléc, `anchor_count` előfordulás `0`, `50` adatsor. Anchor-aggregátumhoz nincs melyik mezőt leképezni, ezért a lapos CSV-ből semmilyen számozott anchor-állítás nem vezethető le | `reverse/evidence/patch_mechanisms_1e270.csv` fejléc és teljes tartalom | `P` |
| Ú-03 | a `14` és a `16` dokumentum `anchor_count` állítása egymással ellentétes volt (`94` kontra `118`) | A `16` `118`-as állítása az érvényes, mert egyetlen mezőből olvasható; a `14` most ezt követi. A `14` korábbi `94` értéke supercedált, és a `16` `16.0.2` 1. sora már ugyanezt a konfliktust rögzíti | `reverse/evidence/patch_record_table.json`; `adhesive-16` §1.2, §12.2 `FA-01`, §16.0.2/1 | `P` |

### Ú.2 Amit az újraellenőrzés nem módosított

- **A `14` saját számai változatlanok.** A `Javított számlálások` `Végleges számlálások` oszlopának mind a nyolc sora, a `C-01`…`C-09` és a `CF-01`…`CF-07` tétel, a 4–18. fejezet minden darabszáma, aránya és RVA-ja változatlan; egyetlen korábbi számszerű állítást nem érintett a konfliktusjavítás.
- **A két nyitott pont továbbra is nyitott.** A handle producer (`P-01`, `STATUS:OPEN`, `Q-01`) és az Nt/Zw szolgáltatásnevek (`STATUS:OPEN`, `Q-02`) állapota nem változott; a `patch_record_table.json` `record_instances_status` és `activation_status` mezői továbbra is `OPEN`.
- **A `patch_record_table.json` és a `0xC856C0` lánc elkülönülése érintetlen.** A §16.3 negatívumai változatlanul érvényesek: a két mechanizmus között nincs statikus él, a `0xC856C0`-nak nincs DIR64-forrása és nincs `.pdata`-szintű hívója.
- **A 21. fejezet kereszt-audit sorai érintetlenek.** A 21.1/10. sor a `patch_record_table.json` digestjének hiányát rögzíti; ez a blokk nem ad hozzá digestet a §16.3-hoz, így az a sor továbbra is pontos. A 21.1/12., 21.1/13. és a `CF-01`–`CF-07` sorok a `c856c0_*.json`, `c856c0_callers.csv`, `cfg_functions.csv` és `xref_edges.csv` mezőire vonatkoznak, és a `patch_record_table.json` `anchor_count` mezőjének korrekciója ezeket nem érinti.
- **Pontosítás a 21.3 első bulletjéhez:** a kereszt-audit a `14` **saját** darabszámaira állított `agree` minősítést, és az `anchor_count` hivatkozás egy idegen evidence-fájl külső mezője, nem a `14` által számolt darabszám. A `21.3` „minden száma változatlan és reprodukálható" mondatának **hatóköre ezért nem terjedt ki** erre a hivatkozásra; a későbbi, célzott konfliktusjavítás kimondta, hogy a `94` nem volt reprodukálható, és `118`-ra cserélte. A 21.3 eredeti audit-mátrixa és megállapítása változatlanul megmarad, csak a hatókörpontosítás került ide.

### Ú.3 Módszertani határ

- A korrekció **számszerű és forrás szerinti**, nem tartalmaz patch-bájtot, patch-címet, előállítási receptet, kikapcsolási vagy bypass-útmutatást. A dokumentum továbbra is kizárólag kódstruktúrát, argumentumsémát és tulajdonosi viszonyokat ír le, a §1. fejezet vizsgálati elve változatlan.
- A javítás kizárólag a `reverse/evidence/patch_record_table.json` és a `reverse/evidence/patch_mechanisms_1e270.csv` **jelenlegi lemezi állapotából** számolt; a `14` nem ad hozzá új, a korábbiaknál nagyobb hatókörű állítást.
- A két érintett evidence-fájl mérete és digestje a `16` dokumentum új `1.6` hash-pin blokkjában rögzített, egyirányú forrással: `patch_record_table.json` = `89a52016…` / `79 401` bájt, `patch_mechanisms_1e270.csv` = `ffc2234d…` / `14 895` bájt.
- **Kódolás és sortörés:** a fájl UTF-8 BOM nélküli, LF sortöréssel, záró sortöréssel; a `cr = 0` / `crlf = 0` állítás a 21.3 fejezetben változatlanul igaz.

---

## V. Pin-konformancia-javítás (2026-09-26)

> **Scope:** kizárólag szövegszerkesztés a `reverse/adhesive-00-index.md`, `adhesive-12`, `adhesive-13`, `adhesive-14` és `adhesive-15` fájlokban. A DLL-t nem futtattam, nem töltöttem be, nem mappeltem, nem hookoltam és nem patcheltem; új evidence-fájl nem készült, és a `reverse/evidence/` vagy a `reverse/scripts/` állományhoz nem nyúltam. A méret- és `sha256`-pinok a `2026-09-26`-i lemezállapothoz lettek igazítva.

### V.1 A `14` dokumentumban frissített pin-ek

| Hely | Artifact / mező | Régi érték | Új érték |
|---|---|---|---|
| 21.1 fejezet, 6. sor | `audit_handle_flow.json` méret + digest | `105 880` bájt, `9279ee8e…` | **`106 955` bájt, `c1636fcd…`** |
| 21.1 fejezet, 21. sor | `audit_handle_flow.json` `observation.audited_document` mezőneve és értéke | `audit.audited_document_sha256` = `1875fe26…` / 94 338 B; a `14` lemezi értéke `ed31dff5…` / 100 418 B | **`observation.audited_document` = `eebcd7c7…` / 101 147 B**, `is_attestation: false`, `carries_a_verdict: false` |
| 21.1 fejezet, 23. sor | `audit_handle_flow.json` `inputs` blokkja | „8 bejegyzés (a 7 evidence + a leört dokumentum)", **részben egyezik** | **7 bejegyzés, mind evidence-artifact, mind egyezik** – **egyezik** |
| 21.2 fejezet, 1. alpont címe és 5 bulletsora | ugyanaz a mező és a nem-attesztáló jelölés | `audit.audited_document_sha256` / `inputs[7]`, `ed31dff5…` | **`observation.audited_document` / `observation.is_attestation` / `inputs_note`**, `eebcd7c7…` |

### V.2 Az önreferenciás digest annotációja

- **A `14` saját magára hivatkozó digestje nem attestation.** Az `audit_handle_flow.json` a dokumentum digestjét az `observation` blokkban figyeli meg (`is_attestation: false`, `carries_a_verdict: false`), nem a `inputs` tanúsított inputhalmazban; az `observation.why_not_attested` a kört nevezi meg: az `E10`-t magát a `14` digesteli, így a kölcsönös pin bármelyik szerkesztésre érvénytelen.
- **Ez szerkesztésre elavuló megfigyelés.** A `eebcd7c7…` / 101 147 B érték az `E10` futásának időpontjában olvasott `14`-byte-okat rögzíti; a jelen pin-konformancia-javítás maga is módosítja a `14` fájlját, tehát a megfigyelés már nem friss. Csak történeti, nem-attesztáló megfigyelésként olvasható.
- **A `14` saját számaira nincs hatása:** a `Végleges számlálások` nyolc sora, a `C-01`…`C-09` és `CF-01`…`CF-07` tételek, és a 4–18. fejezet minden darabszáma változatlan; egyik tanúsított evidence-input sem a `14` dokumentum.

### V.3 Amit a javítás nem módosított

- **Nem változott semmilyen statisztikai szám, finding, státusz vagy confidence érték:** a 2×16 slot, a 32 slot, a 16 direkt `syscall` ág, a 16 wrapper-hívás ág, a 12 wrapper (6+6), a 28 syscall-hely, a 2 handle-load, a 32 fogyasztó él, a 37 elérhető cél, a 444 soros lezárási séta (`14 / 429 / 1`), a 21 `wrapper_forwarding` site és a 7 owning function változatlan.
- **A `163` / `0` értékek változatlanok és ellenőrizhetők:** az `audit_handle_flow.json` `validation` blokkja `check_count = 163`, `failed_count = 0`; `audit.id = AFH-2026-09-26`; a `verdict` 10 `agree` és 2 `contested` (`X-04`, `X-06`) tételt ad, a `contested_statements` listája `CF-01`–`CF-07`.
- **A `P-01` / `Q-01` nyitott pont továbbra is `OPEN`**, és az Nt/Zw szolgáltatásnevek `UNRESOLVED` státusza sem változott.
- **A 21.1 fejezet további, pinelt artifactjai változatlanok** – `c856c0_dataflow.json` (`c39d281a…` / 255 083), `c856c0_forward.json` (`1b33efb7…` / 694 730), `c856c0_callers.csv` (`a12f3e35…` / 50 631), `syscall_inventory.csv` (`bb1879aa…` / 5 993 935), `syscall_service_map.json` (`25e29583…` / 19 589), `cfg_functions.csv` (`041d2365…` / 40 180 030), `xref_edges.csv` (`fc744f61…` / 11 126 183), `patch_record_table.json` (`89a52016…` / 79 401), `patch_mechanisms_1e270.csv` (`ffc2234d…` / 14 895) – mind bitre egyezik a lemezzel.
- **A 21.1/10. sor változatlanul igaz:** a `14` a `patch_record_table.json`-ra továbbra sem rögzít digestet.
- **Kódolás és sortörés:** a fájl UTF-8 BOM nélküli, LF sortöréssel, záró sortöréssel; `cr = 0` / `crlf = 0`.
