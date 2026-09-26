# `adhesive.dll` – `.pdata` function-map, CFG-lefedettség és unresolved-régiók

> **Vizsgálati elv:** kizárólag a `reverse/adhesive.dll` fájl statikus elemzése. Nem történt DLL-betöltés, image-mapping, futtatás, shellelés, dinamikus traceelés, patchelés, debugger-hozzáférés, hálózati vagy fájlrendszer-megfigyelés. A dokumentum **nem tartalmaz** exploit-, bypass- vagy patch-receptet, kézi ellenőrző kódot, runtime-caller-képlet vagy szolgáltatásnév-feloldást. A nagy CSV-fájlokból sorokat nem másolunk be: minden állítás hash + sorszám (`record_index` / `func_index` / `edge_id` / `site_id` / `region_id`, 1-alapú CSV-sorszám = azonosító + 1 fejléc nélkül) hivatkozással azonosított.

**Confidence-jelölés (a `adhesive-00-index.md` 6. fejezete szerint):** `P=proven`, `L=likely`, `U=unknown`.
**BRef-formátum:** `BRef = [RVA:<hex|N/A> | RAW:<hex|N/A> | CONF:<P|L|U> | STATUS:<OBSERVED|INFERRED|NEGATIVE|OPEN>]`.
**Egyéb státuszok:** `OBSERVED` közvetlenül mért, `INFERRED` statikus adatfolyamból valószínű, `NEGATIVE` a megadott scope-on belül nem találtunk, `OPEN` lezáratlan.

---

## 1. Evidence-készlet és producer-lánc

A function-map öt rétegből áll, és minden réteg ugyanahhoz a specimenhez tartozik (`sha256 91cc0aa006d7315cb042c8fa8dca6c1e074a307bba7dcc9eb5509c8a7b81934e`, méret `53 575 264`).

> **Snapshot-pin `[P]`:** az alábbi méret/hash-adatok a jelen dokumentum írásakor lemezen lévő állapotról származnak, és a teljes evidence-készletre érvényesek. A `.pdata`, CFG, klaszter és unresolved rétegek (E1–E4, E7, E8, E11) stabil, időben nem változott generálás. Az **xref/indirect réteg (E5, E6) `00:57:47`–`00:57:48`, az eszközlánc-metaadat (E12) `01:43:44`, az `xref_build.py` `01:01:52`, az audit pedig (E9) `01:45:21` között keletkezett** — vagyis az E9 a legfiatalabb artifact, és minden inputja előtte keletkezett, tehát nem előntegyártott. A 13. fejezet Gate D a teljesen lezárt E9-et rögzíti; a 7. fejezet lineáris-sweep korlátát és a 3–6., 8., 10., 11. fejezet számait ez **nem** érinti.
>
> **Az E8 későbbi revíziója `[P]`:** az `unresolved_regions.json` és az `unresolved_regions.csv` `2026-09-26 02:07:07`–`02:07:08` között újragenerálódott, vagyis a fenti snapshot-pin **E8 és E7 mtime-re már nem igaz**. A tartalom szempontjából azonban a hatás mért és korlátozott: az **E7 `6e5d9430…` / 57 583 948 pinje változatlan** (a 146 005 soros, 37 oszlopos region-tábla azonos), és az **E8 új revíziójának minden a dokumentumban idézett száma változatlan** (`totals`, `families`, `priority`, `pdata_gap_content`, `counters`, a 116 check / 0 hiba, a 9 900 beágyazott régió). Az egyetlen tartalmi változás az **`inputs.patch_cross_references` pinje**: az új E8 a `patch_mechanisms_1e270.csv` `ffc2234d…` / 14 895 bájt értékét rögzíti, ami egyezik a lemezzel, tehát a 17.3/A digest-eltérése lezárult. Az E8 `inputs` többi pinje (`cfg_functions.csv` `041d2365…` / 40 180 030, `pdata_functions.csv` `65ab914c…` / 29 634 365) egyezik a lemezzel, tehát a **Gate B verdiktje az új revízióra is érvényes**. Az E8 fájl-digestje `b9b6498a…` → `0092fef1…` értékre változott (a fájlméret véletlenül változatlan, 12 253 941 bájt) – ld. 13.y.1/1.
>
> **A készlet élő `[P]`:** a `reverse/scripts/` könyvtárban **19** producer-script áll, és az E12 `scripts` tömbje is **19** bejegyzést tartalmaz: `missing_from_inventory` és `drifted_entries` egyaránt üres, minden `size`/`sha256`/`lf_line_count` mező egyezik a lemezen mért értékkel. Az E9 `discrepancies[D-002].bounded` ezt `stored_entries = 19`, `on_disk_entries = 19`, `failing_attestation_checks = []` értékekkel méri le, `status = closed`, `root_cause_closed = true`. Az E5 és az E6 `fc744f61…`/`21e0e1af…` adathash-pal **változatlan**, tehát a dokumentum minden xref/indirect száma továbbra is érvényes.

| # | Fájl | Méret (bájt) | SHA-256 | Oszlop / rekord | Tartalom |
|---|---|---|---|---|---|
| E1 | `reverse/evidence/pdata_functions.csv` | 29 634 365 | `65ab914c1b38986fcb4bf07d55af0bdad16904a0dcd4271d73343ea7723d785b` | 43 oszlop / 142 004 sor | `IMAGE_RUNTIME_FUNCTION` rekordok + dekódolt `UNWIND_INFO` |
| E2 | `reverse/evidence/pdata_stats.json` | 18 329 | `df1e6ff4cc799afc907ac2c0a8568e87912bf14106bd6f5e88b14d5711a70be8` | 37 ellenőrzés / 0 hiba | `.pdata` statisztika és önellenőrzés |
| E3 | `reverse/evidence/cfg_functions.csv` | 40 180 030 | `041d2365e3be008fbacbcb6f957fbd10fe0ae08c52ee1cbc9090e04bb64df788` | 80 oszlop / 142 004 sor | rekordonkénti CFG, entry-, terminátor- és IAT-mérőszámok |
| E4 | `reverse/evidence/cfg_clusters.csv` | 127 104 | `7d90d02c195e89357d8ec9a213a10140445dcffaf401e3bfe7c7c1871f1aa048` | 65 oszlop / 233 sor | 233 RVA-klaszter aggregátumai |
| E5 | `reverse/evidence/xref_edges.csv` | 11 126 183 | `fc744f611f4b94caf3c619a874dbead3b57123ded4e5df55ba128d748334270a` | **22** oszlop / 57 101 sor | él- és kategória-típusú hívási/xref-index |
| E6 | `reverse/evidence/indirect_sites.csv` | 27 390 456 | `21e0e1af566ad8e7972647d78402a254f647c9fb588508e4c5f657cf6de940ee` | **28** oszlop / 157 153 sor | 157 153 közvetett hívási/ugrási hely |
| E7 | `reverse/evidence/unresolved_regions.csv` | 57 583 948 | `6e5d9430ddeb1c65e588b14cf78a7b1f0be8c7215401783b3c4771bf004a8266` | 37 oszlop / 146 005 sor | teljes region-tábla (lefedetlen + feloldatlan) |
| E8 | `reverse/evidence/unresolved_regions.json` | 12 253 941 | `0092fef1f0e07798fd2573909dc3d0cd4d79a84859e42ca24576b407337b34cd` | 116 ellenőrzés / 0 hiba | módszertan, családosztályok, 9 900 beágyazott régió |
| E9 | `reverse/evidence/audit_infra.json` | 170 001 | `251b79e722620af61824b793ced1ade1ffe9b375608a429e109880aaa8b8b1dc` | 632 ellenőrzés / **0 hiba** | független statikus audit, verdict `pass`; mind a négy finding `closed` (**ld. Gate D**) |
| E10 | `reverse/evidence/audit_syscall_candidates.json` | 1 765 141 | `e8cd41f2a27779b4b6265019d167b3c18a4ac32a6220395e7440cb07c26561be` | 31 ellenőrzés / mind átment | kontrollfolyam-bizonyíthatósági mérés |
| E11 | `reverse/evidence/baseline.json` | 36 512 | `dc34cb50f1a002bae4f01e33064f35c0b28019fe7023add0988ab84fb8df67ea` | – | dokumentált `.pdata`-állítások referenciája |
| E12 | `reverse/evidence/toolchain.json` | 27 150 | `72a1eed07d4d8a83df62cce8bd175a56cbba0da22982b34278fb537b15de0e6b` | **19** script-bejegyzés | eszközlánc- és script-leltár-metaadat (**ld. D-002**) |

> **E9 méret- és hash-megjegyzés `[P]`:** a fenti `170 001` bájt és `251b79e7…` digest a `2026-09-26`-i lemezállapot. A `632` / `0` / `verdict=pass` érték nem a dokumentum állítása, hanem a payload `summary` blokkjából közvetlenül ellenőrizhető tény: `check_count = 632`, `failed_count = 0`, `verdict = pass`, `discrepancy_count = 4`, `discrepancy_open_count = 0`, `failed_checks = []`. **A dokumentum által közölt check-szám a jelenlegi audit-futtatásé**, nem egy korábbi payloadé; a 22 csoportos bontás (13. fejezet Gate D) ugyanannak a `summary.by_group` blokknak a `632`-es összegét adja.

**Producer-lánc és hash-pinning `[P]`:**

| Réteg | Script | Script SHA-256 (lemezen, 2026-09-26) | Hol van rögzítve |
|---|---|---|---|
| E1/E2 | `reverse/scripts/pdata_map.py` | `6772cfbfea0db607a626a91f5bcd4c5b2e1eb47d25a6e3c770b031e8c0f845b7` | E2 `producer.script_sha256` |
| – | `reverse/scripts/common.py` | `4aa2ceec1af88b9cd72e64274b779f4fadf6b62d491fead2c865c3fa99eca750` | E2, E8, E12 |
| E3/E4 | `reverse/scripts/cfg_build.py` | `320d8865ebcc2ec1005cd7ceeaa5ae127929d2fec1a132ec7ff38eb3554dbfdb` | E8 `producer.helpers` |
| E5/E6 | `reverse/scripts/xref_build.py` | az E5/E6 payloadon belül **nincs** – lásd F-01 | E12 `scripts[]` `cbb48bcc…` (102 838 bájt) **és** E9 `provenance.digests` `cbb48bcc…` (102 838 bájt) – mindkettő **egyezik a lemezzel** |
| E7/E8 | `reverse/scripts/unresolved_regions.py` | `b4bf6677bc97e7102c05eb65fda9dc2317ea6a14f811b0a48f3586da51671323` | E8 `producer.script_sha256` |
| E9 | `reverse/scripts/audit_infra.py` | `ebf7f4f4547786ad52b780ca3f8ab2b10df8ab2890e2460d7eba5e08f2dc3e9b` | E9 `audit.script_sha256` (egyezik) |
| E10 | `reverse/scripts/audit_syscall_candidates.py` | `dfd90442d93cd591bcbacf2999a85fe50f514f2796136f741c1c94c69114b7a5` | E10 `producer.script_sha256` (egyezik) |
| E12 | `reverse/scripts/refresh_toolchain.py` | `7cfda978f999833f654c4942b02a343264ddcdba5b6ea13c96f980dee61d75ce` | E12 `script_inventory.producer` |

`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E2 `producer`, E8 `producer`, E9 `provenance.digests`, E12 `scripts`).

**F-01 — Az xref/indirect réteg script-digestje nincs stabil pinelve, és a producer aktívan szerkesztett. `[P]`**
Az `xref_edges.csv` és az `indirect_sites.csv` nem tartalmaz `producer` blokkot. A hozzájuk tartozó `xref_build.py` digestje két **rögzített** helyen, két különböző értékkel szerepel:

| Hely | Digest | Fájlméret | Revízióállapot |
|---|---|---|---|
| E12 `scripts[xref_build.py]` | `cbb48bccba566f417a7c70db1821ef1d51fc8841ffa2c897edc6fbcff0c538d9` | 102 838 | **egyezik a lemez jelenlegi revíziójával** |
| E9 `provenance.digests[reverse/scripts/xref_build.py]` | `cbb48bccba566f417a7c70db1821ef1d51fc8841ffa2c897edc6fbcff0c538d9` | 102 838 | **egyezik a lemez jelenlegi revíziójával** |
| Lemez, korábbi snapshot-időpontban | `ac59efaf970884c25d8ba5d2e06935f801839460c88661e2b508561d5d2831e3` | 102 839 | – |
| Lemez, 8 perccel később | `e877c6aebbf8223f9a54b31681b81efa6e21135eb8c8afc88fd95496543c3487` | 102 839 | – |
| Lemez, `2026-09-26 01:01:52` | `cbb48bccba566f417a7c70db1821ef1d51fc8841ffa2c897edc6fbcff0c538d9` | 102 838 | az E9 ezt a revíziót tanúsítja |

**A payloadon belüli pin továbbra sincs `[P]`:** a `xref_build.py` a vizsgálat ideje alatt több revíziót kapott, és a két köztes lemezrevízió (`ac59efaf…`, `e877c6ae…`) **azonos fájlmérettel, eltérő tartalommal** mutatja, hogy pusztán méretből revízió nem azonosítható. A legutóbbi revízió azonban (`01:01:52`, `cbb48bcc…`, 102 838 bájt) már **két rögzített helyen, azonos értékkel** szerepel: az E12 `scripts[]` és az E9 `provenance.digests` mezőjében, és mindkettő egyezik a lemez jelenlegi állapotával. **Következmény:** a dokumentumban használt E5/E6 statisztikák a `fc744f61…` és `21e0e1af…` **adatfájl**-hash-pal vannak pinelve, és ez a két hash a vizsgálat végén is érvényes volt; az írójuk digestje az E12-ből és az E9-ből egyaránt tanúsítható, de az E5/E6 **saját** payloadjából továbbra sem.
Az E9 `provenance.digests_not_recorded` lista ettől függetlenül 7 fájlt nevez meg diagnosztizálhatatlan drift-tel: `toolchain.json`, `pdata_stats.json`, `cfg_functions.csv`, `cfg_clusters.csv`, `xref_edges.csv`, `indirect_sites.csv`, `syscall_candidates_raw.csv`.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E12 `scripts`, E9 `provenance.digests`, `provenance.digests_not_recorded`).


---

## 2. A function-map módszertana (öt réteg)

A módszertan tisztán statikus: a specimen bájtsorozatként olvasódik a section-táblán át, soha nem mappel és nem fut. Az egyetlen közös kulcs a rekord-sorszám.

```
pdata_functions.csv (E1)  ── 142 004 IMAGE_RUNTIME_FUNCTION rekord
        │  record_index  ==  func_index          (join_key, E8.method)
        ▼
cfg_functions.csv (E3)    ── 142 004 disasszembázisú függvénytörzs
        │  cluster_id     (0x1000-as szomszédsági szabály)
        ▼
cfg_clusters.csv (E4)     ── 233 aggregátum
        │
        ├──────────────────────────────► xref_edges.csv (E5)     57 101 él
        └──────────────────────────────► indirect_sites.csv (E6) 157 153 hely
                                             │
                                             ▼
                                  unresolved_regions.csv (E7/E8) 146 005 régió
```

**Rétegek és szabályok `[P]`:**

1. **Párhuzamos kivonatolás (E1).** Az exception directory `IMAGE_RUNTIME_FUNCTION` rekordjait `BeginAddress, EndAddress, UnwindInfoAddress` sorrendben olvassuk, és mindegyikhez dekódoljuk a `UNWIND_INFO`-t. A kiterjesztő mező (handler- és chain-lánc) kezdőoffsetje `align_up(4 + 2 * CountOfCodes, 4)`; a zászlók `EHANDLER=1`, `UHANDLER=2`, `CHAININFO=4`. Minden értékhez tartozik dec-decimális és `0x` előtagos hex forma, plusz `*_raw` fájloffset.
2. **Rekordonkénti CFG (E3).** Minden `IMAGE_RUNTIME_FUNCTION` kezdőcímét entry-ként használjuk: egy lineáris sweep, majd egy rekurzív leszállás építi a blokkgráfot. A kimenet 80 oszlop: blokk- és edge-szám, elért/nem-elhágott blokk, terminátor-mátrix, kilépési mátrix, direct/indirect hívás- és ugrásszám, IAT-célok, jump-table-, `ret`/`ud2`/`int3`/trap/syscall-helyszám, `decode_status`, `doc_anchors`, `cluster_id`.
3. **Klaszterezés (E4).** A szomszédos `.pdata`-tartományok akkor kerülnek egy `cluster_id` alá, ha a köztes hézag `≤ 0x1000` bájt (`DEFAULT_CLUSTER_GAP`). A `cluster_id` 1-alapú, folyamatos; az `audit_infra` ezt `cfg.functions | cluster_id_not_reproducible_from_gap_rule` és `cfg.clusters | cluster_id_not_contiguous_1_based` néven ellenőrzi.
4. **Xref- és indirect-index (E5/E6).** Külön hívásirány: a közvetlen `call rel32`/`jmp rel32` élek, az IAT-slot és fnptr-slot szerinti közvetett élek, a vtable-slot élek, az import thunk élek, valamint az összes közvetett hely annotált sorszáma.
5. **Régió-osztályozás (E7/E8).** Minden `IMAGE_RUNTIME_FUNCTION` tartományt és minden köztes hézagot hét családba sorolunk; minden régióhoz háromszintű `priority`, háromszintű `confidence` és `kind` (kód/adat/ismeretlen) tartozik.

**A `kind` szabályrendszere (E8 `method.kind_rules`) `[P]`:**

| Szabály | Feltétel |
|---|---|
| 1. `data` | `terminators == 0` **és** `dword_rva_ratio ≥ 0.45` **és** `linear_ratio < 0.85` |
| 2. `data` | `terminators == 0` **és** `small_byte_ratio ≥ 0.6` **és** `linear_ratio < 0.85` |
| 3. `code` | `terminators ≥ 1` **és** `linear_ratio ≥ 0.8` |
| 4. `code` | `linear_ratio ≥ 0.95`, terminátortól függetlenül |
| 5. `unknown` | minden más, a tisztán illesztői kitöltést is |

**Küszöbértékek (E8 `method.thresholds`) `[P]`:** `table_dword_ratio=0.45`, `table_dword_ratio_strong=0.9`, `small_byte_ratio=0.6`, `data_linear_max=0.85`, `code_linear_min=0.8`, `code_linear_strong=0.95`, `redecode_max_size=0x10000` (65 536), `pad_bytes={0x00,0x90,0xCC}`.

**F-02 — A `kind` bájtszintű heurisztika, nem szemantikus bizonyíték. `[L]`**
Az E8 `method.limitations` maga rögzíti: „`kind` is a byte level heuristic, not a semantic proof; a range that fits neither rule is reported as unknown rather than guessed.” Ebből 43 288 `unknown` régió következik (29,6% a 146 005-ből). Bármely `code`/`data` minősítés byte-mintázatokon alapul, nem végrehajtási szemantikán.
`BRef = [RVA:N/A | RAW:N/A | CONF:L | STATUS:INFERRED]` (E8 `method.limitations`, E8 `totals.by_kind`).

---

## 3. A 142 004 rekord

**F-03 — Az exception directory pontosan, maradék nélkül felbomlik 12 bájtos rekordokra. `[P]`**

| Tulajdonság | Érték |
|---|---|
| Directory RVA / RAW | `0x2E54E3C` / `0x2E5383C` |
| Directory méret | `1 704 048` (`0x1A0070`) |
| `1 704 048 / 12` | `142 004`, maradék `0` |
| Parse-olt rekord | 142 004 |
| `BeginAddress` legkisebb / legnagyobb | `0x1020` / `0x2BEE4B5` |
| `record_raw` tartomány (zárt) | `0x2E5383C` … `0x2FF38A0` (a 142 004. rekord kezdő-RVA-ja) |

`BRef = [RVA:0x2E54E3C | RAW:0x2E5383C | CONF:P | STATUS:OBSERVED]` (E2 `exception_directory`, sorszám: E1 fejléc + `record_index`).

**F-04 — A rekordok rendezettek, egyediek és nem fedik egymást. `[P]`**
`out_of_order_pairs=0`, `duplicate_records=0`, `duplicate_begin_addresses=0`, `overlapping_records=0`, `record.nonempty_range=true`, `records_outside_size_of_image=0`. Ez a `CFG` szerinti `overlap_role=sole` értékét is magyarázza: E3 mind a 142 004 sorban `sole`-t ír, `overlap_partners=0`, tehát az overlap-képesség a specimenon üresen fut.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E2 `ordering`, E2 `validation`, E3 `overlap_role` oszlop).

**F-05 — A 15 533 `UNWIND_INFO` mind `.rdata`-beli, és mind `Version=1`. `[P]`**
`unique_count=15 533`; `null_address_records=0`, `unmapped_records=0`, `invalid_header_records=0`, `end_outside_section_records=0`, `version_invalid_records=0`; `version_distribution={"1": 142004}`; RVA-tartomány `0x2E0B64C`–`0x30B89E0`. Egyetlen `UNWIND_INFO` igen nagy referencia-számmal rendelkezik: a `0x2FFAC0C` (`unwind_info_index=865`) 93 153 rekordra mutat. Ez nem hiba: az x64-ben a `UNWIND_INFO` `CHAININFO`-mentes, `CountOfCodes=0` esetén ténylegesen újrahasznosítható, és a 142 004 rekord döntő többsége ilyen.
`BRef = [RVA:0x2FFAC0C | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E2 `unwind_info`, E1 `record_index=2` → CSV 3. sor).

**Flag-eloszlás `[P]`** (E2 `unwind_flags`):

| `unwind_flags` | Értelmezés | Rekordonként | Egyedi `UNWIND_INFO`-nként |
|---|---|---|---|
| `0` | nincs handler, nincs lánc | 137 037 | 10 725 |
| `1` | `EHANDLER` | 65 | 65 |
| `2` | `UHANDLER` | 45 | 45 |
| `3` | `EHANDLER\|UHANDLER` | 2 694 | 2 654 |
| `4` | `CHAININFO` | 2 163 | 2 044 |

Név szerinti eloszlás: rekordonként `EHANDLER=2 759`, `UHANDLER=2 739`, `CHAININFO=2 163`; egyedi információnként `EHANDLER=2 719`, `UHANDLER=2 699`, `CHAININFO=2 044`. A rekord- és információszint közti különbség a `unwind_reference_count>1` információkat többször számláló rekordokból adódik; a 2 694−2 654 = 40 `EHANDLER|UHANDLER` és a 2 163−2 044 = 119 `CHAININFO` különbség konzisztens.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E2 `unwind_flags.value_distribution_per_record`, `…_per_unique_info`).

**Rekordméret-diszperzió `[P]`** (E1 `code_size` oszlop): minimum `1` bájt (28 rekord), maximum `1 279 205` bájt (`record_index=116519`, `0x23A8AE0`–`0x24E0FC5`), 44 rekord nagyobb 100 000 bájtnál. A legnagyobb tíz rekord: `0x19A3E0` (184 669), `0x1C83D0` (157 052), `0x25D450` (609 655), `0x2F2970` (236 789), `0x7E6C50` (177 325), `0x81FD20` (120 505), `0x87F3A0` (203 106), `0x91E730` (258 453), `0xA0A870` (598 826), `0xB26510` (149 135).
`BRef = [RVA:0x23A8AE0 | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E1 `record_index=116519` → CSV 116 521. sor).

---

## 4. Handler- és chain-statisztika

**F-06 — 2 804 handler-hordozó rekord 32 egyedi handler-RVA-ra koncentrálódik. `[P]`**
`handlers.record_count=2 804`, `unique_handler_rvas=32`, mind `.text`-ben, RVA-tartomány `0x2A740C0`–`0x2BEDE20`. A top-5 handler-cél: `0x2BEDE10` (2 301 rekord), `0x2AB3450` (328), `0x2BEDE00` (55), `0x2AB3470` (54), `0x2A83EA0` (5). Vagyis a 2 804 rekord 82,06%-a egyetlen közös handler-rutinra mutat; ez a gyakorlatban kivétel-tisztító (`_CxxThrowException`/MSVC-jellegű) diszpécser vagy `__scrt` stílusú közös unwind-handler jele.
`BRef = [RVA:0x2BEDE10 | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E2 `handlers`, E1 `handler_rva` oszlop).

**F-07 — A chain-lánc sekély, de van 4 mélységű lánc és 3 anomália. `[P]`**
`chains.record_count=2 163`, `invalid_chained_entries=0`, `depth_max=4`, egyedi információnkénti mélység-eloszlás `1:1 736`, `2:273`, `3:29`, `4:6`. A 6 darab `chain_depth=4` rekord: `record_index=137443`, `137444`, `138181`, `138182`, `139599`, `139600` — három egymást fedő párt alkotó `chained` tartomány-illesztés (`0x2AC7AA3→0x2AC7AC5→0x2AC7B0C`, `0x2AEEF68→0x2AEEF72→0x2AEEFB4`, `0x2B83BD7→0x2B83C72→0x2B83E12`).
A `chained_range_above_record_begin=3` jelzi, hogy 3 esetben a lánc-cél kezdőcíme meghaladja a saját rekord kezdőcímét. Ez nem sérülés: a `CHAININFO` által kijelzett `RUNTIME_FUNCTION` a *hívó* frame-re vonatkozik, így lehet a hívó kezdőcímétől későbbi tartomány. A 6 rekordból 4 a `0x2AC7*`/`0x2AEEF*` párok 4 tagú láncot alkotó szeletének 5–6. eleme.
`BRef = [RVA:0x2AC7AA3 | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E2 `chains`, E1 `chain_begin_address` oszlop, `record_index=137443`/`137444`).

**F-08 — Minden `UNWIND_INFO` `.rdata`, minden handler `.text`: kevert szerkezet nincs. `[NEGATIVE]` `[P]`**
Ellenőrizve: `unwind.sections={".rdata": 15533}`, `sections_per_record={".rdata": 142004}`, `handlers.sections={".text": 2804}`. Nincs olyan handler- vagy unwind-cél, amely adat-szekcióban lenne. Keresési scope: a teljes `SizeOfImage` (`0x331E000`), minden raw-backed szekció, `UNMIND_INFO` header- és flag-maskolás, `align_up` kiterjesztőszabály.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:NEGATIVE]` (E2 `unwind_info.sections`, E2 `handlers.sections`).

---

## 5. `.text`-lefedettség

**F-09 — A `.pdata` rekordok a `.text` span 80,7646%-át fedik. `[P]`**

| Tulajdonság | Érték |
|---|---|
| `.text` VA / virtuális méret / raw méret | `0x1000` / `0x2BED4B5` (46 060 725) / `0x2BED600` (46 061 056) |
| `.text` virtuális vég / raw vég RVA | `0x2BEE4B5` / `0x2BEE600` |
| Lefedett bájt | `37 200 748` (`0x237A36C`) |
| **Lefedetlen bájt** | `8 859 945` (`0x873129`) |
| Span (első kezdet → utolsó vég) | `46 060 693` (`0x2BED495`) |
| **Span-lefedettség** | **80,764629 %** |
| Virtuális méret szerinti lefedettség | 80,764573 % |
| Vezető hézag / záró hézag | `32` (`0x20`) / `331` (`0x14B`) |
| `bytes_beyond_declared_virtual_size` | `0` |
| `records_outside_text` / `records_outside_size_of_image` | `0` / `0` |

Az identitás `37 200 748 + 8 859 945 = 46 060 693` pontosan zárul, és ezt az E2 `text.covered_plus_gaps` ellenőrzés igazolja.
`BRef = [RVA:0x1000 | RAW:0x400 | CONF:P | STATUS:OBSERVED]` (E2 `text_coverage`).

**F-10 — 137 103 belső hézag, ahol a hézagok szinte mindegyike 16–255 bájt. `[P]`**

| Hézagosztály | Darabszám |
|---|---|
| `0x1` | 2 542 |
| `0x2`–`0xF` | 37 083 |
| `0x10`–`0xFF` | 96 436 |
| `0x100`–`0xFFF` | 810 |
| `0x1000`–`0xFFFF` | 229 |
| `0x10000`–`0xFFFFF` | 3 |
| `0x1000000`+ | 0 |

Minimum 1 bájt, maximum **175 312** bájt (`0x2ACD0`) a `0x1134F00` címen (`record_index=48115`, E1 CSV 48 116. sor, `gap_before=175312`). A következő legnagyobb: `0x198B060` (98 201), `0x91B340` (69 376), `0x13B1860` (43 588), `0xEB35C0` (42 032).
A 96 436 darab 16–255 bájtos hézag az `align_up` jellegű, 16 bájtos lépcsőzetes igazítás tipikus képe: a linker 16-os igazítással helyez el függvényeket, a `.pdata` rekord viszont csak a tényleges kódtartományt fedi le.
`BRef = [RVA:0x1134F00 | RAW:0x1134300 | CONF:P | STATUS:OBSERVED]` (E2 `gaps.largest[0]`, E1 `gap_before` oszlop).

**F-11 — A hézagok 77,35%-a `body`, a nem test-jellegű `INT3`/`NOP` kitöltés együtt csak 22,65% (az `INT3`-kitöltés önmagában 22,30%). `[P]`**
Az E8 `pdata_gap_content` besorolása: `int3_pad=30 579`, `nop_pad=477`, `zero_pad=0`, `mixed_pad=0`, `body=106 049`, összesen 8 860 308 bájt. Vagyis a 137 105 gap-régióból **106 049 (77,35%) `body`**, vagyis a hézagban tényleges bájt található, nem puszta kitöltés; ezek adják a `triage=unresolved` 106 049-es darabszámot. A `zero_pad=0` és `mixed_pad=0` azt jelenti, hogy egyetlen hézag sem áll kizárólag `0x00`-ból, illetve sem kevert `0x00`/kitöltő kombinációból.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E8 `pdata_gap_content`).

**F-12 — A 137 103 és az 137 105 közötti pontosan 2 hézag és 363 bájt különbség a szekció két szélét adja. `[P]`**
A `pdata_stats.json` a rekordok **köztes** hézagait számolja (137 103), és külön kezeli a `leading_gap=32` és `trailing_gap=331` értéket. Az `unresolved_regions` `pdata_gap` család mindkét szélből külön régiót képez, ezért 137 105 (`pdata_gap_content.gap_leading=1`, `gap_trailing=1`). Számtani ellenőrzés: `8 859 945 + 32 + 331 = 8 860 308`, ami pontosan az E8 `families.pdata_gap.bytes`. A két szélrégió CSV-sorszáma: `UR-009889` (`0x1000`–`0x1020`, 32 bájt, `kind=code`, `confidence=MEDIUM`, E7 CSV 9 890. sor) és `UR-146005` (`0x2BEE4B5`–`0x2BEE600`, 331 bájt, `content=int3_pad`, `kind=unknown`, `confidence=HIGH`, E7 CSV 146 006. sor). **Ez nem ellentmondás, hanem definíciókülönbség; a két szám együtt zár.**
`BRef = [RVA:0x2BEE4B5 | RAW:0x2BED8B5 | CONF:P | STATUS:OBSERVED]` (E2 `gaps`, E7 `region_id=UR-146005`).

---

## 6. CFG-mérőszámok (E3)

**F-13 — 1 117 811 alapblokk, 1 014 037 él, 9 331 019 utasítás. `[P]`**

| Metrika | Summa | Függvényenkénti átlag | Legnagyobb |
|---|---|---|---|
| `basic_blocks` | 1 117 811 | 7,8717 | **34 186** (`func_index=116519`, `0x23A8AE0`) |
| `edges` | 1 014 037 | 7,1407 | **30 812** (`func_index=116519`) |
| `instructions` | 9 331 019 | 65,7096 | 321 767 (`func_index=116519`) |
| `decoded_bytes` | 37 199 652 | 262,00 | 1 279 205 (`func_index=116519`) |
| `undecoded_bytes` | 1 096 | 0,0077 | – |
| `back_edges` (klaszter-összeg, E4) | 21 339 | 0,1502 | – |

Medián `size` 18 bájt, 99. percentilis 1 587 bájt, `zero_size=0`, `decode_status=ok` mind a 142 004 sorban.
`BRef = [RVA:0x23A8AE0 | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E3 `func_index=116519` → CSV 116 521. sor).

**F-14 — A terminátor-mátrix és a kilépési mátrix nem azonos. `[P]`**

| Terminátor | Összeg | Kilépési forma | Összeg |
|---|---|---|---|
| `call` | 746 480 | `exit_call` | 746 480 |
| `jmp_direct` | 32 195 | `exit_branch` | 32 195 |
| `jmp_indirect` | 86 509 | `exit_indirect` | 86 335 |
| `jcc` | 118 403 | `exit_cond` | 118 403 |
| `return` | 118 040 | `exit_return` | 118 040 |
| `trap` | 7 478 | `exit_trap` | 7 478 |
| `invalid` | 1 100 | `exit_invalid` | 1 100 |
| `range_end` | 7 606 | `exit_range_end` | 7 606 |
| – | – | `exit_switch` | 174 |

A `jmp_indirect − exit_indirect = 86 509 − 86 335 = 174` pontosan az `exit_switch` darabszáma: a validált jump-table esetek a `jmp_indirect` terminátorból kilépő útként `exit_switch`-ként számolnak. A `term_*` és `exit_*` oszlopok tehát két nézet ugyanarra a blokk-terminátor-halmazra, nem két független mérés.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E3 `term_*`, `exit_*` oszlopok összege).

**F-15 — A 832 jump-table helyből 174 validált, 658 elutasított; az elutasítás túlnyomó oka `NO_BOUND`. `[P]`**

| Metrika | Érték |
|---|---|
| `switch_sites` | 832 |
| `switch_sites_validated` | 174 (20,93 %) |
| `switch_sites_rejected` | 658 (79,07 %) |
| `switch_cases` | 4 286 |
| `switch_reject_reasons` | `NO_BOUND=655`, `TOO_FEW_DISTINCT_TARGETS=2`, `TARGET_OUT_OF_FUNCTION=1` |

A `NO_BOUND` dominanciája módszertani jel: a builder nem képes a switch-index felső korlátját statikusan levezetni, ezért a teljes 4 bájtos ugrótábla-célkészletet el kell vetnie. A 27 elutasított helyet tartalmazó klaszterek száma 27 (E4 `SWITCH_REJECTED` anchor-tag), az 14 tartalmazóé (`JUMP_TABLE`) 14.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E3 `switch_*` oszlopok, E4 `anchor_tags`).

**F-16 — A 86 559 közvetett ugrás 85 727-e (99,067 %) statikusan fel nem oldott célú. `[P]`**
`indirect_jumps_unresolved=85 727`, `indirect_jumps=86 559`; a különbség, vagyis a **832** feloldott közvetett ugrás a 174 validált jump-táblás helytől teljesen független nagyságrend. Az evidence-készlet **nem** tartalmaz olyan checket, amely ezt a két számot összekapcsolná, ezért az egyezőség a `switch_sites=832`-vel itt **nem** értelmezhető ok-okozati viszonyként; a 13. fejezet D-009 korrekciójának egyik kért pontja éppen a kereszt-számlálás. Ez az xref-index korlátjának közvetlen számszerű kifejezése: a közvetett ugrások gyakorlatilag mind dinamikus (regiszter- vagy memóriakivonásból származó) célról szólnak.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E3 `indirect_jumps_unresolved` oszlop összege).

**F-17 — Az entry-számlálás három különálló nézetet kever. `[P]`**

| Nézet | Summa / darabszám | Magyarázat |
|---|---|---|
| `entry_internal` összeg | 361 335 | beszúrt belső entry-címek (ideális esetben 1/függvény) |
| `entry_external_calls` összeg | 5 369 | külső, CALL által célzott belépőhely |
| `entry_external_jumps` összeg | 1 572 | külső, JMP által célzott belépőhely |
| `entry_refs` összeg | 6 941 | az előző kettő összege; 4,89 függvény/függvény-átlag |
| `entry_internal > 1` függvények | 37 238 (26,22 %) | belső multi-entry |
| `entry_internal == 0` függvények | 95 580 (67,30 %) | nincs talált belső entry |
| Külső referenciát kapó függvények | 6 808 (4,79 %) | `entry_refs > 0`; E4 `functions_with_entry_refs` összege |
| `functions_multi_entry` összeg (E4) | 5 303 (3,73 %) | a `multi_entry` család triggerfeltétele |

A `6 808` és az `5 303` közti 1 505 függvény pontosan azok, amelyeknél `entry_internal == 0` **és** pontosan egy külső referencia van (`0 + 1 + 0 = 1`, tehát a trigger nem teljesül). Az E4 két szomszédos oszlopa tehát nem duplikátum, hanem két eltérő szabály; a különbség dokumentált, de a nevük (`functions_with_entry_refs` vs `functions_multi_entry`) könnyen összekeverhető.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E3 `entry_*` oszlopok, E4 `functions_with_entry_refs` / `functions_multi_entry`).

**F-18 — 11 függvény viseli az összes dokumentált anklót; 12 különböző anklóstring. `[P]`**

| CSV-sorszám | `func_index` | Tartomány | `cluster_id` | `doc_anchors` |
|---|---|---|---|---|
| 463 | 461 | `0x1E270`–`0x1E357` | 1 | `0x1E270:patcher_entry` |
| 3 932 | 3 930 | `0x10FEB0`–`0x11FFF5` | 13 | `0x11660B:registry_root_constant` |
| 9 428 | 9 426 | `0x2F2970`–`0x32C665` | 24 | `0x325969:time_url_xref` |
| 38 551 | 38 549 | `0xC85650`–`0xC856C0` | 85 | `0xC85650:handle_forward_wrapper` |
| 38 552 | 38 550 | `0xC856C0`–`0xC87104` | 85 | `0xC856C0:handle_dispatch_site` |
| 38 557 | 38 555 | `0xC873C0`–`0xC876B4` | 85 | `0xC874E3:protection_constant_setup;0xC874E9:allocation_call_site` |
| 38 564 | 38 562 | `0xC8CE70`–`0xC8CF24` | 85 | `0xC8CE70:toolhelp_stub` |
| 38 574 | 38 572 | `0xC8F650`–`0xC8F872` | 85 | `0xC8F650:write_wrapper` |
| 38 575 | 38 573 | `0xC8F880`–`0xC8FA92` | 85 | `0xC8F880:read_wrapper` |
| 39 975 | 39 973 | `0xD7A400`–`0xD7CF5B` | 92 | `0xD7B0AE`, `0xD7B4B9`, `0xD7C0AC`: `direct_syscall_site`; `0xD7B863:open_process_argument_site` |
| 72 102 | 72 100 | `0x1754520`–`0x17545BB` | 167 | `0x1754520:nop_write_helper` |

Ezek a `adhesive-06`, `-07` és `-12` dokumentumokban szereplő, már leírt helyek gépi visszapontjai; nem új megállapítások.
`BRef = [RVA:0xC856C0 | RAW:0xC84AC0 | CONF:P | STATUS:OBSERVED]` (E3 `doc_anchors` oszlop).

**F-19 — A 105 nem teljesen dekódolt függvény mind az 1 096 nem dekódolt bájtot adja, mind a 232-es klaszterben van. `[P]`**
`functions_with_undecoded=105` (E4), `undecoded_bytes=1 096` (E3/E4), `undecoded_regions=247` (E8 `counters.undecoded_runs`, E3 `undecoded_regions` oszlopösszeg), `redecoded_functions=105` (E8 `counters`). Az E4 `functions_with_undecoded` összege 105, és egyetlen klaszterben (`cluster_id=232`) található mindegyik — az `UNDECODED` anchor-tag is pontosan 1 klasztert érint.
`BRef = [RVA:0x2AB6EE0 | RAW:0x2AB62E0 | CONF:P | STATUS:OBSERVED]` (E8 `counters`, E4 `anchor_tags`; ld. F-21).

---

## 7. A lineáris sweep kontrollfolyam-bizonyítottsági korlátja

> **Ez a fejezet a function-map legfontosabb módszertani korlátja, és a dokumentum minden elérhetőségi számára érvényes. Külön, önálló findingként kezelendő; a 11. fejezet D-009 korrekciója erre épül.**

**F-20 — A blokkok 54,971 %-a kizárólag lineáris sweep-pel elérhető, nem rekurzív leszállással. `[P]`**

| Metrika | Érték | Arány |
|---|---|---|
| `basic_blocks` összesen | 1 117 811 | 100 % |
| `blocks_reached` (rekurzív leszállással elért) | 503 338 | **45,03 %** |
| `blocks_linear_only` (csak lineáris sweep-pel elért) | **614 473** | **54,971 %** |
| `functions_with_linear_blocks` | 1 524 (1,07 %) | – |

A két halmaz kizárólagos: `503 338 + 614 473 = 1 117 811`, és az `audit_infra` `cfg.clusters | sum_blocks_reached` és `sum_blocks_linear_only` ellenőrzések ezt lezárják.

**`reached_ratio` megoszlása (142 004 függvény): `[P]`**

| Változó | Darabszám | Arány |
|---|---|---|
| `reached_ratio == 1.0` | 140 480 | 98,93 % |
| `0,9 ≤ r < 1,0` | 123 | 0,087 % |
| `0,5 ≤ r < 0,9` | 227 | 0,160 % |
| `0,05 ≤ r < 0,5` | 542 | 0,382 % |
| `0 < r < 0,05` | 631 | 0,444 % |
| `r == 0,0` | **1** | 0,0007 % |
| Átlag | 0,991822 | – |

**A tíz legrosszabb `linear_only` függvény: `[P]`**

| `func_index` (CSV sor) | Tartomány | `basic_blocks` | `blocks_linear_only` | `reached_ratio` |
|---|---|---|---|---|
| 116 519 (116 521) | `0x23A8AE0`–`0x24E0FC5` | 34 186 | 34 178 | 0,000234 |
| 57 155 (57 157) | `0x13B5D60`–`0x14DFF24` | 32 416 | 32 411 | 0,000154 |
| 116 563 (116 565) | `0x24E1530`–`0x258E21E` | 18 696 | 18 691 | 0,000267 |
| 9 409 (9 411) | `0x25D450`–`0x2F21C7` | 16 253 | 16 248 | 0,000308 |
| 31 532 (31 534) | `0xA0A870`–`0xA9CB9A` | 12 938 | 12 930 | 0,000618 |
| 109 505 (109 507) | `0x2151E30`–`0x21BD321` | 11 967 | 11 962 | 0,000418 |
| 88 077 (88 079) | `0x1B95790`–`0x1C2FE79` | 9 360 | 9 356 | 0,000427 |
| 48 104 (48 106) | `0x106D780`–`0x1101A79` | 8 909 | 8 906 | 0,000337 |
| 74 120 (74 122) | `0x17EE7E0`–`0x183F26C` | 7 496 | 7 492 | 0,000534 |
| 108 125 (108 127) | `0x20F0210`–`0x21342AB` | 7 450 | 7 443 | 0,00094 |

**Mit jelent ez, és mit nem `[P]`:**

- A `blocks_reached` oszlop **nem** a futásidejű elérhetőséget, hanem a **statikus rekurzív leszállás elérését** méri. A leszállás minden futásidejű belépési pontot entry-ként kezel, és csak a feloldható közvetlen ágat követi.
- A `blocks_linear_only` blokkok **nincsenek bizonyítottan elérhetetlenek**; nincsenek **bizonyítottan elérhetők** sem. Egy közvetett (`jmp reg` / `jmp [mem]`) átugrás utáni, vagy a `default` jump-table-ágat követő blokk tipikusan csak a sweep által kerül ide. F-16 szerint a 86 559 közvetett ugrásból 85 727 fel nem oldott, tehát a rekurzív leszállás az ilyen éleket nem tudja követni.
- A `reached_ratio` **egyetlen számban kevert két bizonyítéknyomot**: a rekurzív leszállás eredményét és a lineáris sweep hipotézisét. Nincs olyan oszlop az E3-ban, amely szétválasztaná őket. A `blocks_reached`/`blocks_linear_only` oszloppár a legjobb elérhető proxy, de ez is csak darabszám, nem tartomány.
- A `linear_only_blocks` család 1 524 régiója, 24 358 005 bájttal (a teljes `.text` 52,9 %-a) az E8 `method.confidence_rules` 4. pontja szerint **kizárólag MEDIUM** confidence-ot kaphat, mert „aggregate counters only, sub ranges not re-decoded”. Vagyis a 614 473 blokkhoz az evidence-készlet **nem ad tartomány-szintű** újradekódolást.
- Az E8 `method.limitations` rögzíti: „`linear_ratio` covers the contiguous prefix a straight sweep decodes; a region stops the sweep at its first undecodable byte and the remainder is reported through `first_fail_rva_hex` rather than per instruction.” A `linear_ratio` tehát csak az összefügges előtagot méri, a maradékot nem.

**F-21 — Az E10 független audit ugyanezt a határt méri, és egy másik opkódcsaládon. `[P]`**
Az `audit_syscall_candidates.json` a `0F 05` (`syscall`) opkódra végzi el ugyanezt a kísérletet, két független dekóderrel (Capstone 5.0.7 + GNU objdump 2.47.20260726, 549 tartomány):

| Metrika | Érték |
|---|---|
| Nyers `0F 05` találat, minden szekció | 3 911 |
| Nyers találat a CSV scope-ban (`.text`) | 3 881 |
| **Érvényes (lineáris sweep-verdikt)** | **3 627** (93,4553 %) |
| Ebből `covered_by_instruction` (false positive) | 209 (5,3852 %) |
| Ebből `no_pdata_function` | 45 (1,1595 %) |
| `.rdata`/`.data` (nem végrehajtható szekció) | 30 (az összes szekció 0,7671 %) |
| **Kontrollfolyam-bizonyított (descent) — `fallthrough_proven`** | **243** |
| **Csak sweep-h hipotézis — `sweep_hypothesis`** | **3 384** (93,30 %) |
| Igazoltan nem-syscall mnemonika | 0 |
| Két dekóder közötti ellentmondás | 0 |

A `syscall`-ra mért **6,70 %-os** (243/3 627) kontrollfolyam-bizonyítottság és a blokkokra mért **45,03 %-os** rekurzív-leszállás-elérés **nem ugyanaz a mérőszám, de azonos jelenség két arca**: a sweep-elhelyezés jóval nagyobb területe van, mint amit a leszállás bizonyít. A **24** olyan közvetlen ágcél, amely egy másik utasítás belsejébe esik (a `recursive_descent.direct_branch_targets_inside_another_instruction` lista 24 címet sorol fel), és a 3 384 hipotézis-hely mindegyike annak a bizonyítéka, hogy a sweep **hipotézis**, nem bizonyíték.
A 24 listaelem: `0x2A73F45`, `0x2A73F49`, `0x2A73F4D`, `0x2A73F51`, `0x2A73F55`, `0x2A73F59`, `0x2A73F5D`, `0x2A82051`, `0x2A82063`, `0x2A82068`, `0x2A82099`, `0x2A87263`, `0x2A87268`, `0x2A87C01`, `0x2A87C0D`, `0x2A87C25`, `0x2A87C28`, `0x2A87C73`, `0x2A87C78`, `0x2A87C7D`, `0x2A87C84`, `0x2AB763B`, `0x2B0441D`, `0x2B1187C`. Az E10 `any_candidate_affected=false` szerint **egyetlen** `syscall`-jelölt sem érintett, tehát erre a 24 címre a syscall-audit nem támaszkodik.
Ezzel szemben **egy** listaelem belül van a négy `data_record` tartományán: `0x2B1187C` a `UR-001624` (`0x2B11850`–`0x2B11898`) bájttartományán belül van (F-27), ahol a sweep-verdikt a 4. § 6. pont alapján eleve adathalmaz-értelmezésen alapul. A másik kettő (`0x2AB763B` a `UR-001622` előtt 69 bájttal, `0x2B0441D` a `UR-001623` után 53 bájttal) éppen a szomszédos tartományokon esik kívül, ami azt mutatja, hogy az ilyen ágcélok **nem** tartoznak szükségszerűen a `data_record` táblákhoz.
`BRef = [RVA:0x2B1187C | RAW:0x2B10C7C | CONF:P | STATUS:OBSERVED]` (E10 `instruction_start_validation.recursive_descent`, E7 `region_id=UR-001624`).

**F-22 — A `blocks_reached` nem tekinthető kontrollfolyam-ténynek; a dokumentált anklók java része sem. `[L]`**
A F-18-ban felsorolt 11 anklófüggvény mindegyike `reached_ratio`-ja magas, de a hívási út bizonyítása nem a `blocks_reached` oszlopból jön: az E10 a 9 anklócsoport 64 egyedi helyéből csak **20**-at igazolt `recursive_descent_confirmed`val (`proof_level=fallthrough_proven`), a többi a sweep-hipotézisben marad. Ez összhangban azzal, hogy a `adhesive-12` dokumentum ezeket a hívási útvonalakat nyitottnak (`[U]`) jelöli.
`BRef = [RVA:N/A | RAW:N/A | CONF:L | STATUS:INFERRED]` (E10 `documented_anchors.descent_confirmed_sites=20`, `unique_sites=64`).

---

## 8. A 233 klaszter

**F-23 — A klaszterezés a `0x1000`-es hézagszabályra épül, és 233 zárt, 1–12 475 függvényes csoportot ad. `[P]`**

| Metrika | Érték |
|---|---|
| Klaszterek száma | 233 |
| `cluster_id` tartomány | 1 … 233, 1-alapú, folyamatos |
| `rva_span` min / medián / max | 49 / 56 637 / 2 401 593 |
| `rva_span` összeg | 43 003 998 |
| `function_count` min / medián / max | 1 / 174 / 12 475 |
| `function_count` összeg | **142 004** (a teljes funkciószettel egyezik) |
| Pontosan 1 függvényes klaszter | **4** |
| 100-nál több függvényes klaszter | 174 (74,68 %) |
| Oszlopszám | 65 |

**A tíz legnagyobb klaszter: `[P]`**

| `cluster_id` | `first_rva_hex` | `rva_span` | `function_count` | `size_total` | `basic_blocks` | `blocks_reached` | `gap_bytes` | `entropy_span` / `entropy_code` | `UNDECODED` fn |
|---|---|---|---|---|---|---|---|---|---|
| 181 | `0x19DD4E0` | 1 198 958 | 12 475 | 721 953 | 25 390 | – | 477 005 | 5,754872 / 6,155994 | 0 |
| 224 | `0x25EB030` | 1 612 809 | 10 755 | 895 062 | 29 961 | – | 717 747 | 5,841182 / 6,145451 | 0 |
| 145 | `0x153B880` | 701 934 | 9 128 | 366 872 | 13 596 | – | 335 062 | 5,450774 / 5,966535 | 0 |
| 225 | `0x2775C60` | 1 816 325 | 5 687 | 1 388 771 | 40 575 | – | 427 554 | 6,180297 / 6,236836 | 0 |
| **232** | **`0x2A97E50`** | 1 398 045 | 5 614 | 1 314 462 | 80 383 | 73 934 | 83 583 | 6,439569 / 6,434241 | **105** |
| 45 | `0x596A50` | 1 694 606 | 5 421 | 1 620 297 | 56 657 | – | 74 309 | 6,533830 / 6,532841 | 0 |
| 123 | `0x11A6C10` | 767 646 | 4 434 | 593 638 | 12 828 | – | 174 008 | 6,098514 / 6,200035 | 0 |
| 216 | `0x21C68B0` | 1 128 566 | 4 120 | 799 397 | 24 989 | – | 329 169 | 6,075337 / 6,144070 | 0 |
| 112 | `0xF752E0` | 1 624 319 | 3 890 | 1 468 065 | 33 513 | – | 156 254 | 6,324531 / 6,304643 | 0 |
| 29 | `0x36BD10` | 469 835 | 3 251 | 269 574 | 9 093 | – | 200 261 | 5,946603 / 6,291409 | 0 |

**F-24 — A 232-es klaszter a specimen belépési pontjának és minden láncolt rekordnak a gazdája. `[P]`**
A 232-es klaszter `0x2A97E50`–`0x2BED36D` tartományú, 5 614 függvénnyel, 80 383 blokkal és 1 314 462 kódbájttal. `entry_point_inside=true` (az E2/E8 rögzíti: `AddressOfEntryPoint=0x2AB2770`), `unwind_chaininfo=2 163` — vagyis **az összes 2 163 `CHAININFO` rekord itt van** —, `undecoded=105` — vagyis **az összes nem dekódolt függvény itt van** —, továbbá `entry_point_inside` az egyetlen klaszter, ahol `true`. Az `export_inside` az 1-es klaszternél `true` (`CreateComponent`, `0x101F80`).
A 232-es klaszter `reached_ratio=0,919772` és `blocks_linear_only=6 449`: a 614 473 sweep-only blokkból 6 449 (1,05 %) itt található, tehát a sweep-limit szétszórt, nem egyetlen klaszterben koncentrált.
`BRef = [RVA:0x2AB2770 | RAW:0x2AB1B70 | CONF:P | STATUS:OBSERVED]` (E4 `cluster_id=232`, E8 `baseline.lifecycle_entry_points`).

**F-25 — A klaszter-anklók 18 típusa lefedi a 233 klasztert; a `LINEAR_BLOCKS` 166-on, az `INDIRECT_CALL` 223-on. `[P]`**

| Anchor-tag | Klaszterek száma | Anchor-tag | Klaszterek száma |
|---|---|---|---|
| `INDIRECT_CALL` | 223 | `SWITCH_REJECTED` | 27 |
| `INDIRECT_JUMP` | 221 | `JUMP_TABLE` | 14 |
| `LINEAR_BLOCKS` | 166 | `IAT_JUMP` | 8 |
| `INCOMING_REFERENCE` | 114 | `INT3` | 8 |
| `UNWIND_EHANDLER` | 96 | `DOC_ANCHOR` | 6 |
| `UD2` | 95 | `EXPORT` | 1 |
| `UNWIND_UHANDLER` | 95 | `ENTRY_POINT` | 1 |
| `IAT_CALL` | 84 | `TRAP` | 1 |
| `SYSCALL` | 55 | `UNDECODED` | 1 |
| | | `UNWIND_CHAININFO` | 1 |

Összes `anchor_count` 1 214. A `LINEAR_BLOCKS` 166 és az `INCOMING_REFERENCE` 114 klaszter az a két legfontosabb mutatója, hogy a sweep-limit (F-20) és a bejövő referencia-hiány (F-24) nem egységes jelenség.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E4 `anchor_tags`, `anchor_count`).

**F-26 — A 4 pontosan egyfüggvényes klaszter oka a hézagszabály, nem kivétel. `[L]`**
A 233 klaszterből 4 pontosan egy `IMAGE_RUNTIME_FUNCTION`-t tartalmaz (`function_count=1`): a 4 darab `0x1000`-nél nagyobb héjaggal mindkét oldalon határolt, magára hagyott rekord. A `cfg_build` `ClusterBuilder` csak az egymásutáni tartományok közti `≤ 0x1000` hézagnál tartja össze a klasztert, ezért az ilyen rekord önálló csoportba kerül; ezt a `cluster_without_functions` (egyik klaszter sem üres) és a `cluster_id_not_reproducible_from_gap_rule` check-ek erősítik meg. A negatív állítás, hogy egyik sem hiba: `E9 cfg.clusters | function_count` és `size_min`/`size_max` checkek mind `size_min == size_max == 1` esetén is átmennek.
`BRef = [RVA:N/A | RAW:N/A | CONF:L | STATUS:INFERRED]` (E4 `function_count` oszlop; `reverse/scripts/cfg_build.py` `DEFAULT_CLUSTER_GAP = 0x1000`).

---

## 9. Xref- és indirect-index

**F-27 — 57 101 xref-él, 6 kategóriában, 51 523 kódcélú. `[P]`**

| `category` | Élek | `dst_kind` bontás | `code_instruction_function_index` üres |
|---|---|---|---|
| `direct_call` | 37 969 | 37 969 `code` | 0 |
| `vtable` | 7 046 | 7 024 `code` + 22 `fnptr_slot` | 7 024 |
| `thunk` | 6 691 | 6 304 `code` + 355 `iat_slot` + 32 `code` | 355 |
| `iat` | 3 761 | 3 132 `iat_slot` + 629 `external` | 629 |
| `global_fnptr` | 1 608 | 1 440 `fnptr_slot` + 168 `code` | 168 |
| `direct_jmp` | 26 | 26 `code` | 0 |
| **Összes** | **57 101** | 51 523 `code`, 3 487 `iat_slot`, 1 462 `fnptr_slot`, 629 `external` | **8 176** |

A 22 oszlopból a 7 a forrástulajdonosságot, a 21–22. az **útmutató (thunk) cél-tulajdonosságát** adja. A `relation` marginal: `call_rel_to_code=37 969`, `fnptr_slot_code_target=7 192`, `call_rel32_to_thunk=6 304`, `call_indirect_iat=3 132`, `call_indirect_fnptr=1 449`, `iat_slot_symbol_binding=629`, `iat_jmp_thunk_stub=355`, `jmp_rel32_to_thunk=32`, `jmp_rel_to_code=26`, `jmp_indirect_fnptr=13` (összeg 57 101). A `fnptr_slot_code_target` és `call_indirect_fnptr` marginal kategóriánkénti bontása: 7 024 `vtable` + 168 `global_fnptr`, illetve 1 429 `global_fnptr` + 20 `vtable`; a 13 `jmp_indirect_fnptr` 11 `global_fnptr` + 2 `vtable`.
Az xref-index **10 452** éle visz `dst_module`/`dst_symbol` értéket, és ezek 629 különböző importált szimbólumra oldódnak fel. A 10 452 három útvonalon oszlik el: 6 336 thunk-közvetített él (`call_rel32_to_thunk` 6 304 + `jmp_rel32_to_thunk` 32, ahol a `dst_kind` mégis `code`, de a cél az import thunkon keresztül ért el), 3 487 `iat_slot` él és 629 `external` él. A 15 leggyakoribb cél és darabszáma: `VCRUNTIME140.dll!__std_terminate` (2 896), `api-ms-win-crt-runtime-l1-1-0.dll!_invalid_parameter_noinfo_noreturn` (1 007), `VCRUNTIME140.dll!_CxxThrowException` (599), `VCRUNTIME140.dll!memcpy` (384), `VCRUNTIME140.dll!__std_exception_destroy` (332), `VCRUNTIME140.dll!__std_exception_copy` (234), `VCRUNTIME140.dll!memset` (170), `MSVCP140.dll!?_Throw_Cpp_error@std@@YAXH@Z` (142), `api-ms-win-crt-heap-l1-1-0.dll!_aligned_free` (120), `VCRUNTIME140.dll!memcmp` (114), `api-ms-win-crt-heap-l1-1-0.dll!free` (110), `MSVCP140.dll!_Mtx_unlock` (101), `api-ms-win-crt-runtime-l1-1-0.dll!_errno` (88), `api-ms-win-crt-string-l1-1-0.dll!strcmp` (87), `KERNEL32.dll!LeaveCriticalSection` (84).
A top-15 összege **6 468 él**, vagyis a modul-feloldott élek 61,88 %-a. Az első hét cél kivételkezelés- és memóriaritmus-függvény (`__std_terminate`, `_invalid_parameter_noinfo_noreturn`, `_CxxThrowException`, `memcpy`, `__std_exception_destroy`, `__std_exception_copy`, `memset`) = 5 622 él (53,79 %); ez MSVC CRT hibakezelési felület, nem speciális képesség.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E5 `category`, `relation`, `dst_kind`, `dst_module`).

**F-28 — A 8 176 forrástulajdonosság nélküli él nagy része ismert konstrukció; a 39 „stub" él most tulajdonossággal rendelkezik. `[P]`**
A `vtable` kategóriájú 7 024 él forrása a `.rdata`-beli vtable, nem kód, ezért üres a `code_instruction_function_index`; a hívó függvényt az E6 `code_instruction_function_index` oszlopból lehet visszakeresni. Az `iat` 629 `external` él forrása szintén nem kód.
A `thunk|iat_jmp_thunk_stub` 355 él forrása *kód* (a `jmp [IAT]` stub maga), mégis mindegyiknél üres a `code_instruction_function_index` — **de a 39 korábbi ellentmondás helyett az új `target_thunk_function_index` oszlop 39 sorban kitöltött**. A 39 él (`edge_id` 37 996, 37 999, 38 004, 38 005, 38 037, 38 039, …) `src_rva`/`code_instruction_function_index`/`target_thunk_function_index`/`dst_module!dst_symbol` sorai rendre: `0x1330`/üres/`5`/`KERNEL32.dll!CloseHandle`, `0x1426`/üres/`8`/`KERNEL32.dll!SetEvent`, `0x16C7`/üres/`16`/`KERNEL32.dll!HeapFree`, `0x1860`/üres/`18`/`KERNEL32.dll!HeapFree`, `0x2A3C`/üres/`63`/`KERNEL32.dll!SetEvent`, `0x2BF9`/üres/`65`/`KERNEL32.dll!CreateEventA`. Vagyis az E5 és az E6 **most egyezik** a 39 hely `.pdata`-tulajdonosságáról: mindkettő azt mondja, hogy a bájtpár nem kezdődik utasításkódban, hanem egy már dekódolt `jmp` utasítás belseje. Ez a D-003 javított állapota.
`BRef = [RVA:0x1330 | RAW:0x730 | CONF:P | STATUS:OBSERVED]` (E5 `edge_id=37996`, E6 `annotation`).

**F-29 — 157 153 közvetett hely; a 136 065 regiszter-indirekt hely (86,6 %) statikusan teljesen feloldatlan. `[P]`**

| `kind` | Darabszám | | `target_kind` | Darabszám |
|---|---|---|---|---|
| `jmp_reg` | 86 356 | | `reg` | 136 065 |
| `call_reg` | 49 709 | | `data` | 10 308 |
| `write_rip` | 10 111 | | `unresolved` | 5 533 |
| `call_mem_base` | 5 463 | | `iat_slot` | 3 526 |
| `call_mem_rip` | 5 020 | | `global_fnptr_slot` | 1 448 |
| `jmp_mem_rip` | 408 | | `virtual_tail` | 230 |
| `jmp_mem_base` | 70 | | `vtable_slot` | 22 |
| `raw_ff15_rejected` | 16 | | `rejected` | 16 |
| **Összes** | **157 153** | | `outside_image` | 5 |
| | | | **Összes** | **157 153** |

`source` bontás: `pdata_decode=156 782`, `raw_scan=371` (= 355 import thunk stub + 16 elutasított `ff 15` nyers találat). A 371 nyers-scan sor adja az összes olyan helyet, amelyet **egyetlen `.pdata` függvény sem fed le kezdőutasításként**, és az üres `code_instruction_function_index` darabszáma pontosan `371`, a `by source` bontás igazoltan `{"raw_scan": 371}`. Ez az 1:1 megfelelés a D-003 javítás után áll fenn: a korábbi 39 sor, amely a `function_index` oszlop mellett hamis „outside every pdata function" annotációt hordozott, már nem létezik.
A 355 import thunk stub annotáció szerinti bontása: **316** `import_thunk_stub_outside_every_pdata_runtime_function+import_kind_regular` (ebből 313 sima, 2 `+int_ordinal_116+ordlookup_name=WSACleanup`, 1 `+int_ordinal_151+ordlookup_name=__WSAFDIsSet`), és **39** `import_thunk_stub_interior_byte_of_a_decoded_jmp_inside_a_pdata_function+stub_is_byte_1_of_a_decoded_7_byte_jmp_at_0x…+covering_first_byte=0x48`. A 39 másodlagos annotáció minden egyes címe egy-egy konkrét 7 bájtos `jmp`-et nevez meg (`0x132F`, `0x1425`, `0x16C6`, `0x185F`, `0x2A3B`, `0x2BF8`, `0x2D85`, `0x1310C`, `0x8DBA1`, `0x8E570`, `0x9B2A5`, `0xA5E31`, `0x5A423C`, `0x67918C`, `0x6FF4C8`, `0x730EB9`, `0x730F0A`, `0xC8F4B3`, `0x1F8FCD6`, `0x1F99468`, `0x1F9F856`, `0x2060C8E`, `0x2065D31`, `0x2079FDC`, `0x20BBE51`, `0x20D7EC1`, `0x2A2493D`, `0x2A97E8C`, `0x2A9EE3B`, `0x2AA0A55`, `0x2AB2821`, `0x2AB285A`, `0x2AB28C6`, `0x2AB390D`, `0x2AB4646`, `0x2AB468D`, `0x2AB481D`, `0x2B73782`, `0x2BA8459`), és mindegyiknél a `covering_first_byte=0x48`, vagyis a `jmp` egy `REX.W` prefixszel kezdődik, így a nyers `ff 25` minta a második bájtjára esik. Ez a 39 hely tehát **nem különálló utasítás**, hanem egy már meglévő 7 bájtos közvetett ugrás opkódargumentumának része.
Az operand-formák: `reg=136 065`, `mem_rip=15 555`, `mem_base=5 533`. A 38 modul ellenőrzött és top 10: `api-ms-win-crt-runtime-l1-1-0.dll` (1 091), `KERNEL32.dll` (1 004), `api-ms-win-crt-heap-l1-1-0.dll` (278), `WS2_32.dll` (263), `MSVCP140.dll` (240), `api-ms-win-crt-string-l1-1-0.dll` (170), `api-ms-win-crt-stdio-l1-1-0.dll` (110), `vfs-core.dll` (61), `citizen-resources-client.dll` (58), `v8-9.3.345.16.dll` (48).
A 30 821 érintett függvény közül a legtöbb `register_indirect_jmp_target_not_statically_resolved` (86 356) vagy `static_store_into_data_address_without_static_code_pointer` (9 870) annotációt kap. **94** különböző annotáció van (a D-003 javítás előtt 55), mindegyik explicit, egyetlen `indirect.sites | empty_annotation` hiba nélkül.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E6 `kind`, `target_kind`, `operand_kind`, `annotation`).

**F-30 — A 230 `virtual_tail` cél a loader null-kitöltő farkába mutat, nem fájlba: ezek eleve nem kódpointer-helyek. `[P]`**
A `xref_build.py` osztályozási szabálya: „An RVA that lands behind `SizeOfRawData` but inside `VirtualSize` is reported as `virtual_tail`: loader zero fill, not a file object, and never a code-pointer slot.” A 230 ilyen cél **mind a `.text`on kívülre** esik. Példa (`site_id=154097`, E6 CSV 154 098. sor): az írás helye `insn_rva=0x2A97F0F` (`raw 0x2A9730F`, `kind=write_rip`, `source=pdata_decode`), a cél `target_rva=0x3307010`, ami a `SizeOfImage` (`0x331E000`) belsejében van, de minden raw-backed szekció mögött esik, tehát betöltéskor nulla. Az annotációk 228-szor `static_store_into_loader_zero_fill_virtual_tail` és 2-szer `rip_indirect_call_into_loader_zero_fill_virtual_tail`.
**Következmény a function-mapre `[L]`:** a 228 statikus írás ilyen memóriába ír, ami a betöltési pillanatban ismert módon nulla. Ebből **nem** következik, hogy az írás halott: futásidőben a betöltő/relokáció vagy egy későbbi inicializálás kitöltheti. Statikusan kizárólag az állítható, hogy **nem előre betöltött kódpointer-tábláról** van szó, tehát ezek nem szerepelnek a function-map kódcél- és hívási indexében, és az `fnptr_slot`/`vtable_slot` kategóriákhoz sem tartozhatnak.
`BRef = [RVA:0x2A97F0F | RAW:0x2A9730F | CONF:P | STATUS:OBSERVED]` (E6 `site_id=154097`, `target_kind=virtual_tail`).

**F-31 — A `cfg_functions` és az `indirect_sites` közvetett ugrásszáma nem egyezik, és az evidence-készlet nem zárja le. `[U]`**
E3 `indirect_jumps` összeg: **86 559**. E6 `jmp_reg + jmp_mem_rip + jmp_mem_base`: **86 834**. A különbség 275. A két szám definíciója eltér (E3 a függvényen belül dekódolt helyeket, E6 az összes annotált utasítássort számolja, a `raw_scan` 355 stub-bal együtt, és a `mnemonic`-szintű `jmp` darabszám is 86 834), de az E9 `xref.edges` 33 és `indirect.sites` 19 ellenőrzése **egyiket sem bírálja a másikhoz**: a `cfg.functions` 19 check a számszerű oszlop-önkonzisztenciát vizsgálja, és egyetlen check sem hasonlítja össze az E3 `indirect_jumps` összegét az E6 jmp-helyszámmal. A finding tehát a Gate D-val **szemben is nyitva marad**. A 275/site eltérés forrása a jelen evidence-készletből nem dönthető el.
`BRef = [RVA:N/A | RAW:N/A | CONF:U | STATUS:OPEN]`.

---

## 10. Unresolved- és lefedetlen régiók

**F-32 — 146 005 régió, 59 839 466 bájt, hét családban. `[P]`**

| `family` | Régiók | Bájt | Hex | Resolved | Unresolved | HIGH conf | MEDIUM | LOW |
|---|---|---|---|---|---|---|---|---|
| `pdata_gap` | 137 105 | 8 860 308 | `0x873294` | 31 056 | 106 049 | 31 029 | 106 009 | 67 |
| `multi_entry` | 5 303 | 5 094 698 | `0x4DBD2A` | 5 301 | 2 | 5 289 | 0 | 14 |
| `boundary_cross` | 1 652 | 20 789 037 | `0x13D372D` | 0 | 1 652 | 1 577 | 0 | 75 |
| `linear_only_blocks` | 1 524 | 24 358 005 | `0x173AC75` | 0 | 1 524 | 0 | 1 443 | 81 |
| `undecoded_range` | 247 | 1 096 | `0x448` | 0 | 247 | 247 | 0 | 0 |
| `switch_unvalidated` | 170 | 735 717 | `0xB39E5` | 0 | 170 | 169 | 0 | 1 |
| `data_record` | 4 | 605 | `0x25D` | 4 | 0 | 4 | 0 | 0 |
| **Összes** | **146 005** | **59 839 466** | `0x39113EA` | **36 361** | **109 644** | 38 315 | 107 452 | 238 |

Triage: `unresolved=109 644` (75,10 %), `benign_padding=31 056` (21,27 %), `classified=5 305` (3,63 %). Kind: `code=102 706` (70,34 %), `unknown=43 288` (29,65 %), `data=11` (0,008 %). Priority: `P0=615`, `P1=972`, `P2=4`, `P3=30`, `P4=144 384` (**forrásoszlop: E8 `totals.by_priority`**, a *kizárólagos* hozzárendelés: `615 + 972 + 4 + 30 + 144 384 = 146 005`, tehát minden régió pontosan egy szinten számít; független kereszt-ellenőrzés: a hét `families.<family>.by_priority` blokk oszloponkénti összege `615 / 972 / 4 / 30 / 144 384`). Ez **nem** azonos az F-37 `priority.<level>.regions` forrásoszlopával – a két különbség levezetése az F-37 után és a 13.y/4. pontban.
A 11 `data` minősítés összesen: 4 `data_record` + 4 `boundary_cross` + 3 `linear_only_blocks`; a `pdata_gap` családban **nulla** `data` minősítés van, azaz egyetlen `.pdata`-lefedetlen hézag sem minősült adattá.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E8 `totals`, `families`).

**F-33 — A `boundary_cross` család 20,8 MB-ja a legnagyobb bájtmennyiség, és 1 637 `code` minősítésű. `[P]`**
A `boundary_cross` trigger a `term_range_end > 0 vagy exit_range_end > 0` (E8 `method.families`). Ez a 7 606 `range_end` blokk-terminátort jelenti: olyan blokk, amelynek utasításfolyam átnyúlik a `IMAGE_RUNTIME_FUNCTION` végén, vagy amelynek belseje a határra csatlakozó szomszédos tartományból érkezik. A 1 652 régióból 1 637 `code`, 4 `data`, 11 `unknown`; LOW confidence 75 (a 11. szabály: nem-gap régió, aminek a `kind`-je `unknown` maradt). A 20 789 037 bájt a `.text` 45,1 %-a, tehát ez a legnagyobb **egyedi** nyitott statikus kérdés a function-mapben.
`BRef = [RVA:0x87F3A0 | RAW:0x87E7A0 | CONF:P | STATUS:OBSERVED]` (E8 `families.boundary_cross`; ld. F-35 példa).

**F-34 — A `linear_only_blocks` 1 524 régiója mind MEDIUM, 81 kivételtel LOW. `[P]`**
24 358 005 bájt, 1 510 `code` / 3 `data` / 11 `unknown` minősítés. A HIGH confidence kizárólag az `undecoded_range`, `switch_unvalidated`, `boundary_cross`, `multi_entry` és `data_record` családoknak jár; a `linear_only_blocks` a 4. szabály szerint sosem HIGH, mert „aggregate counters only, sub ranges not re-decoded”. Ez a 7. fejezet korlátjának formális, evidence-szintű kifejezése.
`BRef = [RVA:0x23A8AE0 | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E8 `families.linear_only_blocks`, `method.confidence_rules[3]`).

**F-35 — A legnagyobb `switch_unvalidated` régió 203 106 bájt, 12 elutasított jump-table-tel, LOW confidence-szal. `[P]`**
`UR-000002` (`0x87F3A0`–`0x8B0D02`, 203 106 bájt, `kind=code`, `triage=unresolved`, `priority=P0`, `confidence=LOW`, `cluster_id=59`, `reached_ratio=0,928479`, `dword_rva_ratio=0,101682`, `small_byte_ratio=0,187636`, `linear_ratio=1,0`, E7 CSV 3. sor) a `func_index=28457` függvényt viseli. Az `evidence` mező rögzíti: `term=call:2178, jmp_direct:171, jmp_indirect:12, jcc:695, return:2, trap:4, invalid:0, range_end:14`, `sites=… syscall:32, ijmp:12, ijmp_unresolved:0`, `exit_range_end=14`, `switch_reject_reasons=NO_BOUND=12`, `int_entries=2855`, `overlap_role=sole`, `iat=KERNEL32.dll!GetProcessHeap`, `iat_symbol_count=2`. Ez a függvény a 44 darab >100 000 bájtos rekord egyike, és 32 `syscall`-helyet tartalmaz — a 8. fejezet szerinti legfontosabb prioritizált tér.
`BRef = [RVA:0x87F3A0 | RAW:0x87E7A0 | CONF:P | STATUS:OBSERVED]` (E7 `region_id=UR-000002`).

**F-36 — A `multi_entry` 5 303 régiójából 5 301 lezárt (`classified`); a 2 nyitott a `kind=unknown` eset. `[P]`**
Az `ok_rules` szerint a `code`/`data` minősítésű `multi_entry` régió `ok=true`, mert „a pure entry-point count, nothing left to decode”. Ez a legnagyobb tisztán **számolási** család: 5 303 függvény 5 094 698 bájtja, de a felszabaduló tartalom 0 bájt. Az egyetlen 2 nyitott példány a 14-es LOW-confidence darabszám 2 tagja.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E8 `families.multi_entry`, `method.ok_rules`).

**F-37 — A `priority` öt szintje forrás szerint, nem süly szerint. `[P]`**

| Szint | Régiók — forrásoszlop E8 `priority.<szint>.regions` | Bájt — forrásoszlop E8 `priority.<szint>.bytes` | Forrásszabály (E8 `method.priority_sources`) |
|---|---|---|---|
| `P0` security | 615 | 2 413 908 | kurált KERNEL32/CRYPT32/WS2_32/ADVAPI32/CFGMGR32/IPHLPAPI/ole32 import **vagy** security `doc_anchor` |
| `P1` syscall | 1 012 | 17 434 496 | `syscall_sites > 0` **vagy** `direct_syscall_site` anchor |
| `P2` patch | 15 | 10 064 | `patcher_entry` anchor **vagy** a patch-audit által tulajdonított RVA a tartományban |
| `P3` lifecycle | 264 | 203 444 | modul-load/TLS/init-once/exception-filter/fiber/event-source import, **vagy** a PE entry point, export vagy TLS callback a tartományban |
| `P4` coverage | 146 005 | 59 839 466 | mindig jelen, legalacsonyabb szint |

**Az F-32 és az F-37 prioritás-disztribúciója nem ellentmondás: két külön bemeneti oszlopról számolnak. `[P]`**
Az F-32 `P0=615, P1=972, P2=4, P3=30, P4=144 384` sora az E8 **`totals.by_priority`** oszlopát idézi – ez a *kizárólagos* hozzárendelés, amelyben minden régió az `method.priority_order` szerint elsőként teljesülő forrás szintjén szerepel, és az öt szám összege pontosan `146 005`. Az ezen felüli táblázat az E8 **`priority.<level>.regions`** oszlopát idézi – ez a *forrás szerinti, nem kizárólagos* találatszám, amelyben egy régió minden olyan szinten számít, amelynek forrásszabályát teljesíti, és ahol a `coverage` szint definíció szerint minden régiót tartalmaz (`146 005`). A két oszlop különbsége számszerűen záról, és a `priority_order` sorrendjével magyarázható:

| Szint | `priority.<szint>.regions` (F-37) | `totals.by_priority` (F-32) | Delta | Magyarázat |
|---|---:|---:|---:|---|
| `P0` `security` | 615 | 615 | 0 | a `security` a `priority_order` **első** eleme, így minden security-teljesítő régió `P0`-ba kerül; nincs elvesző tag |
| `P1` `syscall` | 1 012 | 972 | 40 | a `syscall` forrást is teljesítő, de `security` miatt `P0`-ba sorolt régiók |
| `P2` `patch` | 15 | 4 | 11 | a `patch` forrást teljesítő, de magasabb szintre sorolt régiók |
| `P3` `lifecycle` | 264 | 30 | 234 | a `lifecycle` forrást teljesítő, de magasabb szintre sorolt régiók |
| `P4` `coverage` | 146 005 | 144 384 | 1 621 | a `coverage` minden régiót tartalmaz; a kizárólagos hozzárendelésben csak a négy magasabb szintet el nem érő `146 005 − 1 621 = 144 384` kapja |

A záró aritmetika: a nem-`coverage` forrást találatok összege `615 + 1 012 + 15 + 264 = 1 906`, a kizárólagos hozzárendelés összege `615 + 972 + 4 + 30 = 1 621`, a különbség `285 = 40 + 11 + 234` – vagyis a három nem nulla delta összege. A két oszlop tehát nemcsak megkülönböztethető, hanem egymással számszerűen konzisztens, és egyik sem sérti a másikat. **Egyik szám sem változott:** az F-32-éi a `totals.by_priority`, az F-37-éi a `priority.<level>.regions` mező értékei.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E8 `totals.by_priority`, `priority.security| syscall| patch| lifecycle| coverage`, `method.priority_order`).

**Az F-37 `Bájt` oszlopa nem adódik össze. `[P]`** A `priority.<level>.bytes` ugyanazt a nem kizárólagos forrás szerinti számlálást követi: `2 413 908 + 17 434 496 + 10 064 + 203 444 + 59 839 466 = 79 901 378`, nem `59 839 466`. Az egyetlen szint, ahol a forrás szerinti és a kizárólagos értelmezés egybeesik, a `P0` (`615` = `615`, `2 413 908` bájt), mert a `security` a legmagasabb prioritás. Bájtot a prioritás-disztribúcióból kizárólag a `totals` oldalon szabad összegezni; az `59 839 466` a `totals.bytes` és a `priority.coverage.bytes` közös értéke.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E8 `priority.<level>.bytes`, `totals.bytes`).

A `P2` 15 régiója 10 064 bájt. A patch-audit RVA-i az `inputs.patch_cross_references` mezőn keresztül érkeznek; a jelenlegi E8 pinje a `patch_mechanisms_1e270.csv`-ra `ffc2234d4b620c49420e6751bb1d4db9c3d1e2fd07a7833a9f1452f4fd678090` / 14 895 bájt, ami **egyezik a lemezen lévő fájllal**, a `patch_mechanisms_helpers.csv`-ra `49cb7ee8a9bfac3915c199e4911aac388987e071b61d3ac358ae2c0285ae4843` / 81 295 bájt, ami szintén egyezik. **Az elavult elem a `digest` mellett csak a számszerű `rva_count`:** az E8 `35` / `0` értéket ír, míg a jelenlegi `patch_mechanisms_1e270.csv` 50 adatsorából **21** nemüres `site_rva` származik, a `patch_mechanisms_helpers.csv` 119 adatsorából **0** nemüres `RVA` (a `0` tehát reprodukálható, a `35` nem). A `P2` 15-tagú forrásszáma így a `rva_count` mezővel nem reprodukálható – ld. a 14. fejezet 12. nyitott kérdését. A `P3` 264 régiója lefedi az `lifecycle_entry_points` mind az öt pontját (`0x2AB2770` entry point, `0x101F80` export, `0x10D0`, `0x2AB28D0`, `0x2AB2948` TLS callbackek).
`BRef = [RVA:0x2AB2770 | RAW:0x2AB1B70 | CONF:P | STATUS:OBSERVED]` (E8 `priority`, `baseline.lifecycle_entry_points`).

**F-38 — A `pdata_gap` 31 056 `benign_padding` régiója a 30 579 `int3_pad` + 477 `nop_pad` összege. `[P]`**
Ezek azok az egyetlen régiók, amelyekre `ok=true` a `pdata_gap` családban, és ahol a `confidence` HIGH (31 029) vagy MEDIUM (27 a szabály 3. pontja szerint). Ez a bizonyíték arra, hogy a `.pdata` hézagok **nem** rejtett kódot tartalmaznak tömegesen: a 137 105 hézatrégió 82,63 %-a igazoltan ártalmatlan kitöltés. A maradék 106 049 (`body`) a valódi nyitott kérdés.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E8 `pdata_gap_content`, `families.pdata_gap.by_triage`).

**F-39 — Az E8 csak 9 900 régiót ágyaz be, a `pdata_gap` családból 1 000-at. `[P]`**
`regions_scope`: `complete_families=[data_record, undecoded_range, switch_unvalidated, boundary_cross, linear_only_blocks, multi_entry]`, `truncated_families=[pdata_gap]`, `pdata_gap_regions_total=137 105`, `pdata_gap_regions_in_json=1 000`. Vagyis a **teljes** region-tábla a CSV-ben van (146 005 sor); a JSON az összes nem-gap családot tartalmazza, a gap-ekből csak az első 1 000-at sor sorrendben. A `pinned` mező egyetlen tartományt őriz meg kimutatásra: `UR-001625` (`0x2B4D640`–`0x2B4D67E`, 62 bájt), a `pinned.data_record_verdict` ellenőrzéshez.
`BRef = [RVA:0x2B4D640 | RAW:0x2B4CA40 | CONF:P | STATUS:OBSERVED]` (E8 `regions_scope`, `pinned`).

---

## 11. A 4 `data_record` függvény

**F-40 — Négy `IMAGE_RUNTIME_FUNCTION` nem kódot, hanem táblát deklarál kód-tartományként. `[P]`**
Mind a négy a `data_record` családba tartozik (`reason=pdata_range_is_data`), és mindegyikre teljesül a `kind` 1. szabálya: `code_terminators == 0` **és** `dword_rva_ratio ≥ 0,45` **és** `linear_ratio < 0,85`. Mindegyik `unwind_flags=CHAININFO`, `chain_depth=1`, `cluster_id=232`, `priority=P4`, `triage=classified`, `ok=true`, `confidence=HIGH`.

| `region_id` | E7 CSV sor | E1 `record_index` (CSV sor) | Tartomány | `size` | `raw` | `code_terminators` | `dword_rva_ratio` | `small_byte_ratio` | `linear_ratio` | `reached_ratio` | `decoded/undecoded` |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `UR-001622` | 1 623 | 137 107 (137 109) | `0x2AB7680`–`0x2AB7833` | 435 | `0x2AB6A80` | 0 | 0,472222 | 0,933333 | 0,413793 | 0,333333 | 434 / 1 |
| `UR-001623` | 1 624 | 138 668 (138 670) | `0x2B043C4`–`0x2B043E8` | 36 | `0x2B037C4` | 0 | 1,000000 | 0,277778 | 0,777778 | 0,571429 | 34 / 2 |
| `UR-001624` | 1 625 | 138 846 (138 848) | `0x2B11850`–`0x2B11898` | 72 | `0x2B10C50` | 0 | 1,000000 | 0,250000 | 0,777778 | 1,000000 | 72 / 0 |
| `UR-001625` | 1 626 | 139 645 (139 647) | `0x2B4D640`–`0x2B4D67E` | 62 | `0x2BCA40`→`0x2B4CA40` | 0 | 0,600000 | 0,612903 | 0,000000 | 0,000000 | 51 / 11 |
| **Összes** | 1 623–1 626 | – | – | **605** | – | 0 | – | – | – | – | 591 / 14 |

**F-41 — Mind a négy a 232-es klaszterben van, tehát a belépési pont járuléka; kettő közvetlenül a PE entry point után indul. `[L]`**
A négy `begin_rva` rendre `0x2AB7680`, `0x2B043C4`, `0x2B11850`, `0x2B4D640`; a PE entry point `0x2AB2770`. Az első (`0x2AB7680`) az entry point után `0x4F10` bájttal kezdődik, a másik három a `0x2A97E50`–`0x2BED36D` klasztertartomány belsejében van, és mindegyik `cluster_id=232`. Ez az MSVC `CHAININFO`-vel jelzett **kivételkezelési** (eh- és/vagy unwind-) adattáblák tipikus alakja: a rekord nem futtatható kód, hanem a kivételkezelési lánc adattáblájának egy szelete. A `dword_rva_ratio=1,0` a `UR-001623` és `UR-001624` esetén azt jelenti, hogy a core minden 4 bájtos szava a képre belüli RVA-ra mut, ami pontosan egy **RVA-pointer-tábla** jellemzője.
`BRef = [RVA:0x2B11850 | RAW:0x2B10C50 | CONF:L | STATUS:INFERRED]` (E7 `region_id=UR-001624`, E8 `baseline.lifecycle_entry_points`).

**F-42 — A négy rekord `switch`/`syscall`/IAT-hivatkozást egyáltalán nem tartalmaz; a tartalom kizárólag adat. `[P]`**
Mind a négy `evidence` mező azonos szöveggel zárul: `sites=ret:0,ud2:0,int3:0,trap:0,syscall:0,ijmp:0,ijmp_unresolved:0`, `switch_reject_reasons=none`, `overlap_role=sole`, `overlap_partners=0`, `iat=none`, `iat_symbol_count=0`. A négy `jcc` darabszám rendre 6, 3, 1, 1, az `invalid` 2, 3, 1, 11 — vagyis a sweep a `jcc`/`invalid` bájtokat hamis utasításként dekódolja, ami a `code_terminators=0` mellett is **nem jelent valódi vezérlési átmenetet**. A négy tartomány `cross_function_edges` értéke rendre 2, 3, 0, 0 az E3-ban, azaz a bájtszintű dekódolás 2, illetve 3 „edge”-et lát, miközben nincs egyetlen valódi funkcióhatár-átlépés sem.
`BRef = [RVA:0x2B4D640 | RAW:0x2B4CA40 | CONF:P | STATUS:OBSERVED]` (E7 `region_id=UR-001625`, E3 `func_index=139645`).

**F-43 — A négy tartomány 14 bájtja tartozik az 1 096 nem dekódolt bájt poolba, és mind a `0x2B4D640` esetben 11 bájt. `[P]`**
A 1 096 nem dekódolt bájt 105 függvényből jön, mind a 232-es klaszterből. Ebből a négy `data_record` 14 bájtot visz (`1 + 2 + 0 + 11`), vagyis 1,277 %. A 11 bájt a `UR-001625`-nél (`0x2B4D640`–`0x2B4D67E`) a `first_fail_rva_hex` szerint a sweep **első** megállási pontja; ezért ennek a tartománynak a `reached_ratio=0,0` és a `linear_ratio=0,0` — a 62 bájtból a sweep 51-et dekódol, és mind az 51 elérhetetlen, mert nincs belső entry.
`BRef = [RVA:0x2B4D640 | RAW:0x2B4CA40 | CONF:P | STATUS:OBSERVED]` (E7 `region_id=UR-001625`, E3 `func_index=139645`: `decoded_bytes=51`, `undecoded_bytes=11`, `blocks_reached=0`, `blocks_linear_only=18`, `reached_ratio=0.0`).

**F-44 — A négy `data_record` a negatív finding: a `.pdata` nem tartalmaz kódot ott, ahol a rekord kódot ígér. `[L]`**
A négy rekord `pdata` szinten **érvényes és konzisztens** (a `unwind.unmapped_records=0`, `invalid_header_records=0` és az E2 37/37-es ellenőrzés ezt igazolja), tehát nem sérülésről van szó. A finding a *metaadat-szemantika* rétegébe tartozik: a linker `IMAGE_RUNTIME_FUNCTION`-t írt olyan tartományokra, amelyek a `CHAININFO` által egy kivételkezelési lánc adattáblájához tartoznak, és a rekord `EndAddress`/`BeginAddress` mezői így a tábla bájttartományát fedik. **Nyitott:** hogy a build-rendszer ezeket `comdat`-ként, `.rdata`-ba áthelyezve, vagy linker-specifikus unwind-adattömböként állította elő, és hogy a négy tartomány bármelyike valaha is végrehajtódik-e. Statikusan nem dönthető el.
`BRef = [RVA:0x2AB7680 | RAW:0x2AB6A80 | CONF:L | STATUS:INFERRED]` (E7 `families.data_record`, E2 `validation`).

---

## 12. Korrekciók: D-002, D-003, D-009

Az E9 `audit_infra.json` négy ellentmondást (`discrepancy_count=4`) rögzít: `D-001` (toolchain verziók), `D-002` (elavult script-leltár), `D-003` (import thunk annotáció), `D-004` (hiányzó digestek). A `D-005`–`D-008` számok **szabadon állnak**; a `D-009` alábbiakban ezen a dokumentumon, a function-map rétegekre nézve kerül rögzítésre, hogy a sorszám későbbi, ide mutató hivatkozásokra stabil legyen.

> **Korrekció-státusz `[P]`:** a D-002 és a D-003 producer-oldali korrekcióját az E9 `audit_infra.json` (`01:45:21`, 632 check) **ellenőrzi és igazolja**. Az E9 `discrepancies` regisztere mindkettőre `root_cause_closed=true`-t ad, és a jelenlegi állapotban **mind a négy finding `closed`**: a **D-002 `closed`** és a **D-003 `closed`** mellett a D-004 is `closed` lett. A Gate D `verdict=pass`, `failed_count=0`, `discrepancy_open_count=0` – vagyis a mért számokon és a provenance-rétegen **nincs** nyitott hiba (`bounded.affects_decoded_counts=false` mind a négy findingnél).

### D-002 — `toolchain.json` script-leltára: **`closed`, a root cause lezárt és a rezidális is elfogyott**

**Az eredeti ellentmondás `[P]`** (a korábbi, 457 checkes E9 payloadban): az E9 `audit_infra` a `toolchain.scripts.inventory_names` és `inventory_count` néven 17 hibát adott: a `toolchain.json` `scripts` tömbje **egyetlen** bejegyzést tartalmazott (`common.py`), miközben a `reverse/scripts/` könyvtárban 16 `*.py` volt. A `xref_build.py`, `cfg_build.py` és `unresolved_regions.py` digestje így egyik payloadban sem szerepelt.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E9 `discrepancies[D-002]`, `failed_checks[toolchain.scripts.*]`).

**A javított állapot `[P]`:** az újragenerált E12 (`27 150` bájt, `sha256 72a1eed0…`, 11 top-level kulcs: `schema`, `determinism`, `host`, `python`, `libraries`, `binutils`, `specimen`, `script_inventory`, `package_versions`, `digests`, `scripts`) `scripts` tömbje **19 bejegyzést** tartalmaz, ami **pontosan egyezik** a lemezen lévő 19 `*.py` fájllal — `missing_from_inventory` és `drifted_entries` egyaránt üres. A hiányzó bejegyzéseket a `refresh_toolchain.py` (`sha256 7cfda978…`) pótolja, és a `script_inventory` blokk ezt ki is mondja: `producer = "reverse/scripts/common.py script_records, extended by reverse/scripts/refresh_toolchain.py with third_party_imports"`. Az új séma három kiegészítő elemet vezetett be: a `script_inventory.omitted = ["atime","ctime","mtime"]` mezőt (indoklással: „filesystem timestamps are host state rather than evidence"), a `scripts[].third_party_imports` mezőt és a külön `digests` blokkot (`algorithm`, `entries`, `cross_references`, `self`).
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E12 `script_inventory`, `scripts`, `digests`).

**A megmaradt rés `[P]` — nincs: a finding teljesen lezárult.**

| Ellenőrzés | Az eredeti E9-ban | Az E12 korábbi rögzítésekor | A jelenlegi E9-ban (632 check) |
|---|---|---|---|
| `toolchain.scripts.inventory_count` | 1 (expected 16) | 17 (expected 17) | `expected 19`, `actual 19` – **zéró hiba** |
| `toolchain.scripts.inventory_names` | 16 névből 1 egyezett, 15 hiányzott | mind `true` a 17-re | **mind `true`** a 19-re, **0 hiányzó** |
| `toolchain.scripts.entry_present[*]` | 15 `false` | mind `true` | **mind `true`** |
| `*.size` / `*.sha256` / `*.lf_line_count` | – | 5 bejegyzés elavult | **0 elavult bejegyzés** (`drifted_entries = {}`) |
| `toolchain.package_versions.imported_by_matches_the_audit_census` | – | 1 hiba (12 tagú rögzített lista vs 13-as `ast`-cenzus) | **0 hiba** – a rögzített `capstone`-importer-lista is 13 tagú |
| `xref_build.py` digest a fájl saját payloadjában | **nincs** | **nincs** | **nincs** (E5/E6 továbbra sem tartalmaz `producer` blokkot) |
| `xref_build.py` digest az E12-ben | – | `10f62ac6…` (102 744 bájt) | `cbb48bcc…` (102 838 bájt) – **egyezik a lemezzel** |
| `xref_build.py` digest az E9-ben | `3e869306…` (85 172 bájt) | `3e869306…` (két revízióval lemaradva) | `cbb48bcc…` (102 838 bájt) – **egyezik a lemezzel** |
| `xref_build.py` digest a lemezen | – | `ac59efaf…`, majd `e877c6ae…` | `cbb48bcc…` (`01:01:52`), **több revízió után stabil** (F-01) |

A D-002 státusza az E9 szerint **`closed` `root_cause_closed=true`**-lal, és a `bounded` blokk `missing_from_inventory=[]`, `drifted_entries={}`, `stored_entries=19`, `on_disk_entries=19`, `failing_attestation_checks=[]` értékeket ad. A két korábbi ok közül egyik sem él tovább:
1. **A rezidális tartalom-drift megszűnt `[P]`:** az E12 `scripts` tömbje a producer-fa aktuális állapotát őrzi – minden producer benne van, és minden `size`/`sha256`/`lf_line_count` mező egyezik a lemezen mért értékkel; a `package_versions` importer-lista is a 13 tagú audit-cenzust tükrözi. A `xref_build.py` esetében az E12 már a `cbb48bcc…` (102 838) revíziót tartja, **megegyezve** az E9 `provenance.digests` értékével és a lemez állapotával.
2. **A leltár *pillanatnyi* konzisztencia, nem invariant `[P]`:** ez a tulajdonság nem változott – minden új vagy módosított producer ismét elavulttá teszi a leltárat –, de a finding a jelenlegi lemezállapoton már nem nyitott. Az E9 `attestation_checks` listája 11 elemet sorol fel, `failing_attestation_checks` egyet sem.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E9 `discrepancies[D-002].bounded`, `discrepancies[D-002].status`, E12 `scripts`, `script_inventory`, E9 `provenance.digests`, lemez).

**A function-map rétegekre gyakorolt hatás `[P]`:**

| Réteg | Script | Digest hol van pinningolva a payloadon belül? | Érték |
|---|---|---|---|
| E1/E2 `.pdata` | `pdata_map.py` | **igen** (E2 `producer.script_sha256`) | `6772cfbf…` |
| E3/E4 CFG + klaszter | `cfg_build.py` | **igen** (E8 `producer.helpers`) | `320d8865…` |
| E5/E6 xref + indirect | `xref_build.py` | a saját payloadban **nem** (F-01) | `cbb48bcc…` (102 838 bájt) – **az E12-ben és az E9 `provenance.digests`-ben is, egyezik a lemezzel** |
| E7/E8 régiók | `unresolved_regions.py` | **igen** (E8 `producer.script_sha256`) | `b4bf6677…` |
| E9 maga az audit | `audit_infra.py` | **igen** (E9 `audit.script_sha256`) | `ebf7f4f4…` (151 067 bájt) – egyezik a lemezzel |
| E10 | `audit_syscall_candidates.py` | **igen** (E10 `producer.script_sha256`) | `dfd90442…` – egyezik |
| E12 | `refresh_toolchain.py` | **igen** (E12 `script_inventory.producer`) | `7cfda978…` (29 120 bájt) – egyezik a lemezzel |

A function-map **négy** mérőrétegéből három (`pdata`, `cfg`, `unresolved`) továbbra is teljesen önpinningolt és változatlan. Egyedül a `xref`/`indirect` réteg nem az a saját payloadján belül, és ennek oka a D-004-gyel közös: az E5/E6 fejléceiben nincs `producer` blokk. **A D-002 lezárása ezt nem oldja meg**; a két út változatlan: vagy az E5/E6 fejlécébe kell digestet írni, vagy az E12-t a `xref_build.py` minden módosítása után újra kell generálni. A `refresh_toolchain.py` pontosan az utóbbiat automatizálja, tehát a gyökérok a payload-fegyelem hiánya, nem a tooling hiánya.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E9 `provenance.digests`, E2 `producer`, E8 `producer`, E12 `scripts`).

**Kiegészítő, a toolchain-verziókkal kapcsolatos (`D-001`) `[P]`:** a finding **`closed`, `root_cause_closed=true`**, mert a `toolchain.json` már nem kínáljon egyetlen összecsukott verziót csomagonként: a `package_versions` blokk minden harmadik fél csomagot három tengelyen verzionál (`package_metadata`, `imported_module`, `native_engine`), a hármat párhuzamosan tartja, és **soha nem egyezteti** őket; a lapos `libraries` blokkot pedig ehhez képest ellenőrzi. A `capstone` tengelyértékei ettől változatlanok: `package_metadata=5.0.9`, `imported_module=5.0.7`, `native_engine=[5,0,1280]`; a `lief`-nél `1.0.0` és `1.0.0-d05b3499b`; a `pefile` esetén a kettő egyezik (`2024.8.26`). Mindkét eltérés hordoz egy géppel ellenőrizhető bizonyítékot (`imported_version_is_composed_from_binding_constants`, illetve `imported_version_re_exported_from_a_compiled_extension`), és az `effect_on_evidence` minden csomagnál kimondja, hogy a `lief` divergenciája nem lehetett hatással egyetlen dekódolt artifactra sem. A CFG-blokk- és edge-számok, a terminátor-mátrix és a jump-table-értékelés **mind** a Capstone-verziótól függ, ezért a function-map mérőszámai az `imported_module=5.0.7` tengelyen értendők. Ezt az E10 explicit megerősíti: `producer.capstone.module_version = 5.0.7`, `engine_version = [5, 0, 1280]`. A dokumentum minden CFG-száma erre a buildre vonatkozik, és a lezárás ezt **nem** módosítja.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E9 `discrepancies[D-001]`, `discrepancies[D-001].bounded.axis_values`, E12 `libraries`, `package_versions`, E10 `producer.capstone`).

### D-003 — Az import thunk stub annotációja: **`closed` – a producer-oldali korrekciót az E9 ellenőrizte és igazolta**

**Az eredeti ellentmondás `[P]`** (a korábbi, 457 checkes E9 payloadban): az E9 `indirect.sites | thunk_stub_annotation_contradicted_by_own_function_columns` és `xref.edges | thunk_stub_rows_covered_by_a_pdata_function` néven egyaránt hibát adott `actual=39`-gyel. A korábbi E6 mind a **355** `raw_scan` import thunk stub sort az `import_thunk_stub_outside_every_pdata_runtime_function+import_kind_regular` annotációval adta vissza, de **39** ezek közül olyan RVA-n volt, amelyet egy `.pdata` rekord lefedett — és ugyanazok a sorok kitöltötték a **régi sémában** `function_index`, `function_begin` és `function_end` nevű oszlopokat. Az E5 ezzel szemben az összes 355 `thunk|iat_jmp_thunk_stub` élnél **üresen hagyta** a szintén régi `src_function_index`-et, beleértve ugyanezt a 39 RVA-t. A `D-003` emiatt `high` severity volt: a `adhesive-03` azon érvelése, amely az import thunkokat a CALL-helyektől a `.pdata`-határ függetlensége alapján választja el, éppen a hamis annotációra támaszkodott.
`BRef = [RVA:0x1330 | RAW:0x730 | CONF:P | STATUS:OBSERVED]` (E9 `discrepancies[D-003]`, `failed_checks`).

**A javított állapot `[P]` — három konkrét változás:**

1. **Az annotáció feloszlott.** A 355 stub helyett a helyes felismerés: **316** valóban `outside_every_pdata_runtime_function` (313 sima + 2 `int_ordinal_116+ordlookup_name=WSACleanup` + 1 `int_ordinal_151+ordlookup_name=__WSAFDIsSet`), és **39** `import_thunk_stub_interior_byte_of_a_decoded_jmp_inside_a_pdata_function+stub_is_byte_1_of_a_decoded_7_byte_jmp_at_0x…+covering_first_byte=0x48`. A 39 tehát **nem különálló utasítás**, hanem egy már dekódolt 7 bájtos, `REX.W`-prefixszel (`0x48`) kezdődő közvetett `jmp` opkódargumentumának része. A teljes 39 címlista az E6 `annotation` oszlopából kiolvasható (lásd F-29).
2. **Az E6 oszlopai önmagukban következetesek.** Az üres `code_instruction_function_index` darabszáma most pontosan **371**, a `raw_scan` forrás darabszámával egyezően; a 39 korábbi „lefedett és mégis hamisan tagadott" sor megszűnt, így **egyetlen sor sincs**, amely a saját `code_instruction_function_*` oszlopaival ellentmondana. A `indirect.sites` érintett függvényszáma 30 822-ről 30 821-re csökkent.
3. **Az E5 új `target_thunk_function_*` oszlopokat kapott, és a 39 sorban kitölti őket.** A jelenlegi 22 oszlopos sémában a forrás *utasításának* tulajdonosa a `code_instruction_function_index` / `code_instruction_function_begin` / `code_instruction_function_end` hármas (a korábbi `src_function_index/begin/end` neve), és megjelent a `target_thunk_function_index` / `target_thunk_function_begin` / `target_thunk_function_end` hármas (a *cél-thunk* tulajdonosa). A 39 `iat_jmp_thunk_stub` élnél a `code_instruction_function_index` üres, a `target_thunk_function_index` kitöltött: `0x1330`→`5` (`KERNEL32.dll!CloseHandle`), `0x1426`→`8` (`SetEvent`), `0x16C7`→`16` (`HeapFree`), `0x1860`→`18` (`HeapFree`), `0x2A3C`→`63` (`SetEvent`), `0x2BF9`→`65` (`CreateEventA`). Így **az E5 és az E6 már nem vitatkozik** arról, van-e a 39 bájthelynek `.pdata`-tulajdonosa: mindkettő szerint nincs kezdőutasításnak, de van körülötte funkció.
`BRef = [RVA:0x1330 | RAW:0x730 | CONF:P | STATUS:OBSERVED]` (E6 `annotation`, `code_instruction_function_index`; E5 `target_thunk_function_index`, `edge_id=37996`).

**Korrekció a function-map használatához `[L]`:**

1. Az annotáció **ismét tekinthető tulajdonjog-állításnak**, és a 355 import thunk mindhárom darabszáma megmarad: az **import thunkok száma 355** (E9 `documented[import_thunks] = 355`), és **193** éri el legalább egy CALL-xrefet (`documented[thunks_reached_by_call] = 193`). A `6 304` `thunk|call_rel32_to_thunk` él a `adhesive-03` 2. fejezetének „call rel32 xrefs through an import thunk" állítását szolgálja ki, és a szám **nem változott** a korrekció miatt.
2. A korrekció **nem változtatja meg** a function-map számait: az E5 sor- és kategóriaszámai (57 101 él, 6 kategória, 51 523 `code` cél) és az E6 `kind`/`target_kind`/`operand_kind` marginaljai bitre azonosak a korábbi állapottal. Egyedül az annotációk száma (55 → **94**), az érintett függvények száma (30 822 → **30 821**) és a modulok száma (36 → **38**, a két új WS2_32 ordinal-feloldás miatt) változott.
3. **A function-map szempontjából a következmény korlátozott és semleges:** a 39 sor `.text`-beli, 6 bájtos `jmp [IAT]` utasítás opkódargumentuma; egyik sem visel `syscall`-, `patcher_entry`- vagy más security anklót, és egyik sem kerül be a 615 `P0` security-régióba.
4. A 316 valóban `.pdata`-n kívüli stub a `raw_scan` 371 soros csoportjának része, és analóg az E10 `false_positive_explanations` `no_pdata_function` (45 hely) csatornájához: a `.pdata` hiánya nem bizonyítja, hogy a bájt nem kód, csak azt, hogy nincs dekódolási kontextus. A 39-nél a helyzet **nem fordított, hanem pontosított**: van kontextus, és a kontextus kimondja, hogy a bájt egy már meglévő utasítás belseje.
`BRef = [RVA:0x1330 | RAW:0x730 | CONF:L | STATUS:INFERRED]` (E5 `relation=iat_jmp_thunk_stub`, E6 `annotation`, E9 `discrepancies[D-003]`).

**A lezárás bizonyítéka `[P]` – az E9 mind a 16 felsorolt checket lefuttatta és mindet zöldnek adta:** a `discrepancies[D-003]` státusza `closed`, `root_cause_closed=true`, `severity=high` (a magas súly megmaradt, csak a finding oldódott), `bounded.contradicted_rows=0` és `affects_decoded_counts=false`. A `bounded` blokk számszerűen rögzíti a feloszlást: `stub_rows=355`, `annotated_outside_every_pdata_function=316`, `annotated_interior_of_a_decoded_jmp=39`, `interior_rows_hosted_in_a_pdata_function=39`. A döntő checkek: `indirect.sites.thunk_stub_annotation_contradicted_by_own_function_columns` (a korábbi 39-elő hiba most `ok=true`), `indirect.sites.thunk_stub_interior_rows_recompute_from_their_own_annotation` (az annotáció mindhárom mezőjét a specimen bájtjaiból újraszámítja), `indirect.sites.thunk_stub_interior_rows_name_their_hosting_thunk_function`, `xref.edges.thunk_stub_rows_declare_no_code_instruction_function`, `xref.edges.thunk_stub_hosting_thunk_function_covers_the_stub_byte` és `xref.edges.thunk_stub_hosting_thunk_function_agrees_with_indirect_sites` (az E5 és az E6 ugyanazt a `target_thunk_function_index`-et nevezi meg ugyanarra az RVA-ra), továbbá a `code_instruction_function_columns_are_atomic` / `target_thunk_function_columns_are_atomic` és a `target_thunk_function_index` / `target_thunk_function_range` párok mindkét fájlra. A `csv.format | header_matches_producer_declaration` check az új 22/28 oszlopos fejlécet is egyezteti a producer deklarációjával, tehát a korábbi „újrafuttatáskor elhasal" félelem **nem** igazolódott.
A D-003-ra tehát **nem marad nyitott rész**; ami nyitva marad, az a producer-digest kérdése, és az a D-002/F-01 Findinghöz tartozik, nem ehhez.
`BRef = [RVA:0x1330 | RAW:0x730 | CONF:P | STATUS:OBSERVED]` (E9 `discrepancies[D-003]`, `discrepancies[D-003].bounded`, `checks[indirect.sites.*]`, `checks[xref.edges.*]`, `csv.format` `header_matches_producer_declaration`).

### D-009 — A `cfg_functions.csv` elérhetőségi-mérőszámai két eltérő bizonyítéknyomot kevernek egy számba (új, ezen a dokumentumon rögzítve)

**Definíció:** az evidence-készlet azon ellentmondásos vagy félrevezetően reprezentált adata, amelyet sem az E2, sem az E7/E8 `validation`, sem az E9 `checks` nem vizsgálja, és amely a function-map minden elérhetőségi számát érinti.

**Az ellentmondás `[P]`:**

| Forrás | Állítás | Bizonyítéknyom |
|---|---|---|
| E3 `blocks_reached` oszlop | 503 338 blokk elérve | **rekurzív leszállás** – entry-indokolt |
| E3 `blocks_linear_only` oszlop | 614 473 blokk elérve | **lineáris sweep hipotézise** – a sweep folytatása egy vezérlési átmeneten túl, amit a sweep figyelmen kívül hagy |
| E3 `reached_ratio` oszlop | `blocks_reached / basic_blocks` | **kevert** – a két bizonyítéknyomot egyetlen számba sűríti |
| E8 `method.confidence_rules[4]` | a `linear_only_blocks` család **mindig MEDIUM**, sosem HIGH | a szerző maga mondja ki, hogy a sweep-only rész nem bizonyított |
| E8 `method.limitations` | a `linear_ratio` csak az összefügges sweep-előtagot méri | a maradék nincs utasításonként megjelölve |
| E10 `instruction_start_validation.proof_levels` | 3 627 `syscall`-helyből **243** descent-bizonyított, **3 384** csak sweep-hipotézis | független mérés ugyanarra a korlátra |

Vagyis a 614 473 `blocks_linear_only` blokk és a 24 358 005 bájtos `linear_only_blocks` család **jelenleg nincs elérhetőségi-bizonyítékkal alátámasztva**, ugyanakkor az E3 `reached_ratio` oszlopa ezt a nem-bizonyított részt is beleszámítja a nevezőbe, és a számlálóhoz hozzáadja. Sem az E9 `xref.edges`/`indirect.sites` 52 ellenőrzése, sem az E9 `cfg.functions`/`cfg.clusters` 77 ellenőrzése nem tartalmaz olyan checket, amely a két bizonyítéknyomot külön zárná le; az E9 `cfg.functions | reached_ratio` check csak a belső konzisztenciát vizsgálja (`blocks_reached + blocks_linear_only == basic_blocks`), nem a bizonyítéknyomot.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E3 `blocks_reached` / `blocks_linear_only` / `reached_ratio` oszlopok, E8 `method.confidence_rules[4]`, E10 `proof_levels`).

**Korrekció a function-map használatához – kötelező olvasási szabály `[L]`:**

1. Az `adhesive` dokumentumcsillagban **egyetlen** elérhetőségi állítás sem értelmezheti a `cfg_functions.csv` `blocks_reached` oszlopát úgy, mint „a függvény futáskor biztosan ide jut”. A helyes olvasat: „a statikus rekurzív leszállás a belépési pontból elérte”.
2. Az E3 `reached_ratio` **soha nem** használható kizárólagos elérési bizonyítékként. Ha pozitív elérési állítás kell, a `blocks_reached` oszlop (és a `proof_levels` analógiája) az egyetlen használható forrás, **azzal a kikötéssel, hogy a rekurzív leszállás csak a feloldható közvetlen ágakat követi** (F-16: 86 559 közvetett ugrásból 85 727 feloldatlan).
3. A 232-es klaszternél (F-24) a `reached_ratio=0,919772` és a `func_index=116519`-nél a `0,000234` **ugyanannak a mérőszámnak** két szélső értéke; a különbség nem ad hoc függvény-egyéni viselkedés, hanem az, hogy az egyiknél a sweep által elért blokkok száma kicsi, a másiknál szinte az egész függvény.
4. A D-009 javítása három, a jelenlegi payloadban nem elérhető dolgot igényelne: (a) a `cfg_functions.csv` `proof_level` oszlopa minden blokkra (a E10 módszerének átvitele), (b) a `linear_only_blocks` család alatti tartomány-szintű újradekódolás az `redecode_max_size=0x10000` korlát megemelésével, (c) egy kereszt-fájl check, amely a `cfg_functions.indirect_jumps` és az `indirect_sites` jmp-helyszámát összeveti (F-31).
`BRef = [RVA:0x23A8AE0 | RAW:N/A | CONF:L | STATUS:INFERRED]` (E3 `func_index=116519`, E4 `cluster_id=232`).

---

## 13. Gate-eredmények

Négy önellenőrző réteg van, három zöld, egy vörös. A gate-ek egymástól függetlenek: az első három a saját payloadját ellenőrzi, a negyedik kereszt-audit.

### Gate A — `pdata_stats.json` önellenőrzés: **PASS** `[P]`
`check_count=37`, `failed_count=0`. A 37 check 8 csoportot érint: specimen-hash, rekord-szám/maradék/rendezettség/duplikátum/átfedés/üres-tartomány/`SizeOfImage`-on kívül, `UNWIND_INFO` null-cím/teljes egyediség/szekció/verzió/-mapping/fejérvény/tartomány, flag-eloszlás, handler-rekordok és szekciójuk, chain-rekordok és érvényesség, `.text`-rekordok, `covered + gaps` összeg, `baseline.*` mind a 13 mezőre.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E2 `validation`).

### Gate B — `unresolved_regions.json` önellenőrzés: **PASS** `[P]`
`check_count=116`, `failed_count=0`. A 116 check döntő része 105 `redecode.func_<index>_<rva>` check — minden olyan függvényre egy, ahol a `cfg_functions.csv` nem teljesen dekódolt volt, vagyis a 105 függvény mindegyike újradekódolva és egyeztetve. A felsorolt `redecode.*` nevek egy mintát követnek: a legkisebb `redecode.func_136474_0x2A9BCC0`, a legnagyobb `redecode.func_141024_0x2B9F030`; a négy `data_record` közül kettő explicit szerepel: `redecode.func_137107_0x2AB7680` és `redecode.func_138668_0x2B043C4`, valamint `redecode.func_139645_0x2B4D640`. A maradék check a `pinned.data_record_verdict` (egy `data_record` régió rögzített kezdetre) és a számszerű baseline-egyeztetések.
**Pin-megjegyzés `[P]`:** ez a Gate B a `2026-09-26 02:07:08`-i E8-revízión mérve érvényes. Az új payloadban is `check_count=116` / `failed_count=0` (116 `ok:true`, 0 `ok:false`), minden `inputs` pin egyezik a lemezzen, és az E8 fájl-digestje `b9b6498a…` → `0092fef1…` (a méret véletlenül változatlan, 12 253 941 bájt). A 116 check **nem** vizsgálja az `inputs.patch_cross_references` `rva_count = 35` mezőjét, ezért a Gate B PASS verdiktje és a patch-input `rva_count` nyitott eltérése nem zárja ki egymást – ld. 13.y.3.
`BRef = [RVA:0x2AB7680 | RAW:0x2AB6A80 | CONF:P | STATUS:OBSERVED]` (E8 `validation`, `inputs`, `checks[]`).

### Gate C — `audit_syscall_candidates.json` független audit: **PASS** `[P]`
`checks_run=31`, mind az öt verdict-boolean `true`: `ratios_reproduce`, `instruction_start_confirmed`, `anchors_in_subset`, `control_flow_claims_consistent`, `all_checks_passed`. A reprodukció során a független implementáció **0** eltérést talált a dokumentált határértékekben, `sweep_stopped_before_candidate=0`. A 9 dokumentált anklócsoport 64 egyedi helye mind a 3 627-es érvényes részhalmazban van, `missing_from_valid_subset=[]`; a második dekóder 549 tartományban 3 627/3 627 helyet erősített meg, 0 ellentmondással, 0 nem-`syscall` mnemonikával, 0 byte-directive-tal. A módszer egyben kimondja a határt: „a valid entry is a linear sweep verdict, and only the descent proven share of them is control flow proven”.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E10 `verdict`, `boundary_reproduction`, `documented_anchors`).

### Gate D — `audit_infra.json` független audit: **PASS, 0 hiba, mind a négy finding `closed`** `[P]`
`check_count=632`, `failed_count=0`, `verdict=pass`, `discrepancy_count=4`, `discrepancy_open_count=0`, `discrepancy_status={D-001: closed, D-002: closed, D-003: closed, D-004: closed}`. Mind a négy ellentmondásra `root_cause_closed=true`, és mind a négy `bounded.affects_decoded_counts=false`. A `failed_checks` lista **üres**. A 632 check csoport szerinti bontása:

| Csoport | Checkek | Hibák | Attribuált finding | Ok |
|---|---|---|---|---|
| `toolchain.scripts` | 136 | 0 | **D-002 lezárt** | a leltár 19 bejegyzése a lemezen 19 `*.py`-t fedi: `inventory_count` 19 = 19, `inventory_names` mind `true`, `entry_present[*]` mind `true`, `drifted_entries = {}` |
| `toolchain.package_versions` | 16 | 0 | **D-002 lezárt** | `imported_by_matches_the_audit_census`: a rögzített `capstone`-importer-lista és az audit saját `ast`-cenzusa is 13 tagú |
| `toolchain.digests` | 21 | 0 | **D-004 lezárt** | a `digest_attested[…]` checkek mind `true`; a hat korábban nem attestált CSV a `toolchain.json` `digests.entries` blokkjából kap igazolt forrást, `unattested = []` |
| `discrepancy.integrity` | **5** | 0 | – | az attribúció integritása, mind az öt check zöld |
| `xref.edges` | 33 | 0 | – | **D-003 lezárt**: a 39 `iat_jmp_thunk_stub` sor `thunk_stub_rows_covered_by_a_pdata_function` és `thunk_stub_hosting_thunk_function_agrees_with_indirect_sites` checkje is zöld |
| `indirect.sites` | 19 | 0 | – | **D-003 lezárt**: `thunk_stub_annotation_contradicted_by_own_function_columns` és `thunk_stub_interior_rows_recompute_from_their_own_annotation` is zöld |
| `toolchain.libraries` | 1 | 0 | – | **D-001 lezárt**: a lapos blokk a `package_versions` tengelyeihez képest konzisztens |
| `toolchain.inventory` | 9 | 0 | – | a `script_inventory` deklarációja önmagában konzisztens |
| `cfg.functions` | 19 | 0 | – | – |
| `cfg.clusters` | 58 | 0 | – | – |
| `pdata.csv` | 24 | 0 | – | – |
| `pdata.stats` | 52 | 0 | – | – |
| `csv.format` | 60 | 0 | – | a fejléc-ellenőrzés az új 22/28 oszlopos sémát is ismeri |
| `json.format` | 23 | 0 | – | – |
| `provenance` | 8 | 0 | – | a `digest_matches_recorded` checkek mind zöldek |
| `script.common` | 37 | 0 | – | – |
| `script.pdata_map` | 6 | 0 | – | – |
| `script.syscall_scan` | 3 | 0 | – | – |
| `script.xref_build` | 6 | 0 | – | a script deklarációja konzisztens |
| `specimen` | 68 | 0 | – | – |
| `syscall.candidates` | 27 | 0 | – | – |
| `toolchain.host` | 1 | 0 | – | – |
| **Összes** | **632** | **0** | – | – |

**A zéró hiba attribúciója `[P]`:** nincs hibás check, tehát nincs attribuálnivaló sem. A `discrepancy.integrity` csoport mind az öt checkje átment: a `register_holds_exactly_four_findings` check `expected=4`, `actual=4`; a `every_failing_check_is_attributed_to_an_open_discrepancy` és a `closed_discrepancies_have_no_failing_evidence_check` check **üres** listát ad, mert `failed_checks = []` és `discrepancy_open_count = 0`.

**A korábbi FAIL-ek sorsa `[P]`:** a 457 check / 21 hibás payload a **régi xref sémára** vonatkozott; a 616 check / 26 hibás payload pedig az E12 17 bejegyzéses, a producer-fa mögött maradt leltára. A jelenlegi audit **mindkettőt lezárta**: a 21 korábbi hiba mind lezárt findinghez tartozott (D-001 kettő, D-003 kettő, D-002 17), a 26 későbbi hiba pedig a D-002 leltára-driftjéből és a D-004 digest-hatóköréből jött. A mai payloadban egyik csoport sem ad hibát.

**A PASS értelmezése a function-map nézőpontjából `[P]`:** a Gate D `pass` verdictje azt mondja, hogy a function-map **mérőszámai és a producer-fa attestationja is** konzisztens. A `cfg.functions` 19, a `cfg.clusters` 58, a `pdata.csv` 24 és a `pdata.stats` 52 check – összesen 153, a function-map adatkörét adja – mind átment, és az xref/indirect réteg `xref.edges` 33 + `indirect.sites` 19 = **52** checkje is mind átment az új sémán. Ez **nem** cáfolja a F-01 és F-44 közötti egyetlen számot sem, hanem megerősíti, hogy egyik sincs hiba.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E9 `summary`, `summary.by_group`, `summary.discrepancy_status`, `discrepancies`).

**F-45 — A Gate D payloadja a bemenetei UTÁN keletkezett, és a FAIL `bounded residual` állapota is megszűnt. `[P]`**

| Artifact | Lemez-idő (helyi) | Mit tanúsít | Állapot a jelenlegi készleten |
|---|---|---|---|
| E12 `toolchain.json` | `01:43:44` | 19 producer-bejegyzés | **aktuális**: `entry_count 19`, `drifted_entries = {}`, minden `size`/`sha256`/`lf_line_count` egyezik a lemezzel (D-002 `closed`) |
| E5 `xref_edges.csv` | `00:57:47` | a 22 oszlopos xref-index | aktuális; a `csv.format` fejléc-check átmegy, a tartalom `fc744f61…` |
| E6 `indirect_sites.csv` | `00:57:48` | a 28 oszlopos indirect-index | aktuális; a `csv.format` fejléc-check és a D-003 checkjei is átmennek, a tartalom `21e0e1af…` |
| `xref_build.py` | `01:01:52` | az E5/E6/E9 írója | az E12 `scripts[]` **és** az E9 `provenance.digests` is a `cbb48bcc…` (102 838) lemezértéket rögzíti – a két pin már nincs divergens |
| E9 `audit_infra.py` | `01:43:39` | maga az audit | `sha256 ebf7f4f4…` (151 067 bájt) = az E9 `audit.script_sha256`, tehát a script önmagával konzisztens |
| E9 `audit_infra.json` | `01:45:21` | kereszt-audit, 632 check | **a legfiatalabb artifact**: minden inputja előtte keletkezett |

A korábbi **„érvénytelen gate" állítás törölve**, és a **bounded rezidális finding is lezárva**: a Gate D payloadja nem előntegyártott, a `verdict=pass` a jelenlegi készletre érvényes, és a `csv.format | header_matches_producer_declaration` check sem várható elhasalásra. A korábbi 26 pont mind a producer-fa attestationjára vonatkozott (`toolchain.scripts`, `toolchain.digests`, `toolchain.package_versions`), nem a function-map mérőszámaira; a mai payloadban ezek a csoportok is zöldek, a 20 D-002- és 6 D-004-hiba **nullára csökkent**. Két elem marad, mind `[P]`:

1. **A tartalom–író kapcsolat tanúsítása a payloadon kívül marad:** az E5/E6 fejléceiben továbbra sincs `producer` blokk, így az, hogy a `fc744f61…`/`21e0e1af…` tartalmat a `cbb48bcc…` író állította elő, az E12 `scripts[]` és az E9 `provenance.digests` mezőjéből tudható, nem magából az adatfájlból (F-01). Ez **nem** gate-alkalmatlanság és nem nyitott finding: a D-004 ma `closed`, `unattested = []`.
2. **A leltár pillanatnyi konzisztencia, nem invariant:** minden új vagy módosított producer ismét elavulttá teszi az E12-t, tehát a `D-002` a következő producer-változásnál ismét vizsgálandó. Ez a finding **jelenlegi** lezárását nem érinti.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E9 `summary`, `discrepancies[D-002]`, `discrepancies[D-004]`, E9 `provenance.digests`, E12 `script_inventory`; fájl-rendszer mtime-ek).

**Gate-mátrix összegzés `[P]`:**

| Gate | Payload | Checkek | Hibák | Verdikt | Érvényesség a jelenlegi készleten |
|---|---|---|---|---|---|
| A | E2 `pdata_stats.json` | 37 | 0 | PASS | **érvényes** (input változatlan) |
| B | E8 `unresolved_regions.json` | 116 | 0 | PASS | **érvényes** a `2026-09-26 02:07:08`-i revízión is: a 116/0 a új payloadban is, és minden `inputs` pin (`cfg_functions.csv` `041d2365…`, `pdata_functions.csv` `65ab914c…`, `patch_mechanisms_1e270.csv` `ffc2234d…`, `patch_mechanisms_helpers.csv` `49cb7ee8…`) egyezik a lemezzen; a `csv` blokk `row_count=146005` / `column_count=37` értéke az E7 `6e5d9430…` pinjéhez illeszkedik. A `rva_count = 35` mező nem reprodukálható, de a Gate B ezt nem vizsgálja (ld. 13.y.3) |
| C | E10 `audit_syscall_candidates.json` | 31 | 0 | PASS | **érvényes** (input változatlan) |
| D | E9 `audit_infra.json` | 632 | 0 | **PASS** – mind a négy finding `closed` (`root_cause_closed=true`), `discrepancy_open_count = 0` | **érvényes** (a payload a bemenetei után keletkezett); `failed_checks = []`, `discrepancy.integrity` 5/5 zöld |
| – | 12. fejezet D-009 | 0 | 1 | **OPEN** | a payload nem vizsgálja |
| **Összes** | – | **816** | **0** | – | a D-002 és a D-004 rezidális része megszűnt, így a Gate D 26 hibája helyett 0 számít |

---

## 14. Nyitott kérdések

A sorrend a módszertani hatás, nem a kockázat szerinti rangsor. Minden pont a 7. fejezet korlátját hordozza, hacsak nincs külön jelölve.

1. **A `boundary_cross` 1 652 régiója / 20,8 MB `[U]`.** A `range_end` blokkok (7 606 db) valódi, a rekordhatáron átnyúló utasításfolyamot jelölnek, vagy a sweep olyan határra vetődik, ahol valójában másik funkció kezdődik? A 20 789 037 bájt a `.text` 45,1 %-a; a legnagyobb LOW-confidence példány az `UR-000002` (F-35). Nyitott marad, hogy a határon átnyúló rész az eredeti funkcióhoz, a szomszédos funkcióhoz, vagy egy nem a `.pdata`-ben regisztrált kódhoz tartozik. `BRef = [RVA:0x87F3A0 | RAW:0x87E7A0 | CONF:U | STATUS:OPEN]`.
2. **A `pdata_gap` 106 049 `body` régiója / 8,86 MB `[U]`.** A 137 105 hézatrégió 77,35 %-a nem `INT3`/`NOP`/`0x00` kitöltés, hanem `body`: a 96 436 darab 16–255 bájtos hézag (F-10) igen nagy része ebbe esik. Statikusan nem dönthető el, hogy ezek (a) valóban adott függvényekhez tartozó, a `.pdata`-ből kimaradt kód, (b) linker-generált thunk-/stub-terület, vagy (c) a szomszédos függvények által csak `jmp`-pel elért, de külön rekordot nem kapott belépési pont jellegű kód. `BRef = [RVA:0x1134F00 | RAW:0x1134300 | CONF:U | STATUS:OPEN]`.
3. **A 85 727 feloldatlan közvetett ugrás célja `[U]`.** A `jmp reg` / `jmp [mem]` célok 99,067 %-a ismeretlen. A `virtual_tail` 230 hely és a `data` 10 308 írási hely azt jelzi, hogy a célok többsége futásidejű kép- és objektumfüggő; statikus hozzárendelések nem vannak. `BRef = [RVA:N/A | RAW:N/A | CONF:U | STATUS:OPEN]`.
4. **A 658 elutasított jump-table közül 655 `NO_BOUND` `[U]`.** A `UNWIND_INFO`-ból vagy a `.pdata`-ból nem vezethető le az index felső korlátja; a 4 286 validált `switch_cases` a 174 elfogadott helyre jut. A `UR-000002` 12 elutasított helye sem zárul, pedig a függvény 203 106 bájt és 32 `syscall`-hely. `BRef = [RVA:0x87F3A0 | RAW:0x87E7A0 | CONF:U | STATUS:OPEN]`.
5. **A 1 100 `invalid` terminátor és a 7 478 `trap` `[L]`.** A 7 049 `ud2` és 410 `int3` hely nagyrészt ismert MSVC-mintázat (`__fastfail`, kivétel-kiugrás, patch-riasztó). A 23 `trap` hely (`ud2`/`int1`/vektoros kivétel) a 7 478 `trap` terminátorral együtt kontextusra szorul. Nyitott, hogy a `trap_sites=23` (`syscall_sites=3627` mellett) mennyiben különbözik a számlált hardver-kivétel-utasításoktól. `BRef = [RVA:N/A | RAW:N/A | CONF:L | STATUS:OPEN]`.
6. **A 4 `data_record` eredete és életbelépési esélye `[U]`** (F-44). Nyitott, hogy egyetlen `CHAININFO`-láncú adattábláról van szó, amelyet négy rekord ír le, vagy négy különálló tábláról, amelyek véletlenül egy láncba kerültek; és hogy bármelyik tartományba statikalian esik-e futásidejű vezérlési átmenet. `BRef = [RVA:0x2AB7680 | RAW:0x2AB6A80 | CONF:U | STATUS:OPEN]`.
7. **A 2 804 handler-rekord 32 célja `[L]`.** A `0x2BEDE10` célra 2 301 rekord mutat (82,06 %). Statikusan nem különíthető el, hogy ez közös kivétel-tisztító rutin, `__scrt_unhandled_exception`-hasonló diszpécser, vagy a linker által generált közös unwind-sablon. `BRef = [RVA:0x2BEDE10 | RAW:N/A | CONF:L | STATUS:OPEN]`.
8. **A 3 anomális `chained_range_above_record_begin` `[L]`.** A `CHAININFO` által mutatott `RUNTIME_FUNCTION` 3 esetben a saját rekord kezdőcíménél magasabb RVA-ról indul. Ez konzisztens a `CHAININFO` szemantikájával, de nincs független megerősítés. `BRef = [RVA:0x2AC7AA3 | RAW:N/A | CONF:L | STATUS:OPEN]`.
9. **A 136 390 nem a 232-es klaszterbe tartozó függvény anklómentessége `[L]`.** A 11 anklófüggvény mind a 13., 24., 85., 92. és 167. klaszterben van; a 232-es klaszterben egyetlen `DOC_ANCHOR` sincs, noha ott az összes 2 163 `CHAININFO` rekord, az összes 105 nem dekódolt függvény és a PE entry point található. Vagyis a belépési pont és minden `CHAININFO`/`UNDECODED` rekord együtt van, de egyik dokumentált ankló sem. Ez elvárt lehet (a dokumentált helyek más alrendszerekben vannak), de a function-map nem ad hozzájuk mérőszámot. `BRef = [RVA:N/A | RAW:N/A | CONF:L | STATUS:OPEN]`.
10. **A 275 indirect-jump eltérés és a D-009 payload-javítása `[U]`** (F-31, D-009). Mindkettő a jelenlegi payloadban nincs lezárva. `BRef = [RVA:N/A | RAW:N/A | CONF:U | STATUS:OPEN]`.
11. **A producer-fa attestation leletbizonyossága `[L]`** (F-01, F-45, D-002, D-004). Az E9 `audit_infra.json` (`01:45:21`) a beminetei **után** keletkezett, tehát a Gate D verdictje érvényes, a 632 check **0 hibával, `pass` verdikttel** zár. A korábbi 26 attribuált hiba megszűnt: az E12 `toolchain.json` producer-leltára 19 bejegyzésre fedi a lemezen lévő 19 `*.py`-t (`drifted_entries = {}`), és a `digests` blokk már a hat korábban nem attestált CSV-re is rögzített digestet ad, `unattested = []`. **Megmarad:** az E5/E6 payloadon belüli `producer` blokk továbbra sincs, ezért a tartalom és az írója kapcsolata külső tanúsításra marad; és az E12 leltár csak pillanatnyi konzisztencia, ezért a következő producer-változásnál a `D-002`-t újra kell vizsgálni. `BRef = [RVA:N/A | RAW:N/A | CONF:L | STATUS:OPEN]`.
12. **Az E8 `inputs.patch_cross_references` elavult `rva_count` mezője `[L]`** (F-37, ld. 13.y/3). Az E8-ben rögzített **`patch_mechanisms_1e270.csv` SHA-256 és fájlméret már egyezik a lemezzel** (`ffc2234d…` / 14 895 bájt), tehát a korábban jelzett digest-eltérés lezárult; a `patch_mechanisms_helpers.csv` pinje (`49cb7ee8…` / 81 295 bájt) végig egyezett. **Nyitva:** az E8 `rva_count` mezője `35`, míg a jelenlegi CSV 50 adatsorából **21** nemüres `site_rva` érték származik, tehát a `35` a jelenlegi revízióval nem reprodukálható. A `patch` forrásszabály definíció szerint a CSV `site_rva` oszlopán fut, ezért a `P2` **15**-tagú `priority.patch.regions` száma nem származhat a `35`-ös mezőből; a számszerű `rva_count` és a `priority.patch` forrásszáma között a payload nem deklarál kapcsolatot. Statikusan nem dönthető el, hogy a `35` egy régebbi CSV-revízió 50-soros darabszámának gyöke, vagy egy másik számlálási szabály eredménye, és hogy a `P2` 15 régiója a 21, a 35 vagy egy harmadik halmazból származik. `affects_decoded_counts = false`. `BRef = [RVA:N/A | RAW:N/A | CONF:L | STATUS:OPEN]`.

---

## 15. Reprodukálhatóság és determinizmus

**A payloadok közös determinizmus-deklarációja `[P]`:**

| Tulajdonság | Érték |
|---|---|
| Kódolás | `utf-8`, `bom=false` minden CSV és JSON esetén (E9 `files.*.bom` mind `false`) |
| Sorvég | `\n` (LF), `crlf=0`, `cr=0` (E9 `reverse/scripts/common.py`, a `json.format` 23 és `csv.format` 60 checkje) |
| Záró sortörés | `true` |
| JSON `indent` / `ensure_ascii` / `sort_keys` / `allow_nan` | `2` / `false` / `false` / `false` |
| Lebegőpontos kerekítés | 6 tizedes (`ratio_digits=6`), kivétel a `reached_ratio` |
| Időbélyeg a payloadban | nincs (`payload_timestamps=false`) |
| Host-útvonal a payloadban | nincs (`payload_host_paths=false`; E12 kivétel, lásd lent) |
| Halmaziteráció | minden halmaz rendezve kerül a payloadba |
| Sorszám | a `region_id` a `priority`-címke, majd család, majd `begin_rva`, `end_rva`, `reason` szerinti sorrend 1-alapú sorszáma |
| Script-leltár `omitted` mezői | `atime`, `ctime`, `mtime` – „filesystem timestamps are host state rather than evidence" (E12 `script_inventory.omitted_reason`) |

**A host-függőség egyetlen dokumentált kivétele `[P]`:** az E9 `json.format | no_host_dependence` check a `toolchain.json`-ra **nem** fut, mert az `E12` szándékosan tartalmaz `module_path` mezőket (`C:\Users\Admin\AppData\Local\Programs\Python\Python314\Lib\site-packages\…`) és az objdump abszolút útvonalát. Az E10 szintén rögzít egy host-útvonalat (`second_decoder.path`). A function-map számértékei (`pdata_stats`, `cfg_functions`, `cfg_clusters`, `xref_edges`, `indirect_sites`, `unresolved_regions`) egyikét sem érinti.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E9 `audit.determinism`, E12 `libraries.*.module_path`, E10 `producer.second_decoder.path`).

**A jelen dokumentum reprodukálhatósága `[P]`:** minden szám a fenti 12 fájl egyikéből származik, és mindegyikhez hash + azonosító-sorszám hivatkozás tartozik. Ahol a jelen dokumentum **saját** számítást végzett (például a `reached_ratio`-megoszlás, a 233 klaszter 15 legnagyobbja, a 355 thunk-annotáció felosztása, a 39 D-003 `target_thunk_function_index` sor, a 10 452 modul-feloldott él és a top-15 aránya, a 24 `direct_branch_targets_inside_another_instruction` cím, a 44 >100 000 bájtos rekord, a 17 script-leltár-egyezés), az a forrásfájl `sha256` rögzített értékéhez kötött; a számítás reprodukálható a fájl újraolvasásával. **Semmit nem állítottunk a specimen futtatásából.**

**Konkurens regenerálás `[P]`:** az E5, az E6, az E12 és az E9 artifactok, valamint az `xref_build.py`, a `refresh_toolchain.py` és az `audit_infra.py` a vizsgálat ideje alatt változtak, és a vizsgálat végén új producer-script(ek) is megjelentek. A dokumentum `2026-09-26 01:45:21`-i állapotot pineli le az 1. fejezet snapshot-pin megjegyzésének megfelelően; a `.pdata`/CFG/unresolved rétegek változatlanok voltak, tehát a 3–6., 8., 10. és 11. fejezet minden száma stabil. Aki a dokumentumot újraellenőrzi, annak **először** az E1–E12 hashét kell ellenőriznie a fenti táblázat szerint. Fontos különbség: az **adatfájlok** (E1–E8, E10–E12) stabil pinnek alkalmasak, mert tartalmukhoz tartozik egy ellenőrizhető `sha256`; a **producer-script `xref_build.py`** a saját payloadján belül nem pinelt, mert az E5/E6 fejléceiben nincs `producer` blokk – a jelenlegi revízió digestjét (`cbb48bcc…`, 102 838 bájt) az E12 `scripts[]` és az E9 `provenance.digests` is rögzíti, tehát a tartalom reprodukálható, de a kötés külső (F-01). A `pdata`/`cfg`/`unresolved` blokk számai csak a fenti E1–E4, E7, E8, E11 hash-pal vihetők át változtatás nélkül.

**Az E8 későbbi revíziója a reprodukálhatósági határon `[P]`:** a fenti bekezdés a `2026-09-26 01:45:21`-i állapotot írja le, az `unresolved_regions.json` és az `unresolved_regions.csv` azonban `02:07:07`–`02:07:08` között újragenerálódott. A mért hatás: az **E7 `6e5d9430…` / 57 583 948 pinje változatlan**, tehát a teljes region-tábla és a 10. fejezet minden száma stabil; az **E8 `0092fef1…` / 12 253 941 pinre cserélődött**, és az új revízióban a dokumentumban idézett `totals`, `families`, `priority`, `pdata_gap_content`, `counters` értékek, a 116 check / 0 hiba és a 9 900 beágyazott régió mind változatlanok, tehát a Gate B verdiktje és a 3–6., 8., 10., 11. fejezet minden száma érvényes marad. A **tartalmi** különbség az `inputs.patch_cross_references` pinjében van, ahol az új E8 a `patch_mechanisms_1e270.csv` `ffc2234d…` / 14 895 bájt értékét rögzíti, egyezve a lemezzel. Az E8-be nem íródott vissza payload-időbélyeg (`payload_timestamps=false`), ezért ezt az új revíziót **külső** fájlrendszer-idővel (`02:07:08`) lehet csak tanúsítani – az E8-en belül nincs önálló revíziójelző, ugyanaz a korlát, mint amit az F-01 az E5/E6 `producer` blokkja esetén rögzít. Részletek: 13.y.1/1–3 és 13.y.3.

**Specimen `[P]`:** `reverse/adhesive.dll`, `53 575 264` bájt, `sha256 91cc0aa006d7315cb042c8fa8dca6c1e074a307bba7dcc9eb5509c8a7b81934e`, `image_base 0x180000000`, `size_of_image 0x331E000`. Az E2, E8, E9, E10 mind a `specimen.sha256_matches_baseline` ellenőrzést `true`-val zárja, tehát mindegyik ugyanazt a bájtsorozzatot elemezte.

---

## 16. Dokumentum-metaadatok

- **Dokumentum:** `reverse/adhesive-13-pdata-function-map-cfg.md`
- **Kódolás:** UTF-8 BOM nélkül, LF sortörés, magyar nyelv
- **Scope:** statikus, fájlos; nincs DLL-betöltés, futtatás, patch, bypass vagy exploit
- **Hivatkozott evidence:** E1–E12 az 1. fejezet táblázata szerint, hash-pinnel
- **Finding-azonosítók:** F-01 … F-45
- **Eltérés-azonosítók:** D-001 `closed`, D-002 `closed`, D-003 `closed` és D-004 `closed` (mind az E9-ben, `root_cause_closed=true`, `affects_decoded_counts=false`, `discrepancy_open_count = 0`); D-009 (ebben a dokumentumban rögzítve, nyitott)
- **Gate-ek:** A (E2, 37 check, 0 hiba, PASS, érvényes), B (E8, 116 check, 0 hiba, PASS, érvényes), C (E10, 31 check, 0 hiba, PASS, érvényes), D (E9, 632 check, **0 hiba**, **PASS**, **érvényes**; `failed_checks = []`, mind a négy finding `closed`, `discrepancy.integrity` 5/5 zöld)
- **A specimen vizsgálatának dátuma:** 2026-09-26; a specimen fájl-módosítási ideje `2026-09-13T14:17:25Z`, ami metadata, nem build-idő
- **Következő felülvizsgálat:** az E5/E6/E12 bármely újragenerálásakor, illetve az `audit_infra.py` újrafuttatásakor
- **Utolsó pin-korrekció:** a `13.y Pin- és prioritás-javítás` blokk (E8 `b9b6498a…` → `0092fef1…`; a 17.3/A patch-input megjegyzés; az F-32/F-37 prioritás-rekonsziliáció). Az E8 `2026-09-26 02:07:08`-i revíziója óta a Gate B verdiktje érvényes, a 14. fejezet nyitott kérdéseinek száma 11-ről **12**-re nőtt.

---

## 17. Hash- és arány-újraellenőzés (független kereszt-audit, 2026-09-26 01:45:59)

> **Scope:** kizárólag állomány- és mezőolvasás a `reverse/evidence/` készletén és a `reverse/scripts/` leltárán. A DLL-t nem futtattam, nem töltöttem be, nem mappeltem, nem patcheltem; új evidence-fájl nem készült, és a `reverse/scripts/` és `reverse/evidence/` állományához nem nyultam. A mérés kizárólag a `pdata_functions.csv`, `cfg_functions.csv`, `cfg_clusters.csv`, `xref_edges.csv`, `indirect_sites.csv`, `unresolved_regions.csv` oszlop- és sorszám-üszámlása által reprodukálható.

### 17.1 Ellenőrzösi mátrix

| # | Ellenőrzött tétel | Forrás | Eredmény | Állapot |
|---:|---|---|---|---|
| 1 | E1 `pdata_functions.csv` sha256 + méret + 43 oszlop + 142 004 sor | lemez | `65ab914c…` / 29 634 365 / 43 / 142 004 | **egyezik** |
| 2 | E2 `pdata_stats.json` sha256 + méret + 37 check / 0 hiba | lemez | `df1e6ff4…` / 18 329 / 37 / 0 | **egyezik** |
| 3 | E3 `cfg_functions.csv` sha256 + méret + 80 oszlop + 142 004 sor | lemez | `041d2365…` / 40 180 030 / 80 / 142 004 | **egyezik** |
| 4 | E4 `cfg_clusters.csv` sha256 + méret + 65 oszlop + 233 sor | lemez | `7d90d02c…` / 127 104 / 65 / 233 | **egyezik** |
| 5 | E5 `xref_edges.csv` sha256 + méret + 22 oszlop + 57 101 sor | lemez | `fc744f61…` / 11 126 183 / 22 / 57 101 | **egyezik** |
| 6 | E6 `indirect_sites.csv` sha256 + méret + 28 oszlop + 157 153 sor | lemez | `21e0e1af…` / 27 390 456 / 28 / 157 153 | **egyezik** |
| 7 | E7 `unresolved_regions.csv` sha256 + méret + 37 oszlop + 146 005 sor | lemez | `6e5d9430…` / 57 583 948 / 37 / 146 005 | **egyezik** |
| 8 | E8 `unresolved_regions.json` sha256 + méret + 116 check / 0 hiba | lemez | `0092fef1…` / 12 253 941 / 116 / 0 | **javítva** (a kereszt-audit `b9b6498a…` pinje helyett a jelenlegi lemezi érték; ld. 13.y/1) |
| 9 | E9 `audit_infra.json` sha256 + méret | lemez | `251b79e7…` / 170 001 | **javítva** (a `2026-09-26` záró pin-konformancia-javításban: 169 558 / `97134043…`; a még régebbi érték 170 951 / `12386a54…`) |
| 10 | E10 `audit_syscall_candidates.json` sha256 + méret + 31 check | lemez | `e8cd41f2…` / 1 765 141 / 31 | **egyezik** |
| 11 | E11 `baseline.json` sha256 + méret | lemez | `dc34cb50…` / 36 512 | **egyezik** |
| 12 | E12 `toolchain.json` sha256 + méret + bejegyzészám | lemez | `72a1eed0…` / 27 150 / 19 | **javítva** (a `2026-09-26` záró pin-konformancia-javításban: 26 638 / `6f3dd634…`; a még régebbi érték 24 107 / `9a3a4d3a…` / 17) |
| 13 | Specimen sha256 + méret | lemez | `91cc0aa0…` / 53 575 264 | **egyezik** |
| 14 | `pdata_map.py` / `cfg_build.py` / `unresolved_regions.py` / `common.py` / `audit_syscall_candidates.py` digest | lemez | mind az 5 egyezik a dokumentumban rögzítettel | **egyezik** |
| 15 | `xref_build.py` digest a lemezen | lemez | `cbb48bcc…` / 102 838 | **egyezik** |
| 16 | `audit_infra.py` digest + méret | lemez | `ebf7f4f4…` / 151 067 | **javítva** (régebbi: `01c11061…` / 143 167) |
| 17 | `refresh_toolchain.py` digest + méret | lemez | `7cfda978…` / 29 120 | **javítva** (korábbi értékek: `d1643be4…`, majd `91aa2212…`) |
| 18 | **Coverage** – `covered_bytes` ÷ `span_bytes` | E2 `text_coverage` és E1 `code_size`/`gap_before` összeg | 37 200 748 ÷ 46 060 693 = **80,764629 %**; 37 200 748 + 8 859 945 = 46 060 693, az identitás zárul | **egyezik** |
| 19 | Coverage virtuális méret szerinti arány | E2 `coverage_of_virtual_size_percent` | 80,764573 % (37 200 748 ÷ 46 060 725) | **egyezik** |
| 20 | `span_bytes` definíciója | E1 első `begin_address` = `0x1020`, utolsó `end_address` = `0x2BEE4B5` | 0x2BEE4B5 − 0x1020 = 46 060 693 = `0x2BED495` | **egyezik** |
| 21 | `leading_gap` / `trailing_gap` | E1 `gap_before[0]` = 0; E2 `text_coverage` | 32 (`0x1020` − `0x1000`) / 331 (`0x2BEE600` − `0x2BEE4B5`) | **egyezik** |
| 22 | **Flag-megoszlás** rekordonként | E1 `unwind_flags` × 142 004 | `0`:137 037, `1`:65, `2`:45, `3`:2 694, `4`:2 163 | **egyezik** |
| 23 | **Flag-megoszlás** egyedi `UNWIND_INFO`-nként | E1 `unwind_info_address` × 15 533 | `0`:10 725, `1`:65, `2`:45, `3`:2 654, `4`:2 044 | **egyezik** |
| 24 | Flag-nev szerinti bontás (rekord / egyedi) | E1 `unwind_flag_names` | `EHANDLER` 2 759/2 719, `UHANDLER` 2 739/2 699, `CHAININFO` 2 163/2 044 | **egyezik** |
| 25 | Referencia-kontraszt: 2 694−2 654 = 40, 2 163−2 044 = 119 | E1 `unwind_reference_count > 1`: **126 986** rekord | 40 ≤ 126 986, tehát a megállapítás konzisztens | **egyezik** |
| 26 | Hézag-szám és hisztogram | E1 `gap_before > 0` szám; E2 `gaps.histogram` | 137 103 hézag; `0x1`:2 542, `0x2..0xF`:37 083, `0x10..0xFF`:96 436, `0x100..0xFFF`:810, `0x1000..0xFFFF`:229, `0x10000..0xFFFFF`:3, `0x1000000+`:0 | **egyezik** |
| 27 | `basic_blocks` / `blocks_reached` / `blocks_linear_only` összeg | E3 oszlopösszeg | 1 117 811 / 503 338 / **614 473**; 503 338 + 614 473 = 1 117 811 zárul | **egyezik** |
| 28 | **614 473 sweep-only arány** | 614 473 ÷ 1 117 811 | **54,971 %**; a `functions_with_linear_blocks` összeg 1 524 | **egyezik** |
| 29 | `blocks_reached` arány | 503 338 ÷ 1 117 811 | **45,03 %** | **egyezik** |
| 30 | **`reached_ratio` megoszlása** | E3 `reached_ratio` × 142 004 | `=1.0`:140 480, `[0.9,1)`:123, `[0.5,0.9)`:227, `[0.05,0.5)`:542, `[0,0.05)`:631, `=0.0`:**1**; átlag **0,991822** | **egyezik** |
| 31 | `reached_ratio` a 10 legrosszabb `linear_only` függvényre | E3 `func_index` | mind a 10 `func_index` + CSV sorpár, `basic_blocks`, `blocks_linear_only` és `reached_ratio` egyezik, **kivéve a 4. sort** | **javítva** (lásd 17.2/1) |
| 32 | Terminátor- és kilépési mátrix | E3 `term_*` / `exit_*` összeg | `call`746 480, `jmp_direct`32 195, `jmp_indirect`86 509, `jcc`118 403, `return`118 040, `trap`7 478, `invalid`1 100, `range_end`7 606; `exit_switch`174; 86 509 − 86 335 = 174 | **egyezik** |
| 33 | Jump-tábla-klasszifikáció | E3 `switch_*` összeg, `switch_reject_reasons` | 832 = 174 validált + 658 elutasított; 4 286 case; `NO_BOUND`655, `TOO_FEW_DISTINCT_TARGETS`2, `TARGET_OUT_OF_FUNCTION`1 | **egyezik** |
| 34 | Közvetett ugrások | E3 `indirect_jumps` összeg | 86 559 ÷ 86 559, ebből 85 727 feloldatlan, 832 oldott (= `switch_sites`) | **egyezik** |
| 35 | E5 kategória- és `dst_kind` mátrix | E5 57 101 sor | `direct_call`37 969, `vtable`7 046, `thunk`6 691, `iat`3 761, `global_fnptr`1 608, `direct_jmp`26; 51 523 `code` / 3 487 `iat_slot` / 1 462 `fnptr_slot` / 629 `external`; 8 176 üres forrástulajdonosság | **egyezik** |
| 36 | E5 `relation` marginal, modul-feloldott élek | E5 | 10 `relation` érték, összeg 57 101; 10 452 modul-feloldott él, 629 egyedi szimbólum | **egyezik** |
| 37 | E6 `kind` / `target_kind` / `operand_kind` / `source` marginal | E6 157 153 sor | mind a 9 `kind` és mind a 9 `target_kind` érték egyezik; `pdata_decode`156 782 + `raw_scan`371; üres `code_instruction_function_index` = **371** = `raw_scan` | **egyezik** |
| 38 | E6 annotációdarab és különfélekból kategóriák | E6 `annotation` | **94** egyedi annotáció, 0 üres; 316 `outside_every_pdata_runtime_function` + 39 `interior_byte_of_a_decoded_jmp` | **egyezik** |
| 39 | E4 klaszter- és függvény aggregátumok | E4 233 sor | 233 kontiguus 1-alapú klaszter; `function_count` összeg **142 004**; 4 egyfüggvényes; 174 darab >100 függvényes; `rva_span` összeg 43 003 998; `anchor_count` összeg 1 214 | **egyezik** |
| 40 | Cluster 232 összesen állítás | E4 `cluster_id=232` | `0x2A97E50`–`0x2BED36D`, 5 614 függvény, 80 383 blokk, 1 314 462 bájt, `entry_point_inside=true`, `unwind_chaininfo=2 163`, `undecoded_bytes=1 096`, `blocks_linear_only` 6 449 = 80 383 − 73 934, `reached_ratio` 0,919772 | **egyezik** |
| 41 | E4 anchor-tábla 18 típusa | E4 `anchor_tags` | a 18 típus mindegyike egyezik az F-25 táblázatával | **egyezik** |
| 42 | E8 `totals` / `families` / `priority` / `pdata_gap_content` / `counters` | E8 | 146 005 régió / 59 839 466 bájt; mind a 7 család, mind az 5 prioritásszint és a gap-tartalom-mátrix egyezik; 9 900 beágyazott régió | **egyezik** |
| 43 | E8 `families.pdata_gap` → `counters` → F-11/F-38 képlés | E8 | `int3_pad`30 579 + `nop_pad`477 = 31 056 = `benign_padding`; `body`106 049 = `unresolved`; 8 859 945 + 32 + 331 = 8 860 308 = `families.pdata_gap.bytes` | **egyezik** |
| 44 | E7 `region_id` kontiguitás, `UR-000002` / `UR-009889` / `UR-146005` sorszám | E7 146 005 sor | `UR-000001`…`UR-146005` számozás folytonos; CSV sor = `region_id` sorszám + 1 (3 / 9 890 / 146 006) | **egyezik** |
| 45 | A 4 `data_record` teljes mátrixa | E7/E8 `UR-001622`–`UR-001625` | mind a 4 tartomány, `size` (435/36/72/62, összesen 605), `raw`, `dword_rva_ratio`, `small_byte_ratio`, `linear_ratio`, `reached_ratio`, `decoded/undecoded` (591/14), `jcc` 6/3/1/1, `invalid` 2/3/1/11 egyezik | **egyezik** |
| 46 | E3 `doc_anchors` 11 sor és CSV-sorszáma | E3 `doc_anchors` oszlop | mind a 11 `func_index`, `cluster_id` és anchor-szöveg egyezik; a CSV-sorszám mindegyike 1-gyel nagyobb volt | **javítva** (lásd 17.2/2) |
| 47 | **Gate D státusza összevetése az `audit_infra.json` 616/26 értékével** | E9 `summary` | a közlem **állítása** 616 check / 26 hiba / `verdict=fail` / `D-002 bounded_open`, a lemezen **632 check / 0 hiba / `verdict=pass` / mind a négy `closed`** | **javítva** (lásd 17.2/3) |
| 48 | E12 leltár — lemezi producer-digest üszehasonlítás | E12 `scripts[]` vs lemez | 19/19 bejegyzés, mind a 19 `size`+`sha256`+`lf_line_count` egyezik | **egyezik** (a korábbi 17/19 állítás javítva) |
| 49 | E9 `provenance.digests_not_recorded` lista | E9 | 7 fájl: `toolchain.json`, `pdata_stats.json`, `cfg_functions.csv`, `cfg_clusters.csv`, `xref_edges.csv`, `indirect_sites.csv`, `syscall_candidates_raw.csv` | **egyezik** (az F-01 mondata változatlan) |
| 50 | E9 `audit.script_sha256` összevetése a lemezen lévő `audit_infra.py`-val | E9 `audit` vs lemez | `ebf7f4f4…` = lemez, 151 067 bájt | **egyezik** |
| 51 | E9 `files["reverse/evidence/toolchain.json"]` összevetése a lemezen lévő E12-vel | E9 `files` vs lemez | `72a1eed0…` / 27 150 = lemez | **egyezik** (a `2026-09-26` záró pin-konformancia-javításban frissítve) |
| 52 | E9 `by_group` összegzés | E9 `summary.by_group` | 22 csoport × összeg = **632** = `check_count` | **egyezik** |
| 53 | Következő válasz: E8 `inputs.patch_cross_references` digest | E8 `inputs` vs lemez | az E8 `patch_mechanisms_1e270.csv`-ra `ffc2234d…`-ot rögzít (14 895 B) = a lemez; **a `rva_count` `35` viszont a 21 nemüres `site_rva`-val nem reprodukálható** | **részben javítva** (digest-eltérés lezárult; a `rva_count` eltérése nyitott, lásd 17.3/A és 13.y/3) |

### 17.2 Eltérések — javított, minimális diff

**1. F-20 – a tíz legrosszabb `linear_only` függvény 4. sora**

- **Eltérés:** a `func_index = 9 409` (`0x25D450`–`0x2F21C7`, CSV 9 411. sor) sor `basic_blocks = 18 653` és `blocks_linear_only = 18 648` értékért. A `cfg_functions.csv` jelenlegi `func_index = 9 409` sora `basic_blocks = 16 253`, `blocks_reached = 5`, `blocks_linear_only = 16 248`.
- **Bizonyíték, hogy a dokumentum értéke hibás:** a dokumentum saját `reached_ratio = 0,000308` értéke csak az új értékekkel zárul: 5 / 16 253 = 0,000308, míg 5 / 18 653 = 0,000268. Az `18 653` / `18 648` pár a `0x2F2970` (`func_index = 9 426`) anklófüggvényhez sem tartozik – az 5 907 blokk és 6 elért blokk. A régi sor emellett megszúkította a `blocks_linear_only` monoton csökkenését (18 648 > 12 930).
- **Ój érték:** `18 653` → **16 253** és `18 648` → **16 248**. A `func_index`, a CSV-sorszám, a tartomány és a `reached_ratio` változatlan.
- **Forrásfájl:** `reverse/evidence/cfg_functions.csv`, `func_index = 9 409` (CSV 9 411. sor).
- **Confidence: `P`** (OBSERVED — a közvetlen oszlopérték; a dokumentum `reached_ratio`-jának belső konzisztenciája is ezt igazolja).

**2. F-18 – a `doc_anchors` táblázat 11 CSV-sorszáma**

- **Eltérés:** mind a 11 `CSV-sorszám` 1-gyel nagyobb volt a ténylegesnél (`464` vs `463`, `39 976` vs `39 975`, `72 103` vs `72 102`, stb.). A `func_index`, a `cluster_id` és a `doc_anchors` szöveg minden sorban helyes volt.
- **Ok:** a `cfg_functions.csv` `func_index` oszlopa 0-alapú (0…142 003), és a fájl fejlécét tartalmaz, tehát `CSV sor = func_index + 2`. A dokumentum F-13, F-19, F-40 és a 7. fejezet táblázatai ehhez a szabályhoz tartanak; csak az F-18 táblázata tért `func_index + 3`-at.
- **Ój érték:** mind a 11 szám `func_index + 2`-re javítva.
- **Forrásfájl:** `reverse/evidence/cfg_functions.csv`, `doc_anchors` és `func_index` oszlop.
- **Confidence: `P`** (OBSERVED — mind a 11 sor összevetett).

**3. E9 `audit_infra.json` — Gate D, D-002, D-004, producer-leltár**

- **Eltérés:** a dokumentum `170 951` bájt / `12386a54dee40ab8ced8f6231006daa44864f9bbd25fb589c8d08cb6e18ab58f` értéket, `616` check / `26` hiba / `verdict=fail` verdiktet, `discrepancy_open_count=2`-t, `D-002 bounded_open` és `D-004 bounded_open` státuszokat, valamint a 20 D-002 + 6 D-004 hibamegoszlást rögzítette. A jelenlegi `audit_infra.json`: **170 001** bájt, `251b79e722620af61824b793ced1ade1ffe9b375608a429e109880aaa8b8b1dc`, `check_count=632`, `failed_count=0`, `verdict=pass`, `discrepancy_open_count=0`, `discrepancy_status={D-001: closed, D-002: closed, D-003: closed, D-004: closed}`, `failed_checks=[]`. (Közbeeső érték: `169 558` bájt / `97134043e684931b9b8cb1e12c75d4c1f9b7ee0e2681bd9ee41e811137c6ce02`; a méret- és digest-pin a `2026-09-26` záró konformancia-javításban frissült erre.)
- **Csoportbontás változás:** `toolchain.scripts` 124 → **136** check (19 → **0** hiba); `toolchain.package_versions` 16 check, 1 → **0** hiba; `toolchain.digests` 17 → **21** check (6 → **0** hiba). A 20 öd ás által csoport hibaszáma változatlanul 0.
- **Ój érték:** az 1. fejezeti E9-sor; a 12. fejezet nyitó korrekció-státusza; a D-002 alfejezet címe, a korábbi érték, az 5 soros reziduals-táblázat és a következtetés; a D-002 függvény-lánca; a 13. fejezet Gate D címe, a 22 soros csoporttáblázat és az attribúciós ártelmezés; az F-45 címe és időbél-táblázata; a gate-mátrix összegzése (800 → **816** check, 26 → **0** hiba); a 14. fejezet 11. nyitott kérdése; a 15. fejezet konkurens-regenerálás bekezdése; a 16. fejezet metaadat-sorai.
- **Forrásfájl:** `reverse/evidence/audit_infra.json` (`summary`, `summary.by_group`, `failed_checks`, `discrepancies[]`, `audit.script_sha256`, `files`, `provenance`).
- **Confidence: `P`** (OBSERVED — az E9 payloadja a `csv.format` 60 checkje által hitelesített, `header_matches_producer_declaration` zölddel).

**4. E12 `toolchain.json` — méret, hash, leltárdbész**

- **Eltérés:** a dokumentum `24 107` bájt / `9a3a4d3aa54b0f082a4388cfafb70c0626c094863c2df24ceb0bc6cf8faeb32e` értéket és **17** script-bejegyzést rögzített. A lemezen **27 150** bájt / `72a1eed07d4d8a83df62cce8bd175a56cbba0da22982b34278fb537b15de0e6b` és **19** bejegyzés van. A korábbi 17-es állapotot a dokumentum 2 hiányző producerrel (`audit_handle_flow.py`, `syscall_service_map.py`) és 5 elavult `size`/`sha256`/`lf_line_count` mezővel érta le; a jelenlegi 19 bejegyzés mindegyike egyezik a `reverse/scripts/` lemezi állapotával.
- **Ój érték:** `24 107` → **27 150**, `9a3a4d3a…` → **`72a1eed0…`**, `17` → **19** bejegyzés (közbenső érték: `26 638` bájt / `6f3dd634…`).
- **Forrásfájl:** `reverse/evidence/toolchain.json` (`scripts`, `script_inventory.entry_count`) és a `reverse/scripts/*.py` lemezi állapotára.
- **Confidence: `P`** (OBSERVED — a 19 `sha256` a `reverse/scripts/` összes fájljára üszámban egyezik).

**5. `xref_build.py` – az E12 `scripts[]` pinje**

- **Eltérés:** a dokumentum szerint az E12 `10f62ac6…` (102 744 bájt) revzíziót túrtott, míg az E9 már a `cbb48bcc…` (102 838 bájt) lemezértéket. A jelenlegi E12 már a `cbb48bccba566f417a7c70db1821ef1d51fc8841ffa2c897edc6fbcff0c538d9` / 102 838 bájt értéket, tehát a két pin helyen azonos érték áll.
- **Ój érték:** az F-01 táblázat E12-sora a `cbb48bcc…` / 102 838 értékre, állapotja `egyezik a lemez jelenlegi revzíziójával`; a hozzá tartozó szövegblöl kikerült a divergencia álltása. **A finding magja nem változik:** az E5/E6 payloadon belüli `producer` blokk továbbra sincs, tehát a tartalom–író kapcsolat külső tanúsításra marad.
- **Forrásfájl:** `reverse/evidence/toolchain.json` `scripts[xref_build.py]`, `reverse/evidence/audit_infra.json` `provenance.digests[reverse/scripts/xref_build.py]`, `reverse/scripts/xref_build.py`.
- **Confidence: `P`** (OBSERVED).

**6. Producer-script digest- és méret-drift**

- **Eltérés:** `audit_infra.py`: a dokumentum `01c11061c3e5156e65fcb7e4dfae559528ade1ff355cb4e50272712fc49ac798` / 143 167 bájt / `01:24:50` érték → lemez **`ebf7f4f4547786ad52b780ca3f8ab2b10df8ab2890e2460d7eba5e08f2dc3e9b` / 151 067 bájt / `01:43:39`**. `refresh_toolchain.py`: a dokumentum `d1643be45d9eaf98b681db833c195257708620804604cd5da26f063aa93cc758` érték → lemez **`7cfda978f999833f654c4942b02a343264ddcdba5b6ea13c96f980dee61d75ce` / 29 120 bájt / `03:32:16`**; az ezen a soron korábban rögzített `91aa2212…` / 28 319 bájt / `01:42:57` köztes lemezérték azóta elavult. Artifact-mtime-ek: E12 `00:43:08` → `01:43:44`, E9 `01:25:43` → `01:45:21`; a legutóbbi mérésben E12 **`03:32:45`**, E9 **`03:58:12`**.
- **Forrásfájl:** `reverse/scripts/audit_infra.py`, `reverse/scripts/refresh_toolchain.py`, `reverse/evidence/toolchain.json`, `reverse/evidence/audit_infra.json` fájlrendszer-idők.
- **Confidence: `P`** (OBSERVED).

### 17.3 Eltérések — megfigyelve, a dokumentum számát nem módosítva

**A. E8 `inputs.patch_cross_references`: a digest-eltérés lezárult, a számszerű `rva_count` elavult**

- **Korábbi eltérés (a kereszt-audit állapota):** az `unresolved_regions.json` `inputs.patch_cross_references["patch_mechanisms_1e270.csv"].sha256` értéke `66c8e9bcaf5ab7f0ab9cafc6d08f839e34cceb8d324f56aff1199f7763241cb6`, a lemezen lévő fájl `ffc2234d4b620c49420e6751bb1d4db9c3d1e2fd07a7833a9f1452f4fd678090` (14 895 bájt), és a `patch_mechanisms_1e270.csv` mtime-je `2026-09-26 01:27:09` az E8énél (`2026-09-25 21:58:36`) későbbi volt.
- **Jelenlegi állapot:** az E8 **`2026-09-26 02:07:08`**-i revíziójában az `inputs.patch_cross_references["patch_mechanisms_1e270.csv"].sha256` már **`ffc2234d4b620c49420e6751bb1d4db9c3d1e2fd07a7833a9f1452f4fd678090`**, ami a lemezen lévő fájl digestje, a méret pedig `14 895` bájt. **A digest-eltérés tehát lezárult:** az E8 a patch-CSV **után** keletkezett, és a pinje már a jelenlegi revíziót tartalmazza. A `patch_mechanisms_helpers.csv` pinje (`49cb7ee8a9bfac3915c199e4911aac388987e071b61d3ac358ae2c0285ae4843` / 81 295 bájt) egyezett és egyezik.
- **Megmaradt, továbbra is nyitott eltérés:** az E8 `inputs.patch_cross_references` `rva_count` mezője `35` (a `1e270.csv`) és `0` (a `helpers.csv`). A jelenlegi `patch_mechanisms_1e270.csv` **50 adatsorból 21 nemüres `site_rva`** értéket tartalmaz, tehát a `35` a jelenlegi revízióval **nem reprodukálható**; a `patch_mechanisms_helpers.csv` 119 adatsorából **0** nemüres `RVA`, vagyis a `0` reprodukálható.
- **Következmény a dokumentumra:** a 10. fejezet F-37 állítása a `patch_mechanisms_1e270.csv` és a `patch_mechanisms_helpers.csv` RVA-it az `inputs.patch_cross_references` mezőn keresztül érkezőnek nevezi. Ez az E8 `rva_count` mezőjét idézi le, és a mező ma is `35` / `0`. **A dokumentum száma nem változott**, de az értelmezés pontosított: a `P2` **15**-tagú `priority.patch.regions` száma a `method.priority_sources.patch` szabályból jön (a CSV `site_rva` oszlopán futó RVA-tulajdonság a `.pdata` tartományban), **nem** a `rva_count` mezőből, és a payload nem deklarál köztük kapcsolatot. A `35` ezért az E8 `inputs` blokkjában megmaradt, de a `P2` levezetéséhez nem használt elavult adatként kezelendő.
- **Forrásfájl:** `reverse/evidence/unresolved_regions.json` `inputs.patch_cross_references` vs a `reverse/evidence/patch_mechanisms_1e270.csv` (14 895 bájt, 50 adatsor, 21 nemüres `site_rva`) és a `reverse/evidence/patch_mechanisms_helpers.csv` (81 295 bájt, 119 adatsor, 0 nemüres `RVA`) lemezi állapota.
- **Confidence: `P`** (OBSERVED a digest- és méret-egyezésre, és a `35` / `21` számsor eltérésére), **`L`** (INFERRED arra, hogy a `rva_count` nem a `priority.patch` forrásszámok inputja); `affects_decoded_counts = false`.

**B. Az E12 leltár csak pillanatnyi konzisztencia — mért korlát, nem készlethiba**

- **Megfigyelés:** a `toolchain.json` `digests.entries` nyolc bejegyzése ma mind reprodukálható vagy a `pdata_stats.json` által, vagy a `digests` blokkból, ezért a D-004 `unattested = []`-t ad. A leltár azonban nem kötés szabvány, úgy minden producer-változás újra elavulttá teszi – ez a mért korlát, nem a jelenlegi készlet hibája.
- **Forrásfájl:** `reverse/evidence/toolchain.json` `digests.entries_cover` és `digests.self`; `reverse/evidence/audit_infra.json` `discrepancies[D-004].bounded.attested_only_by_the_toolchain_block`.
- **Confidence: `P`** (OBSERVED).

### 17.4 Amit a kereszt-audit nem módosított

- **A 13-as dokumentum statisztikai számai változatlanok** mindegyikén kivéve a fenti 17.2/1. pontot. A 3–11. fejezet minden száma (142 004 rekord, 1 117 811 blokk, 503 338 elért blokk, **614 473 sweep-only blokk**, 1 014 037 él, 9 331 019 utasítás, **37 200 748 / 46 060 693**, 146 005 régió, 59 839 466 bájt, 233 klaszter, 57 101 xref-él, 157 153 közvetett hely, 8 176 forrástulajdonosság nélküli él, 371 `raw_scan`) **változatlan értékével reprodukálható** a jelenlegi CSV-kből.
- **A `reached_ratio`-megoszlás, a flag-megoszlás és a `37200748/46060693` arány mind reprodukálható** — a 17.1 mátrix 18–30. sora.
- **A D-009 finding nyitott marad:** az E9 `cfg.functions | reached_ratio` check továbbra is csak a belső konzisztenciát vizsgálja, nem a bizonyítéknyomot; az E9 `xref.edges` (33) és `indirect.sites` (19) csoport továbbra sem hasonlítja össze az E3 `indirect_jumps` összegét (86 559) az E6 jmp-helyszámmal (86 834). A 275-eltérés tehát továbbra is `STATUS:OPEN`.
- **A Gate A/B/C verdiktje érvényes:** a `pdata_stats.json` (37/0), az `unresolved_regions.json` (116/0) és az `audit_syscall_candidates.json` (31/0) inputjai bitre változatlanok. **Pontosítás az E8 revíziójával (ld. 13.y/1):** az `unresolved_regions.json` `2026-09-26 02:07:08`-i új revíziójának `inputs` pinjei (`cfg_functions.csv` `041d2365…` / 40 180 030, `pdata_functions.csv` `65ab914c…` / 29 634 365, `patch_mechanisms_1e270.csv` `ffc2234d…` / 14 895, `patch_mechanisms_helpers.csv` `49cb7ee8…` / 81 295) mind egyeznek a lemezen, és az új revízióban is `116` check / `0` hiba van, tehát a Gate B verdiktje az új fájlra is érvényes. Az E8 `csv` blokkja az E7-re `row_count=146005` / `column_count=37` értéket ír, ami a lemezen lévő `unresolved_regions.csv` `6e5d9430…` / 57 583 948 pinjével egyezik.
- **Az E8 `inputs.patch_cross_references` `rva_count` eltérése nyitva marad** (`35` a `patch_mechanisms_1e270.csv` 21 nemüres `site_rva` értékével szemben) – a 14. fejezet 12. nyitott kérdése, a 17.3/A és a 13.y/3 pont.
- **BOM és sortörés:** a fájl UTF-8 BOM nélküli, `cr = 0`, `crlf = 0`, záró sortöréssel.

---

## 13.y Pin- és prioritás-javítás

> **Scope:** kizárólag fájlos és mezőszintű újraolvasás a `reverse/evidence/unresolved_regions.json`, a `reverse/evidence/patch_mechanisms_1e270.csv` és a `reverse/evidence/patch_mechanisms_helpers.csv` fájlokon. A DLL-t nem futtattam, nem töltöttem be, nem mappeltem és nem patcheltem; egyetlen CSV vagy JSON sem keletkezett újra, és a `reverse/scripts/` és `reverse/evidence/` állományhoz nem nyúltam. Az alábbi tételek mind `sha256` digestből és fájlméretből mért értékek; ahol a „régi érték" a dokumentum korábbi, `2026-09-26 01:45:59`-i kereszt-auditja során mért pinje, az külön fel van jelölve.

### 13.y.1 Változási napló

| # | Tétel | Régi érték | Új érték | Forrásfájl | Confidence |
|---|---|---|---|---|---|
| 1 | E8 `unresolved_regions.json` SHA-256 (1. fejezet, E8-sor) | `b9b6498aaaa03fcd396e83b2a01938d605fd7e58d26bd292f53e9fd28babf950` — **elavult korábbi érték** | `0092fef1f0e07798fd2573909dc3d0cd4d79a84859e42ca24576b407337b34cd` | `reverse/evidence/unresolved_regions.json` | `P` (OBSERVED) |
| 2 | E8 `unresolved_regions.json` fájlméret | 12 253 941 bájt | **12 253 941 bájt (változatlan)** | `reverse/evidence/unresolved_regions.json` | `P` (OBSERVED) |
| 3 | E8 `unresolved_regions.json` revízió-ideje (a 17.3/A állítás alapja) | `2026-09-25 21:58:36` | `2026-09-26 02:07:08` | `reverse/evidence/unresolved_regions.json` fájlrendszer-idő | `P` (OBSERVED) |
| 4 | E8 `unresolved_regions.json` önellenőrzés | 116 check / 0 hiba | **116 check / 0 hiba (változatlan)**; `ok:true` = 116, `ok:false` = 0 | `reverse/evidence/unresolved_regions.json` `checks[]` | `P` (OBSERVED) |
| 5 | E8 beágyazott régiók száma | 9 900 | **9 900 (változatlan)**; `region_id` bejegyzések = 9 901 (`9 900` + 1 a `pinned[]`-ben) | `reverse/evidence/unresolved_regions.json` `regions[]`, `pinned[]` | `P` (OBSERVED) |
| 6 | E8 `inputs.patch_cross_references["patch_mechanisms_1e270.csv"].sha256` (a lemezhez képest) | `66c8e9bcaf5ab7f0ab9cafc6d08f839e34cceb8d324f56aff1199f7763241cb6` — **eltérés** | `ffc2234d4b620c49420e6751bb1d4db9c3d1e2fd07a7833a9f1452f4fd678090` — **egyezik a lemezzel** (14 895 bájt) | `reverse/evidence/unresolved_regions.json` `inputs.patch_cross_references` vs `reverse/evidence/patch_mechanisms_1e270.csv` | `P` (OBSERVED) |
| 7 | E8 `inputs.patch_cross_references["patch_mechanisms_helpers.csv"].sha256` | `49cb7ee8…` / 81 295 bájt | **`49cb7ee8a9bfac3915c199e4911aac388987e071b61d3ac358ae2c0285ae4843` / 81 295 bájt (változatlan, egyezik)** | ugyanott | `P` (OBSERVED) |
| 8 | E8 `inputs.patch_cross_references` `rva_count` / a patch-CSV nemüres RVA-oszlopa | `35` / `0` a `21` nemüres `site_rva`-val szemben — **eltérés** | **`35` / `0` (változatlan) — az eltérés nyitva marad**; a `1e270.csv` 50 adatsorból 21 nemüres `site_rva`, a `helpers.csv` 119 adatsorból 0 nemüres `RVA` | `reverse/evidence/unresolved_regions.json` `inputs.patch_cross_references` vs a két patch-CSV | `P` (OBSERVED az eltérésre) |
| 9 | F-32 prioritás-disztribúció forrásoszlopa | forrásoszlop nem volt megadva | `E8 totals.by_priority` — **kizárólagos** hozzárendelés; `615 + 972 + 4 + 30 + 144 384 = 146 005` | `reverse/evidence/unresolved_regions.json` `totals.by_priority`, `families.<f>.by_priority` | `P` (OBSERVED) |
| 10 | F-37 prioritás-disztribúció forrásoszlopa | csak szemantikai forrásszabály (`method.priority_sources`) | `E8 priority.<level>.regions` és `priority.<level>.bytes` — **forrás szerinti, nem kizárólagos** találatszám | `reverse/evidence/unresolved_regions.json` `priority.security\| syscall\| patch\| lifecycle\| coverage` | `P` (OBSERVED) |
| 11 | F-32 és F-37 prioritás-számok | ellentmondásként nem kezelve | **nincs ellentmondás, hanem két külön bemeneti oszlop**; a delták `0 / 40 / 11 / 234`, összegük `285 = (615 + 1 012 + 15 + 264) − (615 + 972 + 4 + 30)` | `reverse/evidence/unresolved_regions.json` `totals.by_priority`, `priority.*`, `method.priority_order` | `P` (OBSERVED) |
| 12 | F-37 `Bájt` oszlop összegezhetősége | nem jelölve | **nem adódik össze**: `2 413 908 + 17 434 496 + 10 064 + 203 444 + 59 839 466 = 79 901 378 ≠ 59 839 466`; kizárólag a `totals` oldal összegezhető | `reverse/evidence/unresolved_regions.json` `priority.<level>.bytes`, `totals.bytes` | `P` (OBSERVED) |
| 13 | A 17.1 mátrix 8. sorának (E8 pin) állapota | a `b9b6498a…` pinre vonatkozó `**egyezik**` állítás — **elavult korábbi érték**, a mai lemezre nem érvényes | `**javítva**` a `0092fef1…` pinre (a 13.y/1 tétel) | `reverse/evidence/unresolved_regions.json` | `P` (OBSERVED) |
| 14 | A 17.1 mátrix 53. sorának (patch-input digest) állapota | `**eltérés, nem javított**` | `**részben javítva**` – a digest lezárult, a `rva_count` nyitott (a 13.y/6 és 13.y/8 tételek) | `reverse/evidence/unresolved_regions.json` `inputs` vs lemez | `P` (OBSERVED) |
| 15 | A 17.3/A alpont címe és tartalma | „E8 `inputs.patch_cross_references` elavult input-digest” | „a digest-eltérés lezárult, a számszerű `rva_count` elavult” – a négy bulletsor a jelenlegi állapotot írja le (a 13.y/6 és 13.y/8 tételek) | `reverse/evidence/unresolved_regions.json` `inputs.patch_cross_references` | `P` (OBSERVED) |
| 16 | A 14. fejezet nyitott kérdéseinek száma | 11 tétel | **12 tétel** – a 12. pont az E8 `rva_count` elavultsága (a 13.y/8 tétel) | `reverse/evidence/unresolved_regions.json` `inputs.patch_cross_references`; `reverse/evidence/patch_mechanisms_1e270.csv` `site_rva` | `L` (INFERRED a `P2` levezetés hatására) |

### 13.y.2 Változatlanul hagyott, igazolt számok

A következő értékeket a korrekció **nem** érintette; mindegyik a jelenlegi payloadból változatlanul reprodukálható, és a Gate A/B/C/D verdiktjei (`37/116/31/632`, `0` hiba) érintetlenek:

| Tétel | Érték | Forrásfájl/mező |
|---|---|---|
| `IMAGE_RUNTIME_FUNCTION` rekord | 142 004 | E1 `pdata_functions.csv`; E8 `inputs` `row_count` |
| Egyedi `UNWIND_INFO` | 15 533 | E1 `unwind_info_address` egyedi érték |
| Flag-megoszlás (rekord / egyedi) | `0`:137 037/10 725, `1`:65/65, `2`:45/45, `3`:2 694/2 654, `4`:2 163/2 044 | E1 `unwind_flags` |
| Coverage-arány | 37 200 748 ÷ 46 060 693 = 80,764629 % | E2 `text_coverage` |
| `pdata_gap` régiók | 137 105 | E8 `families.pdata_gap.regions` |
| Alap-blokkok | 1 117 811 | E3 `basic_blocks` oszlopösszeg |
| Élek | 1 014 037 | E3 éloszlopok összege |
| Utasításstart | 9 331 019 | E3 `instructions` oszlopösszeg |
| Sweep-only blokk | 614 473 | E3 `blocks_linear_only` oszlopösszeg |
| Klaszter | 233 | E4 `cfg_clusters.csv` sorszám |
| `data_record` | 4 | E8 `families.data_record.regions`; E7 `UR-001622`–`UR-001625` |
| Unresolved-régiók összesen | 146 005 | E8 `totals.regions`; E7 `unresolved_regions.csv` sorszám |
| Gate A / B / C / D | 37/0, 116/0, 31/0, 632/0 | E2, E8, E10, E9 `checks[]` |

### 13.y.3 Az E8 stale patch-input megjegyzés egységesített állítása

A `patch_mechanisms_1e270.csv` pinjére mostantól nincs eltérés: az E8 `ffc2234d4b620c49420e6751bb1d4db9c3d1e2fd07a7833a9f1452f4fd678090` / 14 895 bájt értéke egyezik a lemezen lévő fájllal, és a `patch_mechanisms_helpers.csv` `49cb7ee8a9bfac3915c199e4911aac388987e071b61d3ac358ae2c0285ae4843` / 81 295 bájt értéke is. **A stale megjegyzés egyetlen eleme a számszerű `rva_count`:** az E8 `35`-öt ír, a jelenlegi CSV-ből viszont csak **21** nemüres `site_rva` származik, tehát a `35` elavult. Ez a `P2` **15**-tagú `priority.patch.regions` számát nem magyarázza, mert a `method.priority_sources.patch` szabály a CSV `site_rva` oszlopán és a `.pdata` tartomány-belsőségen fut, nem az `rva_count` mezőn; a payload nem deklarál kapcsolatot a két szám között. A tétel a 14. fejezet 12. nyitott kérdéseként, `STATUS:OPEN`, `CONF:L` jelöléssel szerepel, `affects_decoded_counts = false` mellett. A `P2` **15**, `10 064` bájt és a `P3` **264**, `203 444` bájt érték változatlan.

### 13.y.4 Az F-32 / F-37 prioritás-rekonsziliáció lezárása

A két prioritás-disztribúció **bebizonyítottan két külön bemeneti oszlopról számol**, tehát nem kell `bounded_open` státuszba venni:

- **F-32** → `reverse/evidence/unresolved_regions.json` **`totals.by_priority`**: kizárólagos hozzárendelés, minden régió az `method.priority_order` szerint elsőként teljesülő forrás szintjén, összeg `146 005`. Független kereszt-ellenőrzés: a hét `families.<family>.by_priority` blokk oszloponkénti összege pontosan `615 / 972 / 4 / 30 / 144 384`. `[P]`
- **F-37** → `reverse/evidence/unresolved_regions.json` **`priority.<level>.regions`** és **`priority.<level>.bytes`**: forrás szerinti, nem kizárólagos találatszám; a `coverage` szint definíció szerint minden régiót tartalmaz (`146 005`). `[P]`

A delták és a magyarázatuk: `P0` `615 − 615 = 0` (a `security` a `priority_order` első eleme), `P1` `1 012 − 972 = 40`, `P2` `15 − 4 = 11`, `P3` `264 − 30 = 234`, `P4` `146 005 − 144 384 = 1 621`. A nem-`coverage` forrást találatok összege `1 906`, a kizárólagos hozzárendelésé `1 621`, a különbség `285 = 40 + 11 + 234`. A két oszlop tehát számszerűen konzisztens, és egyik sem javítandó. A `P2 = 4` (kizárólagos) és a `P2 = 15` (forrás szerinti), valamint a `P3 = 30` és a `P3 = 264` pár **mindkét irányban helyes**, külön-külön, a saját forrásoszlopán.
`BRef = [RVA:N/A | RAW:N/A | CONF:P | STATUS:OBSERVED]` (E8 `totals.by_priority`, `priority.*`, `method.priority_order`, `families.*.by_priority`).

**Táblázat-formázási javítás (2026-09-26):** a 145. sor `Flag-eloszlás` táblázatában a `EHANDLER|UHANDLER`, illetve a 1012. sor `13.y.1` napló táblázatában a `priority.security| syscall| patch| lifecycle| coverage` nem escapelt `|` karakterei `\|` alakra javítva, így a cellaszám egyezik a fejléccel; szám, RVA, finding és sortörés nem változott.

---

## 13.z Pin-konformancia-javítás (2026-09-26)

> **Scope:** kizárólag szövegszerkesztés a `reverse/adhesive-00-index.md`, `adhesive-12`, `adhesive-13`, `adhesive-14` és `adhesive-15` fájlokban. A DLL-t nem futtattam, nem töltöttem be, nem mappeltem és nem patcheltem; új evidence-fájl nem készült, és a `reverse/evidence/` vagy a `reverse/scripts/` állományhoz nem nyúltam. A méret- és `sha256`-pinok a `2026-09-26`-i lemezállapothoz lettek igazítva.

### 13.z.1 A `13` dokumentumban frissített pin-ek (3 artifact, 6 pinérték, 13 cited hely)

| Hely | Artifact | Régi érték | Új érték |
|---|---|---|---|
| 1. fejezet, E9-sor | `audit_infra.json` méret + digest | `169 558` bájt, `97134043e684931b9b8cb1e12c75d4c1f9b7ee0e2681bd9ee41e811137c6ce02` | **`170 001` bájt, `251b79e722620af61824b793ced1ade1ffe9b375608a429e109880aaa8b8b1dc`** |
| 1. fejezet, E12-sor | `toolchain.json` méret + digest | `26 638` bájt, `6f3dd634c494b2dea837cd1da2dd452a82311ce2faa6e5686507fddd5497074d` | **`27 150` bájt, `72a1eed07d4d8a83df62cce8bd175a56cbba0da22982b34278fb537b15de0e6b`** |
| 12. fejezet, D-002 „A javított állapot" bekezdése | `toolchain.json` méret + digest | `26 638` bájt, `sha256 6f3dd634…` | **`27 150` bájt, `sha256 72a1eed0…`** |
| 17.1 fejezet, 9. sor (E9) | `audit_infra.json` méret + digest | `97134043…` / 169 558 | **`251b79e7…` / 170 001** |
| 17.1 fejezet, 12. sor (E12) | `toolchain.json` méret + digest | `6f3dd634…` / 26 638 | **`72a1eed0…` / 27 150** |
| 17.1 fejezet, 51. sor (E9 `files`) | `toolchain.json` méret + digest, ahogyan az E9 `files` blokkja rögzíti | `6f3dd634…` / 26 638 | **`72a1eed0…` / 27 150** |
| 17.2 fejezet, 3. alpont | `audit_infra.json` méret + digest | `169 558` bájt, `97134043e684931b9b8cb1e12c75d4c1f9b7ee0e2681bd9ee41e811137c6ce02` | **`170 001` bájt, `251b79e722620af61824b793ced1ade1ffe9b375608a429e109880aaa8b8b1dc`** |
| 17.2 fejezet, 4. alpont | `toolchain.json` méret + digest | `26 638` bájt, `6f3dd634c494b2dea837cd1da2dd452a82311ce2faa6e5686507fddd5497074d` | **`27 150` bájt, `72a1eed07d4d8a83df62cce8bd175a56cbba0da22982b34278fb537b15de0e6b`** |
| 1. fejezet, producer-táblázat, E12-sor | `refresh_toolchain.py` méret + digest | `28 319` bájt, `91aa22124b41510479acdf27b50099e7d547a3f2ab3b0cf6a9fa5855cc925925` | **`29 120` bájt, `7cfda978f999833f654c4942b02a343264ddcdba5b6ea13c96f980dee61d75ce`** |
| 12. fejezet, D-002 „A javított állapot" bekezdése | `refresh_toolchain.py` méret + digest | `sha256 91aa2212…` | **`sha256 7cfda978…`** |
| 12. fejezet, D-002 pinelési táblázata, E12-sor | `refresh_toolchain.py` méret + digest | `91aa2212…` / 28 319 – egyezik a lemezzel | **`7cfda978…` / 29 120 – egyezik a lemezzel** |
| 17.1 fejezet, 17. sor | `refresh_toolchain.py` méret + digest | `91aa2212…` / 28 319 – **javítva** (régebbi: `d1643be4…`) | **`7cfda978…` / 29 120 – javítva** (köztes érték: `91aa2212…` / 28 319) |
| 17.2 fejezet, 6. alpont | `refresh_toolchain.py` méret + digest | `91aa22124b41510479acdf27b50099e7d547a3f2ab3b0cf6a9fa5855cc925925` / 28 319 bájt / `01:42:57` | **`7cfda978f999833f654c4942b02a343264ddcdba5b6ea13c96f980dee61d75ce` / 29 120 bájt / `03:32:16`** |

A `refresh_toolchain.py` pin javítása a producer-script pineket is lefedi, nem csak az evidence-artifact pineket: a `13` mindenütt a lemez aktuális `7cfda978f999833f654c4942b02a343264ddcdba5b6ea13c96f980dee61d75ce` / `29 120` bájt értékét rögzíti, és ez egyezik az `E12` `toolchain.json` `scripts[]` bejegyzésével is, tehát az „egyezik a lemezzel" és a „javítva" minősítés mindkét irányban igaz.

### 13.z.2 Az E9 `632 / 0 / verdict=pass` értékének ellenőrizhetősége

- **Ellenőrizhető:** az `audit_infra.json` `summary` blokkja `check_count = 632`, `failed_count = 0`, `verdict = "pass"`, `discrepancy_count = 4`, `discrepancy_open_count = 0`, `discrepancy_status = {D-001: closed, D-002: closed, D-003: closed, D-004: closed}`, `failed_checks = []` értékeket ad; a `22` csoportos bontás a 13. fejezet Gate D táblázatában `632`-re összegezik.
- **A dokumentum által közölt check-szám a jelenlegi audit-futtatásé:** a `632` nem a dokumentum állítása, hanem a `summary.check_count` mező értéke, és a hozzá tartozó `170 001` bájt / `251b79e7…` pin ugyanannak a futásnak a payloadjáé. Korábbi futások check-száma (`457 / 21`, `616 / 26`, `628 / 5`) nem érvényes erre a fájlra.
- **A `verdict=pass` érvényességi határa változatlan:** a Gate D a producer-fa attestationjára vonatkozik, a function-map mérőszámaira nem; a `D-009` finding továbbra is nyitott, ahogyan a 17.4 fejezet rögzíti.

### 13.z.3 Az önreferenciás digest annotációja

- **A `13` nem pinel saját magára hivatkozó digestet.** Egyetlen evidence-payload sem – az `E9`, az `E10` és az `E6` sem – rögzíti az `adhesive-13-pdata-function-map-cfg.md` fájl méretét vagy `sha256`-jét, és az `E1`–`E12` pin kizárólag `reverse/evidence/` artifactokra mutat. A `13` saját fájl-digestje ezért nem szerepel tanúsított vagy nem-attesztáló értékként sem.
- **A `13` pinjei egyirányúak és külsőleg tanúsítottak:** az `E9` `files` és `provenance.digests` blokkja rögzíti a `toolchain.json`, `baseline.json`, `pdata_stats.json`, `pdata_functions.csv`, `cfg_functions.csv`, `cfg_clusters.csv`, `xref_edges.csv`, `indirect_sites.csv` és `syscall_candidates_raw.csv` digestjét, a `pdata_stats.json` a `baseline.json`-ét, az `E2` és az `E8` a saját producer-scriptjét. A `toolchain.json` `digests.self` blokkja a saját digestjét szándékosan `null`-ra hagyja, azzal az indoklással, hogy „a payload cannot contain its own digest" – vagyis a lánc egyetlen hiányzó pontja a dokumentum felé nyíló, és ez a `13` esetében is így van.
- **A `13` szerkesztése az őt pinelő artifactokat nem invalidálja**, mert egyik sem olvassa az `adhesive-13…md` fájlt; a `14` dokumentum esetében viszont van ilyen kör, és azt a `14` 21.2/1. alpontja nem-attesztáló, szerkesztésre elavuló megfigyelésként annotálja.

### 13.z.4 Amit a javítás nem módosított

- **Nem változott semmilyen statisztikai szám, finding, státusz vagy confidence érték:** az `E1`–`E8`, `E10` és `E11` pinje bitre változatlan; a `142 004` rekord, a `1 117 811` blokk, az `503 338` elért blokk, a `614 473` sweep-only blokk, a `37 200 748 / 46 060 693` coverage, a `146 005` régió, az `59 839 466` bájt, a `233` klaszter, az `1 014 037` él, a `9 331 019` utasításstart és a `371` `raw_scan` változatlan.
- **A Gate A / B / C / D verdiktje változatlan:** `37/0`, `116/0`, `31/0`, `632/0`; a 14. fejezet 12 nyitott kérdése, a `D-009`, az `F-31`, az `F-01`, a `D-002` és a `D-004` státusza nem változott.
- **A `gate-mátrix` összegzett `816` check / `0` hiba sora változatlan.**
- **A `refresh_toolchain.py` script-pin már nem elavult, hanem javított:** a `13` minden hivatkozott helyen – az 1. fejezet E12-sorában, a 12. fejezet D-002 bekezdésében és pinelési táblázatában, a 17.1 fejezet 17. sorában és a 17.2 fejezet 6. alpontjában – a lemez aktuális `7cfda978f999833f654c4942b02a343264ddcdba5b6ea13c96f980dee61d75ce` / `29 120` bájt értékét rögzíti. Ez **producer-script pin, nem evidence-artifact pin**, ezért a 13.z.1 táblázatába külön sorként került, de a findingre és a státuszra nincs hatása. A korábbi `91aa2212…` / `28 319` bájt állapot elavult; a 17.2 6. alpontja az elavult köztes értéket történeti megfigyelésként, „elavult" jelöléssel megőrizte. A `toolchain.json` `scripts[]` leltára ettől függetlenül 19 bejegyzéses, `drifted_entries = {}`, tehát a `D-002` `closed` státusza érintetlen.
- **Kódolás és sortörés:** a fájl UTF-8 BOM nélküli, LF sortöréssel, záró sortöréssel; `cr = 0` / `crlf = 0`.
