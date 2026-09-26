# `adhesive.dll`: a `CreateComponent` statikus rekonstrukciója

## 1. Vizsgálati határ és jelölés

- **Vizsgált minta:** `reverse/adhesive.dll`
- **Formátum:** PE32+ / x86-64 DLL
- **Image base:** `0x0000000180000000`
- **Export:** `CreateComponent`, ordinal 1, RVA `0x101F80`
- **Vizsgálat dátuma:** 2026-09-25
- **Módszer:** kizárólag statikus PE-, kód-, adatszerkezet-, relokációs és `.pdata`-elemzés. A DLL-t nem futtattuk, nem töltöttük be és nem hívtuk meg.
- **Biztonsági határ:** az alábbi leírás szerkezeti és szemantikai dokumentáció; nem invocation-, exploit-, bypass- vagy patch-recept.

### `RVA` és `raw`

Az **RVA** mindenütt a 32 bites PE relatív virtuális cím. A **`raw`** oszlop a célfüggvény vagy adatszerkezet tényleges fájloffsetje a DLL-ben. A `raw bytes` az adott cél első 12–16 bájtját mutatja.

A három használt szekció file/RVA leképezése:

| Szekció | RVA | Fáloffset | Képlet |
|---|---:|---:|---|
| `.text` | `0x001000` | `0x00000400` | `raw = RVA - 0xC00` |
| `.rdata` | `0x2BEF000` | `0x02BEDA00` | `raw = RVA - 0x1600` |
| `.data` | `0x30B9000` | `0x030B7A00` | `raw = RVA - 0x1600` |

### Bizonyíték-jelölések

- **AZONOSÍTOTT:** közvetlenül a DLL bájtjaiból, a vtable-ből vagy az upstream forrásból adódik; a bináris tények elsőbbséget élveznek.
- **VALÓSZÍNŰ:** több, egymást támogató statikus jel alapján következik, de a forrásnevnél vagy belső paraméternél marad bizonytalanság.
- **FELTEVETT:** szerkezetileg konzisztens lehetőség, de ebből a mintából nem bizonyítható egyértelműen.
- **Konfidencia:** a *nevekre és végső jelentésre* vonatkozik, nem pusztán a pointer/cím azonosítására.
- **Globális `P` / `L` / `U` jelölés (az `adhesive-00-index.md` 6. fejezete szerint):** `AZONOSÍTOTT` = **P** (közvetlenül statikusan bizonyított), `VALÓSZÍNŰ` = **L** (erős indoklású, de nem közvetlen), `FELTEVETT` = **U** (ebből a mintából nem dönthető el). A betűjelölés a dokumentum minden finding- és konfidenciasorán explicit módon szerepel: egyszerű soron a `Konfidencia` oszlopban, több pontból álló findingnél az egyes pontokat minősítő `Státusz` oszlopban, a pontot megnevező szöveg után. A számszerű confidence-érték mindenütt változatlan marad.

### Forráskori cross-check

A nyílt CitizenFX-forrás csak a nevek és az API-vtable-sorrend ellenőrzésére szolgál. Nem bizonyítja, hogy a jelenlegi upstream `master` bitre azonos a vizsgált builddel.

- `code/components/citizen-resources-core/src/Component.cpp`
- `code/client/citicore/ComponentLoader.h`
- `code/client/citicore/om/OMComponent.h`
- `code/client/shared/HookFunction.h`
- `code/client/shared/HookFunction.cpp`

Kapcsolódó ellenőrző oldalak:

- <https://github.com/citizenfx/fivem/blob/master/code/components/citizen-resources-core/src/Component.cpp>
- <https://github.com/citizenfx/fivem/blob/master/code/client/citicore/ComponentLoader.h>
- <https://github.com/citizenfx/fivem/blob/master/code/client/citicore/om/OMComponent.h>
- <https://github.com/citizenfx/fivem/blob/master/code/client/shared/HookFunction.cpp>

## 2. Rövid eredmény

1. Az egyetlen export a `CreateComponent`; az x64 kód egyetlen argumentumot sem olvas, és az `RAX`-ben objektumpointert ad vissza.
2. Az objektum pontosan `0x28` bájt:
   - `+0x00`: elsődleges `Component` vptr;
   - `+0x08`: 32 bites referencia-szám;
   - `+0x10`: `0xFC203F1D` privát interface vptr;
   - `+0x18`: `OMComponent` (`0x5D560A33`) vptr;
   - `+0x20`: közös `OMComponentBaseImpl` singleton pointer.
3. A végleges elsődleges vtable `RVA 0x2C65060`; konstrukció közben átmenetileg `RVA 0x2C650E0` bootstrap vtable látható.
4. Az OM vtable `RVA 0x2C650C8` két valódi slottal és egy null-terminátorral rendelkezik:
   - `CreateObjectInstance` → `RVA 0x102240`;
   - `GetImplementedClasses` → `RVA 0x102460`.
5. A globális OM registry singleton maga a `RVA 0x30E09B0` pointer; a célzott `0x10` bájtos blokk két lista-fejlécet tartalmaz: factory-lista és implemented-class-lista.
6. Az `Initialize` slot (`RVA 0x101D70`) prioritásos inicializálási fát futtat és `true`-t ad vissza. A `DoGameLoad` slot (`RVA 0x101D80`) erősen obfuszkált; a forráskori implementáció `HookFunction::RunAll()`-t, majd `true`-t tartalmaz.
7. Az `IsA` és `As` kód közvetlenül igazolja a két azonosítót és a beágyazott interface-címeket.

## 3. Export és feltételezett signature

### Exportbizonyíték

- Export directory RVA: `0x2E4B96A`
- Export address: `RVA 0x101F80`
- Név: `CreateComponent`
- Ordinal: 1
- A DLL nem tartalmaz más exportnevet.

### A buildnek megfelelő signature

```cpp
extern "C" Component* __cdecl CreateComponent(void);
```

**Státusz:** a nullaargumentumos ABI **AZONOSÍTOTT** (P); a `Component*` típusnév a visszaadott `0x28`-byte objektum és az upstream deklaráció alapján **VALÓSZÍNŰ** (L), 0,99.

Megjegyzések:

- x64-en a `__cdecl` nincs külön gépi kódmegkötéshez.
- A függvény a belépési `RCX`, `RDX`, `R8`, `R9`, `R10`, `R11` értékeket egyetlen utasításban sem használja.
- A normál visszaút az `RAX`-ben tárolt objektumpointer.
- Hibás allokáció esetén a látható straight-line rész nem ad `nullptr` értéket; a kivételkezelésre hagyatkozik.

## 4. A `CreateComponent` rekonstruált statikus törzse

RVA: `0x101F80`
Raw: `0x101380`
Raw kezdőbytes: `55 56 48 83 EC 38 48 8D 6C 24 30 48 C7 45 00`

A végrehajtási sorrend az alábbi statikus adatfolyamot követi; ez nem hívási példa:

1. `0x28` bájtos objektumfoglalás az `RVA 0x2AB23D4` allokálón.
2. Az objektum mind a `0x28` bájtjára nullázzák.
3. `object+0x00` ideiglenesen az `RVA 0x2C650E0` bootstrap vtable-t kap.
4. `object+0x10` az `RVA 0x2C650B0` privát-interface vtable-t kap.
5. `object+0x18` az `RVA 0x2C650C8` OM vtable-t kap.
6. A globális OM singleton (`RVA 0x30E09B0`) nulláját betöltik. Ha még null, `0x10` bájtos, nullázott blokkot allokálnak és odamentik.
7. `object+0x20` a globális OM singleton blokkra mutat.
8. `object+0x00` végleges vptrje az `RVA 0x2C65060` elsődleges vtable lesz.
9. A privát és OM vptr ismét ugyanarra a két statikus vtable-re mutat.
10. Az objektumpointer visszaadja `RAX`-ben.

### Fontos tulajdonságok

| Tulajdonság | Következtetés | Státusz | Konfidencia |
|---|---|---|---:|
| Objektumméret `0x28` | `operator new(0x28)` | AZONOSÍTOTT | P (1,00) |
| Refszám kezdeti értéke `0` | A teljes objektum nullázása; nincs `1` beírás | AZONOSÍTOTT | P (1,00) |
| Argumentumok száma `0` | Egyetlen belépési argumentumregiszter sincs olvasva | AZONOSÍTOTT | P (0,99) |
| `nullptr` helyett kivétel lehetséges | Nincs látható catch/fallback az allokációk körül | VALÓSZÍNŰ | L (0,90) |
| Globális OM singleton inicializálása nem atomi | Egyszerű `load/test/store`, nincs lock vagy CAS | AZONOSÍTOTT | P (0,99) |
| Többszöri példány ugyanazt az OM blokkot használja | A globális pointeren keresztül minden példány ugyanarra mutat | AZONOSÍTOTT | P (0,98) |

## 5. A `0x28`-byte objektum elrendezése

| Offset | Méret | Kezdeti érték | Jelentés | Státusz | Konfidencia |
|---:|---:|---|---|---|---:|
| `+0x00` | 8 | bootstrap, majd final vptr | Elsődleges `Component*` | AZONOSÍTOTT | P (1,00) |
| `+0x08` | 4 | `0` | `fwRefCountable` referencia-szám | AZONOSÍTOTT | P (0,99) |
| `+0x0C` | 4 | `0` | A 8 bájtos objektum- és 32 bites számozás paddingje | AZONOSÍTOTT | P (0,99) |
| `+0x10` | 8 | `0x182C650B0` image VA | `0xFC203F1D` privát interface vptr | AZONOSÍTOTT | P (1,00) |
| `+0x18` | 8 | `0x182C650C8` image VA | `OMComponent` vptr | AZONOSÍTOTT | P (1,00) |
| `+0x20` | 8 | globális `0x10`-byte blokk | `OMComponentBaseImpl* m_impl` | AZONOSÍTOTT | P (0,99) |

Az objektum két többszörös öröklés miatt nem azonosítható egyszerűen az elsődleges `Component` interfésszel: az `As` igazolt interface-címek az objektum belsejébe mutatnak.

## 6. Globális állapot és registry-k

| Globális RVA | Raw | Típus / szerep | Közvetlen bizonyíték | Státusz | Konfidencia |
|---:|---:|---|---|---|---:|
| `0x30E0990` | `0x30DF390` | `0x10`-byte globális lista/state | `RVA 0x101CB0` nullázza; `RVA 0x102180` bejárja | AZONOSÍTOTT viselkedés (P), ismeretlen pontos típus (U) | 0,85 |
| `0x30E09A0` | `0x30DF3A0` | másik `0x10`-byte globális lista/state | `RVA 0x101D10` nullázja; `RVA 0x1021D0` bejárja | AZONOSÍTOTT viselkedés (P), ismeretlen pontos típus (U) | 0,85 |
| `0x30E09B0` | `0x30DF3B0` | `OMComponentBaseImpl::ms_instance*` | `CreateComponent` lazy allokálja; minden OM példány `m_impl` mezője ebből kap értéket | AZONOSÍTOTT | P (0,99) |
| `0x3306F80` | `0x3305980` | prioritásos inicializálási fa gyökere | `RVA 0x2A9F330` beszúr, `RVA 0x2A9F380` futtat | AZONOSÍTOTT viselkedés (P), forráskori név VALÓSZÍNŰ (L) | 0,94 |

### Az OM singleton `0x10` bájtos tartalma

| Offset a blokkon belül | Jelentés | Státusz | Konfidencia |
|---:|---|---|---:|
| `+0x00` | `OMFactoryDefinition* m_factoryList` | AZONOSÍTOTT forráskori és bináris szerkezet | P (0,98) |
| `+0x08` | `OMImplements* m_implList` | AZONOSÍTOTT forráskori és bináris szerkezet | P (0,98) |

A `CreateObjectInstance` az első listából, a `GetImplementedClasses` a másodikból indul ki. A `CreateComponent` maga nem tölti fel ezeket a listákat; az OM statikus definíciós/factory objektumok más kódútvonalakon teszik ezt.

### Globális inicializálók

- `RVA 0x101CB0`, raw `0x1010B0`: a `0x30E0990` állapotot nullázza, majd regisztrál teardownet.
- `RVA 0x101D10`, raw `0x101110`: a `0x30E09A0` állapotot nullázza, majd regisztrál teardownet.
- E két globális lista nem azonosítható biztonságosan az upstream `HookFunction` egyszerű `g_hookFunctions` pointerével. A bináris belépésük és a hozzájuk tartozó közvetlen futtatók eltérő szerkezetűek.

## 7. Vtable-katalógus

| Vtable | Image VA | RVA | Raw | Publikus szerep | Közvetlen használat |
|---|---:|---:|---:|---|---|
| priority/callback vtable | `0x182C65030` | `0x2C65030` | `0x2C63A30` | `RVA 0x101F50` stack callback/leképező objektumához adja | Statikusan igazolt |
| végleges elsődleges vtable | `0x182C65060` | `0x2C65060` | `0x2C63A60` | `Component` lifecycle, refcount, `IsA`, `As` | `CreateComponent` végén állítja |
| privát interface vtable | `0x182C650B0` | `0x2C650B0` | `0x2C63AB0` | hash `0xFC203F1D`, két ismeretlennevű metódussal | `CreateComponent`, `As` |
| OM vtable | `0x182C650C8` | `0x2C650C8` | `0x2C63AC8` | `OMComponent`, két metódussal és null-terminátorral | `CreateComponent`, `As` |
| bootstrap vtable | `0x182C650E0` | `0x2C650E0` | `0x2C63AE0` | köztes konstrukciós vtable | `CreateComponent` ideiglenesen, majd lecseréli |

## 8. Végleges elsődleges vtable: `RVA 0x2C65060`

A `fwRefCountable` és `Component` forráskori virtual-lista sorrendje a bináris tíz slottal egyezik.

| Slot | Forráskori név | Target RVA | Target raw | Raw bytes | Statikus szemantika | Státusz | Konfidencia |
|---:|---|---:|---:|---|---|---|---:|
| `0` | deleting destructor / `~fwRefCountable` | `0x102110` | `0x101510` | `56 57 48 83 EC 28 89 D7 48 89 CE E8` | Az `EDX` delete-flaget továbbítja; a primary vptr-t alaphasonlóra állítja; csak `delete=1` esetén szabadít | AZONOSÍTOTT | P (0,99) |
| `1` | `AddRef` | `0x2AA2110` | `0x2AA1510` | `F0 FF 41 08 C3 CC CC CC CC CC CC CC` | `lock inc dword [this+8]`, nincs explicit return value | AZONOSÍTOTT | P (1,00) |
| `2` | `Release` | `0x2AA2120` | `0x2AA1520` | `48 83 EC 28 B8 FF FF FF FF F0 0F C1 41 08 83 F8 01` | `lock xadd -1`; régi érték 1 esetén meghívja a vtable 0. slotját `delete=1` flaggel | AZONOSÍTOTT | P (1,00) |
| `3` | `Initialize` | `0x101D70` | `0x101170` | `48 83 EC 28 E8 07 D6 99 02 B0 01 48 83 C4 28 C3` | `RVA 0x2A9F380` prioritásos lista-futtatót hív, majd `true` | AZONOSÍTOTT név (P) és viselkedés (P) | 0,99 |
| `4` | `SetCommandLine` | `0x1170` | `0x570` | `C3` | Egyetlen `ret`; nem használ argumentumot, ezért a forráskori `void` contract szerint no-op | AZONOSÍTOTT | P (1,00) |
| `5` | `SetUserData` | `0x51B20` | `0x50F20` | `B0 01 C3 CC CC CC CC CC CC CC CC CC` | `AL=1`; argumentumokat nem használ | AZONOSÍTOTT | P (0,99) |
| `6` | `Shutdown` | `0x51B20` | `0x50F20` | `B0 01 C3 CC CC CC CC CC CC CC CC CC` | `AL=1`; nincs látható extra cleanup | AZONOSÍTOTT | P (0,99) |
| `7` | `DoGameLoad` | `0x101D80` | `0x101180` | `41 57 41 56 56 57 53 48 83 EC 20 E8 30 0B 00 00` | Nagyon obfuszkált, számított vezérlési folyam; a végén `true`; upstream szerint `HookFunction::RunAll()` | AZONOSÍTOTT név (P), részben feltételes belső cél (U) | 0,96 |
| `8` | `IsA` | `0x102140` | `0x101540` | `81 FA 33 0A 56 5D 0F 94 C1 81 FA 1D 3F 20 FC` | `true` két azonosítóra: `0x5D560A33` vagy `0xFC203F1D` | AZONOSÍTOTT | P (1,00) |
| `9` | `As` | `0x102160` | `0x101560` | `4C 8D 41 10 31 C0 81 FA 1D 3F 20 FC 49 0F 44 C0` | A privát hashhez `this+0x10`, az OM hashhez `this+0x18`, más hashhoz `nullptr` | AZONOSÍTOTT | P (1,00) |

### A 4. slot közvetlen implementációja

A primary vtable 4. qwordja közvetlenül az `RVA 0x1170` (`raw 0x570`) címet tartalmazza, ahol egyetlen `C3` (`ret`) utasítás található. Ez stabil, szándékolt no-op levélcél a forráskori `void SetCommandLine(...)` slothoz; nincs utasításközepi célcím vagy bootstrap/final konfliktus. Saját `.pdata` rekordja nincs, ami egy stack-unwindot nem igénylő levélfüggvény mellett konzisztens.

### `.pdata` a fő vtable céljaihoz

| Target RVA | Runtime function | Unwind RVA | Megjegyzés |
|---:|---|---|---|
| `0x102110` | `0x102110–0x102136` | `0x2FFE954` | Destructor unwind |
| `0x2AA2110` | nincs saját rekord | — | Nincs stack-allokáló prologue; levélfüggvény |
| `0x2AA2120` | `0x2AA2120–0x2AA2150` | `0x2FF4F00` | `Release` stack unwindje |
| `0x101D70` | `0x101D70–0x101D80` | `0x2FF4F00` | `Initialize` |
| `0x1170` | nincs saját rekord | — | Egy bájtos `ret`; nincs stack-unwindot igénylő prologue |
| `0x51B20` | nincs rekord | — | Nincs stack-allokáló prologue |
| `0x101D80` | `0x101D80–0x101F44` | `0x3008F58` | `DoGameLoad` |
| `0x102140` | nincs rekord | — | Nincs stack-allokáló prologue |
| `0x102160` | nincs rekord | — | Nincs stack-allokáló prologue |

## 9. Privát interface vtable: `RVA 0x2C650B0`

Az `As` kivétel nélkül ezt a vptr-t adja vissza `0xFC203F1D` esetén. Az interface forráskori neve ebből a mintából nem állapítható meg.

| Slot | Target RVA | Target raw | Raw bytes | Statikus viselkedés | Státusz | Konfidencia |
|---:|---:|---:|---|---|---|---:|
| `0` | `0x102180` | `0x101580` | `56 48 83 EC 20 48 8B 35 04 E8 FD 02 48 85 F6` | A `0x30E0990` listából indul; minden csomópont `+0x38` objektumának vtable 2. slotját hívja `false` visszatérésig | Viselkedés AZONOSÍTOTT (P), név ismeretlen (U) | 0,75 |
| `1` | `0x1021C0` | `0x1015C0` | `E9 4B 94 B6 00 CC CC CC CC CC CC CC` | Ötbájtos tail jump az `RVA 0xC6B610` célra | AZONOSÍTOTT átirányítás | P (0,99) |

A második slot követő célja:

- Követő RVA: `0xC6B610`
- Követő raw: `0xC6AA10`
- Raw kezdőbytes: `55 41 57 41 56 41 55 41 54 56 57 53 48 81 EC`
- Runtime function: `0xC6B610–0xC819AF`
- Unwind RVA: `0x3063878`
- A nagy, vezérlésfolyam-kódolt függvény statikus értelmezése nem ad stabil, rövid API-szemantikát. **Státusz: FELTEVETT (U)**, konfidencia legfeljebb 0,25.

### Nem vtable-slot

Az `RVA 0x1021D0`, raw `0x1015D0` közvetlenül a privát vtable utáni, különálló kód. A `0x30E09A0` listát járja, és a csomópontok `+0x38` objektumának vtable 2. slotjának átad egy pointert. Ez az `RVA` **nem része** a `0x2C650B0` vagy `0x2C650C8` vtable-nek.

## 10. `OMComponent` vtable: `RVA 0x2C650C8`

Az `IsA` és `As` közvetlenül igazolja, hogy a `0x5D560A33` hash ehhez a beágyazott interface-hez vezet. Az upstream deklaráció szerint pontosan két virtuális metódusa van.

| Slot | Forráskori név | Target RVA | Target raw | Raw bytes | Státusz | Konfidencia |
|---:|---|---:|---:|---|---|---:|
| `0` | `CreateObjectInstance` | `0x102240` | `0x101640` | `41 57 41 56 41 55 41 54 56 57 55 53 48 83 EC 48` | AZONOSÍTOTT forrás- és bináris egyezéssel | P (0,99) |
| `1` | `GetImplementedClasses` | `0x102460` | `0x101860` | `55 56 57 48 83 EC 30 48 8D 6C 24 30 48 C7 45 F8` | AZONOSÍTOTT forrás- és bináris egyezéssel | P (1,00) |
| `+8` sentinel | `nullptr` | `0` | `0x2C63AD8` | `00 00 00 00 00 00 00 00` | AZONOSÍTOTT vtable-terminátor | P (1,00) |

### 10.1. `CreateObjectInstance`

Forráskori signature:

```cpp
result_t CreateObjectInstance(const guid_t& guid, const guid_t& iid, void** objectRef);
```

x64 ABI szerinti statikus szerepek:

- `RCX`: az `OMComponent` subobject, vagyis az eredeti objektum `+0x18`;
- `RDX`: `guid` pointer;
- `R8`: `iid` pointer;
- `R9`: kimeneti object pointer.

A kód igazolt viselkedése:

1. `[this+8]` az objektum `+0x20` mezőjét, vagyis az `m_impl` singleton blokkot adja.
2. A blokk `[0]` listája a factory-lista.
3. Ha a `guid` null GUID, a `matchingGuid` helyett az `iid` használódik; ezt a 16 bájt összefoglalása és a `cmove` igazolja.
4. A factory-lista minden bejegyzésének 16 bájtos azonosítóját összehasonlítja.
5. A kiválasztott factory által létrehozott objektumon interface-lekérdezést végez.
6. A temporary object reference-t a release mechanizmuson keresztül elengedi.
7. Ha a lekérdezés eredménye nem `FX_E_NOINTERFACE`, azonnal visszaadja azt.
8. Ha egyik factory sem ad megfelelő interface-t, `0x80004002`, azaz `FX_E_NOINTERFACE` kerül vissza.

**Státusz:** AZONOSÍTOTT (P), konfidencia 0,99. A factory- és release-sorrend upstream forrással is egyezik.

### 10.2. `GetImplementedClasses`

Forráskori signature:

```cpp
std::vector<guid_t> GetImplementedClasses(const guid_t& iid);
```

A nem triviális x64 return value miatt a tényleges gépi paramétereloszlás:

- `RCX`: `OMComponent` subobject;
- `RDX`: hidden return pointer egy 24 bájtos vectorhoz;
- `R8`: `iid` pointer.

A kód igazolt viselkedése:

1. A hidden return pointeren létrehoz egy üres `begin/end/capacity` triadot.
2. Az `m_impl+0x08` listából indul.
3. Minden bejegyzés első 16 bájtját az `iid`-vel hasonlítja.
4. Egyezéskor a bejegyzés következő 16 bájtját, vagyis a class GUID-ját másolja a vectorba.
5. A végén visszaadja a vektort.

**Státusz:** AZONOSÍTOTT (P), konfidencia 1,00. A 16 bájt GUID, a 24 bájtos vector és az `iid` szerinti szűrés binárisan is egyértelmű.

### `.pdata`

| Target RVA | Runtime function | Unwind RVA |
|---:|---|---:|
| `0x102240` | `0x102240–0x102458` | `0x30140FC` |
| `0x102460` | `0x102460–0x102581` | `0x3018084` |

## 11. Az `RVA 0x2C65030` priority/callback vtable

Ez a vtable nem az `object+0x00`, `object+0x10` vagy `object+0x18` mező. Az `RVA 0x101F50` függvény egy stack callback/leképező objektumhoz használja. Hat qword szélességű, majd az `RVA 0x2C65060` vtable következik.

| Slot | Target RVA | Target raw | Raw bytes | Statikus viselkedés | Státusz | Konfidencia |
|---:|---:|---:|---|---|---|---:|
| `0` | `0x102060` | `0x101460` | `48 89 D0 48 8D 15 C6 2F B6 02 48 89 10 0F B6 49 08` | Új destination vptr-jét a `0x2C65030` vtable-re állítja, majd az source `+0x8` bájtját másolja | Clone/copy adapter; AZONOSÍTOTT viselkedés (P) | 0,94 |
| `1` | `0x102060` | `0x101460` | `48 89 D0 48 8D 15 C6 2F B6 02 48 89 10 0F B6 49 08` | Ugyanaz a clone/copy adapter | AZONOSÍTOTT | P (0,94) |
| `2` | `0x102080` | `0x101480` | `56 48 83 EC 20 E8 F6 08 00 00 48 89 C6 E8 7E 16 F5 FF` | Obfuszkált callable; a statikus végén `AL=1` | Viselkedés VALÓSZÍNŰ (L) | 0,70 |
| `3` | `0x19A90` | `0x18E90` | `48 83 EC 28 E8 87 45 BD 02 0F 0B` | Az importált `abort`ot hívja, majd `ud2`; szándékos trap | AZONOSÍTOTT | P (1,00) |
| `4` | `0x1B360` | `0x1A760` | `84 D2 75 01 C3 BA 10 00 00 00 E9 A9 70 A9 02` | `DL=0` esetén `ret`, egyébként `0x10` bájtos deallokációs helperbe ugrás | AZONOSÍTOTT | P (1,00) |
| `5` | `0x19AF0` | `0x18EF0` | `48 8D 41 08 C3` | `this+0x08` pointert ad vissza | AZONOSÍTOTT | P (1,00) |

### `RVA 0x101F50` kapcsolata a prioritásos regisztrálóval

- `RVA 0x101F50`
- Raw: `0x101350`
- Raw kezdőbytes: `48 83 EC 68 48 8D 05 D5 30 B6 02 48 89 44 24 28`
- Runtime function: `0x101F50–0x101F78`
- Unwind RVA: `0x3014FC0`

A function:

1. stack objektum `+0x00` mezőjébe a `0x2C65030` vtable-t írja;
2. a stack objektum `+0x38` mezőjébe saját pointerét írja;
3. prioritás `0` mellett átadja az `RVA 0x908E0` regisztrálónak.

Az `RVA 0x908E0` (`raw 0x8FCE0`) a callbacket vtable 0. sloton keresztül klónozza, majd `0x58` bájtos prioritás-fába helyezi. A vtable `0x2C65030` és a `0x908E0` kapcsolata **AZONOSÍTOTT (P)**.

Az, hogy ez pontosan a forráskori `HookFunction` regisztrálója, **VALÓSZÍNŰ (L), de nem közvetlenül bizonyított**: az upstream `HookFunctionBase` egyszerű LIFO listát használ, míg a `0x908E0` prioritásos fa. Ezért a dokumentum nem azonosítja automatikusan a kettőt.

## 12. Bootstrap vtable: `RVA 0x2C650E0`

A `CreateComponent` ezt állítja be az allokáció után, majd a végleges `0x2C65060` vtable-re cseréli. A köztes célok valamelyikének közvetlen virtuális meghívása nem látható.

| Slot | Bootstrap cél RVA | Target raw | Raw bytes | Közvetlen jelentés | Státusz | Konfidencia |
|---:|---:|---:|---|---|---|---:|
| `0` | `0x34C80` | `0x34080` | `0F 0B 0F 0B` | `ud2`, majd `ud2`: szándékos trap | AZONOSÍTOTT | P (1,00) |
| `1` | `0x2AA2110` | `0x2AA1510` | `F0 FF 41 08 C3` | Ugyanaz az `AddRef` | AZONOSÍTOTT | P (1,00) |
| `2` | `0x2AA2120` | `0x2AA1520` | `48 83 EC 28 B8 FF FF FF FF F0 0F C1 41 08` | Ugyanaz a `Release` | AZONOSÍTOTT | P (1,00) |
| `3` | `0x51B20` | `0x50F20` | `B0 01 C3` | `true` | AZONOSÍTOTT | P (0,99) |
| `4` | `0x1170` | `0x570` | `C3` | Ugyanaz a közvetlen no-op `SetCommandLine` cél | AZONOSÍTOTT | P (1,00) |
| `5` | `0x51B20` | `0x50F20` | `B0 01 C3` | `true` | AZONOSÍTOTT | P (0,99) |
| `6` | `0x2BEDEA0` | `0x2BEC2A0` | `FF 25 CA 03 26 00` | Importthunk az IAT `0x2E4E270` slotjára; az import `_purecall` | AZONOSÍTOTT | P (1,00) |
| `7` | `0x51B20` | `0x50F20` | `B0 01 C3` | `true` | AZONOSÍTOTT | P (0,99) |
| `8` | `0x102140` | `0x101540` | `81 FA 33 0A 56 5D 0F 94 C1 81 FA 1D 3F 20 FC` | `IsA` | AZONOSÍTOTT | P (1,00) |
| `9` | `0x102160` | `0x101560` | `4C 8D 41 10 31 C0 81 FA 1D 3F 20 FC` | `As` | AZONOSÍTOTT | P (1,00) |

A bootstrap 0. slot közvetlen `ud2` trapokat tartalmaz, a 6. slot pedig `_purecall`: ezek klasszikus „ne hívd a még nem kész objektumot” őrök. A 4. slot közvetlen `0x1170` no-op célja nem ütközik a final vtable-qwordjával.

## 13. `IsA`, `As` és a két hash

### `IsA`

Feltételezett, de a kódból közvetlenül levezetett signature:

```cpp
bool IsA(Component* self, uint32_t typeId);
```

A `RVA 0x102140` két 32 bites összehasonlítást végez:

| Hash | Jelentés | Státusz | Konfidencia |
|---:|---|---|---:|
| `0x5D560A33` | `OMComponent` | AZONOSÍTOTT | P (1,00) |
| `0xFC203F1D` | privát interface | AZONOSÍTOTT az azonosítóra (P), név ismeretlen (U) | 1,00 |

### `As`

Feltételezett, de a kódból közvetlenül levezetett signature:

```cpp
void* As(Component* self, uint32_t typeId);
```

| `typeId` | Visszaadott érték | Státusz | Konfidencia |
|---:|---|---|---:|
| `0xFC203F1D` | `self+0x10` | AZONOSÍTOTT | P (1,00) |
| `0x5D560A33` | `self+0x18` | AZONOSÍTOTT | P (1,00) |
| más | `nullptr` | AZONOSÍTOTT | P (1,00) |

A kód a privát hashet előbb vizsgálja, majd az OM hashet; mivel a két konstans különböző, nincs ütközés.

## 14. Refcount és destrukció

### `AddRef`

```text
lock inc dword [this+8]
ret
```

- A referencia-szám a `+0x08` címen található 32 bites `DWORD`.
- Az allokáció értéke `0`.
- Nincs látható overflow-ellenőrzés vagy visszatérési érték.
- Az `AddRef` az `RVA 0x2AA2110` levélfüggvény.

### `Release`

A `RVA 0x2AA2120` atomi `xadd` művelettel `-1`-et ad a számlálóhoz. Az `eax` az előző értéket tartalmazza:

- ha a régi érték `1`, a primary vtable 0. slotját `EDX=1` értékkel hívja, majd `AL=1`-et ad vissza;
- ha a régi érték nagyobb `1`, `AL=0`;
- a `0xFFFFFFFF` régi érték, azaz alulfutás, nem indít destrukciót, mert az `unsigned` összehasonlítás `>1`.

### Destructor

Az `RVA 0x102110`:

1. elmenti a `this` pointert;
2. elmenti a delete flaget;
3. a primary vptr-t a `0x2BF0168` RVA-jú bázisvtable-re állítja;
4. csak `delete=1` esetén hívja az `RVA 0x2AB2410` felszabadítót.

A látható destrukció:

- nem törli a `0x10` bájtos OM singleton blokkot;
- nem üríti a globális OM listákat;
- nem hívható explicit konstruktor-/operátor-destruktort az objektum más részeire, mert a `0x28` bájtos memóriában nincs más látható tulajdonolt erőforrás.

## 15. `Initialize`, `DoGameLoad` és a hook-kapcsolat

### `Initialize` – slot 3

A `RVA 0x101D70` az `RVA 0x2A9F380` helperre hív, majd `AL=1`-et ad vissza.

Az `RVA 0x2A9F380`:

- raw: `0x2A9E780`;
- a `RVA 0x3306F80` prioritásos fa headjét olvassa;
- minden csomópont vtable 0. slotját meghívja;
- csomópontonként `node+0x8` következő pointerre lép.

A közvetlenül következő beszúró `RVA 0x2A9F330` a `+0x10` mezőben tárolt prioritás szerint rendez. Az upstream `ComponentInstance::Initialize()` ehhez `InitFunctionBase::RunAll()`-t hív. A helper pontos forráskori neve ezért **VALÓSZÍNŰ (L)**, 0,94.

### `DoGameLoad` – slot 7

A `RVA 0x101D80` a legjobban obfuszkált lifecycle-cél:

- több, különböző globális konstansból és helperből számított vezérlési célra ugrál;
- a közvetlen lineáris utasításfolyamat nem ad stabil közvetlen `HookFunction::RunAll` hívást;
- a normál végén `AL=1`.

Az upstream `citizen-resources-core` `ComponentInstance::DoGameLoad()` törzse:

1. `HookFunction::RunAll()`;
2. `return true`.

A vtable-sorrend, a `true` végpont és az upstream törzs együtt forráskohoz konzisztens `DoGameLoad` slot-azonosítást ad, de nem bizonyítja, hogy a binárium belső obfuszkált dispatche a jelenlegi `HookFunction::RunAll()` implementációt hívja. A konkrét belső call target nyitott marad.

### `HookFunction::RunAll` kapcsolatának mérlege

| Állítás | Státusz | Konfidencia |
|---|---|---:|
| A `DoGameLoad` upstream megvalósítása `HookFunction::RunAll()`-t tartalmazza | AZONOSÍTOTT forráskori | P (0,99) |
| A bináris 7. slot a `DoGameLoad` | AZONOSÍTOTT vtable-sorrend és source cross-check | P (0,99) |
| Az `RVA 0x2A9F380` az `Initialize` által használt prioritásos runner | VALÓSZÍNŰ (L) | 0,94 |
| Az `RVA 0x2A9F380` közvetlenül a `HookFunction::RunAll` | FELTEVETT (U), és a prioritásos fa miatt valószínűleg nem | 0,15 |
| Az `RVA 0x101F50` ugyanazt a hook-listát tölti, amelyet a `DoGameLoad` futtat | FELTEVETT (U) | 0,40 |
| Az `RVA 0x101F50` ugyanazt a prioritásos fát tölti, amelyet az `Initialize` futtat | VALÓSZÍNŰ (L) | 0,75 |

A biztonságos statikus állítás az, hogy a slot és a forrásszintű lifecycle-kapcsolat azonosított, de az obfuszkált `DoGameLoad` belső célát nem szabad tévesen a prioritásos `Initialize` helperhez kötni.

## 16. Exception és unwind

### `CreateComponent`

| Adat | Érték |
|---|---:|
| Runtime function | `0x101F80–0x10202B` |
| `.pdata` record RVA | `0x2E5FDF8` |
| `.pdata` record raw | `0x2E5E7F8` |
| Unwind RVA | `0x301801C` |
| Unwind raw | `0x3016A1C` |
| Unwind header raw bytes | `19 0B 04 35 0B 03 06 62 02 60 01 50` |
| Exception handler | `RVA 0x2BEDE10`, raw `0x2BEC210` |
| Handler import | `__CxxFrameHandler3` az IAT `0x2E4E230` slotján |

A `0x19` unwind fejléc:

- unwind version 1;
- EH- és termination-handler flag beállítva;
- a scope/handler-leírás C++ kivételkezelésre mutat.

A function elején az `RBP-`-rel képzett helyre `0xFFFFFFFFFFFFFFFE` kerül. Ez az MSVC EH/GS unwind-állapot sentinelje, nem a `CreateComponent` által végzett explicit security-cookie-ellenőrzés.

### Kivételkezelési következmény

- A `0x28`-os és `0x10`-es objektumallokáció kivételt képes dobni.
- A straight-line kódban nincs látható `catch`, HRESULT-fallback vagy `nullptr` visszaadás.
- Ha az első allokáció sikerül, a második hibája nem láthatóan szabadítja fel explicit módon az első objektumot; egy esetleges C++ cleanup-funclet viszont a nyelvi unwind adattá tartozhat.
- A dokumentum nem állítja, hogy kivétel esetén leak vagy duplikált cleanup biztos; ehhez a teljes EH scope-table és runtime viselkedés kellene.

### Releváns további unwind-rekordok

| Function | Runtime range | Unwind RVA | Unwind raw |
|---|---|---:|---:|
| destructor | `0x102110–0x102136` | `0x2FFE954` | `0x2FFD354` |
| `Release` | `0x2AA2120–0x2AA2150` | `0x2FF4F00` | `0x2FF3900` |
| `Initialize` | `0x101D70–0x101D80` | `0x2FF4F00` | `0x2FF3900` |
| `DoGameLoad` | `0x101D80–0x101F44` | `0x3008F58` | `0x3007D58` |
| privát interface 0 | `0x102180–0x1021BA` | `0x2FF7034` | `0x2FF5A34` |
| privát interface 1 follow | `0xC6B610–0xC819AF` | `0x3063878` | `0x3062278` |
| OM 0 | `0x102240–0x102458` | `0x30140FC` | `0x3012AFC` |
| OM 1 | `0x102460–0x102581` | `0x3018084` | `0x3016A84` |
| `DoGameLoad` előtti `Initialize` runner | `0x2A9F380–0x2A9F3A9` | `0x2FF52B8` | `0x2FF36B8` |

Az `AddRef`, `SetCommandLine`, `SetUserData`, `Shutdown`, `IsA` és `As` levélfüggvények; nincs saját `.pdata` rekordjuk. Ez x64-en normális lehet, ha nincs stack-unwindot igénylő prologue.

## 17. Lehetséges lifecycle és szemantikai sorrend

Ez a lifecycle leírása, nem végrehajtási útmutató.

### 17.1. Globális előkészítés

1. Az OM singleton még nem szükséges a korábbi globális listák inicializálásához.
2. A `0x30E0990` és `0x30E09A0` globális állapot nullázódik és teardown-regisztrációt kap.
3. Az OM factory- és implements-definíciók statikus életciklusa más kódútvonalakon kezdődhet.

### 17.2. Példánylétrehozás

1. `CreateComponent` nullázott `0x28` bájtos objektumot készít.
2. A bootstrap vtable csak köztes konstrukciós állapot.
3. Az OM subobject és a közös OM registry singleton bekerül.
4. A végleges primary vtable aktíválódik.
5. A referencia-szám még `0`.

### 17.3. Külső tulajdonosi átvétel – forráskori contract

1. A `CreateComponent` export nem hívja meg az `AddRef` slotot; az objektum a visszaadáspontban `0` referenciaszámmal létezik.
2. A forráskori `fwRefContainer` ownership contract szerint a külső framework `AddRef`-et és `SetUserData`-t is hívhat; ez a konkrét hívási sorrend nem látható a specimenben.
3. A vizsgált `SetUserData` cél közvetlenül `true`-t ad és nem használja a string argumentumot; a `0x28` bájtos objektumban nincs látható tárolási mező.

### 17.4. Inicializálás – forráskori contract szerinti sorrend

1. Külső tulajdonosi átvételkor az `AddRef` slot növeli a `+0x08` referencia-számot; a specimen önmagában nem igazolja, hogy ez megtörténik.
2. A `Initialize` slot közvetlenül a prioritásos runnert hívja, majd `true`-t ad.
3. A runner a prioritásos fa callbackjeit sorban hívja; ez közvetlenül látható.
4. A komponens `true`-t jelez.

### 17.5. Game load – forráskori contract

1. A forráskori lifecycle contract szerint a loader később, külön fázisban éri el a `DoGameLoad` slotot; a konkrét host-hívás nem statikusan bizonyított.
2. A forráskori implementáció a `HookFunction` listáját futtatja.
3. A bináris `DoGameLoad` belső dispatch erősen obfuszkált, de `true`-t ad vissza.

### 17.6. Leállás és felszabadítás

1. A `Shutdown` `true`-t ad vissza.
2. A tulajdonos csökkenti a referenciaszámot.
3. Az utolsó `Release` meghívja a deleting destructort.
4. A destructor nem törli a process-globális OM singleton blokkot.

### 17.7. Típuslekérdezés

- `IsA` és `As` a végleges vtable kialakítása után értelmezhetők.
- Az `As` két beágyazott subobject pointert ad vissza; az OM pointer nem egyezik meg az elsődleges `Component` pointerrel.
- Ismeretlen hash esetén `IsA=false`, `As=nullptr`.

## 18. Thread- és állapotkezelési megjegyzések

1. **OM singleton:** a `0x30E09B0` lazy inicializálása `test`/`new`/`store` sorrendű, lock nélkül. Két párhuzamos első példánylétrehozás elméletileg két blokkot allokálhat; a gyorsítható global pointer közben csak az utolsóként store-olt blokkra mutathat. **Státusz: VALÓSZÍNŰ (L)**, 0,85.
2. **Referenciaszám:** a nullázás és az első `AddRef` között nincs explicit publikálási mechanizmus a `CreateComponent` törzsében. Az életciklus feltételez egy külső framework-szerinti átvételi sorrendet.
3. **OM listák:** a bináris singleton és a látható listamódosítások körül nincs látható mutex. Az upstream forrás is egyszerű, lock nélküli listakezelést használ az OM definíciók számára.
4. **Hook lifecycle:** a `DoGameLoad` globális hook-listájának módosítása és futtatása közötti konkrét szinkron nem állapítható meg ebből a korlátozott statikus nézetből.

## 19. Bizonyíték-erősségű összefoglaló

### Magas konfidencia, azonosított

- `CreateComponent` export, RVA és nullaargumentumos x64 viselkedése.
- `0x28` bájtos objektum és minden mező kezdeti értéke.
- Vtable-címek és az össze nem nullázott slot-targetek.
- `AddRef`, a `0x1170` no-op `SetCommandLine`, `Release`, destructor, `IsA` és `As` gépi viselkedése.
- `0x5D560A33` → `object+0x18` és `0xFC203F1D` → `object+0x10` mapping.
- OM factory-lista, implements-lista és `GetImplementedClasses` 16 bájtos GUID-szűrése.
- `CreateComponent` C++ unwindja és `__CxxFrameHandler3` használata.
- `RVA 0x2C65030` callback vtable és `RVA 0x908E0` prioritásos regisztráló kapcsolata.

### Közepes konfidencia, valószínű

- Az `RVA 0x2A9F380` pontos neve `InitFunctionBase::RunAll`.
- Az `RVA 0x101F50` a konkrét upstream hook-regisztráló adapterének felel meg.
- A privát `0xFC203F1D` interface forráskori osztályneve.

### Alacsony konfidencia, feltételezett

- Az `RVA 0xC6B610` privát interface metódusának pontos szerzői neve.
- A `0x2C65030` callback-vtable 2–5. slotjainak forráskori szerzői neve.
- A `DoGameLoad` obfuszkált belső közvetlen call targetje.

## 20. Végkövetkeztetés

A `CreateComponent` egy ismert CitizenFX component-vázat állít elő, amely a `Component` lifecycle-ot, egy 32 bites refcountot, egy második privát interface-et és az `OMComponent` adaptert egyetlen `0x28` bájtos objektumban egyesíti. A legfontosabb rekonstrukciós eredmények a végleges `0x2C65060` primary vtable, a `0x2C650B0` privát vtable, a `0x2C650C8` OM vtable, a `0x30E09B0` OM singleton, valamint a közvetlen hash-to-interface mapping. Az `Initialize` és `DoGameLoad` forráskori nevei a vtable-sorrendből azonosíthatók, de a `DoGameLoad` belső obfuszkált dispatchét nem szabad a hasonló prioritás-futóval tévesen azonosítani.

## 21. `P` / `L` / `U` jelölési összegzés

Ez a blokk a dokumentum confidence-jelölésének konformancia-javítását rögzíti, nem új evidence-ot ad hozzá.

- **Hatókör:** a dokumentum összes `66` számszerű confidence-értéket hordozó finding- és konfidenciasora, továbbá `2` olyan prose finding, amely a dokumentum saját `AZONOSÍTOTT` / `VALÓSZÍNŰ` / `FELTEVETT` skáláját használja számszerű érték nélkül (3. fejezet, 11. fejezet). Összesen `68` jelölt tétel.
- **Alkalmazott megfeleltetés:** `AZONOSÍTOTT` = `P`, `VALÓSZÍNŰ` = `L`, `FELTEVETT` = `U`, az `adhesive-00-index.md` 6. fejezetének globális szerződése szerint.
- **Elhelyezés:** egyszerű soron a `Konfidencia` oszlopban, `P (1,00)` alakban; több pontból álló findingnél a `Státusz` oszlopban, az egyes pontokat minősítő szöveg után, `(P)`, `(L)`, `(U)` alakban.
- **Pontszintű egyértelműség:** a `8` összetett finding mindkét pontja külön betűjelölést kapott, így egyik sor sincs egyetlen pontra visszavezetve.
- **Darabszám:** `P` = `59`, `L` = `9`, `U` = `8` betűjelölés, összesen `76` jelölés a `68` tételen; a darabszám a finding-sorokra vonatkozik, az 1. és a 21. fejezet jelölési magyarázata nem finding, ezért nem számít bele.
- **Változatlanul maradt:** minden számszerű confidence-érték (`0,15`–`1,00`), minden RVA, raw offset, vtable-cím, slot-szám, hash, kulcsliteral és a `Státusz` oszlop szövege. A vizsgálati határ változatlan: a DLL-t ez a blokk sem futtatta, nem töltötte be és nem patchelté; új evidence-fájl nem keletkezett, és nincs benne exploit-, bypass- vagy patch-recept.
