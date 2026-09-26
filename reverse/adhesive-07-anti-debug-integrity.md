# `adhesive.dll` — anti-debug, process-query, tamper és integrity

## 1. Vizsgálati hatókör és módszertan

- **Artifact:** `reverse/adhesive.dll`
- **SHA-256:** `91cc0aa006d7315cb042c8fa8dca6c1e074a307bba7dcc9eb5509c8a7b81934e`
- **Méret:** `53 575 264` byte (`0x3317E60`)
- **Formátum:** PE32+ / AMD64 DLL
- **Image base:** `0x180000000`
- **Entry point RVA:** `0x2AB2770`
- **PE time stamp:** `0x6AA418EA` — 2026-09-11 15:06:18 UTC
- **Elemzés:** kizárólag statikus fájl- és PE-parse, importtábla-, sztring-, IAT-xref-, `.pdata`- és Capstone/objdump-disasszemblálás.
- **Vizsgálati határ:** a DLL-t nem töltöttem be és nem futtattam; dinamikus hook-, bypass- vagy patch-próbát nem végeztem.
- **RVA:** a PE képbeli relatív virtuális cím.
- **Raw:** nulla alapú fájloffset a `reverse/adhesive.dll` fájlban.
- **Megállapítás:** a `0F 05` opcode önmagában nem szolgáltatásazonosítás, de a célzott helyeken a `.pdata`-függvényhatár, az argumentumregiszterek és az eredményfeldolgozás együtt közvetlen statikus bizonyítékot ad.
- **Confidence:** `Magas` = közvetlen, helyesen validált utasítás- és adatfolyam; `Közepes` = a mechanizmus magas, de a pontos Nt-szolgáltatásnév, a caller vagy a runtime-elérhetőség nyitott; `Alacsony` = a jel jelen van, de az önálló anti-debug szándék nem igazolt.

A `.text` nagy része lokalizáltan erős opaque-transform/CFF-jelű kódot tartalmaz. A jelentés ezért a teljes CFG rekonstrukciója helyett a konkrét, reprodukálható utasítás- és argumentumláncokat minősíti observed evidence-nek.

## Felülírt részek

Kizárólag visszirányú navigáció: a feltüntetett szöveghelyek egyike sem módosult, a blokk csak megmutatja, mely későbbi dokumentum az érvényes. Ahol ellentmond, a jobb oldali dokumentum élvez elsőbbséget; az itt maradó szöveg történeti állítás, nem ellenkező állítás. Jelölés: `P` = proven, `L` = likely, `U` = unknown.

| Itt érintett szakasz / állítás | Felülíró forrás | CONF | Forrás evidence |
|---|---|---|---|
| §3.1 `ProcessBasicInformation` osztályozás (a `0xD7A400` három hely az `other` csoportba esik); §3.3 `7`, `0x1E`, `0x1F` process-debug osztályok; §3.4 class `0x28` (8 közvetlen + 6 segéd hely); §7.1 valódi `RDTSC` dispatch | `15` §8 anchor-csoportok, §9 producer-kind cenzus, §14 `N-01`–`N-05`, §16 `B15-15`–`B15-18` | `P` a számlálásra, `U` a szolgáltatásnévre | `reverse/evidence/syscall_inventory.csv` (3 627 sor / 106 oszlop), `syscall_arg_classes.json`, `syscall_service_map.json`, `audit_syscall_candidates.json` |
| §2 „Javított összegzés" Nt-s szolgáltatásnév-implicit; §3.3–§3.4 mapping-állítása; §9 negatívumai | `15` §10 és §14 `N-01`: mind a 3 627 sor `nt_service = UNRESOLVED`, `nt_confidence = none`; a naming gate sosem ért el a névágat. A `07` class- és argumentumkompatibilitási minősítése ettől változatlanul érvényes | `P` a negatív findingra, `U` a névre | `reverse/evidence/syscall_service_map.json` (28 check), `syscall_inventory.csv` |
| §6.1, §6.2 Toolhelp telepítő/visszaállító; §6 „szimmetrikus" és „nem állítja vissza az oldalvédelmet" minősítése; §9 „Toolhelp telepítő/visszaállító párhoz nem igazolt a közvetlen hívó" pontja | `16` §6.3, §12/12., §12/14., §12/15.: a célcím a `0x317E398` írható cache globálist olvassa, `symmetry_target_source` = `ASYMMETRIC`, a telepítő a régi védelmet a hívó rekord `+0x10` mezőjébe adja át | `P` | `reverse/evidence/patch_mechanisms_helpers.csv` (`symmetry_*`), `thread_context_map.json` |
| §6 nyitott kérdés (a telepítő közvetlen hívója és aktiválása); az APC-részletek, amelyeket ez a dokumentum nem tartalmaz | `16` §13.0 (a hiány `P`, a „nem fut" következtetés `L`), továbbá §8.1–§8.4 a hét `QueueUserAPC` ágról; az APC-cél `RVA 0x1170` a `06` §6-ban is dokumentált | `P` a hiányra, `L` a következtetésre, `U` a kapcsoló írójára | `reverse/evidence/patch_mechanisms_helpers.csv`, `apc_sites.csv`, `unresolved_regions.json` |

## 2. Javított összegzés

| Terület | Statikus eredmény | Értékelés |
|---|---|---|
| Natív process query | `ProcessBasicInformation`, `ProcessDebugPort=7`, `ProcessDebugObjectHandle=0x1E` és `ProcessDebugFlags=0x1F` syscallos ágak | A három debug-class erős anti-debug képesség; a négy top-level rutinnak nincs közvetlen statikus hívója |
| Parent PID | `PROCESS_BASIC_INFORMATION` kimenet `+0x28` mezője kerül az `OpenProcess` PID-argumentumába | Magas confidence; a kért jog `0x1000`, azaz `PROCESS_QUERY_LIMITED_INFORMATION` |
| `NtSetInformationProcess` class `0x28` | Nyolc közvetlen és hat segéd-`syscall` ág `R10=-1`, `EDX=0x28`, `R9=0x10` és 16 bájtos, kezdetben nullázott bufferrel | A `ProcessInstrumentationCallback`-kompatibilis hívás pozitív; nem null callback telepítését, hanem null adatot mutat |
| CoreRT resolver | A két module-feloldó ág `GetModuleHandleW`-t és `GetProcAddress`-et használ | A korábbi `GetModuleHandleA`/típushiba állítás téves |
| `IsDebuggerPresent` | Egy közvetlen IAT-hívás az MSVC/UCRT fatal-error/unwind útvonalon | Valós debugger-state API, de nem önálló anti-debug check |
| Toolhelp | `CreateToolhelp32Snapshot` export inline felülírását és visszaállítását végző pár | Erős anti-enumerációs képesség; közvetlen telepítőhívó nem igazolt |
| RDTSC/PEB | Több valódi `RDTSC; and eax,0xf` dispatch és több `GS:[0x30]`→PEB hozzáférés | Nem pusztán literál- vagy timing-jel; szolgáltatásszám-keverést és process-debug állapotfeldolgozást dokumentál |
| Integrity | A PE checksum konzisztens; PKCS#7 security blob jelen van; saját checksum/signature runtime self-check nincs igazolva | Statikus fájlintegritás és a kódképviselet elkülönítendő |

## 3. Natív process-information syscallok

A standard és delay importtáblában nincs `NtQueryInformationProcess` vagy `NtSetInformationProcess` név, és a fájlban nincs ezek ASCII/UTF-16 literálja. Ez nem zárja ki a közvetlen syscallokat. Az alábbi syscall-számokat (`EAX`) a kód `KUSER_SHARED_DATA`, globális konstansok, TEB/PEB és keverő műveletek segítségével állítja elő.

### 3.1 `ProcessBasicInformation`

Három közvetlen `0F 05` hely található ugyanabban a `.pdata`-függvényben:

| `syscall` RVA | Raw | Közvetlen argumentumkészlet |
|---:|---:|---|
| `0xD7B0AE` | `0xD7A4AE` | `R10=-1`, `EDX=0`, `R8=RBP`, `R9D=0x30`, ötödik argumentum `NULL` |
| `0xD7B4B9` | `0xD7A8B9` | `R10=-1`, `EDX=0`, `R8=RBP`, `R9D=0x30`, ötödik argumentum `NULL` |
| `0xD7C0AC` | `0xD7B4AC` | `R10=-1`, `EDX=0`, `R8=RBP`, `R9D=0x30`, ötödik argumentum `NULL` |

Az első két előkészítés például:

```text
0xD7B08A  49 C7 C2 FF FF FF FF       mov r10, -1
0xD7B091  31 D2                      xor edx, edx
0xD7B098  49 89 E8                   mov r8, rbp
0xD7B09B  41 B9 30 00 00 00          mov r9d, 0x30
0xD7B0A5  48 C7 44 24 28 00...00    mov qword ptr [rsp+0x28], 0
0xD7B0AE  0F 05                      syscall
```

A `0xD7A400–0xD7CF5B` RUNTIME_FUNCTION-bejegyzésen belüli, a későbbi `RBP+0x28` olvasással együtt ez három `NtQueryInformationProcess(ProcessBasicInformation)`-kompatibilis ágat bizonyít. A service number nincs közvetlen konstansként kiolvasható, de az ABI, a 48 bájtos kimeneti buffer és a parent-PID mezőhasználat együtt magas confidence.

### 3.2 Parent PID és `OpenProcess`

| Jel | RVA | Raw | Nyers utasítás / érték |
|---|---:|---:|---|
| Parent PID olvasása | `0xD7B863` | `0xD7AC63` | `44 8B 45 28` — `mov r8d, dword ptr [rbp+0x28]` |
| Kért jog | `0xD7B867` | `0xD7AC67` | `B9 00 10 00 00` — `0x1000` |
| `bInheritHandle` | `0xD7B86C` | `0xD7AC6C` | `31 D2` — `FALSE` |
| `OpenProcess` | `0xD7B86E` | `0xD7AC6E` | `FF 15 4C 1C 0D 02` |
| `OpenProcess` IAT | `0x2E4D4C0` | `0x2E4BEC0` | `KERNEL32.dll!OpenProcess` |
| Eredmény mentése | `0xD7B874–0xD7B879` | `0xD7AC74–0xD7AC79` | Az output-pointerre kerül a handle |

A `PROCESS_BASIC_INFORMATION.InheritedFromUniqueProcessId` mező az x64 struktúrában `+0x28`, ezért a korábbi „nincs parent PID” megállapítás cáfolt. A `0x1000` jog kifejezetten `PROCESS_QUERY_LIMITED_INFORMATION`; önmagában nem ad `PROCESS_VM_OPERATION` vagy `PROCESS_VM_WRITE` jogot. A callhelyen nincs azonnali `NULL`-ellenőrzés vagy `GetLastError`.

### 3.3 Process-debug query classok

Három külön, nincs függvényargumentumot fogadó, `RDTSC & 0xF` ágfelosztó top-level rutin található:

| Osztály | Top-level RVA / raw | `RDTSC` RVA / raw | Buffer és hossz | Közvetlen `syscall` RVA / raw párok |
|---|---|---|---|---|
| `ProcessDebugPort=7` | `0x293EF20–0x293FDE3` / `0x293E320–0x293F1E3` | `0x293EF3F` / `0x293E33F` | 8 bájtos qword, kezdetben `-1`; `R10=-1` | `0x293F124/0x293E524`, `0x293F2ED/0x293E6ED`, `0x293F4B8/0x293E8B8`, `0x293F73D/0x293EB3D`, `0x293F8CF/0x293ECCF`, `0x293FA42/0x293EE42`, `0x293FC0B/0x293F00B`, `0x293FDA9/0x293F1A9` |
| `ProcessDebugObjectHandle=0x1E` | `0x293FDF0–0x2940CB5` / `0x293F1F0–0x29400B5` | `0x293FE0F` / `0x293F20F` | 8 bájtos handle, kezdetben nulla; `R10=-1` | `0x293FFF4/0x293F3F4`, `0x29401BD/0x293F5BD`, `0x2940388/0x293F788`, `0x294060D/0x293FA0D`, `0x294079F/0x293FB9F`, `0x2940912/0x293FD12`, `0x2940ADB/0x293FEDB`, `0x2940C79/0x2940079` |
| `ProcessDebugFlags=0x1F` | `0x293E060–0x293EF20` / `0x293D460–0x293E320` | `0x293E07E` / `0x293D47E` | 4 bájtos ULONG, kezdetben `1`; `R10=-1` | `0x293E263/0x293D663`, `0x293E42C/0x293D82C`, `0x293E5F7/0x293D9F7`, `0x293E87C/0x293DC7C`, `0x293EA0E/0x293DE0E`, `0x293EB81/0x293DF81`, `0x293ED4A/0x293E14A`, `0x293EEE8/0x293E2E8` |

A közvetlen ágak argumentumai következetesen:

```text
R10 = -1                  NtCurrentProcess pseudo-handle
EDX = ProcessInformationClass
R8  = helyi kimeneti buffer
R9D = 8 vagy 4
[rsp+0x28] = NULL         opcionális ReturnLength
```

Egy közvetlen `ProcessDebugObjectHandle` ág:

```text
0x293FFD0  4C 8D 44 24 38             lea r8, [rsp+0x38]
0x293FFD5  49 C7 C2 FF FF FF FF       mov r10, -1
0x293FFDC  BA 1E 00 00 00             mov edx, 0x1e
0x293FFE1  41 B9 08 00 00 00          mov r9d, 8
0x293FFEB  48 C7 44 24 28 00...00    mov qword ptr [rsp+0x28], 0
0x293FFF4  0F 05                      syscall
```

Eredményfeldolgozás:

- **DebugPort:** a syscall `EAX` értékét a PEB-be írja; siker esetén a 8 bájtos portértéket, negatív NTSTATUS esetén `-1`-et ad vissza.
- **DebugObjectHandle:** `0x2940C8B` `0xC0000353`-hoz hasonlítja a státuszt, `0x2940C93` a handle nullát, majd a kettő logikai OR-ját adja vissza.
- **DebugFlags:** a `0x293EEFA–0x293EEF7` ág a negatív státuszt és a `0x293EEFF` körüli kimeneti értéket egyetlen logikai eredménnyé vonja össze.

A class- és argumentumazonosítás `NtQueryInformationProcess`-kompatibilis és magas confidence. A négy top-level process-query/set rutinnál nem találtam közvetlen `E8 rel32` callsite-ot vagy megbízható, nem `.pdata`-származékú statikus függőpointert. A felsorolt 32 bites előfordulások a kivételkezelési funkcióhatár-táblázat bejegyeei. Ezért a mechanizmus observed, a konkrét runtime-elérhetőség latent.

### 3.4 `NtSetInformationProcess(ProcessInstrumentationCallback)`, class `0x28`

A `0x293D370–0x293E058` top-level rutin (`raw 0x293C770–0x293D458`) a belépéskor 16 null bájtot készít, majd egy 16 elemű `RDTSC` ágtáblát használ. Nyolc ág közvetlenül, további ágok hat segédrutinán keresztül hajtják végre ugyanazt a kompatibilis Nt-s hívást.

| Argumentum | Közvetlen ág | Segéd-`syscall` ágak |
|---|---|---|
| `R10` | `0xFFFFFFFFFFFFFFFF` | `0xFFFFFFFFFFFFFFFF` |
| `EDX` | `0x28` | `0x28` |
| `R8` | `&[RSP+0x20]`, a 16 bájtos nullákkal inicializált buffer | Az `RCX`-ből átvitt bufferpointer |
| `R9D` | `0x10` | `0x10` |

Közvetlen syscallok:

| `syscall` RVA | Raw |
|---:|---:|
| `0x293D4DE` | `0x293C8DE` |
| `0x293D63D` | `0x293CA3D` |
| `0x293D7FC` | `0x293CBFC` |
| `0x293DA15` | `0x293CE15` |
| `0x293DBF5` | `0x293CFF5` |
| `0x293DD1D` | `0x293D11D` |
| `0x293DE7C` | `0x293D27C` |
| `0x293E030` | `0x293D430` |

A hat dedikált segédrutin syscallja:

| Segédrutin RVA | `syscall` RVA | Raw |
|---:|---:|---:|
| `0x29418D0` | `0x2941AC2` | `0x2940EC2` |
| `0x2941AF0` | `0x2941CB7` | `0x29410B7` |
| `0x2941CC0` | `0x2941DEB` | `0x29411EB` |
| `0x2941E10` | `0x2941FCF` | `0x29413CF` |
| `0x2941FF0` | `0x294212A` | `0x294152A` |
| `0x2942150` | `0x29422AA` | `0x29416AA` |

Egy közvetlen ág:

```text
0x293D4C3  4C 8D 44 24 20             lea r8, [rsp+0x20]
0x293D4C8  49 C7 C2 FF FF FF FF       mov r10, -1
0x293D4CF  BA 28 00 00 00             mov edx, 0x28
0x293D4D4  41 B9 10 00 00 00          mov r9d, 0x10
0x293D4DE  0F 05                      syscall
```

A service number itt kevert, ezért az API-név nem importnévből vagy közvetlen állandó syscall-számból származik. A `current process + class 0x28 + 16 bájtos {Version, Reserved, Callback} descriptor` kombináció azonban erősen `ProcessInstrumentationCallback`-kompatibilis `NtSetInformationProcess` műveletet azonosít.

A 16 bájtos buffer a belépési `xorps/movaps` után nem kap nemnulla callback-címet. Ezért a finding **nem** annak bizonyítéka, hogy a modul saját instrumentation callbacket telepít; a statikus payload null descriptor. A syscall `EAX` státuszt a `0x293E03F` utasítás a `PEB+0x68` mezőbe írja. A top-level rutinnak nincs közvetlen statikus callsite-ja, így a class `0x28` képessége pozitív, a konkrét időzítés és eredmény nyitott.

## 4. CoreRT debugger resolver — az IAT-típus javítva

### 4.1 Literálok

| Tartalom | RVA | Raw | Nyers kezdőbajtok |
|---|---:|---:|---|
| `CoreIsDebuggerPresent` hivatkozott példány | `0x2E0CBED` | `0x2E0B5ED` | `43 6F 72 65 49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6E 74 00` |
| Második ASCII példány | `0x2E25C88` | `0x2E24688` | ugyanaz |
| UTF-16 `CoreRT.dll` | `0x2E1F7FA` | `0x2E1E1FA` | `43 00 6F 00 72 00 65 00 52 00 54 00 2E 00 64 00 6C 00 6C 00 00 00` |

### 4.2 A két debugger-feloldó ág

| Lépés | Első RVA / raw | Második RVA / raw |
|---|---:|---:|
| UTF-16 `CoreRT.dll` pointer | `0x52D3/0x46D3` | `0x5C2A/0x502A` |
| Modulfeloldó call | `0x52DA/0x46DA` | `0x5C31/0x5031` |
| Nyers call | `FF 15 B0 80 E4 02` | `FF 15 59 77 E4 02` |
| Feloldott IAT-cél | `0x2E4D390` | `0x2E4D390` |
| IAT név | `GetModuleHandleW` | `GetModuleHandleW` |
| `CoreIsDebuggerPresent` pointer | `0x52E0/0x46E0` | `0x5C37/0x5037` |
| `GetProcAddress` | `0x52EA/0x46EA` | `0x5C41/0x5041` |
| Feltételes pointerhívás | `0x52FC/0x46FC` | `0x5C53/0x5053` |
| Igaz eredmény → `INT3` | `0x5302/0x4702` | `0x5C59/0x5059` |

A `GetModuleHandleW` IAT RVA `0x2E4D390`, raw `0x2E4BD90`; a `GetModuleHandleA` IAT RVA `0x2E4D380`, raw `0x2E4BD80`. A fenti két call nem az A-változathoz mutat. Mindkettő `GetModuleHandleW`, ezért a korábbi UTF-16/ANSI típushiba és az ebből következő „alaphelyzetben inaktív” minősítés nem állja meg a helyét.

A function-pointer cache RVA `0x30D4288`, raw `0x30D2C88`, kezdetben `00 00 00 00 00 00 00 00`. A resolver elmenti a `GetProcAddress` eredményét; a `0x5302`/`0x5C59` `INT3` csak akkor következik, ha a feloldott CoreRT-függvény nem nulla értéket ad vissza.

A `0x4D20` resolver-funkciónak közvetlen hívói vannak RVA `0x4C5D` és `0x5950`; a `0x5BB0` duplikált segédet a `0x4D20` belülről hívja. A statikus call graph tehát nem tekinthető elérhetetlennek. CoreRT betöltése, az export elérhetősége, a pointer tárolása és az `INT3` ág tényleges lefutása továbbra is runtime-függő.

## 5. Közvetlen `IsDebuggerPresent`

| Jel | RVA | Raw | Nyers utasítás / kontextus |
|---|---:|---:|---|
| `IsDebuggerPresent` IAT | `0x2E4D458` | `0x2E4BE58` | `KERNEL32.dll!IsDebuggerPresent` |
| Közvetlen call | `0x2AE1008` | `0x2AE0408` | `FF 15 4A C4 36 00` |
| Pdata | `0x2AE0F10–0x2AE1058` | `0x2AE0310–0x2AE0458` | MSVC/UCRT fatal-error helper |

A `.text` közvetlen `call [IsDebuggerPresent-IAT]` utasításainak száma egy. A környező blokk:

1. `IsProcessorFeaturePresent(0x17)`;
2. `RtlCaptureContext`;
3. `RtlLookupFunctionEntry` és `RtlVirtualUnwind`;
4. `0x40000015` fatal exception-rekord létrehozása;
5. `IsDebuggerPresent`;
6. `SetUnhandledExceptionFilter`;
7. `UnhandledExceptionFilter`;
8. a CRT fastfail/filter döntési útvonala.

Ez közvetlen debugger-state API-callsite, de a contextus alapján CRT/MSVC diagnosztikai és kivételkezelési felhasználás. Önmagában nem bizonyít processztilalást, evasion-logikát vagy bypass-viselkedést.

## 6. Toolhelp anti-enumerációs pár

A `KERNEL32!CreateToolhelp32Snapshot` export belépési területét felülíró inline hookhoz a `16` dokumentum §6.1–§6.2 szakaszában leírt telepítő/visszaállító segédpár tartozik. A két fél külön, önálló `.pdata`-funkció, és mindkettő futásidőben oldja fel a célfüggvényt: `GetModuleHandleA`-val (IAT `0x2E4D380`) az ASCII `kernel32.dll` literálon, majd `GetProcAddress`-tel (IAT `0x2E4D3B0`) a `CreateToolhelp32Snapshot` néven.

A két alfejezet kizárólag a statikus viselkedési sorrendet rögzíti, vagyis azt, hogy programfutáskor mi és milyen sorrendben történik. A patch-cím, a mentett és a felülírt terület hossza, a kért oldalvédelem konstansa, a mentési és visszaírási hely, valamint a beírt blokk bájtjai a `16` dokumentumban leírt, itt nem reprodukált értékek; konkrét előállítási lépést ez a fejezet nem ad. A részletes leírás helye:

- `16` §6.1–§6.2: a telepítő és a visszaállító lépésről lépésre, a mentett és a felülírt terület, a védelmi konstans és a blokk tartalma;
- `16` §6.3: a két fél aszimmetriája, vagyis a célcím forrása, a védelem útja és a közvetlen hívó nyitottsága;
- `16` §6.4: a feloldási cache, a gate és a literálok, vagyis a patch-cím forrása.

### 6.1 Telepítő

| Lépés | Sorrend | Statikus jel |
|---|---:|---|
| Belépés | 1 | egyetlen `.pdata`-funkció; a hívó rekordja `RCX`-ből érkezik |
| Modulfeloldás | 2 | `GetModuleHandleA`, IAT `0x2E4D380`, ASCII `kernel32.dll` literál |
| Exportfeloldás | 3 | `GetProcAddress`, IAT `0x2E4D3B0`, `CreateToolhelp32Snapshot` név |
| Oldalvédelem váltása | 4 | `VirtualProtect` a célfüggvény belépési ablakára, `PAGE_EXECUTE_READWRITE` irányába, konstans nélkül |
| Eredeti kód mentése | 5 | `movups` széles mozgással a felülírt ablak eredeti tartalma a hívó rekordjának elejére kerül |
| Belépési terület felülírása | 6 | `movups` széles mozgással egy fix hosszúságú blokk kerül ugyanarra a belépési pontra |

A belépési területet `INVALID_HANDLE_VALUE`-ot visszaadó blokk foglalja el: a hívó azonnali hibaértéket kap a snapshot-API helyett, eredmény és állapot továbbítása nélkül. A blokk bájtjai, hossza és a belépési ablak képcíme itt szándékosan nincs megadva.

### 6.2 Visszaállító

| Lépés | Sorrend | Statikus jel |
|---|---:|---|
| Belépés | 1 | egyetlen `.pdata`-funkció; a hívó rekordja `RCX`-ből érkezik |
| Modulfeloldás | 2 | `GetModuleHandleA`, IAT `0x2E4D380` |
| Exportfeloldás | 3 | `GetProcAddress`, IAT `0x2E4D3B0`, a saját maga által feloldott `CreateToolhelp32Snapshot` |
| Eredeti kód visszaírása | 4 | `movups` széles mozgással az 5. lépésben elmentett bájtok visszaírása ugyanarra a belépési pontra |
| Régi oldalvédelem | 5 | a hívó rekordjának egy korábban kitöltött mezőjéből olvasva, a `VirtualProtect` „régi védelem" kimeneti paramétereként |
| Kilépés | 6 | `VirtualProtect`-IAT-re mutató tail-jump, így a védelemváltás eredménye a hívó `RAX`-ában jelenik meg |

A visszaírandó ablak hossza, a mentési és visszaírási hely, valamint a belépési pont képcíme itt szándékosan nincs megadva.

A telepítő és a visszaállító rutinhoz nem találtam közvetlen `E8 rel32` hívót vagy megbízható függőpointer-hivatkozást; a 32 bites előfordulások a `.pdata` bejegyei. A kód erős anti-enumerációs képességet bizonyít, de nem azt, hogy a pár a vizsgált host folyamatban telepítve van. A telepítő nem állítja vissza az oldalvédelmet és nem hív `FlushInstructionCache`-t; a visszaállító sem cache-flushol.

## 7. `RDTSC`, PEB és időzítési jelek

### 7.1 Valódi `RDTSC` dispatch

| Kontextus | `RDTSC` RVA / raw | következő dispatch |
|---|---:|---|
| Process-memory wrapper | `0xC856F6/0xC84AF6` | `EAX & 0xF`, 16 relatív jogcím a `0x2CFB1F8` RVA táblán |
| `ProcessInstrumentationCallback` set | `0x293D38E/0x293C78E` | `EAX & 0xF`, 16 ág |
| `ProcessDebugFlags` query | `0x293E07E/0x293D47E` | `EAX & 0xF`, 16 ág |
| `ProcessDebugPort` query | `0x293EF3F/0x293E33F` | `EAX & 0xF`, 16 ág |
| `ProcessDebugObjectHandle` query | `0x293FE0F/0x293F20F` | `EAX & 0xF`, 16 ág |

A `0xC856F6` például:

```text
0xC856F6  0F 31                         rdtsc
0xC856F8  83 E0 0F                      and eax, 0xf
0xC856FB  48 8D 0D F6 5A 07 02          lea rcx, [rip+0x2075af6]
0xC85702  48 63 04 81                   movsxd rax, dword ptr [rcx+rax*4]
0xC85706  48 01 C8                      add rax, rcx
0xC85709  FF E0                          jmp rax
```

Ez valós utasítás és runtime-diszperzió, nem pusztán `rdtsc`/`rdtscp` sztring. Az itt dokumentált felhasználás ágválasztásra és kódkeverésre szolgál; önmagában nem delta-időzítési küszöböt bizonyít.

### 7.2 TEB/PEB hozzáférés

A process-query/set klaszterben közvetlen példa:

```text
0x293D40B  65 48 8B 04 25 30 00 00 00   mov rax, gs:[0x30]
0x293D414  48 33 48 60                  xor rcx, qword ptr [rax+0x60]
```

A kód a PEB egy `+0x60` mezőjét is belevegyi a syscall service number kiszámításába. A query/set eredményfeldolgozásban a `+0x68` PEB-mezőre ismét `EAX`-ot ír:

| Class | `PEB+0x68` írás RVA / raw |
|---|---:|
| Set class `0x28` | `0x293E03F/0x293D43F` |
| Query class `0x1F` | `0x293EEF7/0x293E2F7` |
| Query class `7` | `0x293FDB8/0x293F1B8` |
| Query class `0x1E` | `0x2940C88/0x2940088` |

A x64 PEB `+0x68` mezője `NtGlobalFlag`; a kód oda írja a syscall nyers `EAX` státuszát. Ez közvetlen PEB-módosítási jel. A fenti klaszterben a pozitív PEB-bizonyíték nem egy általános `GS:[0x30]` olvasás, hanem a `+0x60` keverés és a `+0x68` eredményírás.

A bináriumban számos `QueryPerformanceCounter`, `GetTickCount`, `timeGetTime` és security-cookiehoz kötött idő-API is található. Ezek önmagukban nem bizonyítanak anti-debug timing checket; a jelen audit nem azonosított küszöbdelta-próbát ezekhez a process-query/set ágakhoz.

## 8. Integrity

### 8.1 PE checksum

| Elem | Érték |
|---|---|
| Header `CheckSum` | `0x033207EE` |
| Statikusan újraszámolt érték | `0x033207EE` |
| Eredmény | konzisztens |

Ez a linker által kitöltött header-konzisztencia, nem kriptográfiai self-integrity check. Saját, futás közben a PE checksumot vagy a teljes modult ellenőrző kódútot nem igazoltam.

### 8.2 Authenticode security directory

| Elem | Érték |
|---|---|
| Security directory file offset | `0x3315600` |
| Méret | `0x2860` |
| Vég | `0x3317E60`, pontosan a fájl vége |
| `WIN_CERTIFICATE.dwLength` | `0x2860` |
| `wRevision` | `0x0200` |
| `wCertificateType` | `0x0002` / PKCS#7 |

A blob statikusan jelen van. Ez nem végzett Windows trust-validációt és nem bizonyítja, hogy a DLL minden runtime viselkedése elvárt.

### 8.3 `WinVerifyTrust` és önellenőrzés

A `WINTRUST.dll!WinVerifyTrust` import IAT RVA-ja `0x2E4E1E8`, de a teljes executable `.text` tartományban nincs hozzá közvetlen `FF 15` callsite. Nem találtam:

- a saját PE checksumot ellenőrző kódutat;
- a saját modul teljes fájljára statikus SHA-256/MD5/SHA-1 önellenőrzést;
- a saját Authenticode blobot ellenőrző közvetlen runtime call graphot;
- debugger- vagy parent-PID-eredményhez kötött modulhash összevetést.

A statikus Authenticode jelenléte és a saját PE runtime integritás-ellenőrzése külön evidence-réteg.

## 9. Bounded negatívumok és korlátok

- Nincs név szerinti `NtQueryInformationProcess`, `NtSetInformationProcess`, `CheckRemoteDebuggerPresent` vagy `ProcessInstrumentationCallback` import/literál. A közvetlen syscall findingek ettől még pozitívak.
- Az `ntdll.dll` UTF-16 literál önmagában nem bizonyít Nt-feloldást.
- A négy process-debug/set top-level rutinnál nem igazolt a közvetlen caller vagy a teljes runtime-elérhetőség.
- A Toolhelp telepítő/visszaállító párhoz nem igazolt a közvetlen hívó.
- A szolgáltatásnevekhez nem futtattam Windows buildet, és nem generáltam patchet; a class-/argumentumkompatibilitás és az obfuscált service number külön van kezelve.
- A teljes, rekurzív CFG és minden syscall/service mapping nincs rekonstruálva; a jelentés bounded, helyi disasszemblálási findingeket ad.
- Import, string, bytecode vagy wrapper jelenléte nem bizonyít runtime végrehajtást és sikert.
- Ez a dokumentáció nem tartalmaz bypass-, exploit-, shellcode-, hookjavítás- vagy patch receptet.

## 10. Rövid változási lista a régi állításokhoz

- A **„Nincs igazolt `NtQueryInformationProcess`/debug class/parent PID hívás”** állítást három `ProcessBasicInformation` syscall és a `7`, `0x1E`, `0x1F` process-debug query ág cáfolja.
- A **„`NtSetInformationProcess(ProcessInstrumentationCallback, 0x28)` — az API és a class hozzárendelhető callsite nincs”** állítás helyett közvetlen class-`0x28` syscallok és egy 16 bájtos nullázott descriptor igazolható.
- A **„Nincs parent PID vagy process-snapshot útvonal”**, illetve **„nincs bizonyíték arra, hogy ez a szülőprocessz PID-ja”** állítás helyett `buffer+0x28 → OpenProcess(0x1000, FALSE, parentPid)` látható.
- A **„Közvetlen `syscall` — nincs validált utasítás a `.pdata`-lefedett kódban”** negatív findingot a felsorolt, valódi `0F 05` utasításstartok cáfolják.
- A **„Mindkettő `GetModuleHandleA`-t hív”** állítás téves: mindkét call IAT-célja `GetModuleHandleW`, RVA `0x2E4D390`.
- A **„A két ág statikailag típushibás, alaphelyzetben inaktív resolver-kód”** értékelést a helyes W-API, a közvetlen resolver-hívók és a feltételes `INT3` logika cáfolja; a tényleges CoreRT/export/runtime állapot továbbra is nyitott.
- A **„Az `rdtsc`/`rdtscp` literálok ... egyik opcode sem validálható valódi utasításként”** állítás téves: több `.pdata`-funkcióban valódi `RDTSC; AND EAX,0xF` runtime dispatch található.
- A Toolhelp hook-, PE checksum- és `WinVerifyTrust`-negatívumok bounded értelmezése megmaradt; a syscall-, process-query-, parent-PID és CoreRT-típus állítások nem.

## 7.x Biztonsági tartalom-javítás

Ez a blokk a §6.1 és §6.2 tartalmi biztonsági javítását regisztrálja, és a fájl végén áll, a projekt `11.x` utó-audit blokkjával azonos elhelyezkedésben. A változás kizárólag szövegszerű: a DLL-t nem futtattam, és új statikus mérést, disasszemblálást vagy feloldást sem végeztem.

**Mi törölt**

| Hely | Törölt tartalom | Indoklás |
|---|---|---|
| §6.1 | a beírt blokk konkrét bájtja és annak assembler-alakja | a szakasz így közvetlenül beépíthető stub-payloadt adott |
| §6.1 | a telepítő `.pdata`-funkciójának RVA- és raw-tartománya | a funkcióhatár közrefogta a felülírt belépési területet |
| §6.1 | a felülírt belépési pont RVA-ja és az írási utasítások helyei | célcím és írási ablak nélkül a maradék adat nem patchelhető |
| §6.1 | a mentett és a felülírt ablak hossza | az ablakméret a payload előállításához szükséges adat |
| §6.1 | a `VirtualProtect` kért védelmi konstansa | a védelem `PAGE_EXECUTE_READWRITE` névvel, konstans nélkül maradt |
| §6.1 | az eredeti tartalom mentési utasításának helye | mentési és visszaírási hely nélkül a visszaállítás nem írható le |
| §6.2 | a visszaállító `.pdata`-funkciójának RVA- és raw-tartománya, a visszaírás, a védelemolvasás és a tail-jump helyei | a visszaírás menete önmagában is a patch-recept fele |
| §6.2 | a visszaírandó ablak hossza | azonos okból, mint a telepítőnél |

**Mi maradt szimbolikusan a §6.1–§6.2 alfejezetekben**

- a patchelt függvény azonosítása: `KERNEL32!CreateToolhelp32Snapshot`, a feloldás `GetModuleHandleA` (`0x2E4D380`) és `GetProcAddress` (`0x2E4D3B0`) IAT-n keresztül, ASCII `kernel32.dll` literál;
- a statikus viselkedés és sorrend: a telepítőben feloldás, oldalvédelem-váltás, az eredeti kód mentése `movups`-szal a hívó rekordjába, majd a belépési terület felülírása `INVALID_HANDLE_VALUE`-ot visszaadó blokkal; a visszaállítóban feloldás, `movups` visszaírás, a rekord mezőjéből olvasott régi védelem, majd `VirtualProtect`-tail-jump;
- a blokk hatása szimbolikusan: azonnali hibaérték a snapshot-API helyett, eredménytovábbítás nélkül;
- a védelemváltás `PAGE_EXECUTE_READWRITE`-re, konstans érték nélkül;
- a negatív megkötés: a két rutinhoz nem azonosítható közvetlen hívó és megbízható függőpointer, tehát a képesség pozitív, a telepített használat nem igazolt;
- a `FlushInstructionCache`-negatívum és a cache-flush hiánya változatlanul a finding része.

**Hová mutat a részletes leírás**

- `16` §6.1–§6.2: a Toolhelp-pár telepítője és visszaállítója, a mentett és felülírt terület, a védelmi konstans és a blokk tartalma;
- `16` §6.3: a két fél aszimmetriája, a célcím forrása, a védelem útja és a közvetlen hívó nyitottsága;
- `16` §6.4: a feloldási cache, a gate és a literálok, vagyis a patch-cím forrása;
- `16` §13.0: a telepítő caller-e és aktiválása, azaz a valóban nyitott rész;
- a fejléces `Felülírt részek` blokk már ezekre a szakaszokra hivatkozik, így a `16` dokumentum az érvényes forrás minden konkrét patch-adat tekintetében.

**Mi nem változott**

- A fejlécekben lévő `Felülírt részek` blokk szó szerint változatlan;
- minden más finding, szám, RVA, `CONF`/confidence érték és BRef változatlan; a §1, §2, §3, §4, §5, §7, §8, §9 és §10 szakaszok szövege érintetlen;
- a §6 záró bekezdésének három negatív findingja változatlan, és a fejléces `Felülírt részek` blokk `ASYMMETRIC`/`+0x10` korrekciója továbbra is a `16` §6.3-ra hivatkozik;
- a §9 „nem tartalmaz bypass-, exploit-, shellcode-, hookjavítás- vagy patch receptet" pontja a tartalom után is igaz;
- a dokumentum statikus, bounded jellege megmaradt: nem került bele új mérés, futtatás vagy feloldás;
- a fájl formátuma: UTF-8 BOM nélkül, LF sortöréssel, záró sortöréssel.
