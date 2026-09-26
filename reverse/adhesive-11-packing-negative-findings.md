# `adhesive.dll` — packing, obfuscation, entropy és bounded negative findings

## 1. Vizsgálati keret

**Vizsgált artifact:** `C:\Users\Admin\Desktop\Dumper - AllInOne\reverse\adhesive.dll`

**Vizsgálat típusa:** kizárólag statikus, fájlszintű elemzés. A DLL-t nem futtattam, nem töltöttem be, nem unpackeltem, nem dekompresszeltem és nem hajtottam végre hálózati, registry-, ETW- vagy IPC-műveletet. A dokumentációban nincs bypass-recept.

A negatív findingok kifejezetten erre a fájlra és a benne látható, statikusan feloldható kódra vonatkoznak. A PE által importált, de a munkaterületen nem található `v8`, `citizen-*`, `gta-*`, `rage-*`, `net-*` és más külső modulok viselkedését nem minősítettem.

## Felülírt részek

Kizárólag visszirányú navigáció: a feltüntetett szöveghelyek egyike sem módosult, a blokk csak a negatív findingok **korlátait** és mérési alapját mutatja meg. Az `N-01`–`N-10` következtetések önmagukban változatlanul érvényesek; ahol ellentmondás van, a jobb oldali dokumentum élvez elsőbbséget. Jelölés: `P` = proven, `L` = likely, `U` = unknown.

| Itt érintett szakasz / állítás | Felülíró forrás | CONF | Forrás evidence |
|---|---|---|---|
| §10 `N-01`–`N-10` *Scope* és *Módszer* sorai; §11/14. pont (`pefile` parser-warning); §13 `B13` és `B14` | `13` §7 `F-20`, §12 `D-002`, `D-003`, `D-009`, §15–§17: a mérési alap 142 004 runtime-function rekord, 233 klaszter, 157 153 közvetett hely; a producer-leltár 19 bejegyzés | `P` a számokra, `L` a használati szabályra | `reverse/evidence/cfg_functions.csv` (`cross_function_targets`), `pdata_functions.csv`, `unresolved_regions.json`, `toolchain.json` |
| §10 minden pont *False-negative korlát* sora; §12 „Mit nem lehet kizárni ebből az elemzésből" – a syscall-, argumentum- és mapping-limitek | `15` §14 `N-01`–`N-06`, §15, §17: a service mapping legitim módon lezáratlan, 3 627 valid helyből 243 fallthrough-bizonyított | `P` a negatív findingokra, `U` a szolgáltatásnevekre | `reverse/evidence/syscall_inventory.csv`, `syscall_arg_classes.json`, `syscall_service_map.json`, `audit_syscall_candidates.json` |
| §4.6, §8.1 és §13 `B15` process-memory és anti-debug részei; §12 harmadik pontja (a syscall-számok keverése) | `15` §16 `B15-01`–`B15-18`: 3 881 nyers → 3 627 valid felbontás, 21 762 argumentumosztály, `A3_INOUT_BUF = 0`; a `0xD7A400` három hely `other` csoportban marad | `P` a számlálásra, `U` az elérhetőségre | `reverse/evidence/syscall_inventory.csv`, `audit_syscall_candidates.json`, `syscall_arg_inventory.csv` |
| §4.1 „nem hordoz `RWX` kombinációt" és a statikus szekcióflag-megkötés; §14 végső bounded értékelés | `13` §7 `F-20` kötelező olvasási szabály: a `blocks_reached` nem jelent futásidejű elérést, a `reached_ratio` nem kizárólagos elérési bizonyíték; a sweep-only rész soha nem HIGH | `P` a korlátra, `L` a szabályra | `reverse/evidence/cfg_functions.csv` (`blocks_reached`, `blocks_linear_only`), `unresolved_regions.json` (`method.confidence_rules`) |

## 2. Rövid összegzés

A statikus kép egy nagy, x64-es, MSVC-stílusú C++ komponenst mutat, nem egy klasszikus UPX- vagy más tipikus packerrel tömörített PE-t. A szekciók neve és jogosultságai normálisak, a szekciók teljes entropyja közepes, nincs statikus RWX szekció, és az overlay teljes egészében a PE Authenticode security directoryjához tartozik. A teljes fájlban nem találtam valid, plaintext beágyazott PE-t, ZIP-ot, ELF-et vagy más szokásos csomagoló/payload-formátumot.

Van azonban több valódi, lokális technikai finding:

- magas entropy-jú, csak olvasható `.rdata` szigetek, amelyek Botan/OpenSSL/Ed25519-jellegű előre kiszámított kriptográfiai táblákkal észlelhetők;
- kiterjedt, részben opaque-transform/CFF-jellegű kódkeverés, valamint `RDTSC`, PEB- és `KUSER_SHARED_DATA`-alapú dispatch;
- közvetlen `syscall` utasítások és processzmemória-allokáció/írásra kompatibilis wrapper-argumentumok;
- dinamikus importfeloldás `CoreRT.dll` és `wtsapi32.dll` opcionális exportjaihoz;
- több lokalizált runtime patching/trampoline útvonal, köztük szál-kontextus-módosítás, NOP-feltöltés és `CreateToolhelp32Snapshot` inline stub;
- feltételes `int3`-ágak, de a `CoreIsDebuggerPresent` resolver-ágak pontosan követhetők, az aktív anti-debug döntés és a host betöltési állapot azonban nem igazolt;
- normál MSVC TLS-callbackek és egy nem futtatható `.retplne` metadata-szekció.

Ezért a következő korlátozott állítás indokolt: **nincs bizonyíték klasszikus teljes-image packingre vagy valid plaintext embedded payloadra, de a kód obfuszkációja, natív memóriaútvonalai, patchingje és hálózati/kriptográfiai képessége miatt a DLL nem minősíthető teljesen inert vagy ártalmatlan csak ebből a statikus negatív findingek listájából.**

## 2.1 BRef- és confidence-jelölés

A dokumentum a projekt kanonikus BRef-formáját használja:

```text
BRef = [RVA:<hex|N/A> | RAW:<hex|N/A> | CONF:<P|L|U> | STATUS:<OBSERVED|INFERRED|NEGATIVE|OPEN>]
```

A `CONF:P` közvetlen statikus szerkezeti bizonyítékot, `CONF:L` több jelből származó likely következtetést, `CONF:U` nyitott vagy csak korlátozottan látható kérdést jelöl. A `STATUS:OBSERVED` közvetlenül megfigyelt jelenlétet, `STATUS:INFERRED` adatfolyam-alapú értelmezést, `STATUS:NEGATIVE` bounded hiányt, `STATUS:OPEN` lezáratlan kérdést jelent. Az `N/A` RVA a security directory és más overlay- vagy fájl-szintű tartalmaknál használatos.

## 3. Artifact- és PE-identitás

| Tulajdonság | Statikus eredmény |
|---|---|
| SHA-256 | `91cc0aa006d7315cb042c8fa8dca6c1e074a307bba7dcc9eb5509c8a7b81934e` |
| Fájlméret | `53 575 264` byte (`0x3317E60`) |
| Machine | AMD64 (`0x8664`) |
| Optional header | PE32+ (`0x20B`) |
| ImageBase | `0x180000000` |
| Entry point | RVA `0x2AB2770`, file offset `0x2AB1B70` |
| COFF timestamp | `2026-09-11T15:06:18Z` |
| Header checksum | `0x033207EE`; a PE újraszámított checksumme azonos |
| Export | `CreateComponent`, RVA `0x101F80` |
| Import descriptorok | 42 DLL, 628 import-entry |
| Delay import | `ole32.dll!CoTaskMemFree` |
| Rich header | nincs |
| Authenticode | a PowerShell `Signature verified` állapotot adott; signer `Rockstar Games, Inc.` |

A `DllCharacteristics` értéke `0x160`: high-entropy VA, dynamic base és NX bit be van állítva. CFG-flag nincs beállítva; a Load Config táblában a GuardCF tábla- és count-mezője nulla. Ez nem packer-jel, de a biztonsági profilhoz és a `VirtualAlloc`/patching findinghöz fontos kontextus.

## 4. Packing, obfuscation és entropy

### 4.1 Szekciók és statikus jogosultságok

| Szekció | RVA | Virtual size | Raw file range | Entropy | Statikus jogosultság |
|---|---:|---:|---:|---:|---|
| `.text` | `0x1000` | `0x2BED4B5` | `0x400–0x2BEDA00` | `6.354389` | RX, code |
| `.rdata` | `0x2BEF000` | `0x4C9FDC` | `0x2BEDA00–0x30B7A00` | `6.067497` | R, initialized data |
| `.data` | `0x30B9000` | `0x252734` | `0x30B7A00–0x3305A00` | `3.837675` | RW, initialized data |
| `.retplne` | `0x330C000` | `0x5C` | `0x3305A00–0x3305C00` | `0.845849` | PE characteristics `0x0` |
| `.tls` | `0x330D000` | `0x54A1` | `0x3305C00–0x330B200` | `0.006118` | RW, initialized data |
| `.rsrc` | `0x3313000` | `0x698` | `0x330B200–0x330BA00` | `3.923278` | R |
| `.reloc` | `0x3314000` | `0x9AD0` | `0x330BA00–0x3315600` | `5.477351` | R, relocations |

**Következtetés:** egyik szekció sem hordoz `IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE` kombinációt. A `.data` és `.tls` írható, de nem futtatható; a `.text` futtatható, de nem írható. A `.retplne` szekcióban nincs sem `MEM_EXECUTE`, sem `MEM_READ` flag.

Ez csak **statikus szekcióflag-szintű** állítás. A 7. pontban dokumentált `PAGE_EXECUTE_READWRITE` allokációt és `VirtualProtect`-et kérő call-site-ok miatt a „nincs RWX” kijelentés nem terjeszthető ki minden sikeres runtime műveletre.

### 4.2 Entropy-kép

A teljes szekcióentropy mellett 64 KiB-os, nem átfedő ablakokat is mértem a teljes fájlon, majd a magas értékű `.rdata` környezetén 4 KiB-os ablakokat vettem.

- A teljes `.text` legmagasabb 64 KiB-os ablak-entropiája `6.796888`; nem látszik tömörített vagy teljesen kódként értelmezhető szekció.
- A 4 KiB-os sweepben a `.text` raw `0x2A96000–0x2A97000`, RVA `0x2A96C00–0x2A97C00` tartomány `7.965173` bit/bájtot ér el, de a kezdőutasítások érvényes x86-64 kódot adnak; ez kódkeverésre utal, nem titkosított payloadra.
- A `.rdata` egyetlen 64 KiB-os, `7.0` feletti ablakja file offset `0x2CA0000–0x2CB0000`, RVA `0x2CA1600–0x2CB1600`, entropy `7.741525`.
- A 4 KiB-os mérésben a `0x2CA9000` körüli szigetek több blokkban `7.95–7.99`, a `0x2CB1000–0x2CB3FFF` tartományban `8.0` körüli értéket érnek el. Ezek kis, egymásba ékelődő lookup-/mezőtáblák, nem egyetlen folytonos, önálló csomagolt envelope.
- A `.rdata` teljes entropyja csak `6.067497`; a magas érték nem az egész modult, hanem egy localizált kryptoadat-szigetet érint.

### 4.3 A magas entropy-jú sziget értelmezése

A magas entropy-jú `.rdata` tartalom erős statikus kapcsolatot mutat beépített kriptográfiai könyvtárakkal:

- Botan source path: `..\..\fivem-private\components\adhesive\src\botan\botan_all.cpp` file offset `0x2E0ECA6`;
- Botan `PointGFp` és `Precomputed sufficient values for scalar mult` szövegek, például file offset `0x2E0B84F`;
- `SigEd25519 no Ed25519 collisions` domain-separator string file offset `0x2CBD188`;
- OpenSSL/Botan EC és Ed25519/X25519 hiba- és algoritmusnevek széles körben jelen vannak;
- a magas entropy-sziget belső célpontjára, RVA `0x2CB18E0` (file offset `0x2CB02E0`) négy közvetlen RIP-relative kódxref mutat: RVA `0x3E1AF`, `0x40166`, `0x40316`, `0x4FA2C`.

Ez a kép **kriptográfiai tábla-envelope-ként** értelmezhető: a bitek előre kiszámított EC/Ed25519-szerű mezőket, lookup-adatokat és strukturált paddinget reprezentálnak. A `.rdata` szekció nem írható, a blobok nem valid embedded fájlként mennek át, és a közvetlen kódreferenciák fix adatként használják őket. Ebből nem következik, hogy minden egyes magas entropy-blob pontos botanikai jelentése bizonyított; az sem zárható ki, hogy a statikus kód egyes részei titkosított adatot használnának.

### 4.4 UPX és klasszikus packer-jelek

Nem találtam:

- `UPX0`, `UPX1`, `UPX!` szekciónév/marker kombinációt;
- ASPack, PECompact, Themida, VMProtect, MPRESS, Petite, Enigma, Obsidium, Armadillo vagy hasonló klasszikus packer-markert;
- gzip, 7z, RAR, CAB, zstd, LZ4, ZIP vagy ELF magic-et;
- minimális importstubot vagy csak egy nagy entropy-jú szekciót tartalmazó PE-struktúrát.

A file offset `0x2C43306` környékén található `UUPx((` jellegű ascii részlet nem UPX-marker: nincs hozzá `UPX!` magic, nincs UPX szekciónév, és a környezet nem UPX header. Ez klasszikus string-validator false positive.

### 4.5 Obfuscation-kép

A teljes modult nem lehet egyszerűen „nem obfuszkáltnak” minősíteni. A modul szerkezete egyrészt normál PE/MSVC felületet mutat:

- 42 import-DLL és 628 import-entry látható;
- a kódban számos világos API-, hiba-, vendor- és forrás-path string van;
- CodeView/PDB metadata jelen van;
- a resource-ek között verzió-, manifest- és `FXCOMPONENT`-metadata is van;
- a `.text` tartalmaz normál MSVC exception/unwind- és TLS-struktúrákat.

Ugyanakkor a `.text` nagy részén erős opaque-transform/CFF-jellegű kódkeverés, számított célcímek, `RDTSC`/`GS:[0x30]`-alapú diszperzió és adatfüggő wrapperlogika látszik. A kódot ezért **lokalizáltan erősen obfuszkált, teljes képű packerrel viszont nem igazoltan csomagolt** artifactként lehet leírni. Az opaque-transform miatt a teljes CFG rekonstrukciója és minden runtime-elérhetetlenség következtetése korlátos.

### 4.6 Közvetlen syscall- és processzmemória-jelek

A korábbi, csak importnév-alapú anti-debug/packing közelítéshez képest a részletes statikus disasszemblálás további pozitív jeleket mutat:

- `ProcessBasicInformation` argumentummintát követő közvetlen syscall-ágak: RVA `0xD7B0AE`, `0xD7B4B9`, `0xD7C0AC`;
- a `0xC856C0` wrapper `RDTSC & 0xF` által választott 16 ága közül több közvetlen `syscall`-t tartalmaz;
- processzhandlehez, `MEM_COMMIT`-hez és `PAGE_EXECUTE_READWRITE`-hoz illeszkedő allokációs argumentumok;
- a `0xC86477`/`0xC864A0` körüli írásra hasonlító syscall-argumentumok, amelyek `NtWriteVirtualMemory`-kompatibilisek lehetnek, de a szolgáltatásszám futás közben keverődik;
- PEB- (`GS:[0x30]`) és `KUSER_SHARED_DATA`-hivatkozások, amelyek a syscall-számok és wrapper-változatok rejtését valószínűsítik.

Ezek a jelek az obfuscation és process-memory capability erős statikus bizonyítékai, nem adnak közvetlen bizonyítékot arról, hogy a művelet sikeresen lefutott, milyen Nt-szolgáltatás volt, melyik processz volt a cél, vagy milyen adatot írtak. A negatív findings ezért nem állíthatják, hogy nincs natív syscall; csak azt, hogy a konkrét szolgáltatásnév és végrehajtás statikusan nem lezárt.

A `07` anti-debug audit korábbi, `.pdata`-lefedett kódra szűkített syscall-negatívuma ütközik a `06` és `12` dokumentumokban kézzel validált direct syscall-helyekkel. Ez a riport a kézzel látott `0F 05` utasításokat observed evidence-nek, a szolgáltatásnév-meghatározást és runtime-elérhetőséget open kérdésnek tekinti.

## 5. Kriptográfiai adatok, amelyek nem klasszikus payload-jellegűek

A negatív findingok nem jelentik azt, hogy nincs kriptográfia vagy hálózati kód. A file-ben ténylegesen megtalálható:

- statikusan linkelt Botan/OpenSSL-szerű kód, TLS 1.2/1.3 setup- és cipher-katalógus-jelek;
- Ed25519/EC/X25519 algoritmusnevek, hardveres kriptográfiai opcode-ok és `BCryptGenRandom`;
- `CryptMsg*`, `CryptQueryObject`, `CryptUnprotectData`, tanúsítványtár- és `WinVerifyTrust`-felületek;
- `WS2_32` socket API-k, libuv, libcurl/nghttp2, HTTP/2 és WebSocket-jelek;
- `net`, `net-tcp-server`, `net-base` és `v8` függőségek;
- `CreateFileMappingW`/`MapViewOfFile`, event- és semaphore-szinkron primitívumok, amelyek lehetnek IPC-felületet alkotó capability-k.

Ezért a hálózati, kriptográfiai és IPC API-k jelenlétéét nem lehet úgy kezelni, mintha azok önmagukban payload- vagy C2-bizonyítékok lennének. A `http://clients2.google.com/time/1/current` RVA `0x2C5B0D0`, raw `0x2C59AD0` időszinkronhoz illő literál; a közvetlen RIP-relative kódxref RVA `0x32569` / raw `0x31969`, de a fogyasztó feltétele és jelentősége nem igazolt.

## 6. Dinamikus importfeloldás

A statikus IAT és a közvetlen kódxrefek alapján a következő opcionális feloldás látható:

| IAT RVA | Import | Közvetlen cél / literal | Finding |
|---:|---|---|---|
| `0x2E4D390` | `GetModuleHandleW` | UTF-16 `CoreRT.dll`, RVA `0x2E1F7FA` | már betöltött host-komponens opcionális exportjainak keresése |
| `0x2E4D3B0` | `GetProcAddress` | `GetErrorData`, `CoreGetGameWindow`, `CoreIsDebuggerPresent`, `CoreGetGlobalInstanceRegistry`, `CoreGetComponentRegistry` | opcionális CoreRT exportok |
| `0x2E4D480` | `LoadLibraryW` | UTF-16 `wtsapi32.dll`, RVA `0x2E1F828` | Windows Terminal Services API-k betöltése |
| `0x2E4D3B0` | `GetProcAddress` | `WTSQuerySessionInformationW`, `WTSFreeMemory` | a betöltött WTS modul opcionális exportjai |

A `GetProcAddress` call-site-ek és az IAT-ba mutató közvetett hívások például RVA `0x4D74`, `0x52A3`, `0x52EA`, `0x546B`, `0x5BFA`, `0x5C41`, `0x5DC2`, `0x904B`, `0x91CB`, `0x1ACCB`, `0x1BADB` és `0x5049B` környékén vannak. A `CoreRT.dll`-hez tartozó hívások `GetModuleHandleW`-t használnak, tehát nem igazolt, hogy a DLL maga betölti azt. A `wtsapi32.dll` betöltése egy konkrét, kis, system-API célú dinamikus importút.

A modulkezelésben külön, név alapján azonosított útvonal is van: `KERNEL32.DLL`, `CreateToolhelp32Snapshot`, `Module32First` és `Module32Next` dinamikus feloldása, majd `TH32CS_SNAPMODULE` enumeráció. A `0x2BD0FBE`–`0x2BD133E` közötti két helper saját processz-modulokra koncentrál; a pontos exportkeresési szemantika egyik ágban közepes bizonyosságú.

A feloldott nevek szövegesen jelen vannak; a vizsgált call-site-eknél nem láttam API-hashing alapú rejtett feloldást. Ettől még egy másik, közvetett vagy futásidőben generált resolver nem zárható ki.

## 7. Runtime patching és trampoline

Ez **pozitív statikus finding**, nem negatív finding. A statikus evidence több, egymástól különálló patch-mechanizmust mutat.

### 7.1 Memóriakezelés

Az RVA `0x1D280` körüli allokációs útvonalon két hívás található:

- RVA `0x1D3A2`, raw `0x1C7A2`;
- RVA `0x1D43E`, raw `0x1C83E`.

Mindkettő `0x3000` (`MEM_COMMIT | MEM_RESERVE`) allokációt és `0x40` (`PAGE_EXECUTE_READWRITE`) védelmet kér. Ezek siker esetén futásidejű RWX memóriát adnának, ezért a statikus „nincs RWX szekció” állítás nem jelent teljes runtime RWX-mentességet. A `0xC874E9` call-site szintén `0x40` (`PAGE_EXECUTE_READWRITE`) védelmet kér, `MEM_COMMIT` típussal.

### 7.2 Szál-kontextus és relatív jump-patch

Az RVA `0x1DFF0` körüli alrendszer a következő importokat használja:

- `OpenThread` — RVA `0x1E0F4`, raw `0x1D4F4`;
- `SuspendThread` — RVA `0x1E109`, raw `0x1D509`;
- `GetThreadContext` — RVA `0x1E11F`, raw `0x1D51F`;
- `SetThreadContext` — RVA `0x1E214`, raw `0x1D614`;
- `VirtualProtect` — RVA `0x1E2D1` és `0x1E31B`, raw `0x1D6D1` és `0x1D71B`;
- `FlushInstructionCache` — RVA `0x1E330`, raw `0x1D730`;
- `ResumeThread` — RVA `0x1E484` és `0x1E537`.

A `0x1DFF0` a saját processz szálait `TH32CS_SNAPTHREAD` snapshotból választja ki, `THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION` (`0x5A`) jogú thread handle-eket nyit, `CONTEXT_CONTROL` állapotot olvas és ír vissza, majd patch-rekordokból új `RIP`-et képez. Az `0x1E270` patcher a `0x38` bájtos rekordból célcímet, rel32-jumpot és alternatív rövid jumpot választ, majd a régi oldalvédelmet visszaállítja.

A `0x1E425` és `0x1E4FD` közvetlen hívók mutatják, hogy ez nem pusztán import- vagy stringjel. A patchcél, a rekordtáblázat és a célmodul azonban futás előtt dinamikusan töltődhet; a pontos cél és a sikeres telepítés statikusan nem ismert.

### 7.3 További patch-mechanizmusok

- Az RVA `0x1754520` körüli segéd a célterületet `PAGE_EXECUTE_READWRITE` védelemre állítja, majd egyetlen konstans bájt ismétlésével, a caller által megadott hosszban kitölti, végül visszaállítja a védelmet. A kitöltő bájt értékét sem ez a dokumentum, sem a `16` nem adja meg: a `16` §7.2–§7.3 csak a szimbolikus szabályt rögzíti (egyetlen konstans bájt ismétlése, a hossz a caller argumentuma), itt szándékosan nem reprodukálva. Közvetlen hívója nincs, ezért a képesség pozitív, az aktív használat nem bizonyított.
- A `KERNEL32!CreateToolhelp32Snapshot` belépési területét felülíró inline hookhoz a `16` dokumentum 6.1–6.2. szakaszában leírt telepítő/visszaállító segédpár tartozik; a patchelt függvényt az import IAT-slotja, `0x2E4D290` azonosítja. A telepítő az eredeti belépési bájtokat egy hívó által adott rekordba menti, majd a belépési területet egy `INVALID_HANDLE_VALUE`-t visszaadó stub foglalja el; a visszaállító a rekord tartalmát írja vissza. A mentett és felülírt terület **szélesség- és ablakleírása** a `16` §6.1–§6.3-ban van, a patch-cím forrása pedig a `16` §6.4-ben; a szűk konstans-tárolások szélességeire vonatkozó felülírt állítás a `16` §12.2 regiszterében, szimbolikusan szerepel. A `16` §6.1 a stub tartalmát és írási bájtértékeit nem adja meg, ezért az itt felsorolt viselkedés leírása szimbolikus marad. A patch-site kifejezés és a területmézet módszertana a `16` §3.3/§3.4 szakaszában van. A `0xC8CEF4` `VirtualProtect`-hívás, a `0xC8F4B3` pedig az importált `VirtualProtect` felé leadó tail-jump; a `0xC8F47F`–`0xC8F498` resolver/memóriaírási útvonal. Közvetlen hívó vagy megbízható függőpointer a routine-hoz nem azonosítható.
- A `0xC856C0` processzmemória-wrapper és a `0xC86420`, `0xC8F84C`, `0xC8FA6C`, `0xC870DB` syscall-helyek külön, processzhandlealapú útvonalat alkotnak. Az argumentumok allokációra és távoli buffer írására hasonlítanak, de a szolgáltatásszám és a handle eredete nincs lezárva.

A `WriteProcessMemory`, `CreateRemoteThread` és importált `NtWriteVirtualMemory` név hiánya ezért **nem zárja ki** a távoli memória-képességet. Ugyanakkor a közvetlen Win32 távoli-write API és a sikeres runtime végrehajtás sem bizonyított.

### 7.4 Runtime patching értelmezési korlát

A patching/trampoline finding a saját folyamat hook-, NOP- és kontextusmódosítási képességeket igazolja. Nem bizonyítja, hogy a kód rosszindulatú, hogy a cél egy másik processz, hogy a patch tartalma shellcode, vagy hogy a művelet valóban lefutott. A patch-cím és a patch-tartalom nem nyitott kérdés: mindkettő a `16` dokumentumban leírt, itt szándékosan nem reprodukált érték (`16` §3.3/§3.4 a patch-site kifejezés és a területmézet, `16` §6.1–6.2 a Toolhelp-pár telepítőjét, visszaállítóját és a felülírt terület szélesség- és ablakleírását, `16` §7.2 a NOP-kitöltőt). Nyitott kérdés marad a célmodul, a patchet inicializáló caller, a futásidejű feloldási és oldalvédelmi állapot, valamint az, hogy a művelet a gyakorlatban lefutott-e.

## 8. Anti-debug és TLS

### 8.1 Anti-debug

A statikus kódban két különböző jelcsoport látszik.

**Közvetlen CRT-hívás.** Az `IsDebuggerPresent` IAT RVA `0x2E4D458`; közvetlen hívása RVA `0x2AE1008`, raw `0x2AE0408`. A környező `0x2AE0F10–0x2AE1058` kód kontextusmentést, `RtlCaptureContext`-et, `SetUnhandledExceptionFilter`-t és `UnhandledExceptionFilter`-t használ. Ez közvetlen debugger-state API-callsite, de a kontextus alapján CRT/fatal-error diagnosztika, nem önálló evasion-képesség; az anti-debug szándék confidence alacsony.

**Dinamikus CoreRT-ág.** A `CoreIsDebuggerPresent` ASCII literál hivatkozott példánya raw `0x2E0B5ED`, RVA `0x2E0CBED`; a UTF-16 `CoreRT.dll` literál RVA `0x2E1F7FA`, raw `0x2E1E1FA`. Az alábbi két ág ugyanazt a mintát követik:

- `GetModuleHandleW` RVA `0x2E4D390` az UTF-16 modulnévvel;
- `GetProcAddress` RVA `0x2E4D3B0` az `CoreIsDebuggerPresent` névvel;
- a feloldott pointer feltételes meghívása, majd igaz eredmény esetén `INT3` RVA `0x5302`, illetve `0x5C59`;
- a közös function-pointer cache RVA `0x30D4288`, raw `0x30D2C88`, kezdetben nulla.

A `GetModuleHandleW` a UTF-16 névet helyesen kezeli, ezért a két ág nem pusztán sztringtípus-hiba. A normál `CoreRT.dll` betöltés mellett a feloldás és az `int3`-ág statikusan lehetséges; a cache kezdeti értéke, a host betöltési állapota, a pointertárolás és a szándék azonban nem ismert. Ezért a finding **feltételes anti-debug-/tamper-jel és képesség**, nem bizonyított aktív anti-debug döntés. Az `OutputDebugStringA`, az Event Log API-k és az `IsDebuggerPresent` CRT-út önmagukban nem igazolnak anti-debug intentet.

A két callsite `FF 15` IAT-hívása az `RVA 0x2E4D390` `GetModuleHandleW` slotra oldódik, nem `GetModuleHandleA`-ra. A korábbi `GetModuleHandleA`-ra épülő „típushibás resolver” minősítés ezért téves.

A közvetlen syscall-ágak alapján a `ProcessDebugPort=7`, `ProcessDebugObjectHandle=0x1E` és `ProcessDebugFlags=0x1F` process-query, valamint az `NtSetInformationProcess` class `0x28` instrumentation-descriptor művelet statikusan pozitív. A pontos service number, a top-level callerlista, a runtime-elérhetőség és az anti-debug szándék nyitott. A `CheckRemoteDebuggerPresent` vagy `NtSetInformationThread` konkrét, névhez kötött hívását ez a bounded review nem igazolta; ez nem zárja ki kódolt vagy külső wrapperben megvalósított változatot.

### 8.2 TLS

A TLS directory jelen van:

- directory RVA `0x2E0A1D0`, file offset `0x2E08BD0`;
- callback-array RVA `0x2E4B8B8`, file offset `0x2E4A2B8`;
- callback pointerek: RVA `0x2AB28D0`, `0x10D0`, `0x2AB2948`;
- TLS raw data a `.tls` szekcióban, `0x330D000` RVA környezetében;
- `SizeOfZeroFill = 0`.

A callbackek disassembler szerint az MSVC/CRT TLS-életciklus- és destructor-kezeléséhez kapcsolódnak: a process/thread attach/detach reason értékeket vizsgálják, TLS blokkokat járnak be, illetve guard-ellenőrzött pointer-listákon keresztül hívnak. Nem találtam olyan TLS callbacket, amely közvetlenül a PE-képet vagy egy ismert packer-staget dekompaktálná.

### 8.3 `.retplne`

A `.retplne` szekció 92 valid bájtnyi `RetpolineV1` metadata-jel és számezett recordokkal nem tartalmaz valódi x86 thunkot:

- section RVA `0x330C000`, file offset `0x3305A00`;
- PE characteristics `0x0`, nincs executable/readable memory flag;
- a `.text` RIP-relative referencia-scanben nem találtam rá mutató xrefet.

A finding tehát **metadata-szekció**, nem statikus retpoline-kód vagy anti-debug trampoline. A `.retplne` név önmagában nem bizonyít retpoline-jelenlétet.

## 9. `.data` zero tail és nulla-kitöltések

A `.data` zero tail nem rejtett payloadként értelmezhető:

- raw file range `0x30B7A00–0x3305A00`;
- a raw utolsó nem nulla byte file offset `0x3305964`;
- raw trailing zero bytes: `155`;
- `VirtualSize - SizeOfRawData = 0x4734` byte loader zero-fill;
- a `.data` belső, legalább 4 096 bájtos nulla-részletei file offsetban: `0x311A790` (`12 392` byte), `0x3129C49` (`32 135` byte), `0x3161128` (`19 040` byte), `0x325A260` (`16 104` byte).

Ezek a writable initialized-data szekció tipikus statikus/tároló- és alignment-részei lehetnek. A zero-fill és a padding nem önmagában titkosító, packer vagy payload-jel. A `.tls` szintén alacsony entropyjű és erősen nulla-dominált.

## 10. Bounded negative-findings checklist

Az alábbi minden pont negatív findingként, de szándékosan **bounded** formában szerepel. A scope, módszer, confidence, false-negative korlát és BRef minden pontban kötelező.

### N-01 — WinHTTP/WinINet: nem találtam ilyen API-felületet

- **Scope:** kizárólag az `adhesive.dll` statikus import-, delay-import-, string- és kódxref-felülete; futásidő és külső DLL-ek nélkül.
- **Módszer:** PE importtábla- és delay-import-parse; ASCII/UTF-16 string-scan `WinHTTP*`, `WinInet*`, `InternetOpen*`, `HttpOpen*`, `URLDownload*` mintákra; URL-scan és közvetlen xref-ellenőrzés.
- **Confidence:** **magas** arra, hogy nincs közvetlen WinHTTP/WinINet API vagy DLL a látott importtáblában; **közepes** arra, hogy dinamikus vagy külső modul által nem használható.
- **False-negative korlát:** API-hashing, titkosított string, runtime `LoadLibrary`, COM/WinRT helper, child process vagy hálózati kód egy másik betöltött modulban. A fájlban ténylegesen van `WS2_32` és libuv, tehát ez **nem** jelent hálózat-mentességet.
- **BRef:** `[RVA:0x2E4B9B9 | RAW:0x2E4A3B9 | CONF:P | STATUS:OBSERVED]`; `[RVA:0x2E4D930 | RAW:0x2E4C330 | CONF:P | STATUS:OBSERVED]`; `[RVA:N/A | RAW:0x0 | CONF:P | STATUS:NEGATIVE]`.

### N-02 — Persistence: nem találtam statikus persistence-láncot

- **Scope:** a DLL-ben látható service-, startup-, Run-key-, Task Scheduler- és persistence-jelű API/stringek; nem a host gép állapotának vagy más process-ek registry-jének vizsgálata.
- **Módszer:** importnevek, ASCII/UTF-16 stringek, manifest/resource és a `RegGetValueW`/fájl-API-k kontextusának statikus review-ja.
- **Confidence:** **magas** a közvetlen, cleartext persistence-mechanizmus hiányára; **közepes** a teljes viselkedésre, mert a DLL külső host- és FiveM-komponensekre támaszkodik.
- **False-negative korlát:** más DLL által létrehozott startup-bejegyzés, registry- vagy feladatscheduler-művelet, WMI-event subscription, COM-eleváció, illetve runtime generált útvonal.
- **Megjegyzés:** a `CitizenFX.ini`, `RegGetValueW` és `CitizenFX_SubProcess_%s.bin` lokalizált konfiguráció/artifactum-jelek, önmagukban nem startup- vagy persistence-lánc.
- **BRef:** `[RVA:0x2E4B9B9 | RAW:0x2E4A3B9 | CONF:P | STATUS:OBSERVED]`; `[RVA:0x2E48FE8 | RAW:0x2E479E8 | CONF:P | STATUS:OBSERVED]`; `[RVA:N/A | RAW:0x0 | CONF:P | STATUS:NEGATIVE]`.

### N-03 — Registry write: nem találtam write-API-t

- **Scope:** a DLL statikus IAT-ja, delay-importjai és cleartext API-nevei; nem a Windows registry tényleges állapota.
- **Módszer:** `RegSetValue*`, `RegCreateKey*`, `RegDeleteKey*`, `SHSetValue*`, `RegSetKeyValue*` és kapcsolódó nevek import/string-scanje; a látott `ADVAPI32.dll!RegGetValueW` külön ellenőrzése.
- **Confidence:** **magas** a közvetlen statikus registry-write API hiányára; **közepes** a dinamikus API-resolution és kernel/native syscall miatt.
- **False-negative korlát:** ntdll/syscall, API-hash, registry helper, COM/WMI, másik modul vagy későn bekötött host-viselkedés. A `RegGetValueW` olvasó API, nem önmagában író mechanizmus.
- **BRef:** `[RVA:0x2E4B9B9 | RAW:0x2E4A3B9 | CONF:P | STATUS:OBSERVED]`; `[RVA:N/A | RAW:0x0 | CONF:P | STATUS:NEGATIVE]`.

### N-04 — ETW/WMI: nem találtam egyértelmű ETW- vagy WMI-használatot

- **Scope:** a DLL statikus importjai, ETW/WMI API-nevek, WMI GUID/namespace/query stringek és a látható ADVAPI32-hívások.
- **Módszer:** `StartTrace*`, `EnableTrace*`, `ControlTrace*`, `TraceEvent*`, `EventWrite*`, `IWbem*`, `root\cimv2`, `Win32_Process`, `SELECT ... FROM` minták scanje; az Event Log API-k külön osztályozása.
- **Confidence:** **magas** az egyértelmű ETW-provider/WMI-felület hiányára; **közepes** a COM-on keresztüli WMI vagy dinamikusan betöltött provider miatt.
- **False-negative korlát:** WMI COM-activation, ETW provider másik DLL-ben, API-hashing, syscalls, ETW-session létrehozása külső helperrel, illetve a host által végzett telemetry.
- **BRef:** `[RVA:0x2E4B9B9 | RAW:0x2E4A3B9 | CONF:P | STATUS:OBSERVED]`; `[RVA:N/A | RAW:0x0 | CONF:P | STATUS:NEGATIVE]`.

### N-05 — Named pipe/mailslot/ALPC/RPC transport: nem találtam cleartext transport-API-t

- **Scope:** a DLL import-, string- és kódxref-felülete; a `RPCRT4` import és a socket API külön kezelése.
- **Módszer:** `CreateNamedPipe*`, `ConnectNamedPipe`, `TransactNamedPipe`, `CallNamedPipe`, `CreateMailslot*`, `\\.\pipe`, ALPC-, RPC-binding és endpoint-mapper string/API scan.
- **Confidence:** **magas** a közvetlen named-pipe/mailslot/ALPC/RPC-client API hiányára; **közepes** a dinamikus endpoint- és path-generálás miatt.
- **False-negative korlát:** `CreateFileW`-lel kialakított pipe, ntdll ALPC, RPC COM-stub, másik modul, gyerekprocessz vagy futásidőben összeállított endpoint.
- **Megjegyzés:** az `RPCRT4.dll` importok csak `RpcStringFreeA` és `UuidToStringA`; az `nui::RPCHandlerManager` string osztály-/namespace-nevnek tűnik, nem RPC-transzport-bizonyítéknak. A DLL-ben `CreateFileMappingW`/`MapViewOfFile`, event- és semaphore-primitívumok is látszanak, ezért ez a finding nem állít IPC-mentességet.
- **BRef:** `[RVA:0x10FBFB | RAW:0x10EFFB | CONF:P | STATUS:OBSERVED]`; `[RVA:0x10F28B | RAW:0x10E68B | CONF:P | STATUS:OBSERVED]`; `[RVA:N/A | RAW:0x0 | CONF:P | STATUS:NEGATIVE]`.

### N-06 — COM activation: nem találtam COM-aktiválási felületet

- **Scope:** a DLL statikus és delay-importjai, GUID/CLSID-stringjei és COM activation API-nevei.
- **Módszer:** `CoCreateInstance*`, `CoInitialize*`, `OleInitialize`, `CoGetClassObject`, `CLSIDFromString*` és COM-activation stringek scanje; a delay import ellenőrzése.
- **Confidence:** **magas** a közvetlen, cleartext COM-activation API hiányára; **közepes** a dinamikus COM és a másik modul általi aktiválás miatt.
- **False-negative korlát:** runtime generált CLSID, COM proxy/stub, `ole32`/`combase` által betöltött helper, RPC-COM interface, child process vagy külső FiveM-komponens.
- **Megjegyzés:** az egyetlen delay-import `ole32.dll!CoTaskMemFree` memóriafelszabadítás, nem COM-aktiválás.
- **BRef:** `[RVA:0x2E4B900 | RAW:0x2E4A300 | CONF:P | STATUS:OBSERVED]`; `[RVA:N/A | RAW:0x0 | CONF:P | STATUS:NEGATIVE]`.

### N-07 — Hardcoded credential/private key: nem találtam teljes, használható plaintext secretet

- **Scope:** a teljes plaintext ASCII/UTF-16 tartalom, PEM-markerek, credential/password/private-key jelű szövegek, resource-ek és a közvetlen crypto-API-k.
- **Módszer:** credential-keyword scan (`password`, `passphrase`, `credential`, `client_secret`, `api_key`, `access_token`), PEM `BEGIN`/`END` blokk-ellenőrzés, a közvetlenül következő bájtok és base64-hossz vizsgálata, valamint a releváns crypto-importok review-ja.
- **Confidence:** **magas** a teljes plaintext privátkulcs és önálló credential literal hiányára; **közepes** minden titkosított/runtime titokra vonatkozó állításra.
- **False-negative korlát:** titkosított credential, DPAPI-blob, runtime visszafejtett kulcs, host-konfiguráció, részben maszkolt/karakterenként összeállított string, illetve másik modulban lévő secret.
- **Megjegyzés:** a `private key`, `password` és `Authorization: Basic/Bearer/NTLM` literálok OpenSSL/curl/diagnosztikai könyvtárstringek. A `CryptUnprotectData` ezzel szemben importált API, amelyhez a vizsgált statikus xref-scan nem talált közvetlen hívást. A `PUBLIC KEY` és `EC PARAMETERS` PEM-markerekhez nem tartozik base64 törzs; a scan nem talált teljes `PRIVATE KEY` blokkot.
- **BRef:** `[RVA:0x2E4D920 | RAW:0x2E4C320 | CONF:P | STATUS:OBSERVED]`; `[RVA:0x2C29840 | RAW:0x2C28240 | CONF:P | STATUS:OBSERVED]`; `[RVA:N/A | RAW:0x0 | CONF:P | STATUS:NEGATIVE]`.

### N-08 — Fix C2: nem találtam egyértelmű fix C2-indikátort, de a hálózati lehetőség fennáll

- **Scope:** csak a DLL-ben plaintext módon látható URL/domain/IP és a statikus hálózati API-k; forgalom, DNS, TLS és runtime callback nem vizsgálva.
- **Módszer:** URL/domain/IP-literál scan, a hálózati importok és a talált endpointok kontextusának review-ja.
- **Confidence:** **magas** arra, hogy a felsorolt endpointok nem mutatnak egyértelmű C2 mintát; **közepes** az általános „nincs fix C2” következtetésre, mert a modul hálózati komponenseket importál.
- **False-negative korlát:** titkosított/konfigurációból generált domain, DGA, DoH, legitim szolgáltatás visszaélése, runtime callback, szerver által adott parancs, child process vagy másik DLL.
- **Megjegyzés:** a `http://clients2.google.com/time/1/current` RVA `0x2C5B0D0`, raw `0x2C59AD0` időszinkronhoz illő URL; a `curl.se/docs/...` szövegek RVA `0x2E1DA80`, `0x2E1DAF0`, `0x2E1DF03` és raw `0x2E1C480`, `0x2E1C4F0`, `0x2E1C903` körüli libcurl-dokumentációk; a DigiCert URL-ek az Authenticode overlay részei. Ezek nem C2-bizonyítékok, de a hálózati kép miatt a teljes kommunikáció nem zárható ki.
- **BRef:** `[RVA:0x2C5B0D0 | RAW:0x2C59AD0 | CONF:P | STATUS:OBSERVED]`; `[RVA:0x2E1DA80 | RAW:0x2E1C480 | CONF:P | STATUS:OBSERVED]`; `[RVA:N/A | RAW:0x0 | CONF:P | STATUS:NEGATIVE]`.

### N-09 — Privilege token API: nem találtam token-privilege API-t

- **Scope:** a DLL statikus importjai, API/string-nevek és privilege/token szövegek; a tényleges process token és jogosultságok nem futásidőben vizsgálva.
- **Módszer:** `AdjustTokenPrivileges`, `OpenProcessToken`, `LookupPrivilegeValue*`, `DuplicateToken*`, `Impersonate*`, `SetTokenInformation`, `CreateProcessAsUser`, `LogonUser`, `GetTokenInformation`, `SeDebugPrivilege` és `TOKEN_*` scan.
- **Confidence:** **magas** a közvetlen token-privilege API hiányára; **közepes** a dinamikus/native és külső modul miatt.
- **False-negative korlát:** ntdll syscall, token helper, API-hash, privilege escalation másik DLL-ben, vagy a host által végrehajtott tokenművelet.
- **Megjegyzés:** az `OpenProcess`/`OpenThread`, `GetThreadContext`/`SetThreadContext` és `QueueUserAPC` import nem önmagában privilege-token API. A `Privilege Withdrawn` string és a manifest `requestedPrivileges` blokkja szintén nem igazolja tokenmódosítást.
- **BRef:** `[RVA:0xD7B86E | RAW:0xD7AC6E | CONF:P | STATUS:OBSERVED]`; `[RVA:N/A | RAW:0x0 | CONF:P | STATUS:NEGATIVE]`.

### N-10 — Embedded packer/payload: nem találtam valid plaintext PE/ZIP/ELF/payload envelope-t

- **Scope:** a teljes `53 575 264` bájtos file, beleértve a szekciókat, az overlayt és a resource-eket; nem történt unpack/decompress.
- **Módszer:** szekció- és marker-scan; 135 `MZ` előfordulás valid PE-fejléceinek és szekcióhatárainak ellenőrzése; ZIP local/central/EOCD, ELF és gyakori archive magic validáció; resource- és overlay-tisztítás.
- **Confidence:** **magas** a valid, plaintext, közvetlenül beágyazott PE/ZIP/ELF és a felismerhető klasszikus packer hiányára; **közepes** minden titkosított, custom-formátumú vagy runtime-generált payloadra.
- **False-negative korlát:** XOR/RC4/AES-zal dekódolt blob, custom packer, overlap/truncated header, runtime-generált kód, process-memory payload, certificate/host által átadott kód vagy külső fájl letöltése. A szándékos, bounded statikus vizsgálat ezeket nem zárja ki.
- **Megjegyzés:** az overlay kizárólag a security directory `0x3315600` kezdődő, `0x2860` bájtos Authenticode-része; nem külön payload.
- **BRef:** `[RVA:0x1000 | RAW:0x400 | CONF:P | STATUS:OBSERVED]`; `[RVA:N/A | RAW:0x3315600 | CONF:P | STATUS:OBSERVED]`; `[RVA:N/A | RAW:0x0 | CONF:P | STATUS:NEGATIVE]`.

## 11. Fontos false positive-ok és félreértelmezések

1. **Magas entropy ≠ packing.** A `.rdata` sziget read-only, kód által hivatkozott, Botan/OpenSSL/Ed25519-jellegű előre kiszámított kryptoadat; a teljes szekcióentropy közepes.
2. **PEM-markerek ≠ private key.** A `PUBLIC KEY`/`EC PARAMETERS` és `PRIVATE KEY` szövegek parser/formátum-literalok; a scan nem talált base64 törzsöt privát kulcs blokkban.
3. **`password`/`Authorization` ≠ hardcoded credential.** Ezek a beépített crypto/curl könyvtár diagnosztikai és protokoll-stringjei.
4. **Google/curl/DigiCert URL ≠ C2.** A Google URL időszinkronhoz, a curl URL-ek libcurl-dokumentációhoz, a DigiCert URL-ek pedig az Authenticode tanúsítvány-adathoz tartoznak.
5. **`RPCRT4.dll` és `UuidToStringA` ≠ RPC transport.** A látott RPCRT4-importok UUID-formázási segédfüggvények; `nui::RPCHandlerManager` inkább osztályazonosító.
6. **`RegisterEventSourceW`/`ReportEventW` ≠ ETW.** Ezek klasszikus Event Log API-k; ETW provider/control API és WMI query nem került elő.
7. **`RegGetValueW` ≠ registry write.** A jelen levő ADVAPI32-import olvasó API; write-API nem látható.
8. **`Privilege Withdrawn` és manifest-privilege blokk ≠ token escalation.** Ezek szöveges/manifest-adatok.
9. **`.retplne` név ≠ futtatható retpoline.** A szekció metadata, characteristics `0x0`, `.text`xref nélkül.
10. **TLS callback ≠ rejtett unpacker.** A három callback a CRT/compiler TLS lifecycle-hoz és destructor-listákhoz kapcsolódik; nincs közvetlen PE-dekompaktálás.
11. **Runtime RWX ≠ statikus RWX szekció.** A statikus section flags tiszták, de a patcher call-site-ok statikusan `PAGE_EXECUTE_READWRITE` memóriát kérnek.
12. **Patching/anti-debug ≠ ártalmatlan vagy ártalmas önmagában.** Ezek valódi findingok; a felhasználási cél és a host-kontextus nélkül sem ártalmatlanság, sem ártalmasság nem állapítható meg.
13. **Valid signature ≠ bizonyított benignitás.** Az aláírás integritási/provenance kontextus, nem a viselkedés statikus bizonyítéka.
14. **PE parser warning ≠ packing finding.** A 119 `pefile` unwind-parser warning mind `Chained function entry cannot be changed` típusú; ez parser-kompatibilitási/elemzési korlát, nem önálló packer-indikátor.

## 12. Mit nem lehet kizárni ebből az elemzésből

- Nem futott a DLL, ezért nincs runtime-hozzáférés a tényleges hálózati, registry-, fájl-, ETW-, WMI-, IPC-, COM- vagy token-műveletekhez.
- Nem vizsgáltam a betöltött `CoreRT.dll`, `citizen-*`, `gta-*`, `net-*`, `v8` és más függőségi modulok kódját.
- Nem oldottam fel teljesen az API-hashinget, a futásidőben generált neveket, a titkosított stringeket vagy a syscall-számok keverését; a közvetlen syscall-utasításokat és argumentummintákat azonban lokálisan validáltam.
- Az entropy-ablakok közepes méretűek; kis, strukturált ciphertext- vagy adatblobok kimaradhatnak egy 4/64 KiB-os mérésből.
- A valid magic/header ellenőrzés nem találhat meg egy szándékosan hibás, titkosított, overlapelt vagy teljesen custom payload-formátumot.
- A `.rdata` krypto-tábla és a patcher célpontjának pontos runtime jelentősége nem bizonyított statikusan.
- A resource-eket és az Authenticode certificate-adatot nem tartalmaztam ki és nem dolgoztam fel payloadként.
- A Git-munkafa, build-cache és PDB/source path provenance nem tekinthető önálló bizalom- vagy ártalmatlansági bizonyítéknak.

## 13. BRef-katalógus

A katalógus a fenti kanonikus `[RVA | RAW | CONF | STATUS]` mezőket használja. A `RAW:0x0` önálló BRefben a teljes fájl bounded scan-scope-jának kezdőoffsetje; a pontos scan-scope minden negatív finding scope- és módszerleírásában szerepel. Az `RVA:N/A` a security directory vagy más overlay-tartalom miatt szükséges.

- **B01 — Identity/header:** `[RVA:0x2AB2770 | RAW:0x2AB1B70 | CONF:P | STATUS:OBSERVED]`; entry point, PE32+ AMD64, export `CreateComponent` RVA `0x101F80`, checksum `0x033207EE`.
- **B02 — Section flags és entropy:** `[RVA:0x1000 | RAW:0x400 | CONF:P | STATUS:OBSERVED]`; a hét szekció értékei a 4.1. táblázatban; egyetlen szekció sem `RWX`; magas `.text` ablak RVA `0x2A96C00–0x2A97C00`, raw `0x2A96000–0x2A97000`, H=`7.965173`; magas 64 KiB-os `.rdata` ablak RVA `0x2CA1600–0x2CB1600`, raw `0x2CA0000–0x2CB0000`, H=`7.741525`.
- **B03 — Import/export scope:** `[RVA:0x2E4B9B9 | RAW:0x2E4A3B9 | CONF:P | STATUS:OBSERVED]`; 42 descriptor, 628 standard entry, IAT RVA `0x2E4D208`, delay descriptor RVA `0x2E4B900` / raw `0x2E4A300`.
- **B04 — Resource/overlay/signature:** `[RVA:N/A | RAW:0x3315600 | CONF:P | STATUS:OBSERVED]`; `0x2860` bájtos security directory pontosan a fájl végéig tart; debug PDB, `FXCOMPONENT`, verzió és manifest a 3. és 4. pontban.
- **B05 — Crypto/high-entropy envelope:** `[RVA:0x2CB18E0 | RAW:0x2CB02E0 | CONF:P | STATUS:OBSERVED]`; Botan/OpenSSL/Ed25519 stringek és kódxrefek a 4.3. pontban; a 4 KiB-os `.rdata` csúcs `8.0` körüli.
- **B06 — Dynamic resolver:** `[RVA:0x2E4D3B0 | RAW:0x2E4BDB0 | CONF:P | STATUS:OBSERVED]`; `GetModuleHandleW` RVA `0x2E4D390`, `LoadLibraryW` RVA `0x2E4D480`, `CoreRT.dll` RVA `0x2E1F7FA`, `wtsapi32.dll` RVA `0x2E1F828`.
- **B07 — Runtime patch/trampoline:** `[RVA:0x1E2D1 | RAW:0x1D6D1 | CONF:P | STATUS:OBSERVED]`; `VirtualProtect`/context-patch útvonal, `VirtualAlloc` RVA `0x1D3A2` / raw `0x1C7A2`, Toolhelp hook RVA `0xC8CE70` / raw `0xC8C270`, NOP helper RVA `0x1754520` / raw `0x1753920`.
- **B08 — Anti-debug és feltételes ág:** `[RVA:0x5302 | RAW:0x4702 | CONF:P | STATUS:OBSERVED]`; `[RVA:0x5C59 | RAW:0x5059 | CONF:L | STATUS:INFERRED]`; `GetProcAddress` RVA `0x52EA` / `0x5C41`, cache RVA `0x30D4288` / raw `0x30D2C88`, közvetlen `IsDebuggerPresent` RVA `0x2AE1008` / raw `0x2AE0408`.
- **B09 — TLS/retplne/load config:** `[RVA:0x2E0A1D0 | RAW:0x2E08BD0 | CONF:P | STATUS:OBSERVED]`; TLS callback-array RVA `0x2E4B8B8` / raw `0x2E4A2B8`, `.retplne` RVA `0x330C000` / raw `0x3305A00`, `DllCharacteristics=0x0160`.
- **B10 — `.data` zero tail:** `[RVA:0x30B9000 | RAW:0x30B7A00 | CONF:P | STATUS:OBSERVED]`; trailing raw zero `155`, virtual zero-fill `0x4734`, a belső nulla-runok raw `0x311A790`, `0x3129C49`, `0x3161128`, `0x325A260`.
- **B11 — Embedded object scan:** `[RVA:N/A | RAW:0x0 | CONF:P | STATUS:NEGATIVE]`; 135 `MZ` előfordulásból csak a file kezdetén valid PE, ZIP/ELF/archive valid header nincs, resource-ekben nincs executable blob.
- **B12 — Endpoint és string false positive-ok:** `[RVA:0x2C5B0D0 | RAW:0x2C59AD0 | CONF:P | STATUS:OBSERVED]`; curl-doc RVA `0x2E1DA80` / raw `0x2E1C480`, RPC/UUID és OpenSSL/Botan/credential parser stringek a 4., 5. és 11. pontban.
- **B13 — Negatív API/string scan:** `[RVA:N/A | RAW:0x0 | CONF:P | STATUS:NEGATIVE]`; WinHTTP/WinINet, persistence, registry-write, ETW/WMI, pipe/mailslot/ALPC/RPC transport, COM activation, credential/private-key és token-privilege minták teljes statikus sweepje.
- **B14 — Korlátok:** `[RVA:N/A | RAW:0x0 | CONF:U | STATUS:OPEN]`; 119 `pefile` `UNWIND_INFO` parser-warning, a külső modulok és runtime-viselkedés nem vizsgálva, entropy-ablakméret és statikus xref korlátok a 12. pontban.
- **B15 — Közvetlen syscall/process-memory capability:** `[RVA:0xD7B0AE | RAW:0xD7A4AE | CONF:P | STATUS:OBSERVED]`; `[RVA:0xC86477 | RAW:0xC85877 | CONF:L | STATUS:INFERRED]`; `ProcessBasicInformation`-kompatibilis syscall, `0xC856C0` dispatch és `0xC86420` / `0xC870DB` inline syscall-helyek; a szolgáltatásnév és végrehajtás `STATUS:OPEN`.


## 14. Végső bounded értékelés

**Packing:** a teljes képre nincs UPX/klaszikus packer-, overlay-payload- vagy valid plaintext embedded PE/ZIP/ELF-bizonyíték. A `.rdata` magas entropyja lokalizált kriptográfiai/lookup-adatra, a `.text` egyes 4 KiB-os csúcsai pedig részben valódi, obfuszkált kódra mutatnak.

**Obfuscation:** a normál import/resource/debug struktúra nem zárja ki a kódkeverést; a `.text` nagy részén opaque-transform/CFF-jellegű logika, direkt syscall- és process-memory-wrapper-útvonalak, valamint több runtime patch-mechanizmus igazolható. Ez erős obfuscation-képesség, de nem teljes-image packer bizonyítéka.

**Entropy:** a `.rdata` egyetlen szigete eléri a jelentésben választott magas-entropia küszöböt, de ez önmagában nem packer-kritérium. A kódxrefek, a read-only helyzet, a Botan/OpenSSL/Ed25519-kontextus és a valid embedded-object scan a krypto-/lookup-tábla értelmezését erősíti. A `.text` magas oldalai nem bizonyítanak titkolt payloadot.

**Negatív findings:** az N-01–N-10 pontok szigorúan bounded statikus következtetések, kanonikus BRef-ekkel és explicit false-negative korlátokkal. Egyik sem zárja ki a dinamikus feloldást, a közvetlen syscall-okat, a host- és companion-modulok viselkedését, a titkosított/custom payloadot vagy a teljes FiveM-komponens ökoszisztémáját.

## 11.x Biztonsági tartalom-javítás

Ez a blokk a `7.3` és `7.4` szakasz tartalmi biztonsági javítását regisztrálja, és a fájl végén áll, a projekt `16.x`/`16.y` utó-audit blokkjaival azonos elhelyezkedésben. A változás kizárólag szövegszerű: a DLL-t nem futtattam, és új statikus mérést, disasszemblálást vagy feloldást sem végeztem. A más dokumentumokban maradt hibás fájlneveket szándékosan nem javítottam.

**Mi törölt**

| Hely | Törölt tartalom | Indoklás |
|---|---|---|
| `7.3` 2. pont | az inline hook konkrét stub-payloadja, annak hex- és assembler-alakjával együtt | a szakasz így közvetlenül beépíthető hook-payloadt adott |
| `7.3` 2. pont | a mentett és a felülírt terület bájtban megadott hossza | a területméret a payload előállításához szükséges adat |
| `7.3` 2. pont | a hook-hely `VirtualProtect`-hívásának védelmi immediate-ja | a védelem a `PAGE_EXECUTE_READWRITE` névvel, konstans nélkül maradt |
| `7.3` 2. pont | a telepítő és a visszaállító segéd belépési RVA-ja a receptszerepükben | cél + patch-tartalom + restore együtt már kész patch-mechanizmust adott |
| `7.3` 1. pont | a NOP-kitöltő konkrét bájtértéke | a `16` §7.3 harmadik pontja ugyanezt a szimbolikus gyakorlatot írja elő |

**Mi maradt szimbolikusan a `7.3` pontban**

- a patchelt függvény azonosítása: `KERNEL32!CreateToolhelp32Snapshot`, IAT RVA `0x2E4D290`;
- a viselkedés: az eredeti belépési bájtok mentése hívó által adott rekordba, a belépési terület elfoglalása `INVALID_HANDLE_VALUE`-t visszaadó stubbal, a rekord tartalmának visszaírása a páros segéddel, illetve a NOP-kitöltés egyetlen konstans bájt ismétlése a caller hosszargumentuma szerint;
- a védelemváltás `PAGE_EXECUTE_READWRITE`-re, konstans érték nélkül;
- a szerkezeti evidence-helyek: `0x1754520`, `0xC8CEF4`, `0xC8F4B3`, `0xC8F47F`–`0xC8F498`;
- a negatív megkötés: közvetlen hívó és megbízható függőpointer nem azonosítható, tehát a képesség pozitív, az aktív használat nem bizonyított.

**A `7.3`/`7.4` ellentmondás feloldása**

A `7.4` korábban a patch-címet és a patch-tartalmat is nyitott kérdésnek nevezte, miközben a `7.3` konkrétan megadta őket. Mindkét helyen most egységes jelölés szerepel: a patch-cím és a patch-tartalom a `16` dokumentumban leírt, itt nem reprodukált érték; a nyitott kérdés kizárólag a célmodulra, a patchet inicializáló callerre, a futásidejű feloldási és oldalvédelmi állapotra, valamint a tényleges lefutásra vonatkozik.

**Hová mutat a részletes leírás**

- `16` §3.3 és §3.4: a patch-site kifejezés, a területmézet, a védelmi konstans és a két írási csoport szélesség-, cél- és ablakleírása;
- `16` §6.1–§6.3: a Toolhelp-pár telepítője és visszaállítója, a mentett és felülírt terület **szélesség- és ablakleírása**, valamint a két fél aszimmetriája; a szűk konstans-tárolások szélességeire szóló felülírt állítás szimbolikusan a `16` §12.2 regiszterében (11. sor) van, a `16` §6.1 a stub tartalmát és írási bájtértékeit nem adja meg;
- `16` §6.4: a feloldási cache, a gate és a literálok, vagyis a patch-cím forrása;
- `16` §7.1–§7.3: a NOP-kitöltő célcím-újrabázelése, a kitöltés és a szimbolikus bájtérték-elv;
- `16` §13.0: a telepítő caller-e és aktiválása, azaz a valóban nyitott rész;
- evidence: `patch_mechanisms_helpers.csv`, `patch_mechanisms_1dff0.csv`, `thread_context_map.json`.

**Mi nem változott**

- A fejlécekben lévő `Felülírt részek` blokk szó szerint változatlan;
- minden meglévő finding, `CONF`/`STATUS` érték és BRef változatlan; a `13` pont `B07` BRef-je is, amely a Toolhelp hook RVA-ját a finding azonosítására továbbra is tartalmazza;
- a `7.3`-ban egyetlen új szám jelent meg, a patchelt import IAT RVA-ja (`0x2E4D290`, a `03` és `06` dokumentum importtáblája alapján), mert ezzel azonosítható a patchelt függvény; a telepítő és a visszaállító segéd belépési RVA-ja pedig kikerült a receptszerepéből, nem a findingból;
- a `2.`, `7.1.`, `7.2.` pont, a false positive-ok `11.` pontja, valamint a `12.`, `13.` és `14.` pont szövege nem módosult;
- a fájl formátuma: UTF-8 BOM nélkül, LF sortöréssel, záró sortöréssel.

---

## 11.y Hivatkozás-pontosítás a `16` dokumentum tartalmára

Ez a blokk a `7.3`, a `7.4` és a fenti `11.x` „Hová mutat a részletes leírás" listájának `16`-ra vonatkozó mondatait pontosítja. A DLL-t nem futtattam, nem töltöttem be, nem hookoltam és nem patcheltem; új statikus mérés, disasszemblálás vagy feloldás nem készült, és egyetlen finding, szám, BRef, táblázat vagy `CONF`/`STATUS` érték nem változott.

**Mi volt pontatlan**

| Hely | Régi mondat | Javított mondat |
|---|---|---|
| `7.3` 1. pont | „A kitöltő bájt értékét a `16` dokumentum 7.2. szakasza adja meg" | sem ez a dokumentum, sem a `16` nem adja meg az értéket; a `16` §7.2–§7.3 csak a szimbolikus szabályt rögzíti, az érték szándékosan nincs reprodukálva |
| `7.3` 2. pont | a patch-cím, a mentett és felülírt terület hossza, a kitöltő bájtok és a védelmi konstansok a `16`-ban leírt értékek | a `16` §6.1–§6.3 a terület **szélesség- és ablakleírását** adja; a szűk konstans-tárolások szélességeire vonatkozó felülírt állítás a `16` §12.2 regiszterében, szimbolikusan szerepel; a `16` §6.1 a stub tartalmát és írási bájtértékeit nem adja meg |
| `7.4` | a `16` §6.1–6.2 hivatkozás általános, a patch-tartalomra is kiterjedő volt | a hivatkozás a telepítőre, a visszaállítóra és a felülírt terület szélesség- és ablakleírására szűkült |
| `11.x` „Hová mutat" lista 2. sora | a `16` §6.1–§6.3 tartalmazza „az immediátokat, a stub tartalmát" | a `16` §6.1–§6.3 a terület szélesség- és ablakleírását és a két fél aszimmetriáját tartalmazza; ahol a stub leírása szimbolikus, az a `16` §12.2 regiszterének 11. sorára hivatkozik |

**Mi nem változott:** a fejlécekben lévő `Felülírt részek` blokk, a `2.`, `4.`, `5.`, `7.1`, `7.2`, `8.`, `9.` és `10`–`14.` pont szövege, az `N-01`–`N-10` következtetések, a `B01`–`B15` BRef-katalógus és a `11.x` teljes „Mi törölt" / „Mi maradt szimbolikusan" blokkja; a javítás kizárólag a `16`-dokumentumra való hivatkozások pontosságára vonatkozott. A fájl formátuma: UTF-8 BOM nélkül, LF sortöréssel, záró sortöréssel.
