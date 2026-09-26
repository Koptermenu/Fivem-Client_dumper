# adhesive.dll – kockázati módszertani összegzés és nyitott kérdések

**Vizsgált példány:** `C:\Users\Admin\Desktop\Dumper - AllInOne\reverse\adhesive.dll`
**Vizsgálat dátuma:** 2026-09-25
**Dokumentum státusza:** peerrel auditált szintézis; a `01`–`11` riportokkal összevetve, konfliktusjegyzékkel; nem új, önálló bináris finding.
**Vizsgálati határ:** kizárólag statikus fájl- és PE-elemzés, nyilvános forráskód-korreláció és hitelesítés-ellenőrzés. A DLL-t nem töltöttem be és nem futtattam, hálózati kapcsolatot nem létesítettem vele, és exploit-, bypass-, patch- vagy credential-recovery receptet nem adok.

## 1. Végkövetkeztetés

A vizsgált fájl erős belső konzisztenciával illeszkedik a FiveM/CitizenFX kliens `adhesive` komponenséhez:

- a PE erőforrása `adhesive` néven azonosítja a komponenst, a `CreateComponent` export pedig illeszkedik a CitizenFX komponensbetöltő modelljéhez;
- a FileVersion és ProductVersion `1.0.0.36109`, a beágyazott `FXCOMPONENT` verzió `0.1.0`;
- a függőségek között `fx[2]`, `legitimacy`, `glue`, `net`, `vfs:core`, CitizenFX/GTA/RAGE komponensek és `vendor:openssl_ssl` szerepelnek;
- a debug PDB útvonala `C:\gl\builds\cfx-fivem-0\...`, tehát a FiveM/CitizenFX buildkörnyezetre utal;
- az Authenticode aláírója a `Rockstar Games, Inc.`, és a vizsgálat környezetében az aláírás érvényes;
- a nyilvános CitizenFX forrás az `adhesive` komponenst felsorolja; a nem-SDK kliensútban Wine vagy a `xtajit64.dll` jelenléte esetén `sticky` komponenst választ, miközben az anti-cheat komponensek nem támogatott környezetéről tájékoztat.

Ezek **magas konfidenciájú komponensazonosítást** és **magas konfidenciájú, aktuálisan érvényes Rockstar-aláírást** támasztanak alá. Nem zárják le a pontos release/csatorna, az eredeti letöltési hely vagy a terjesztési lánc provenanciáját. A loader szövege, a `legitimacy`/`glue` függőségek és a statikus integritási képességek együtt **valószínűsítik** a biztonsági, integritási vagy anti-cheat szerepet, de a nyilvános source nem validálja a privát belső implementációt vagy annak pontos célját.

A DLL-ben nagy hatású statikus képességek figyelhetők meg: processz- és szálkezelés, memória- és oldalvédelem-kezelés, közvetlen `syscall` végrehajtás, feltételes debugger-jel, kódkeverés, TLS/HTTP/WebSocket-képesség, DPAPI-import és gépadapter-információk. Ezek **potenciálisan nagy hatású képességek**, de az import, sztring vagy disasszembláció önmagában nem bizonyítja, hogy minden képesség végrehajtásra kerül, milyen célra szolgál, vagy milyen adatot kezel.

**Összesített értékelés:**
- Provenance/komponensazonosítás: magas konfidenciával FiveM/CitizenFX `adhesive` komponenssel összhangban álló specimen; a jelenlegi bytes-együttes a vizsgálatkor érvényesen Rockstar Games aláírásával rendelkezik.
- Szerep: közepes konfidenciával integritás-/biztonsági/anti-cheat jellegű; a pontos funkció és anti-debug szándék nem lezárt.
- Rosszindulatú működés: nincs pozitív statikus bizonyíték credential theftre, persistence-re, ismeretlen C2-re vagy exfiltrációra. Ezek bounded statikus negatívumok, nem teljes kizáró bizonyítékok. Explicit `SetWindowsHookEx`/Detour hook nincs; lokális patch-, stub- és NOP-segédmechanizmusok vannak, célmodul, hívó és aktiválás ismeretlen.
- Potenciális hatás: a process-memory és lokális patch-útvonalaknál magas; a tényleges végrehajtás, jogosultság, cél és adatfolyam nem ismert. Az összesített evidence alapján malware-, incidens- vagy jogi kockázatminősítés nem adható.

## 2. Likelihood és provenance

| Hipotézis | Értékelés | Confidence | Alap |
|---|---|---:|---|
| A fájl a FiveM/CitizenFX `adhesive` komponensének része | Támogatott | Nagy (P) | Export, erőforrás, PDB, függőségek, importok és a hivatalos loader/komponenslista |
| A pontos bájtsorozat Rockstar Games aláírásával rendelkezik, és a vizsgálatkor érvényes | Támogatott | Nagy (P) | Authenticode `Valid`, aláíró és időbélyeglánc; ez nem terjeszti ki az érvényességet minden környezetre |
| A szerepe anti-cheat/anti-tamper/biztonsági komponens | Valószínű, de a privát implementáció ismerete nélkül nem bizonyított | Közepes (L) | `legitimacy`/`glue`, process-memory és feltételes anti-analysis jelek, valamint a loader anti-cheat-kontextusa |
| A `1.0.0.36109` pontos build hiteles eredetű | A specimen ezt a verziót tartalmazza; a konkrét release/csatorna baseline nélkül nem zárható le | Közepes (L) | Konzisztens metaadatok és aláírás, de nincs azonos buildű, hivatalos helyi referencia |
| A jelenlegi fájl aláírás utáni byte-módosítást tartalmaz | Nincs pozitív jel; bármilyen szignált byte módosítása az aláírt digestet érvénytelenítené | Nagy (P) a jelenlegi integritásra | A Windows és a beágyazott digest egyezik |
| A DLL credential stealer, persistence-modul, ismeretlen C2 kliens vagy exfiltráló komponens | Nincs pozitív statikus támogatás a vizsgált scope-on | Közepes (L) | Nincs igazolt credential-artifact, persistence-lánc vagy production endpoint; dinamikus és companion-kód nem zárható ki |
| A process/hook lehetőségek automatikusan exploit-vé konvertálhatók | Nem a következtetés | Nagy (P) | A dokumentum nem ad invokációs, exploit-, bypass- vagy patch-receptet |
**Confidence-jelölés:** a fenti `Nagy (P)`, `Közepes (L)` és `Bizonyítatlan (U)` értékek a dokumentumcsalád `P`/`L`/`U` skálájára adjak egyértelmű megfeleltetést: `Nagy = P`, `Közepes = L`, `Bizonyítatlan = U`; a 12. fejezet Confidence-oszlopa ugyanezt a skálát használja.
### Korrelált nyilvános források

2026-09-25-én elérhető és tartalmilag ellenőrzött, commit-pinnelt CitizenFX források:

- a `ComponentLoader.cpp` az `adhesive` komponenst kezeli; SDK/Guest módban kihagyja, a nem-SDK kliensútban Wine vagy `xtajit64.dll` esetén `sticky` komponenst választ, és a master processben az anti-cheat komponensek nem támogatott környezetéről üzen:
  https://github.com/citizenfx/fivem/blob/08bb8647cdc64f5d6200cc2dccb7386f6e9bcec4/code/client/citicore/ComponentLoader.cpp
- a `components.json` az `adhesive` elemet felsorolja a klienskomponensek között:
  https://github.com/citizenfx/fivem/blob/c6345f85952e00aa4eedcd27a21cdec8ede885b7/data/client/components.json

Ezek a források a komponensazonosítást és az anti-cheat-kontextust erősítik. Nem tartalmazzák a vizsgált privát `adhesive` implementáció mappingjét, ezért nem validálják az `0xC856C0` wrappert, a syscall-számokat, a patch-célokat vagy a hálózati végpontokat.

## 3. Validált identitás, aláírás és PE-adatok

### 3.1 Fájlazonosítás

| Tulajdonság | Validált érték |
|---|---|
| Fájlnév | `adhesive.dll` |
| Fájlméret | `53 575 264` bájt (`0x3317E60`) |
| MD5 | `2E24179CC01167E50190FDD3BCF6939A` |
| SHA-1 | `AE5627C6AAB786095A816FC43F0E4CE04CEE8829` |
| SHA-256 | `91CC0AA006D7315CB042C8FA8DCA6C1E074A307BBA7DCC9EB5509C8A7B81934E` |
| Fájlmódosítás ideje | `2026-09-13T14:17:25.1851835Z`; ez fáblrendszer-idő, nem megbízható build idő |
| PE timestamp | `1789139178` = `2026-09-11T15:06:18Z` |
| PE checksum | Headerben `0x033207EE`; a számított érték egyezik |
| Architektúra | AMD64/x86-64, PE32+ |
| Image base | `0x180000000` |
| Entry point RVA | `0x02AB2770` |
| SizeOfImage | `0x0331E000` |
| Szekciók | 7: `.text`, `.rdata`, `.data`, `.retplne`, `.tls`, `.rsrc`, `.reloc` |
| DllCharacteristics | `0x0160`: high-entropy VA, ASLR és NX; CFG function-table/count/flags nem található |
| TLS | TLS directory megvan; három callback a `0x2AB28D0`, `0x0010D0`, `0x2AB2948` RVA-kon, a negyedik táblaelem nulla |
| .NET | Nincs COM descriptor; nem .NET assembly |
| VersionInfo | Company `Cfx.re`; Product `CitizenFX`; File/Product version `1.0.0.36109` |
| Original filename | `adhesive.dll` |
| Manifest | `asInvoker`, `uiAccess=false` |

A PE checksum egyezése önmagában nem biztonsági garancia, de a header és a tényleges PE-tartalom konzisztens. A TLS callback-listát a parser által nem kitöltött callback mező ellenére a nyers callback-array qwordjeiből ellenőriztem.

### 3.2 Authenticode

| Tulajdonság | Validált érték |
|---|---|
| Windows verifier állapot | `Valid` / `Signature verified.` |
| Signature type | Authenticode |
| Beágyazott signature count | 1 |
| Security directory | file offset `0x03315600`, méret `0x2860`; a fájlon belül van |
| Aláírt Authenticode image SHA-256 | `82D63CBAF1EAD1CC9E2B9FC871F4778E68C2ADC06F0DF7144E1892B38A1E575A` |
| Aláíró subject | `CN="Rockstar Games, Inc.", O="Rockstar Games, Inc.", L=New York, S=New York, C=US` |
| Aláíró issuer | `DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1` |
| Aláíró thumbprint | `FF0EE06434B1695115A35FB077DE538FD1F66D9C` |
| Aláíró serial | `0B0AF411D651006A4562E07B6F086D75` |
| Aláíró érvény | `2026-07-21T00:00:00Z` – `2027-09-05T23:59:59Z` |
| Időbélyeg signer | `DigiCert SHA256 RSA4096 Timestamp Responder 2026 1` |
| Időbélyeg signer thumbprint | `51D9ABDA034973D84F4266ACA48248E6B369C439` |
| Időbélyeg signer érvény | `2026-08-05T00:00:00Z` – `2037-11-04T23:59:59Z` |
| Nested signing time attribútum | `2026-09-11 15:08:46 UTC` |

A `Valid` eredmény a vizsgálati gép trust state-jétől és időpontjától függ. Az Authenticode image hash a PE-specifikus kivételek miatt nem egyezik a teljes fájl SHA-256-val. Az Authenticode bizonyítja a szignált tartalom integritását és az aláíró tanúsítványát, **nem a program ártalmatlanságát vagy azt, hogy minden runtime viselkedés elvárt**.

### 3.3 Import/export számok

A számolás szabálya: a regular import descriptorokat null-terminátorig, a thunkokat null-terminátorig, a delay-importokat külön, az exportokat az export directory alapján számoltam. A `pefile` és a LIEF eredménye egyezett; a GNU `objdump` támogatta a kézi ellenőrzést.

| Kategória | Validált szám |
|---|---:|
| Regular import descriptor / importált DLL | 42 |
| Regular import thunk / funkcióbejegyzés | 628 |
| Regular név szerinti import | 604 |
| Regular ordinal szerint importált bejegyzés | 24; mind a `WS2_32.dll`-ben |
| Delay-import descriptor / DLL | 1 (`ole32.dll`) |
| Delay-import funkció | 1 (`CoTaskMemFree`) |
| Regular + delay import összesen | 43 descriptor, 629 funkcióbejegyzés |
| Export descriptor | 1 |
| Export funkció | 1 |
| Export | `CreateComponent`, ordinal 1, RVA `0x00101F80`, nincs forwarder |

A LIEF `imported_functions=629` értéke a regular és delay importot együttesen számolja; ezért a 628 nem ellentmondás. A `pefile` az ordinal importokhoz feloldott exportnevet is társíthat, ezért a besorolást nem a `name` mező, hanem az `ImportData.import_by_ordinal`/`ImportData.ordinal`, illetve a nyers INT/IAT thunk magas bitje alapján végeztük.

### 3.4 Erőforrások és debug

- Erőforrástípusok: version info, manifest és `FXCOMPONENT`.
- Az `FXCOMPONENT` JSON neve `adhesive`, verziója `0.1.0`.
- A dependency list többek között: `fx[2]`, `rage:device`, `gta:core`, `gta:streaming`, `vfs:core`, `net`, `citizen:scripting:core`, `citizen:resources:gta`, `citizen:legacy-net:resources`, `scripting`, `legitimacy`, `glue`, `vendor:openssl_ssl`, `vendor:imgui`.
- A debug directory egyetlen CodeView/RSDS bejegyzést tartalmaz.
- PDB path: `C:\gl\builds\cfx-fivem-0\.build-cache\bin\five\release\dbg\adhesive.pdb`.
- PDB GUID: `CB927E36-3F3D-8D77-4C4C-44205044422E`.
- PDB age: `1`.
- A PDB maga nem található a vizsgált könyvtárban; a bináris csak a path/GUID/age referenciát tartalmazza.
- A security directory pontosan a fájl végéig tart (`0x03315600 + 0x2860 = 0x03317E60`); nincs külön, nem aláírt trailing overlay.
- A `.text` és `.rdata` entropyja `6.3544` és `6.0675`; nincs klasszikus teljes-image UPX/packer-kép, de lokalizált kriptográfiai adat és anti-analysis/obfuscation létezik.

## 4. Evidence hierarchy és státuszjelölés

### Evidence hierarchy

1. **Artifact-azonosítás és aláírási integritás:** a fájl hash-e azonosítja a mintát; a PE checksum konzisztenciát, a Windows Authenticode eredménye pedig a szignált PE image és tanúsítványlánc integritását támasztja alá.
2. **Kereszt-tool szerkezeti egyezés:** a PE import/export/resource/debug számlálás legalább két független parserrel egyezik.
3. **Lokális statikus control-flow bizonyíték:** ismert funkcióhatárokból, `.pdata`-ból és disasszemblációból igazolt utasítás-, IAT- és lokális xref-kapcsolatok.
4. **Statikus képességindikátor:** import, export, resource, ASCII/UTF-16 sztring és beágyazott kód. Ezek lehetőséget jeleznek, nem végrehajtást.
5. **Hivatalos nyilvános forrás-korreláció:** a CitizenFX loader és komponenslista a komponensazonosítást és az anti-cheat-kontextust erősíti, de nem belső implementációs vagy intent-bizonyíték.
6. **Intent/reputation következtetés:** a legkisebb erejű réteg; önmagában nem alkalmas malware-, jogi vagy fenyegetési minősítésre.

### Observed, latent és unknown

- **Observed:** a képesség vagy szerkezet statikusan jelen van, vagy a lokális call path végig követhető. Az „observed” nem jelenti, hogy futáskor ténylegesen meghívták.
- **Latent:** a mintában megvan az ehhez szükséges primitív, de a konkrét hívási feltétel, cél, adat vagy eredmény nem validált.
- **Unknown:** nincs elég statikus bizonyíték; string hiánya sem zárja ki az obfuszkált vagy külső forrásból érkező megvalósítást.

## 5. Capability-impact mátrix

A **Potenciális hatás** oszlop a statikusan jelen lévő képesség lehetséges hatását, nem észlelt kárt, incidenciát vagy bizonyított rosszindulatot értékeli. A **Evidence confidence** kizárólag a capability bizonyítékának erőssége; az intent és a visszaélés külön nyitott kérdés.

| Component | Statikus evidence | Observed vs latent | Potenciális hatás / előfeltétel | Evidence confidence |
|---|---|---|---|---|
| **Files** | Közvetlen `CreateFileW`, `WriteFile`, CRT-olvasás, `CopyFileW`, `DeleteFileW`, `MoveFileW`, find/path API-k; VFS importok; `CitizenFX.ini`; `CitizenFX_SubProcess_%s.bin` | **Observed:** helyi konfiguráció-, cache-, subprocess- és fájlműveleti kód. **Unknown:** minden konkrét célfájl, futási út és adatérték. | Helyi fájlok olvasása, módosítása, törlése és cache-kezelése; megfelelő handle és írási jog szükséges. | Nagy (P) a capabilityre; alacsony (U) a visszaélésre. |
| **Process / memory** | Három `ProcessBasicInformation`-kompatibilis inline syscall a saját folyzat `-1` pseudo-handlével, `0` information-class értékkel, `0x30`-bájtos bufferrel és `buffer+0x28` parent-PID olvasással; `OpenProcess(..., 0x1000, ...)`; process-handle-alapú allokáció- és írás-/olvasás-kompatibilis syscall-argumentumok; saját szálak context-kezelése; `QueueUserAPC`, miközben az APC cél egyetlen `ret` | **Observed:** közvetlen utasítások és kompatibilis argumentumsémák. **Unknown:** pontos Nt-szolgáltatásnév, handle-eredet, célprocessz, jogosultság, siker és írás iránya. A query-limited parent-handle nincs összekötve a `0xC856C0` descriptorrel. | Megfelelő processz- és memory-jog mellett processzmemória- és végrehajtásbefolyásolás lehetősége; tetszőleges APC-kód vagy távoli injektálás nincs igazolva. | Nagy (P) a statikus szerkezetre; közepes (L) a logikai Nt-szemantikára; alacsony (U) a célra. |
| **Hooks / patch** | Nincs explicit `SetWindowsHookEx`, Detour vagy MinHook. A `0x1DFF0` körüli alrendszer `OpenThread`, suspend/get/set context, `VirtualProtect` és `FlushInstructionCache` útvonalakat használ; a `0xC8CE70`/`0xC8F470` Toolhelp stub/restore pár; a `0x1754520` NOP-patch segéd; több `PAGE_EXECUTE_READWRITE` allokáció | **Observed:** lokális patch-, stub- és NOP-write mechanizmusok. **Unknown:** célcím/modul, hívó, telepítés és aktiválás; a Toolhelp-párnak és NOP helpernek nincs közvetlen statikus hívója. | A saját processz kódjának vagy egy elérhető céloldalnak a végrehajtási és integritási viselkedésének módosítása. | Nagy (P) a mechanizmusra; alacsony (U) a célra és aktiválásra. |
| **Anti-analysis / debugger** | Közvetlen `ProcessDebugPort=7`, `ProcessDebugObjectHandle=0x1E` és `ProcessDebugFlags=0x1F` process-query syscallágak; `NtSetInformationProcess` class `0x28` null descriptorrel; `IsDebuggerPresent` egy CRT/fatal-error környezetben; két `GetModuleHandleW`-alapú `CoreIsDebuggerPresent` feltételes ág `INT3`-tal; Toolhelp stub/restore; sok timing API; `RDTSC`, PEB és KUSER_SHARED_DATA-alapú kódkeverés | **Observed:** a class-/argumentum-kompatibilis direct syscallok, a null instrumentation descriptor, a feltételes debugger-jel és az obfuszkáció. **Not proved:** a top-level callerlista, a pontos service number, a runtime-elérhetőség, aktív anti-debug döntés, delta-timing check, evasion vagy processzkizárás. | Process-debug/instrumentation lekérdezés, feltételes debugger-trigger vagy `INT3`-alapú megszakítás; a valódi szabály, cél és kiváltó feltétel ismeretlen. | Nagy (P) a közvetlen kódstruktúrára; közepes (L) a logikai Nt-szemantikára; alacsony (U)–közepes (L) az anti-debug intentre. |
| **Crypto / trust** | Beágyazott OpenSSL `1.1.1t` és Botan; TLS 1.2/1.3 setup; X.509 ROOT-store és közvetlen `CryptQueryObject`/`CryptMsgGetParam` útvonal; `BCryptGenRandom`; `WinVerifyTrust` és `CryptUnprotectData` import/thunk | **Observed:** statikus kriptográfiai és bizalmi felület. **Unknown:** alkalmazásszintű kulcs/hatás, blob és kimeneti adat. A `WinVerifyTrust` és `CryptUnprotectData` thunk/IAT közvetlen `rel32`/IAT-call referenciája nem található. | TLS-, tanúsítvány- és adatvédelmi műveletek lehetséges hatása; kulcs, blob és jogosultság szükséges. Nem credentiallopás-bizonyíték. | Nagy (P) a statikus felületre; közepes (L) az alkalmazási útvonalra. |
| **Network** | `WS2_32.dll` 41 import; libuv 9 import; `net`, `net-base`, `net-tcp-server`; közvetlen socket callsite-ok és loopback önteszt; cURL/OpenSSL, HTTP/2; HTTP/3 közepes és WebSocket alacsonyabb evidence-szel | **Observed:** socket-, TLS-, HTTP/1.1- és HTTP/2-képesség, valamint helyi önteszt. **Unknown:** production endpoint, request schema, payload, célzott adat és külső kapcsolat. | Külső kommunikáció lehetősége; valódi végpont, hálózat és hasznos adat nélkül nincs exfiltráció- vagy C2-bizonyíték. | Nagy (P) a socket/HTTP stackre; közepes (L) HTTP/3-ra; alacsony (U) WebSocket használatra és ismeretlen végpontra. |
| **IPC** | Közvetlen `CFX_%s_%s_SharedData_%s` mapping, `CreateFileMappingW`/`MapViewOfFile`; event- és semaphore-API-k; IOCP; `RegisterSuspendResumeNotification`; RPCRT4 UUID/string API-k | **Observed:** shared-memory és szinkronizációs primitívek. **Unknown:** konkrét partner, protokolltartalom és adatcsere. Cleartext named-pipe/mailslot/ALPC/RPC-transport API nem látható. | Komponensek/processzek közötti állapot- vagy adatcsere; közös objektumnév vagy partnerkomponens szükséges. | Nagy (P) a mappingre; közepes (L) az IPC-használatra. |
| **Fingerprint** | `GetAdaptersInfo`, system/CPU/process, command-line/environment és window-station API-k; `CM_Get_Device_Interface_List*`; session-adat API-k | **Observed:** gép- és környezetadatok lekérésének képessége. **Unknown:** kiválasztott mezők, tárolás, kimeneti séma és továbbítás. | Gép- és környezetprofil kialakításának lehetősége; adatáramlási kapcsolat nincs igazolva. | Nagy (P) a primitívekre; alacsony (U) a teljes fingerprint céljára. |

## 6. A kiemelt kérdések statikus kontextusa

> **Számlálási figyelmeztetés:** a 6.1–6.3 alfejezet `8 syscall`, `2 wrapper`, `1 load` és egyetlen diszperziós tábla alakot használ. A 12.3. fejezet `C-01`–`C-06` tételei ezeket felülírták (`16` közvetlen `syscall`, `16` wrapper-hívás ág, `12` wrapper, `2` külön handle-olvasás, `2 × 16` slot). Az itt maradó szöveg történeti állítás, a jelenleg érvényes szám a 12.3. fejezeté; a minősítési és korlát-megállapítások változatlanul érvényesek.

### 6.1 `0xC856C0`: mi bizonyított a handle-ről?

Kanonikus azonosítás:

- `0xC856C0` itt RVA; preferált image base mellett VA `0x180C856C0`;
- file offset `0x0C84AC0`, `.text` szekció;
- a `.pdata` szerint tartalmazó RUNTIME_FUNCTION: `0x0C856C0–0x0C87104`, unwind RVA `0x30640A0`;
- a közvetlen hívó `0x0C85650`, a call helye `0x0C85681`.

Lokális adatfolyam:

1. A `0x0C856C0` függvény `RCX`-et kontextus-/closure-pointerként kezeli.
2. A `0x0C856F3` utasítás a `[RCX]` értéket `R14`-be másolja.
3. A legtöbb ágon `R14` a közvetlen `syscall` első argumentumaként, `R10`-be kerül; a helper wrapper ágak is megőrzik ezt az argumentumhelyzetet.
4. A `0x0C85650` a closure `+8` mezőjét adja át kontextusként, a sztring pointert és a `hossz * 2 + 2` méretet további argumentumként adja, a `0x0C856C0` eredményét pedig egy vektorba fűzi.
5. A `0x0C85650` funkcióra nem találtam közvetlen `rel32`, RIP-relatív vagy abszolút kódhivatkozást a vizsgált statikus tartományokon; az objektum létrehozója ezért közvetlen xrefből nem azonosítható.

**Statikus következtetés:** a `0xC856C0` első syscall-argumentumként továbbadott qword process-handle-jellegű értéket dolgoz fel. Az allokációs argumentumok erősen `NtAllocateVirtualMemory`-kompatibilisek: processzhandle, báziscím-pointer, `ZeroBits=0`, méretpointer, `MEM_COMMIT` és `PAGE_EXECUTE_READWRITE`; az allokáció utáni ötargumentumos írás-/olvasásséma közösen illeszkedik `NtWriteVirtualMemory`/`NtReadVirtualMemory` ABI-jához. Az obfuszkált service-szám miatt a konkrét Nt-szolgáltatásnév és az írás iránya nem bizonyított.

**Nem bizonyított:** a qword valódi Windows `HANDLE` típusa, létrehozó API-ja, namespace-e, kívánt hozzáférése, tulajdonosa, duplication/close életciklusa és a kernel által elvégzett jogosultságellenőrzés eredménye. A producerhez vezető visszafelé futó adatfolyam az elsődleges nyitott kérdés.

A külön process-library audit három `ProcessBasicInformation`-kompatibilis inline syscallt (`0x0D7B0AE`, `0x0D7B4B9`, `0x0D7C0AC`) azonosít. Mindháromnál `R10=-1`, `EDX=0`, `R9D=0x30`, a kimeneti buffer `0x30` bájtos, és az `EAX` service-számot futás közben előállított logika adja. Az ezt követő `buffer+0x28` olvasás a szokásos `PROCESS_BASIC_INFORMATION.InheritedFromUniqueProcessId` mezővel, majd az `OpenProcess(0x1000, FALSE, parentPid)` hívás PID-argumentumával kompatibilis. Ez erős statikus parent-PID-bizonyíték, de az obfuszkált syscall-szám önmagában nem írja le a szolgáltatás nevét. A `0x1000` jog `PROCESS_QUERY_LIMITED_INFORMATION`; ez a query-handle önmagában nem bizonyítja a `0xC856C0` által használt memória-jogosultságot, és a két handle-láncot a statikus adatfolyam nem kapcsolja össze.

### 6.2 Runtime dispatch

A `0x0C856F6` `RDTSC` utasítás után az `EAX & 0xF` választja ki a `0x02CFB1F8` RVA-n lévő 16 elemű relatív jogcím-táblát. A 16 cél:

`0x0C8570B`, `0x0C85741`, `0x0C85777`, `0x0C858EB`, `0x0C85921`, `0x0C85AA5`, `0x0C85ADB`, `0x0C85BBB`, `0x0C85BF1`, `0x0C85C27`, `0x0C85DCE`, `0x0C85E04`, `0x0C85FD7`, `0x0C8614B`, `0x0C86181`, `0x0C86305`.

A manuálisan ellenőrzött 16 blokk közül:

- 8 ág közvetlenül a `0x0C858E0`, `0x0C85A9A`, `0x0C85BB0`, `0x0C85DC3`, `0x0C85FCC`, `0x0C86140`, `0x0C862FA`, `0x0C86420` helyen `syscall`-t ad;
- 8 ág a `0x051D680`, `0x051D880`, `0x051DAB0`, `0x051DC60`, `0x051DDE0`, `0x051DFF0` wrapperek egyikét hívja.

A process-memory audit a konkrét allokációhoz a `0x0C85737`/`0x0C8576D` wrapperhívásokat és a `0x0C86420` inline ágat, az írás-/olvasás-jellegű további útvonalakhoz pedig `0x0C86477` → `0x0C8F650` (`syscall 0x0C8F84C`), `0x0C864A0` → `0x0C8F880` (`syscall 0x0C8FA6C`) és `0x0C870DB` inline ágat kapcsol. Ezek a service-nevek még validált syscall-számmal nem azonosítottak.

A nyitott kérdés az, hogy ez az időzítéssel kiválasztott diszperzió:

- azonos NT szolgáltatás szemantikailag ekvivalens, eltérően kódolt ágait jelenti-e;
- különböző szolgáltatásokat vagy adatstruktúrákat választ-e;
- tisztán anti-analysis/utánzat;
- vagy a futási környezettől függő érdemi dispatch.

### 6.3 Dinamikus Nt wrapper-ek

A `0x051D680–0x051EBB9` környezetében 12, disasszemblációval kézileg validált közvetlen `syscall` hely található:

`0x051D84C`, `0x051DA7B`, `0x051DC2A`, `0x051DDAE`, `0x051DFC5`, `0x051E180`, `0x051E345`, `0x051E4FE`, `0x051E6C9`, `0x051E835`, `0x051E9B4`, `0x051EBB9`.

A process-memory audit további, nem a 12-es klaszterbe tartozó syscall-helyeket is azonosít: `0x0D7B0AE`, `0x0D7B4B9`, `0x0D7C0AC` (`ProcessBasicInformation`-kompatibilis argumentumkészlet), `0x0C8F84C`, `0x0C8FA6C` és `0x0C870DB` (allokált/kezelő bufferhez kapcsolódó argumentumszerkezet). Ezek további service-hozzárendelésének vizsgálata nyitott.

A vizsgált wrapperek jellemzői:

- a `syscall` előtti számérték-feldolgozás több kevert műveletet, bswapot, shiftet, XOR-t és konstans keverést használ;
- több helyen `GS:[0x30]` segítségével PEB-adatokhoz nyúlnak;
- a `0x7FFE0260`, `0x7FFE026C`, `0x7FFE0270` és `0x7FFE0330` KUSER_SHARED_DATA-címek szerepelnek;
- a `ntdll.dll` UTF-16 sztring és a `GetModuleHandleW`/`GetProcAddress` importok jelen vannak, de ebből önmagában nem következik egy adott wrapper pontos Nt-szolgáltatáskötése.

A pontos service number, Nt/Zw név és verzióalkalmazkodási stratégia jelenleg ismeretlen. A teljes `.text` nyers bájtsorában `3 881` `0F 05` találat van; ez nyers keresési szám, nem validált utasításlista. Ezzel szemben a fenti 12 wrapperhely, a `0xC856C0` 8 közvetlen ága, a három parent-PID-kompatibilis hely és a `0x0C8F84C`/`0x0C8FA6C`/`0x0C870DB` további helyei valódi, `.pdata`-funkcióhatáron belüli `syscall` utasítások.

**Feloldott evidence-konfliktus:** a korábbi `07` anti-debug audit túl széles, `.pdata`-lefedett kódra vonatkozó „nincs validált syscall” negatív findingje és a process-debug/parent-PID hiányát állító megállapításai a bináris újraolvasásával megdöltek. A javított `07` közvetlen `.pdata`-határon belüli `0F 05` utasításokat, `ProcessBasicInformation`- és `ProcessDebug*`-kompatibilis argumentumkészleteket, valamint class `0x28`-as `NtSetInformationProcess`-kompatibilis ágakat igazol. A pontos service number, a top-level callerlista, a runtime-elérhetőség és a cél/dataflow továbbra is open.

### 6.4 CoreRT debugger-jel: feloldott `A`/`W` konfliktus

A két `CoreIsDebuggerPresent`-ág mindkettőben az UTF-16 `CoreRT.dll` literál kerül `RCX`-be, majd a `0x2E4D390` IAT-sloton lévő **`GetModuleHandleW`** hívódik. Ez közvetlenül cáfolja a korábbi `07` audit `GetModuleHandleA`-val leírt „típushibás resolver” minősítését. A `GetProcAddress` az ASCII `CoreIsDebuggerPresent` nevet használja; a közös function-pointer cache RVA-ja `0x30D4288`, a fájlban kezdetben nulla. Ha a pointer nem nulla, az `AL` visszatérési érték igaz volta `INT3`-hoz vezet a `0x5302`, illetve `0x5C59` RVA-n.

Ez **nagy konfidenciájú feltételes debugger-/tamper-jel**, de nem bizonyít aktív anti-debug döntést vagy evasiont. A cache runtime feltöltése, a `CoreRT.dll` betöltési állapota, az ág elérhetősége és az `INT3` szándéka nem ismert. Az `IsDebuggerPresent` közvetlen callsite ezzel szemben CRT/fatal-error környezetben van; a timing-, PEB- és KUSER_SHARED_DATA-jelek önmagukban nem debugger-checkek.

### 6.5 Endpoint- és konfigurációforrás

#### Validált helyi konfiguráció

A `CitizenFX.ini` UTF-16 string RVA-ja `0x02E48FE8`, két közvetlen kódxrefje van: `0x02AA258B` és `0x02AA3761`. Az érintett funkciók statikusan az alábbi INI-elemeket használják:

- `[Game] IVPath`;
- `[Game] PathCL2`;
- `[Game] DefaultBuild`;
- `[Game] ReplaceExecutable`.

A környező kód `GetFileAttributesW`, `GetPrivateProfileStringW` és `GetPrivateProfileIntW` importokat hív. Emiatt a `CitizenFX.ini` **validált helyi konfigurációs forrás** ezekhez az értékekhez. Ez nem bizonyítja, hogy hálózati endpointot szolgáltat.

További statikus jelek:

- `CitizenFX_SubProcess_%s.bin` UTF-16 mintanév, RVA `0x02E1F78E`, közvetlen xref `0x0047E88E`;
- `GetEnvironmentVariableA/W`, `GetCommandLineW` és `RegGetValueW` importok;
- `CitizenFX_SDK_Guest` környezeti/flag jellegű sztring, validált xrefekkel;
- `CitizenFX_ToolMode` sztring, de közvetlen xrefje nem volt azonosítható;
- a `FXCOMPONENT` és a `CreateComponent` alapján a komponens a CitizenFX komponenskeretben kap runtime kontextust, de ebből konkrét hálózati adatforrás nem következik.

#### Hálózati sztringek

- `http://clients2.google.com/time/1/current` az RVA `0x02C5B0D0` címen, közvetlen RIP-relatív xref `0x00325969` környezetében. Ez statikus URL-literal; a fogyasztó feltétele, tényleges hálózati használata és jelentősége nem igazolt. Az URL-t nem kértem le.
- A többi tiszta HTTP URL jellemzően DigiCert OCSP/CRL/CA-adat a beágyazott tanúsítványláncból, illetve curl dokumentációs komment.
- Tiszta `rockstar`, `cfx.re` vagy FiveM production endpoint a bounded statikus URL-szűrésben nem jelent meg.

A négy validált `CitizenFX.ini` kulcs helyi játékút/build-konfiguráció, nem endpoint-bizonyíték. A registry-, environment- és parent-kontextus sem azonosítható végpontforrásként; dinamikus konfiguráció, companion-komponens vagy későbbi szerverválasz szintén csak lehetőség. A production végpont, request schema és kimeneti payload statikusan nem igazolt.

### 6.6 PDB- és build-korreláció

A PDB path, GUID és age erős build-korrelációt ad, de nem tartalmaz forrásrevíziót. A hiányzó azonos buildű hivatalos referencia miatt:

- a `1.0.0.36109` pontos artifact provenienceje nem zárható le;
- a PDB GUID/age összevethető egy hivatalos build manifesttel vagy azonos buildből származó más binárissal;
- a nyilvános FiveM source az általános komponensbetöltést és az `adhesive` anti-cheat-kontextusát mutatja, nem a privát wrapper-logikát;
- a PDB-guid alapján symbol serverhez való hozzáférés nélkül nem adható megbízható függvénynév-korreláció.

### 6.7 Komponens-lifecycle és hook-keret

A `CreateComponent` export (`RVA 0x00101F80`) statikusan nullaargumentumos x64 konstrukciós belépési pont. A `0x28` bájtos objektum elsődleges `Component` vptr-t, 32 bites referenciaszámot, privát interface-vptr-t (`0xFC203F1D`), `OMComponent` vptr-t (`0x5D560A33`) és közös OM-singleton pointert tartalmaz. A végleges primary vtable `0x02C65060`, az OM vtable `0x02C650C8`; a globális OM singleton pointer `0x030E09B0`.

Az `Initialize` slot (`0x00101D70`) egy prioritásos inicializálási fát futtat. A `DoGameLoad` slot (`0x00101D80`) erősen obfuszkált; a nyilvános CitizenFX forrás szerint az upstream `DoGameLoad` `HookFunction::RunAll()`-t tartalmaz, de a bináris belső dispatch-célja nem azonosítható egyértelműen. A 4. vtable-slot stabil `RVA 0x1170` (`raw 0x570`) no-op `ret` célra mutat, amely a forráskori `SetCommandLine` contract szerint elhanyagolja az argumentumot.

Ez a komponens-lifecycle és a `0xC856C0`/wrapper-kód közti konkrét kapcsolatot nem bizonyítja. A hook-keret működése és a lokális process-patch mechanizmus külön evidence-réteg; a kettő összekötése további statikus CFG-korlátot igényel.

## 7. Metodológia és reproduction boundary

### 7.1 Eszközök

- Windows PowerShell 5.1: `Get-FileHash`, `Get-AuthenticodeSignature`, fájlméret;
- Python `3.14.7`;
- `pefile 2024.8.26`;
- `LIEF 1.0.0-d05b3499b`;
- Capstone `5.0.7`;
- GNU objdump `2.47.20260726`.

### 7.2 Statikus módszertan

1. A mintát olvasási módban kezeltem; hash és méret a PE-feldolgozás előtt és után azonos volt.
2. Authenticode-ellenőrzést és a cert chain mezőinek kiolvasását végeztem.
3. A PE headert, data directorykat, szekciókat, resource-öket, import/export táblákat, TLS-t, load configot és debug információt parsereltem.
4. A regular és delay importokat külön számoltam; az exportot a név/ordinal/RVA megadásával rögzítettem.
5. ASCII és UTF-16 stringeket külön kerestem; a nagy beágyazott OpenSSL/curl stringkészletet nem tekintettem automatikusan saját alkalmazási logikának.
6. Az x64 funkcióhatárokat a PE exception directoryból vettem, a disasszemblációt Capstone-tal végeztem.
7. A releváns RIP-relatív, `rel32` és IAT-hivatkozásokat statikusan ellenőriztem.
8. A `0x0C856C0` környezetében a dispatch táblát, 16 ágat, calleradatfolyamot és syscall-helyeket kézzel revideáltam.
9. A PE-t két független parserrel cross-checkeltem.
10. A komponensazonosítást és a szerepkontextust a CitizenFX hivatalos, commit-pinnelt loader- és komponenslistával korreláltam; belső implementációt nem tulajdonítottam a forrásnak.
11. A peer `01`–`11` dokumentumait claimenként összevetettem; ahol eltérés volt, a nyers PE/IAT/`.pdata`/disassembly bizonyíték volt döntő.
12. Újraolvastam a két CoreRT resolver callsite-ot, a 12 wrapper-, 8 dispatch-, 3 parent-PID- és további syscallpontokat, a `0xC874E9` protectiont és a `RegGetValueW` rootkonstanst.
13. A `WinVerifyTrust` és `CryptUnprotectData` thunk/IAT közvetlen `rel32` és `FF 15` referenciáit külön szűrtem; a negatív eredmény csak ezekre a közvetlen mintákra bounded.

### 7.3 Reproduction boundary

A reprodukálhatóság e fájl és az alábbi statikus lekérdezések szintjén értendő:

- azonos SHA-256 újraellenőrzése;
- azonos PE timestamp/checksum/import/export/resource/debug értékek;
- a felsorolt RVA-k disasszemblálása az image base `0x180000000` mellett;
- a jelzett string- és IAT-xrefek újraillesztése.

Ez **nem** reprodukálja a DLL runtime viselkedését, hálózati forgalmát, hookjait, fájlmutációját vagy syscall-megoldását. A dokumentum szándékosan nem tartalmaz load/export invocationt, process injection receptet, hook-patch lépést, bypass technikát, credential recovery folyamatot vagy működő exploitot.

## 8. Korlátok

1. **Nincs dinamikus bizonyíték:** nem láttuk, mely API-k, wrapper-ek, ágak vagy hálózati műveletek futnak ténylegesen.
2. **Import ≠ hívás:** az IAT-bejegyzés capability, nem végrehajtási esemény.
3. **Sztring hiánya ≠ képesség hiánya:** obfuszkáció, kódolt konstans, késői visszafejtés vagy külső konfiguráció elrejtheti a valós endpointot.
4. **Sztring jelenléte sem bizonyítja az alkalmazási célját:** az OpenSSL/curl/Botan nagy beágyazott készlete sok általános vagy hibakeresési stringet tartalmaz.
5. **Direct syscall scope:** a teljes `.text` nyers `0F 05` keresése `3 881` találatot ad, ezért nem szolgál utasításlistaként. A dokumentált 12 wrapper-, 8 dispatch-, 3 parent-PID-kompatibilis és 3 további hely valódi, `.pdata`-határon belüli utasítás; a `07` általános negatív syscall-claimje ezért elvetett. Teljes szolgáltatás- és caller-CFG továbbra is nyitott.
6. **Disassembly korlát:** az időalapú és közvetlen ugrások, jump table-ök és kódkeverés miatt a teljes CFG rekonstrukciója nem történt meg. A `.pdata` funkcióhatárok és lokális kézi ellenőrzés csökkentik, de nem szüntetik meg a félreillesztési kockázatot.
7. **Nincs endpoint capture:** nem láttuk kimenő DNS-, TLS- vagy alkalmazásszintű forgalmat.
8. **Nincs runtime konfiguráció:** a `CitizenFX.ini`, registry-, environment- és parent-komponensből érkező lehetséges bemenetek tényleges prioritása és aktuális értéke ismeretlen.
9. **Nincs azonos build baseline:** a pontos `1.0.0.36109` hivatalos artifact és PDB nincs a vizsgált környezetben.
10. **Nincs PDB:** a PDB GUID/age nem pótolja a szimbólumokat.
11. **A privát source nem publikus:** a nyilvános CitizenFX source nem ad közvetlen mappinget a `0x0C856C0` és wrapper függvényekre.
12. **Only one artifact:** a dokumentum nem vizsgálta a `legitimacy.dll`, `glue`, net, resource, V8, OpenSSL/curl és más companion artifactokat hashét, aláírását vagy viselkedését.
13. **Trust/time függés:** az Authenticode státusz a vizsgáló Windows trust state-jétől és idejétől függ.
14. **Nincs vulnerability claim:** az `OpenSSL 1.1.1t` string önmagában nem bizonyít konkrét sebezhetőséget; külön, verzió–CVE és konfiguráció alapú értékelés szükséges.
15. **Nincs credential-artifact claim:** a `CryptUnprotectData` import jelenlége önmagában sem tárolt credentialt, sem credential-recovery folyamatot nem bizonyít.
16. **Bounded persistence-negatívum:** a standard és delay importban nincs service-manager, registry-write, `CreateRemoteThread`, `WriteProcessMemory`, `ReadProcessMemory`, `VirtualAllocEx` vagy `VirtualProtectEx` név; a teljes ASCII/UTF-16 scanben nincs `CurrentVersion\Run`, `CurrentVersion\RunOnce` vagy teljes privát PEM kulcsmarker. Dinamikus, natív, COM/WMI, child-process és companion-modulbeli viselkedés nincs kizárva.
17. **Bounded network-negatívum:** a fix, nem-metaadat URL-ek között a Google time URL az egyetlen releváns literál; FiveM/Rockstar production végpont, kimeneti séma és exfiltráció nem azonosítható. A szűrés nem zárja ki a dinamikus vagy companion-komponensből kapott végpontot.
18. **Bounded credential-negatívum:** a `CryptUnprotectData` és `WinVerifyTrust` import/thunk megvan, de egyik thunk/IAT célra nincs közvetlen `rel32` vagy közvetlen IAT-call a `.text` tartományában; a statikus scan nem talált plaintext credentialt vagy használható privát kulcsot. Közvetett pointer-, obfuszkált vagy companion-hívás nincs kizárva.

## 9. Prioritizált open questions

A lista a 12. fejezet konfliktusnaplója után áll. A naplóban lezárt tételek nem szerepelnek itt nyitottként; ahol egy tételnek csak egy komponente zárult le, az alábbi szöveg kizárólag a lezáratlan komponenst tartalmazza. A tételszámok változatlanok, hogy a `13`–`16` dokumentumok `§9/…` hivatkozásai érvényesek maradjanak.

### 9.0 Státusz a tételekről a 12. fejezet után

| §9 tétel | Státusz | Mi lezárult | Mi maradt nyitva |
|---:|---|---|---|
| 1 | `open` | a hívóklóza belépési határa a hat enumerált élformán (`P-01`) | a handle producer és a tulajdon; a két olvasás értékének azonossága |
| 2 | `open` | a dispatch geometria: `2` tábla × `16` slot, `32` ág-törzs, fázisonként `16/16` séma-egyezés (`C-01`, `C-02`, `C-03`) | az `RDTSC & 0xF` szemantikai hatása és a service-szintű azonosság |
| 3 | `open` | a mapping fázis lefutott és `0` nevet adott (`SVC-01`) | az Nt/Zw szolgáltatásnevek |
| 4 | `open` | – | a production végpont, a request séma és a payload |
| 5 | `open` | a reprodukálható korrelációs kulcsvektor és a liftelési feltételek | a hivatalos build manifest, a PDB és a build provenance |
| 6 | `open` | a boundary-újraszűrés `3 881` → `3 627 / 209 / 45`, két dekóderrel (`SWEEP-01`) | a hívólista, és a `3 384` hely kontrollfolyam-bizonyítottsága (`SWEEP-02`) |
| 7 | `open` | a cél szimbolikus alakja, a hét APC-ág közös `0x1170` célja, a komponens belépésnélkülisége (`PCH-01`–`PCH-03`) | a célmodul, a kezdeményező, az időzítés, a `0x3254270` kapcsoló írója |
| 8 | `open` | a bounded negatívum változatlan, és a `13`–`16` evidence-készlet nem érintette | az alkalmazásszintű DPAPI-hívási útvonal |
| 9 | `open` | – | a továbbított adatmennyiség, a séma és a célzott mezők |
| 10 | `open` | – | a tényleges fingerprint-mezők és az eszközazonosítás |
| 11 | `open` | a resolver-típus konfliktus, lásd a 11. fejezetet | a cache producer, a host betöltési feltétel, a hívó, az `INT3` környezete |
| 12 | `open` | – | a companion artifact-komponensek megbízhatósága |
| 13 | `open` | – | a buildváltozások korrelálható diffje |
| 14 | `open` | az `adhesive.dll`-en belüli negatív oldal: nincs belépési pont, és a három segédnek sincs közvetlen hívója | a teljes FiveM-kontextus, persistence, service és driver |

### P0 – a következő statikus döntésekhez szükséges

1. **Mi az eredete a `0x0C856C0` által továbbadott handle-szerű qword-nek?**
   Ki írja a context `+0` mezőjét; mely objektum/closure hívja közvetetten a `0x0C85650` függvényt; milyen Create/Open/Query/Duplicate/Close szerver vagy wrapper adja az értéket; van-e namespace, desired-access és ownership? A `0x0D7B0AE` környezetének query-limited parent-handle-je ugyanaz-e, vagy teljesen külön érték? A 12.8. pont `P-01` tétele szerint a belépési határ lezárt: a `444` soros, `0 → 1 → 2` szintű lezárási séta mind a hat enumerált élformán kimerült, a frontier üres, a `0x0C856C0`-nak egyetlen `rel32` bejövő hívása van (`0x0C85681`), a `0x0C85650`-nek nulla, és a `19 041` DIR64 slot egyike sem tart a klaszterbe mutató VA-t. A producer ettől még `OPEN`, mert a séta csak a statikus élformákat követi, tehát regiszter-indirekt vagy stack-slot hívó nem zárható ki. A két olvasás (`0x0C856F3` `r14`, `0x0C86440` `rbx`) értékének azonossága sem bizonyított, mert a második olvasás az allokációs merge-pont után történik.
   **Sikeres statikus válasz:** producer store → callback registration → handle creator → close/lifetime minden szála visszafelé igazolt.

2. **A `0x0C856C0` 32 runtime ága azonos vagy eltérő Nt-szolgáltatást hív?**
   A korábbi `8` közvetlen és `8` wrapper-ág alak a 12.3. fejezet szerint `16 + 16 = 32` ágra javított: két szomszédos `16` elemű tábla (`0x2CFB1F8` és `0x2CFB238`), fázisonként `8` inline `syscall` és `8` wrapper-hívás, és fázisonként `16` sémához illeszkedő, `0` divergáló ág. Lezárt a geometria és az argumentumséma; nyitott, hogy a `32` ág service-szinten azonos-e, és hogy a `RDTSC & 0xF` valóban megváltoztatja-e a szemantikát.

3. **Mely Nt/Zw szolgáltatások a 12 validált wrapperhez tartoznak?**
   A service-szám kiderül-e statikusan vagy szimbolikusan a PEB-, KUSER_SHARED_DATA- és konstanskeverésből; milyen fallback és Windows-verzióalkalmazkodás van? A `0x0C8F650` / `0x0C8F880` írás-/olvasás-wrapperek és a `0x0D7B*` process-basic-information syscallok mely szolgáltatások? A 12.6. pont szerint a mapping fázis a teljes `3 627` helyes korpuszon lefutott és `0` helyet nevezett meg: mind `UNRESOLVED`, `nt_confidence = none`, `static_constant` producer `0` helyen, tehát a gate névágata egyetlen soron sem futott le. A service-map `wrapper_forwarding` `21` helye nem a `12` wrapper census, és a `12` wrapperrel, a `16` inline hellyel és a kódklaszterrel is diszjunkt. A szolgáltatásnév nyitva marad.
   **Sikeres statikus válasz:** mind a 12 helyhez egyértelmű service mapping, argumentumstruktúra és callerlista.

4. **Van-e statikusan azonosítható production endpoint- vagy végpont-feloldó forrás?**
   A `CitizenFX.ini` négy kulcsa helyi játékút/build-konfiguráció. A `0x00325969` xrefhez tartozó Google-time URL producer→consumer útját kell lezárni, és keresni kell statikus végpont-feloldó hívást vagy más alkalmazásjellegű URL-t; a parent/env/registry önmagában nem végpontbizonyíték. Ha ilyen út nem adódik, a végpont forrása open marad. A `13`–`16` dokumentumok evidence-készlete nem hozott új végpont-adatfolyamot, ezért a bounded negatívum a 8. fejezet 17. pontjában változatlanul érvényes.
   **Sikeres statikus válasz:** egy lezárt végpont-adatfolyam, vagy explicit bounded negatív finding a keresett mintákra.

5. **Korrelálható-e a PDB egy hivatalos `1.0.0.36109` builddel?**
   Azonos SHA/PDB GUID+age, signature timestamp, FileVersion, resource- és szektorhash szükséges; létezik-e hivatalos symbol server vagy manifest a buildhez? A `pdb_correlation.json` a kérdést reprodukálható korrelációs kulcsvektorrá szűkítette: `pdb_debug_id` `CB927E363F3D8D774C4C44205044422E1`, `pdb_match_key`, `authenticode_image_sha256`, `section_content_key` és `correlation_vector_sha256`, mindegyikhez determinisztikus újraszámítási recepttel. A négy liftelési feltétel egyike sem teljesült: nincs PDB a vizsgált környezetben, nincs azonos buildű második artifact, nincs hivatalos build manifest, és a tanúsítványláncot ez a lépés nem validálta. A build provenance `undetermined`, `authentic_build_asserted = false`.

### P1 – a capability értelmezéséhez

6. **Teljes, validált syscall-inventory készíthető-e a teljes CFG-ből?**
   A boundary-fele lezárt a 12.7. pont `SWEEP-01` tétele szerint: a nyers `3 881` `0F 05` jelölést a `142 004` parse-elt runtime-function határral újraszűrve `3 627` valid, `209` `covered_by_instruction` és `45` `no_pdata_function` rész keletkezett, plusz `30` találat a nem végrehajtható szekciókban; független implementáció és második dekóder sorszintánként egyezik, `0` vitával, és a `9` dokumentált anklócsoport `64` helye mind a valid részhalmazban van. Két rész marad. **(a) A hívólista:** a `syscall_inventory.csv` a funkcióhatárt, a hat argumentumosztályt és a service-szám producer-láncát annotálja, de hívóoszlopa nincs, tehát a call-site annotáció nem készült el. **(b) A kontrollfolyam-bizonyítottság:** a `3 627` helyből `243` fallthrough-bizonyított, `3 384` csak sweep-hipotézis, ezért az elérhetőségi arányra ez alsó korlát; a `SWEEP-02` tétel szerinti payload-hiány továbbra is nyitva. A syscall-létezési konfliktus lezárt, a service mapping nyitva.

7. **Van-e statikusan lezárható hook/patch cél és aktiválási út?**
   A `VirtualProtect`, `FlushInstructionCache`, `Get/SetThreadContext` és `QueueUserAPC` call site-okat a 12.4. fejezet osztályozta. A cél **szimbolikusan** lezárható, a hét `QueueUserAPC` ág közös célja az `RVA 0x1170`, amely egyetlen `ret` (a `43` adat-slot ezt a placeholder VA-t tárolja, nem az owning függvény belépési VA-ját), tehát a hívások szál-ébresztésre szolgálnak, nem kódinjektálásra. A patch-komponens a dekódolt CFG-ben belépés nélküli: az `init`, a `registrar` és az `orchestrator` sincs közvetlenül hívva, a heap-gate ezért a komponensen belül teljesíthetetlen, a `0xC8CE70` / `0xC8F470` / `0x1754520` hármasnak pedig nincs közvetlen hívója, mutatója vagy `rva32` előfordulása. Lezáratlan: a célmodul, a kezdeményező, az időzítés, a `0x3254270` kapcsoló írója (`7` olvasó, `0` író) és a közvetett, futásidejű vagy képkívüli hívás lehetősége. A lifecycle-hook és a processz-patch nem egyesíthető pusztán közös előfordulásból.

8. **Van-e statikusan azonosítható alkalmazásszintű DPAPI-hívási útvonal?**
   A `CryptUnprotectData` import és thunk igazolt, de közvetlen `rel32`/IAT-call callsite nincs. Keresendő-e közvetett pointer-, regiszter- vagy obfuszkált caller-útvonal, és ha van, milyen trust-kontextust szolgál ki; credential-artifact kapcsolat csak pozitív bizonyíték esetén állítható. A `13`–`16` evidence-készlet ezt a kérdést nem érintette, tehát a 8. fejezet 18. pontjának bounded negatívuma változatlan. Credential recovery módszer nem vizsgálandó és nem közölhető.

9. **Milyen hálózati adatmennyiséget továbbít?**
   A curl/HTTP2/WebSocket/WS2 call graphból a destination, request/response schema, header mezők, retry/log és cert-verification útvonal kell; különösen az adapter- és processzfingerprint továbbítása.

10. **Milyen fingerprint-mezőt képez ténylegesen?**
     Az `GetAdaptersInfo`, system/CPU/process és device-interface adatokból melyeket vonja össze, tárolja vagy továbbítja; bizonyít-e eszközazonosítást vagy csak platformkompatibilitási vizsgálatot.

11. **A CoreRT debugger-ágak statikusan elérhetők és milyen célt szolgálnak?**
     A resolver-típus konfliktus már lezárt és a 11. fejezetben rögzített: mindkét ág a `0x2E4D390` IAT-sloton lévő `GetModuleHandleW`-t hívja, nem `GetModuleHandleA`-t. Lezáratlan a cache producer, a `CoreRT.dll` betöltési feltétele, a hívó és az `INT3` eredményének környezete; a közös function-pointer cache (`0x30D4288`) fájlban nulla. Az intent továbbra sem vezethető le pusztán a szerkezetből.

### P2 – kontextuális megerősítés

12. **Megbízható-e a teljes companion komponenskészlet?**
     A `legitimacy.dll`, `glue`, net/resource DLL-ek, V8, VC runtime, valamint a statikusan linkelt Botan/OpenSSL/libcurl artifactokat hash-, signature- és build-verziójának összevetése.

13. **Mely buildváltozások korrelálnak a direkt syscall- és obfuszkációs felülettel?**
     Hivatalos, azonos családú korábbi és jelenlegi aláírt build statikus diffje alapján a megfigyelt delta dokumentálható az anti-cheat-szerep előfeltételezése nélkül; a különbségeket hash- és bizonyítékszinten kell kezelni.

14. **Van-e persistence, service vagy driver a teljes FiveM kontextusban?**
     Az `adhesive.dll` önmagában nem adott pozitív ilyen bizonyítékot. A 12.4. fejezet az `adhesive.dll`-en belüli negatív oldalt erősíti: a patch-komponensnek nincs statikusan elérhető belépési pontja, és a három segédnek nincs közvetlen hívója, mutatója vagy címliterálja. Ez nem zárja ki a teljes hivatalos komponenshalmaz vizsgálatát, és nem minősíti a DLL-t; a statikus vizsgálat külön változtatás nélkül szükséges.

## 10. Ajánlott következő statikus analízis lépések

1. **Freeze és baseline:** rögzítsd a SHA-256-ot, section hashokat és Cert blob hashét; minden új offszethez addig a specimen hashig kösd.
2. **Function-map készítése:** használd a `.pdata` RUNTIME_FUNCTION határokat, majd rekurzív/worklist CFG-t; a jump table-öket külön, ellenőrzött node-okként kezeld.
3. **Hitelesített syscall-inventory:** minden `syscall` helyhez jegyezz funkcióhatárt, caller-listát, `R10/RDX/R8/R9` és stack argumentumokat, service-number producert, valamint a `ProcessBasicInformation`, allokáció és írás/olvasás jelölt logikai műveletet.
4. **C856C0 producer-trace:** backward slice a `[context]` store-okra, a closure `+8` mező feltöltésére és az indirect callback registrykre; RTTI/vtable és companion metadata segítségével nevezd az objektumot.
5. **16-ágú dispatch normalizálás:** azonosítsd a hat közvetlenül hívott wrappert és a nyolc inline ág argumentumszerkezetét; hasonlítsd azokat Nt-szintű sémákká; külön kódoldalként rekonstruáld a `DoGameLoad` lifecycle-dispatch-et.
6. **Wrapper-számítás:** PEB és KUSER_SHARED_DATA értékeket kezeld szimbolikus ismeretlenként; a keverési lépéseket értékeld ki offline, futtatás nélkül.
7. **IAT call-site audit:** készíts teljes, kódolt RVA-val ellátott listát a process-memory, file, crypto, network, IPC és fingerprint API-khoz; a jelenlétet ne azonosítsd hívással.
8. **Config- és endpoint-def-use:** indulj a `CitizenFX.ini` xrefektől és a `0x00325969` URL xreftől; kövesd a stringet átstruktúrákon, wrapper-eken és hívókon, amíg forrás vagy konstansfeltöltés nem látszik.
9. **Kódolt adattartalom:** külön projekttel kezeld a kevert `.data`/`.rdata` blokkokat és a dinamikusan felépített stack/string objektumokat; csak visszafejtési és kontextusfenntartó lépéseket dokumentálj.
10. **PDB/build korreláció:** szerezz hivatalos, azonos buildű artifactot; hasonlítsd a PDB GUID/age, FileVersion, Authenticode timestamp, import/export és section szintű hash értékeket.
11. **Differential statics:** hasonlíts egy korábbi és egy jelenlegi hivatalos aláírt buildet ugyanazzal a script-pel; csak a biztonsági kérdésekhez releváns, reprodukálható delta-kat emeld ki.
12. **Evidence ledger:** minden claimhez rögzíts RVA/file offset, forrásfájl, parser-eszköz, confidence, observed/latent státusz és ellenkező bizonyítékot.

## 11. Peer- és bináris konfliktus-jegyzék

Az alábbi lista a sibling riportok ellentmondásait és a target-dokumentum belső pontatlanságait rögzíti. „Feloldott” esetén a nyers specimen-evidence döntött; ahol nincs ilyen bizonyíték, az állapot open marad.

| Téma | Konfliktus | Statikus feloldás és következő határ |
|---|---|---|
| **Nt/parent PID és syscall-létezés** | `06`, `11` és a korábbi `12` konkrét direct syscallokat és parent-PID-kompatibilis argumentumokat talált; `07` általánosan azt írta, hogy nincs validált `syscall`, és nem igazolt parent PID-t. | A `0x0D7B0AE`, `0x0D7B4B9`, `0x0D7C0AC` valódi `0F 05`; mindhárom `R10=-1`, `EDX=0`, `R9D=0x30`. A `buffer+0x28` érték a `0x0D7B863`-nál az `OpenProcess` PID-argumentumába kerül. A `07` széles negatívuma elvetett; a konkrét Nt-szolgáltatásnév továbbra is open. |
| **CoreRT resolver** | A korábbi `07` audit mindkét ágat `GetModuleHandleA`-val és alaphelyzetben típushibásnak írta; `11` `GetModuleHandleW`-t jelzett. | Mindkét callsite a `0x2E4D390` IAT-slotot, azaz `GetModuleHandleW`-t hívja. A korábbi `A`/típushiba téves. A feltételes `CoreIsDebuggerPresent` + `INT3` szerkezet valós, az aktív anti-debug intent és runtime-elérhetőség nem igazolt. |
| **`0xC874E9` protection** | `06` `PAGE_EXECUTE_READWRITE`-ot, `11` `PAGE_READWRITE`-ot állított. | A `0x0C874E3` `mov r9d, 0x40`, majd a `0x0C874E9` `VirtualAlloc` hívás következik: `06` helyes, a `11` `PAGE_READWRITE` sora téves. |
| **Registry root és típus** | `05` korábban `HKCU`-t írt; a `0x80000002` low 32 bites alak önmagában nem elég a sign-extension figyelmen kívül hagyásához. | A `0x11660B` utasítás `mov rcx, 0xffffffff80000002`, vagyis sign-extended `HKEY_LOCAL_MACHINE`. A `0x116618` `RegGetValueW` hívás `R9D=2`, azaz `RRF_RT_REG_SZ` típusszűrőt használ. A rejtett subkey/value továbbra is ismeretlen. |
| **DPAPI callsite** | A korábbi `12` open question már `CryptUnprotectData` call site-ről beszélt, miközben `08` és `11` csak import/thunk jelenlétet igazolt. | A `.text` tartományban nulla közvetlen `rel32` és nulla közvetlen IAT-call mutat a `0x2BED750` thunk vagy `0x2E4D920` IAT felé. Ez nem bizonyítja az import használatát, de nevezhető közvetlen callsite sincs; a kérdés indirekt útvonalra pontosított. Ugyanez igaz a `WinVerifyTrust` thunk/IAT esetén. |
| **Szerepkövetkeztetés** | A target korábban magas konfidenciájú anti-cheat/biztonsági komponenst állított; a public source csak kontextust ad. | A komponensazonosítás és az aláírás magas konfidenciájú. A biztonsági/anti-cheat szerep közepes konfidenciájú, mert a loader, a függőségek és a statikus primitívek konzisztensen támasztják, de nincs privát implementációmapping. |
| **Kockázati mátrix** | A korábbi mátrix a crypto, network és anti-analysis capabilityket magas „kockázatnak” minősítette, miközben a peer auditok intent-, cél- és adatfolyamot ismeretlennek tartották. | A mátrix most a statikusan jelen lévő képesség **potenciális hatását** és külön az evidence confidence-ot adja meg; nincs összesített malware-, incidens- vagy jogi minősítés. |
| **GitHub URL-ek és source-szerep** | A két `master` URL elérhető volt, de mutatható branchet használt. | Mindkét file commit-pinjelt ellenőrzéssel szerepel. A loader anti-cheat-kontextust és fallbacket, a lista pedig az `adhesive` nevet adja; egyik sem bizonyít belső függvénymappinget. |
| **Számclaims és negatívumok** | A peer dokumentumok többsége egyezett a 42/628/604/24 import-, 1 delay-import-, 1 export- és `142 004` runtime-function számokban. | Ezek újraszámolva egyeznek. A persistence-, credential- és fix-C2-negatívumok csak a dokumentált bounded scope-on érvényesek; dinamikus és companion-kód nincs kizárva. |

## 12. P0 lezárási konfliktusnapló

Ez a fejezet a `13`, `14`, `15` és `16` dokumentum, valamint a három független audit — `audit_infra.json` (`632` check, `0` hiba, `verdict = pass`), `audit_handle_flow.json` (`AFH-2026-09-26`, `163` check, `0` hiba) és `audit_syscall_candidates.json` (`31` check, `31/31` zöld) — által lezárt, határolt vagy nyitva maradt tételeket egyetlen táblázatba foglalja. Két célja van: egyrészt, hogy a 9. fejezet által nyitottként kezelt tételek ne maradjanak felsorolva lezáratlanul, másrészt, hogy a felülírt korábbi állítások supercedált jelölést kapjanak, és ne olvashatók ellenkező állításként. A vizsgálati határ változatlan: a DLL-t ez a fejezet sem tölti be, nem futtatja és nem patcheli; nincs benne exploit-, bypass-, patch- vagy credential-recovery recept, konkrét patch-cím vagy írási bájtérték sem.

**Státusz-jelölés**

| Státusz | Jelentés |
|---|---|
| `closed` | A nyers specimen- vagy evidence-bizonyíték lezárta a tételt; nincs nyitott része. |
| `bounded_open` | A negatív oldal lezárt és mért, a pozitív oldal nyitva marad. |
| `open` | Sem a negatív, sem a pozitív oldal nem zárható le a dokumentált scope-on. |

**Confidence-jelölés:** a dokumentumcsalád `P` / `L` / `U` skálája. `Nagy (P)` = közvetlen statikus szerkezeti bizonyíték; `Közepes (L)` = a fájlból levezethető, de egy futásidejű előfeltételre conditional; `Bizonyítatlan (U)` = a fájl önmagában nem dönti el.

### 12.1 A négy infra discrepancy

| Tétel ID | Korábbi állítás | Új hitelesített állítás | Forrás artifact | Státusz | Confidence |
|---|---|---|---|---|---|
| `D-001` | A `toolchain.json` csomagonként egyetlen összecsukott verziót ad, így nem dönthető el, melyik build decode-olta az evidence-ot. | A `package_versions` blokk minden harmadik fél csomagot három, egymástól független tengelyen verzionál (`package_metadata`, `imported_module`, `native_engine`), a hármat párhuzamosan tartja és soha nem egyezteti. A `capstone` eltérése `5.0.9` kontra `5.0.7`, géppel ellenőrizve `imported_version_is_composed_from_binding_constants`; a `lief` eltérése `1.0.0` kontra `1.0.0-d05b3499b`, `imported_version_re_exported_from_a_compiled_extension`; a `native_engine` soha nem hasonlított release-sztringhez. A 7.1. fejezetben nevezett verziók az `imported_module` tengelyen értendők, és a dokumentum minden dekódolt száma ahhoz a buildhez tartozik; a `lief` divergencia egyetlen dekódolt artifactot sem befolyásolhatott. | `audit_infra.json#discrepancies[D-001]`, `toolchain.json#package_versions`, `audit_syscall_candidates.json#producer.capstone` | `closed` | Nagy (P) |
| `D-002` | A `toolchain.json` `scripts` tömbje egyetlen bejegyzést tartalmazott, miközben a `reverse/scripts/` könyvtárban `16` `*.py` volt, így a `xref_build.py`, `cfg_build.py` és `unresolved_regions.py` digestje egyik payloadban sem szerepelt. | A `script_inventory` blokk deklarálja a gyökérútvonalat, a globot, a mezőkészletet és a szándékosan kihagyott timestamp-eket, `sha256`-t ad minden producerhez, köztük a cfg-, xref-, indirect- és syscall-evidence íróit, és fájlonkénti harmadik fél import census `ast`-ból újraszámítható. A tárolt payloadok frissítettek: `19` producer a lemezen `19` `*.py`, `missing_from_inventory = []`, `drifted_entries = {}`, `failing_attestation_checks = []`. Egyetlen dekódolt szám sem függ script digesttől. | `audit_infra.json#discrepancies[D-002]`, `toolchain.json#script_inventory` | `closed` | Nagy (P) |
| `D-003` | Mind a `355` nyers-scan import thunk stub sor az `import_thunk_stub_outside_every_pdata_runtime_function` annotációt viselte, miközben `39` közülük olyan RVA-n volt, amelyet `.pdata` rekord lefedett, és ugyanazok a sorok a régi sémában a `function_index` / `function_begin` / `function_end` oszlopokat is kitöltötték. | A producer szétválasztja a két esetet: `316` sor valóban minden runtime functionön kívül van, és mindkét funkcióoszlop-csoportja üres; a `39` sor egy már dekódolt hétbájtos `jmp` belső marker-bájtja, `import_thunk_stub_interior_byte_of_a_decoded_jmp_inside_a_pdata_function` annotációval, a bájt-offsettel, az utasításstarttal és a lefedő első bájttal. A `39` `xref_edges` `iat_jmp_thunk_stub` sor ugyanazt a gazdafüggvényt nevezi meg ugyanarra az RVA-ra, tehát a két evidence-fájl már nem vitatkozik. A `355` stub- és a `6 304` thunk-mediated CALL-xref szám változatlan, és egyezik a `03` állításaival. | `audit_infra.json#discrepancies[D-003]`, `indirect_sites.csv#annotation`, `xref_edges.csv#target_thunk_function_index` | `closed` | Nagy (P) |
| `D-004` | A digest-bejegyzési szabály hiányzott, ezért hat auditált artifact nem-attesztáltként jelent meg, holott a `toolchain.json` `digests` blokkja már lefedte őket. | A szabály a payloadban kimondva van és az audit függetlenül újraszámolja: minden bevett digestnek a fájlból kell reprodukálódnia, a bevett rekordok a `pdata_stats.json` és a `toolchain.json#digests.entries`, a bevett artifact-lista lefedettsége pedig önálló check. `unattested = []`, `cross_references = 2`, két ciklusőr tartja a blokkot a fixponton kívül. A `bounded.affects_decoded_counts` mind a négy findingnél `false`. | `audit_infra.json#discrepancies[D-004]`, `audit_infra.json#provenance.digests`, `toolchain.json#digests` | `closed` | Nagy (P) |

Az infra audit összesítése: `632` check, `0` hiba, `verdict = pass`, `failed_checks = []`, `discrepancy_count = 4`, `discrepancy_open_count = 0`, mind a négy finding `root_cause_closed = true`. A `discrepancy.integrity` csoport `5/5` zöld, és a `register_holds_exactly_four_findings` check `expected 4 / actual 4`.

### 12.2 A `0xC856C0` handle-flow hét vitatott tétele

A `163` ellenőrzés a `14` dokumentum nyolc aritmetikai kérdését mind megerősítette, és `0` auditált számot nem változtatott. A hét `CF-01`–`CF-07` tétel a dokumentum más állításaira vonatkozott; a javítások a `14` „Javított számlálások" blokkjában alkalmazva vannak.

| Tétel ID | Korábbi állítás | Új hitelesített állítás | Forrás artifact | Státusz | Confidence |
|---|---|---|---|---|---|
| `CF-01` | A wrapper-ek `54` distinct hívója, `54` a anchoron kívül, `0` a klaszteren belül. | A `12` wrapper distinct hívója `37` (`408` szint-1 sor); `36` a `0xC85000`–`0xC88000` tartományon kívül, `1` belül: maga az anchor `0xC856C0`, `16` hívóhelyről. A `54` csak a `13` forward sinkre érvényes (`12` wrapper plusz a `0x495D0` növekedési segéd), ahol `2` hívó van a tartományban. | `audit_handle_flow.json#contested[CF-01]`, `c856c0_callers.csv` | `closed` | Nagy (P) |
| `CF-02` | `NEG-15`: a publikált élkészlet forrásoldali `src_rva`i kizárólag `0x0`–`0x9` magas nibble alá esnek, tehát a kódklaszterből `0` forrásoldali él származik. | A `src_rva` oszlop decimális, és a legnagyobb érték `0x3306F60`, így a valódi hex magas nibble kizárólag `0x0`; a `0xA`–`0xF` nulla cella igaz, de üres. A klaszterből `17` forrásoldali sor van, `5` forrásfüggvényből, `6` `call_indirect_iat` és `11` `call_rel_to_code` relációval. A bounded negatívum megmarad: `0` `CloseHandle` és `0` `DuplicateHandle` forrásoldali sor a klaszterből. | `audit_handle_flow.json#contested[CF-02]`, `xref_edges.csv#src_rva`, `xref_edges.csv#code_instruction_function_begin` | `closed` | Nagy (P) |
| `CF-03` | A forward elérhető halmazban `21` `.pdata`-lefedett függvény mellett `16` olyan cél is van, amelyre nincs `RUNTIME_FUNCTION`. | A `37` elérhető célból `23` `RUNTIME_FUNCTION` rekorddal rendelkezik és `14` anélkül; mind a `14` felsorolva van, a `0xCAC150` is, amely a globális cím-thunk táblából hiányzott. A `37` cél és a `2 / 22 / 6 / 5 / 2` mélységi bontás helyes. | `audit_handle_flow.json#contested[CF-03]`, `c856c0_forward.json#forward_reachable_set` | `closed` | Nagy (P) |
| `CF-04` | A `0xC8FEE4` a `0xCAC0D0` thunk második hívóhelye, és az `5` tagú backward thunk-lista a teljes lista. | A `0xC8FEE4` a `0xCAC150` thunk hívóhelye, a hívó a `0xC8FDE0` transzfer wrapper; a backward pass `5` tagú listája változatlan, a hatodikat csak a forward pass rögzíti. Egyetlen auditált szám sem változik. | `audit_handle_flow.json#contested[CF-04]`, `c856c0_dataflow.json#global_address_thunks`, `c856c0_forward.json#wrappers[].helper_calls` | `closed` | Nagy (P) |
| `CF-05` | A `12` wrapper a klaszteren kívül van, és a `6` transzfer wrapper `cluster_id = 85`, „tehát a klaszteren belül". | A `cluster_id = 38` és `cluster_id = 85` két `cfg_functions.csv` közelség-csoport azonosítója, nem a `16` függvényes `0xC85000`–`0xC88000` tartomány; a két azonosító nem felcserélhető. Mind a `12` wrapper a tartományon kívül van, és egyetlen transzfer wrapper sem esik bele. | `audit_handle_flow.json#contested[CF-05]`, `cfg_functions.csv#cluster_id`, `c856c0_dataflow.json#cluster` | `closed` | Nagy (P) |
| `CF-06` | A wrapper-ág törzse `8`–`9` utasítás, az inline-ágé `41`–`113`. | A `16` wrapper-ág törzse a forward passzban `8`–`9` (allokáció `9`, transzfer `8`), a backward passzban `9`–`10`, mind a `16` érintett ágon egységesen `−1` különbséggel; a `16` inline-ág `41`–`113` mindkét passzban azonos. Definíciókülönbség, nem ellentmondás. | `audit_handle_flow.json#contested[CF-06]`, `c856c0_dataflow.json#dispatch.tables[].branches[].block_instruction_count`, `c856c0_forward.json#stages[].branches[].instruction_count` | `closed` | Nagy (P) |
| `CF-07` | A növekedési segédet a belépő függvény és a `0x176F860` hívja. | A `0x495D0` növekedési segédnek `17` distinct hívója van, `20` szint-1 sorral; a `0xC85650` (a tartományon belül) és a `0x176F860` ezek közül kettő, a többi felsorolatlan volt. Hiányosság, nem számhiba, és egyetlen auditált számot sem érint. | `audit_handle_flow.json#contested[CF-07]`, `c856c0_callers.csv` | `closed` | Nagy (P) |

### 12.3 A korábbi `8 syscall` / `2 wrapper` / `1 load` alak felülírása

Az alábbi sorok a jelen dokumentum 6.1–6.3 fejezeteinek azon mondatait írják felül, amelyek a `8 syscall`, a `2 wrapper` vagy az `1 load` alakot használták. A 6. fejezet szövege változatlanul, történeti állításként megmarad, és e táblázat nincs ellene értelmezendő; ahol eltérés van, az itt felsorolt szám az érvényes.

| Tétel ID | Korábbi állítás | Új hitelesített állítás | Forrás artifact | Státusz | Confidence |
|---|---|---|---|---|---|
| `C-01` | 6.2 és a korábbi számlálások: `8` közvetlen `syscall` ág az anchorban, azaz `8` dispatch-syscallpont. | Az anchorban `16` közvetlen `syscall` van, `8` allokációs és `8` transzfer, a `0xC858E0`, `0xC85A9A`, `0xC85BB0`, `0xC85DC3`, `0xC85FCC`, `0xC86140`, `0xC862FA`, `0xC86420`, `0xC865ED`, `0xC86737`, `0xC8694F`, `0xC86ACC`, `0xC86CBC`, `0xC86E0A`, `0xC86F54`, `0xC870DB` helyeken. A `12` wrapper-függvény további `12` `syscall`-t tartalmaz, tehát a teljes forward tárgykörben `28` syscall-hely van. | `c856c0_dataflow.json#dispatch.tables[].branches[].sink_kind`, `c856c0_forward.json#inline_syscalls`, `cfg_functions.csv#syscall_sites` | `closed` | Nagy (P) |
| `C-02` | 6.2 egyetlen diszperziós táblát és egyetlen `RDTSC` selectort ír le (`0x02CFB1F8`, `0x0C856F6`). | Két egymástól független `16`-águ tábla létezik, szomszédos `.rdata` címeken (`0x2CFB1F8` és `0x2CFB238`, `0x40` bájttal), külön selector-sorozattal (`0x0C856F6` és `0x0C86443`, mindkettő `AND EAX, 0xF`) és külön merge-ponttal (`0x0C86426`, `0x0C870E1`). Összesen `32` slot és `32` ág-törzs. | `c856c0_dataflow.json#dispatch`, `c856c0_forward.json#stages`, `audit_handle_flow.json#authoritative_table[D-01,D-02,D-03]` | `closed` | Nagy (P) |
| `C-03` | 6.2: `8` ág a `0x051D680`, `0x051D880`, `0x051DAB0`, `0x051DC60`, `0x051DDE0`, `0x051DFF0` wrapperek egyikét hívja; a korábbi szövegek `2` wrappert neveztek meg. | `16` wrapper-hívás ág van, `12` distinct wrapperrel: `6` allokációs (`0x51D680`, `0x51D880`, `0x51DAB0`, `0x51DC60`, `0x51DDE0`, `0x51DFF0`) és `6` transzfer (`0xC8F650`, `0xC8F880`, `0xC8FAA0`, `0xC8FC00`, `0xC8FDE0`, `0xC8FF60`), egyenként pontosan `1` `syscall`-lal, `0` API-callsite-tal, `0` close és `0` duplicate művelettel. A `16` ág `4`-szer ismétli a `12` célt. | `c856c0_forward.json#wrappers`, `c856c0_dataflow.json#dispatch.tables[].branches[].sink_kind`, `audit_handle_flow.json#authoritative_table[B-02,W-01,S-01]` | `closed` | Nagy (P) |
| `C-04` | 6.1 pont 2: a descriptor `+0` mezőjének egyetlen olvasása, a `0x0C856F3` (`mov r14, qword ptr [rcx]`), amelyet az „olvasás, nem írás" megállapítás támaszt alá. | `2` külön olvasás van ugyanarról a `descriptor+0` mezőről: `0x0C856F3` (`r14`, `4c 8b 31`, `16` fogyasztó) és `0x0C86440` (`rbx`, `48 8b 1b`, `16` fogyasztó), összesen `32` fogyasztási hely. Egyetlen más descriptor-mező soha nem nyúlik. A két érték azonossága nem bizonyított, mert a második olvasás az allokációs merge-pont után történik; ez a 9. fejezet 1. pontjánál nyitva marad. | `c856c0_dataflow.json#handle`, `c856c0_forward.json#handle_lifetime.consume_sites`, `audit_handle_flow.json#authoritative_table[H-01,H-02]` | `closed` | Nagy (P) |
| `C-05` | 6.1 pont 3: „a legtöbb ágon `R14` a közvetlen `syscall` első argumentumaként, `R10`-be kerül". | Pontosan `16` ágon megy `R10`-be, a másik `16` ágon a `RDX` a második argumentumhelyzetbe, mert a wrapper első helyen egy állapotglobálist kap. A hordozó szerinti megoszlás tehát `50/50`, nem domináns. | `c856c0_dataflow.json#handle.use_sites`, `audit_handle_flow.json#recompute_detail.handle_flow.argument_register_split` | `closed` | Nagy (P) |
| `C-06` | 6.3: a `0x051D680`–`0x051EBB9` tartományban `12`, kézzel validált wrapper-syscall található. | Az a tartomány `6` allokációs wrappert tartalmaz, egyenként `1` syscalllal. A másik `6` transzfer wrapper a `0x0C8F650`–`0x0C90144` tartományban van. A korábbi `12` a két halmaz összege volt, de csak az egyik halmaz RVA-ja szerepelt. | `c856c0_forward.json#wrappers`, `c856c0_forward.json#wrappers[].syscall` | `closed` | Nagy (P) |

### 12.4 A patch-mechanizmus korrekciói

| Tétel ID | Korábbi állítás | Új hitelesített állítás | Forrás artifact | Státusz | Confidence |
|---|---|---|---|---|---|
| `PCH-01` | A `0x1830D44F0` globális processz-heap handle, „a publikált processz-heapon”; a `06` és `11` dokumentum hallgatólagosan ezt feltételezte. | A globális egy `KERNEL32!HeapCreate(0, 0, 0)` eredménye, és az egyetlen író utasítás az `init` belsője. A `GetProcessHeap` a képben `7` helyről hívódik, és egyik előfordulása sem esik a `0x1D280`–`0x1E9D0` komponensbe; a komponens egyetlen allokátor-hozzáférése a publikált globálist olvassa. Az `init` `0`-t ad vissza siker esetén és `9`-et, ha a `HeapCreate` nullát ad. Az evidence szövege maga is javítva van (`heap.is_process_heap: false`, `heap.kind: private_heap`), tehát a korrekció ma már a `06` / `11` dokumentumra vonatkozik. | `patch_record_table.json#heap`, `patch_record_table.json#capacity_model`, `patch_mechanisms_helpers.csv`, `xref_edges.csv#dst_symbol` | `closed` | Nagy (P) |
| `PCH-02` | A korábbi `apc_sites.csv` `target` oszlopa és a `06` / `07` állítás: „`43` data slots store the entry VA `0x1F90720`". | A `43` slot a `0x1170` placeholder VA-ját, vagyis a `0x180001170` értéket tárolja. Független, `8` bájtos lépésközű szkennelés a nem végrehajtható szekciókban `43` találatot ad, köztük a felsorolt `0x2C1E948`, `0x2C1E950`, `0x2C5E820`, `0x2C60038` példákat; az owning függvény `0x1F90720` belépési VA-ját `1` slot tárolja, a `0x2D89678`, és azt a `fn` oszlop számolja. Az érvelés végeredménye helyes, a benne szereplő cím téves volt; az evidence szövege már javított. | `apc_sites.csv#target`, `apc_sites.csv#fn`, `adhesive-16` 8.2. pont | `closed` | Nagy (P) |
| `PCH-03` | A `0x1E270` és a `0x1DFF0` „observed” képesség, és a patchernek közvetlen hívója van; a heap-gate `2`-es kódja a heap-handle hiányát jelenti. | A `4` közvetlen hívás intra-komponens. A teljes `0x1D280`–`0x1E9D0` rendszer zárt: az `init`-nek, a registrarnak és az orchestratornak nincs közvetlen hívója, tehát a komponensnek nincs belépési pontja a dekódolt CFG-ben. A `0x1E3A4` heap-gate-ot egyetlen utasítás írja, az `init` belsője, ezért a kapu a komponensen belül teljesíthetetlen, és a manager `2`-vel tér vissza, mielőtt bármelyik dispatch callhelyhez érne. Amit ez nem zár: a közvetett, futásidejű vagy képkívüli hívás, tehát a futásidejű elérhetetlenség és a pontos időzítés. | `patch_record_table.json#activation`, `thread_context_map.json#heap_gate`, `cfg_functions.csv#cross_function_targets`, `adhesive-16` 2.1. és 5.6. pont | `bounded_open` | Nagy (P) a hívási gráfra, Közepes (L) a futásidejű elérhetetlenségre |

### 12.5 A `0x2B4D640` tartomány státusza

| Tétel ID | Korábbi állítás | Új hitelesített állítás | Forrás artifact | Státusz | Confidence |
|---|---|---|---|---|---|
| `REC-01` | A jelen dokumentum a `0x2B4D640`–`0x2B4D67E` tartományt nem értékelte; a CFG-builder lineáris sweepje `62` bájtot `18` alap-blokkból dekódol, `51` dekódolt és `11` megálló bájttal, `blocks_reached = 0`, `blocks_linear_only = 18`, `reached_ratio = 0,0` értékkel, anélkül, hogy kimondaná, kód-e a tartomány. | A tartomány a `UR-001625` `data_record`: `reason = pdata_range_is_data`, `triage = classified`, `kind = data`, `confidence = HIGH`, `priority = P4`, `ok = true`, `cluster_id = 232`, `unwind_flags = CHAININFO`, `code_terminators = 0`, `dword_rva_ratio = 0,6`. Nem tartalmaz `call`, `jmp`, `ret`, `ud2`, `int3`, `syscall` vagy közvetett ugrás helyet, és `iat = none`; a sweep csak `1` `jcc` és `11` `invalid` bájtot „lát” belőle. A `11` nem dekódolt bájtja a sweep első megállási pontja, és a négy `data_record` `14` bájtjából `11`-et ez a tartomány adja az `1 096` bájtos nem dekódolt poolból. A `unresolved_regions.json` egyetlen `pinned_ranges` bejegyzése, hogy a `pinned.data_record_verdict` check a `116` checkes, `0` hibás önellenőrzésben reprodukálható maradjon. Külön, nyitva maradó kérdés a négy tartomány eredete és az, hogy kontrollfolyam valaha belép-e. | `unresolved_regions.json#pinned`, `unresolved_regions.csv#UR-001625`, `cfg_functions.csv#func_index=139645`, `pdata_functions.csv#record_index=139645` | `closed` az osztályozásra, a keletkezés nyitva | Nagy (P) az osztályozásra, Bizonyítatlan (U) a keletkezésre |

### 12.6 A syscall service mapping eredménye

| Tétel ID | Korábbi állítás | Új hitelesített állítás | Forrás artifact | Státusz | Confidence |
|---|---|---|---|---|---|
| `SVC-01` | A 9. fejezet 3. pontja: a service-szám kiderül-e statikusan vagy szimbolikusan a PEB-, KUSER_SHARED_DATA- és konstanskeverésből, és mely Nt/Zw szolgáltatások a `12` validált wrapperhez tartoznak. | A mapping fázis a teljes `3 627` helyes korpuszon lefutott és `0` helyet nevezett meg. Mind a `3 627` sor `nt_service = UNRESOLVED`, `nt_confidence = none`, `status = unresolved_symbolic_service_number`; `static_service_numbers = {}`, `static_service_number_sites = 0`, és a `svc_kind` census `static_constant` értéke `0`, tehát a gate névágata egyetlen soron sem értékelődött ki. A service-map `wrapper_forwarding` csoportjának `21` helye nem a `12` wrapper census: mind `21` azonos négy `A6_SELF_HANDLE` alakú, a `0x291C08F`–`0x2951479` sávban, `7` runtime function alatt; a `12` wrapper 4. argumentumpozíciója `A7_REG_INDIRECT`, ezért a konjunkció egyikükre sem teljesül, és a `21` halmaz a wrapperrel, a `16` inline hellyel és a kódklaszterrel is diszjunkt. Az audit `1 439 / 1 210 / 978` provenance-osztálya oldhatósági jel, nem mapping. Lezáratlan: az Nt/Zw név bármelyik helyre. | `syscall_service_map.json#naming_gate`, `syscall_inventory.csv` (`3 627` sor, `106` oszlop), `syscall_arg_classes.json`, `audit_syscall_candidates.json#unresolved_service_mapping`, `audit_handle_flow.json#wrapper_forwarding_predicate` | `bounded_open` | Nagy (P) a kimerítő negatív eredményre, Bizonyítatlan (U) bármely névre |

### 12.7 A lineáris sweep kontrollfolyam-korlát

| Tétel ID | Korábbi állítás | Új hitelesített állítás | Forrás artifact | Státusz | Confidence |
|---|---|---|---|---|---|
| `SWEEP-01` | A 8. fejezet 5. pontja és a 9. fejezet 6. pontja: a teljes `.text` nyers `3 881` `0F 05` találat nem szolgálhat utasításlistaként, és a `142 004` parse-elt runtime-function határral, rekurzív CFG-vel és call-site annotációval újra kell szűrni. | Az újraszűrés megtörtént és reprodukálódott. A `3 881` `.text` találat `3 627` `instruction_start` (`93,4553 %`), `209` `covered_by_instruction` (`5,3852 %`) és `45` `no_pdata_function` (`1,1595 %`) részre bomlik; a CSV scope-on kívül `30` találat van a `.rdata`-ban (`27`) és a `.data`-ban (`3`), összesen `3 911` minden raw-backed szekción. Független implementáció és második dekóder (`GNU objdump 2.47.20260726`, `549` tartomány) sorszintánként egyezik: `3 627 / 3 627` utasításstart, `3 627 / 3 627` `syscall` mnemonika, `0` vita, `0` más mnemonika, `0` byte-directive, `0` sweep-megállás a candidate előtt, és `0` owning function, amelyet a sweep a saját végéig nem fogyasztott el. A `9` dokumentált anklócsoport `64` egyedi helye mind a valid részhalmazban van. Amit a fázis nem ad: a hívólista. A `syscall_inventory.csv` a funkcióhatárt, a hat argumentumosztályt és a service-szám producer-láncát annotálja, hívóoszlopa nincs, ezért a kérdés call-site fele nyitva marad. | `syscall_candidates_raw.csv`, `audit_syscall_candidates.json#boundary_reproduction`, `#instruction_start_validation`, `#documented_anchors`, `#verdict` | `closed` a boundary-újraszűrésre | Nagy (P) |
| `SWEEP-02` | A 8. fejezet 6. pontja és az 5. fejezet capability-mátrixa a `blocks_reached` oszlopot és a `reached_ratio`-t elérhetőségi mérőszámként használta. | A két oszlop két különböző bizonyítéknyomot hordoz, és egyetlen számba keveri őket. Az `1 117 811` alap-blokkból `503 338` (`45,03 %`) rekurzív leszállással ért el, `614 473` (`54,971 %`) csak lineáris sweep-pel; `1 524` függvény (`1,07 %`) tartalmaz ilyen blokkot, és a `linear_only_blocks` család `24 358 005` bájtot fed le. A `142 004` függvényből `140 480`-nak `reached_ratio = 1,0` és pontosan `1`-nek `0,0` az értéke. Ugyanez a korlát a `syscall` opkódon: `3 627` valid helyből `243` `fallthrough_proven` (`6,70 %`), `0` `branch_proven` és `3 384` `sweep_hypothesis` (`93,30 %`), kiváltva `2 786` indirekt jumppel, `575` direkt jumppel és `23` terminátorral; a leszállás `3 964 288` utasításstartot ér el, `24` direkt ágcél esik egy másik utasítás belsejébe, és egyetlen candidate sem érintett. A `64` dokumentált helyből csak `20` descent-bizonyított. A kötelező olvasási szabály: a `blocks_reached` a statikus rekurzív leszállás elérését méri, nem a futásidejű elérhetőséget, és a `reached_ratio` soha nem használható kizárólagos elérési bizonyítékként. Nyitva marad a payload-hiány: a blokkonkénti proof-szint oszlop, a `linear_only_blocks` család tartomány-szintű újradekódolása, és a `cfg_functions.indirect_jumps` kontra `indirect_sites` jmp-szám keresztfájl-ellenőrzése. | `cfg_functions.csv`, `cfg_clusters.csv`, `unresolved_regions.json#method.confidence_rules`, `audit_syscall_candidates.json#instruction_start_validation.proof_levels`, `adhesive-13` 7. fejezet (F-20, F-21, F-22, D-009), `adhesive-15` 5. fejezet | `open` | Nagy (P) a mérésre |

### 12.8 A handle producer, ami nyitva marad

| Tétel ID | Korábbi állítás | Új hitelesített állítás | Forrás artifact | Státusz | Confidence |
|---|---|---|---|---|---|
| `P-01` | 6.1. pont 5: a `0x0C85650` funkcióra nem találtam közvetlen `rel32`, RIP-relatív vagy abszolút kódhivatkozást, ezért az objektum létrehozója közvetlen xrefből nem azonosítható; a producerhez vezető visszafelé futó adatfolyam az elsődleges nyitott kérdés. | A belépési határ lezárt a hat enumerált statikus élformán, a producer továbbra sem azonosított. A lezárási séta `444` sort ad a `0 / 1 / 2` szinteken `14 / 429 / 1` bontásban, `429` `direct_call`, `14` `forward_subject` és `1` `no_inbound_edge_in_enumerated_forms` élfajtával, `220` sor `F-U-01` jelöléssel és `0` fedésben maradt callsite-tal; a frontier üres és a séta kimerült. A `0x0C856C0`-nak pontosan `1` bejövő `rel32` hívása van, a `0x0C85681`-en; a `0x0C85650`nek `0` helye mind a hat formában; a `19 041` DIR64 slot egyike sem tart a klaszterbe mutató VA-t. A `producer_status` és az `ownership` egyaránt `OPEN`, a `producer_identified = false`. A séta csak az enumerált statikus élformákat követi, tehát regiszter-indirekt vagy stack-slot hívó statikusan nem zárható ki. | `audit_handle_flow.json#authoritative_table[P-01]`, `#recompute_detail.producer_and_caller_boundary`, `c856c0_forward.json#caller_closure`, `c856c0_callers.csv` | `open` | Bizonyítatlan (U) |

### 12.9 A napló lezáró mérlege

A napló `25` tételt tartalmaz: `21` `closed`, `2` `bounded_open` (`PCH-03`, `SVC-01`) és `2` `open` (`SWEEP-02`, `P-01`). A `closed` státusz nem jelent korlátlan állítást: minden mögöttes negatívum a dokumentált bounded scope-on érvényes, és a dinamikus, companion- és natív viselkedés nincs kizárva (lásd a 8. fejezet 16–18. pontját). A négy valóban nyitott téma a 9. fejezetben marad: a handle producer, az Nt/Zw szolgáltatásnevek, a patch-aktiválás és a dinamikus viselkedés. Egyik sor sem járul hozzá futtatási, invokációs, patch-, bypass- vagy credential-recovery eljáráshoz.

## 13. Javított végkövetkeztetés

A specimen erősen összhangban van a FiveM/CitizenFX `adhesive` komponenssel, és a vizsgálat környezetében érvényes Rockstar Games Authenticode-aláírással rendelkezik. A pontos kiadás, a terjesztési csatorna és az eredeti letöltési hely nincs lezárva. A public loader, a `legitimacy`/`glue` függőségek és a statikus integritási/process-memory jelek valószínűsítik a biztonsági/anti-cheat szerepet, de a privát implementáció nyilvános mappingje nélkül ez közepes konfidenciájú következtetés.

Statikusan megfigyelhető a három `ProcessBasicInformation`-kompatibilis direct syscall és a `buffer+0x28` → `OpenProcess` parent-PID-adatfolyam, a process-handle-alapú allokáció- és írás-/olvasás-kompatibilis wrapperlogika, a kétlépéses diszperziós dispatch `32` ág-törzse (`16` közvetlen `syscall` és `16` wrapper-hívás, a `12` wrapperrel összesen `28` syscall-hely), a feltételes CoreRT-debugger-jel, valamint a lokális patch-, Toolhelp stub- és NOP-write mechanizmus. A `3 627` valid syscall-hely service mappingje lefutott és `0` nevet adott, tehát a pontos Nt-szolgáltatások, a `0xC856C0` handle producer, a célprocessz, a jogok, a hívó- és adatfolyam, valamint a hálózati végpont és payload statikusan nyitott.

Nincs pozitív statikus bizonyíték credential theftre, persistence-re, ismeretlen C2-re vagy exfiltrációra; a megfelelő negatívumok bounded scope-on érvényesek, és nem zárják ki a dinamikus vagy companion-komponensbeli viselkedést. A process-memory és patch-mechanizmusok potenciális hatása nagy lehet, de a statikus evidence önmagában nem támaszt alá malware-, incidens-, jogi vagy fenyegetési minősítést. A következő bizonyító lépések továbbra is kizárólag statikus CFG-, def-use és korrelációs elemzések lehetnek; runtime betöltés, exploit, bypass, patch és credential recovery nem része ennek a módszertannak.

---

## 14. Pin- és arány-konformancia-javítás (2026-09-26)

> **Scope:** kizárólag szövegszerkesztés ebben a fájlban. A DLL-t nem futtattam, nem töltöttem be, nem mappeltem és nem patcheltem; új evidence-fájl nem készült, és a `reverse/evidence/` vagy a `reverse/scripts/` állományhoz nem nyúltam. A méret- és `sha256`-pinok a `2026-09-26`-i lemezállapothoz lettek igazítva.

### 14.1 Frissített pin-ek

**Nem volt frissítandó pin.** Ez a dokumentum nem rögzít egyetlen `reverse/evidence/` artifact méretét vagy `sha256`-digestjét sem táblázatos, sem szöveges formában, így a `13`, `14`, `15` és `00` dokumentum pin-megállapodásával nem érintkezik. A specimen- és Authenticode-adatok (`53 575 264` bájt, `91CC0AA0…`, `82D63CBA…`) nem evidence-artifact pinok, és változatlanok.

### 14.2 Frissített arány

| Hely | Régi érték | Új érték | Ellenőrzés |
|---|---|---|---|
| 12.7. fejezet, `SWEEP-02` sor (a `3 384 sweep_hypothesis` aránya) | `93,32 %` | **`93,30 %`** | `3 384 ÷ 3 627 = 0,9330024…` → `93,30 %` |

A `SWEEP-02` sorban szereplő többi százalékérték a `3 384 / 3 627` aránnyal összhangban van, és változatlan: `243 ÷ 3 627 = 6,6998 %` → `6,70 %` (`fallthrough_proven`), `0` `branch_proven`. Az `1 117 811` alap-blokkra vonatkozó értékek (`503 338 ÷ 1 117 811 = 45,03 %`, `614 473 ÷ 1 117 811 = 54,971 %`, `1 524 ÷ 142 004 = 1,07 %`) más nevezőt használnak, és nem érintettek. A `SWEEP-01` sor `3 881`-es nevezőjű értékei (`93,4553 %`, `5,3852 %`, `1,1595 %`) szintén változatlanok.

### 14.3 Amit a javítás nem módosított

- **Nem változott semmilyen statisztikai szám, finding, státusz vagy confidence érték:** a `3 881` → `3 627 / 209 / 45 / 30` felbontás, a `9` anklócsoport `64` helye, a `64`-ből `20` descent-bizonyított darabszám, a `2 786` / `575` / `23` terminátor-megkötés, a `3 964 288` utasításstart és a `24` közvetlen ágcél mind változatlan.
- **A `SWEEP-02` státusza továbbra is `open`, confidence-ja `Nagy (P)` a mérésre**; a nyitott payload-hiány (blokkonkénti proof-szint oszlop, a `linear_only_blocks` család tartomány-szintű újradekódolása, a `cfg_functions.indirect_jumps` kontra `indirect_sites` jmp-szám keresztfájl-ellenőrzése) nem záródott.
- **A 12.9. fejezet mérlege érintetlen:** a napló `25` tétele, a `21` `closed`, a `2` `bounded_open` (`PCH-03`, `SVC-01`) és a `2` `open` (`SWEEP-02`, `P-01`) feloszlás változatlan.
- **A `13:374`, a `15:264` és a `15:863` már `93,30 %`-ot írt**, tehát a mostani javítás a `12` 12.7. fejezetét hozza összhangba velük; újraszámolt arány egyik másik dokumentumban nem volt szükséges.
- **Kódolás és sortörés:** a fájl UTF-8 BOM nélküli, LF sortöréssel, záró sortöréssel; `cr = 0`.
