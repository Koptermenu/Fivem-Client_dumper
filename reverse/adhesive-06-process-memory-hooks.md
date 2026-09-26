# `adhesive.dll` – processz-, szál-, modul-, memória- és hook-képességek

## 1. Vizsgálati hatókör

- Minta: `reverse/adhesive.dll`
- Architektúra: PE32+ / x86-64
- Preferált image base: `0x180000000`
- Méret: `53 575 264` bájt
- SHA-256: `91CC0AA006D7315CB042C8FA8DCA6C1E074A307BBA7DCC9EB5509C8A7B81934E`
- Elemzés: kizárólag statikus PE-, import-, sztring-, disasszemblál- és közvetlen hívási elemzés.
- A DLL-t nem futtattam, nem töltöttem be, és nem végeztem dinamikus patchelést vagy bypass-ellenőrzést.

Az alábbi címek mind RVA-k. A bizonyítéki szintek `P`/`L`/`U` jelöléssel egyértelműen megfeleltetnek: **Magas = P**, **Közepes = L**, **Ismeretlen = U**. A szintek jelentése:

- **Magas:** közvetlen call/syscall látható, az argumentumok és az adatfolyamat statikusan egyértelműek.
- **Közepes:** a művelet valószínű, de az obfuscált szolgáltatásszám vagy a hívó kontextusa nem teljesen azonosított.
- **Ismeretlen:** nincs elég statikus kapcsolat; ebből működést nem lehet következtetni.

**Az importtáblázat önmagában nem bizonyítja az API végrehajtását.** Az alábbi „magas” minősítések konkrét közvetlen call-, `call [IAT]`- vagy `syscall` helyekre és statikus argumentumvizsgálatra támaszkodnak, nem pusztán importnévre.

## Felülírt részek

Kizárólag visszirányú navigáció: a feltüntetett szöveghelyek egyike sem módosult, a blokk csak megmutatja, mely későbbi dokumentum az érvényes. Ahol ellentmond, a jobb oldali dokumentum élvez elsőbbséget; az itt maradó szöveg történeti állítás, nem ellenkező állítás. Jelölés: `P` = proven, `L` = likely, `U` = unknown.

| Itt érintett szakasz / állítás | Felülíró forrás | CONF | Forrás evidence |
|---|---|---|---|
| §4.3 query-handle és wrapper kapcsolat; §9.1–§9.5 handle-, wrapper- és ágszámok; §11 táblázat `Folyamatmemória-allokáció` és `Távoli pufferírás` sora; §13 `Távoli allokáció` / `Távoli írás` sora; §14/1. és §14/2. | `14` §3 `C-01`–`C-09`: 16 közvetlen syscall az anchorban, 12 wrapper, 2 handle-load, 2 diszperziós tábla, 32 ág | `P` a számokra, `U` a handle producerre | `reverse/evidence/audit_handle_flow.json` (`AFH-2026-09-26`, 163 check, 0 hiba), `c856c0_dataflow.json`, `c856c0_callers.csv`, `c856c0_forward.json` |
| §5.2, §5.3, §8.2, §10.1, §10.2 patch-rekord-, védelem- és hívási útvonalak; §13 `VirtualProtect` sora; §14/3. és §14/4. | `16` §5.6, §12/2., §12/4., §12/10., §12/16., §12/19., §12/20.: a négy közvetlen hívó intra-komponens, a `0x1D280`–`0x1E9D0` lánc belépési pont nélkül statikusan holt | `P` a gráf, `L` a futásidejű elérhetetlenség, `U` a `0x1754520` hívójára | `reverse/evidence/patch_record_table.json`, `patch_mechanisms_1e270.csv`, `patch_mechanisms_1dff0.csv`, `patch_mechanisms_helpers.csv`, `thread_context_map.json` |
| §6 és §12 `APC` blokkja (`0x183254270` kapcsoló, `RVA 0x1170` cél); §7.2 és §10.3 Toolhelp telepítő/visszaállító; §8.2 `FlushInstructionCache` | `16` §6.3, §7.1, §8.3, §10.2, §12/12.–§12/15.: a célcím a `0x317E398` írható cache globálist olvassa, a pár `ASYMMETRIC`, a védelem a hívó rekord `+0x10` mezőjébe kerül, a kapcsolónak 7 olvasója és 0 írója van | `P` a szerkezetre, `U` a kapcsoló írójára | `reverse/evidence/patch_mechanisms_helpers.csv` (`symmetry_*`), `apc_sites.csv` |
| §14/3. és §14/4. nyitott kérdés lezárása; minden elérhetőségi állítás olvasási szabálya | `16` §12/20. a negatív oldalt statikusan lezárja, a közvetett, futásidejű vagy képkívüli hívást nem; `13` §7 `F-20` szerint egyetlen elérhetőségi szám sem kizárólagos elérési bizonyíték | `P` a negatív oldalon, `U` a lezáratlan oldalon | `reverse/evidence/unresolved_regions.json`, `pdata_functions.csv` |

## 2. Rövid összegzés

| Terület | Statikus megállapítás | Bizonyosság |
|---|---|---:|
| Folyamat | A saját folyamat `PROCESS_BASIC_INFORMATION` mezőiből a szülő PID kerül kiolvasásra, majd arra `OpenProcess(0x1000, FALSE, parentPid)` kérés történik. | Magas (P) |
| Folyamatmetadat | `NtQueryInformationProcess`-kompatibilis inline syscallok vannak `-1` pseudo-handellel, `0` információs osztállyal és `0x30` bájtos bufferrel. | Magas (P) |
| Szálak | Toolhelp-pel a saját processz szálai kerülnek kiválasztásra; `OpenThread`, suspend, context-get, context-set és resume útvonalak vannak. | Magas (P) |
| APC | Hét `QueueUserAPC` hívás mind `RVA 0x1170` célt használ; az APC-rutin egyetlen `ret`. | Magas (P) |
| Modulok | `KERNEL32.DLL` és `CreateToolhelp32Snapshot`, `Module32First`, `Module32Next` dinamikus feloldása, majd `TH32CS_SNAPMODULE` enumeráció. | Magas (P) |
| Memória | Helyi `VirtualAlloc`/`VirtualQuery`/`VirtualProtect` használat, továbbá processzhandle-alapú `NtAllocateVirtualMemory` és valószínű `NtWriteVirtualMemory` direkt syscallok. | Magas (P) az allokációra, közepes (L) a write szolgáltatásnévre |
| Hook | Táblavezérelt rel32 jump patch, NOP-feltöltés és egy `CreateToolhelp32Snapshot`-ot `INVALID_HANDLE_VALUE` visszatéréssel felülíró inline hook. | Magas (P) |
| Távoli handle eredete | A `RVA 0xC856C0` wrapper handle-t egy objektum első qwordjából olvas, de a felsőbb szintű létrehozási lánc nem azonosítható. | Ismeretlen (U) |
| `RVA 0x1754520` | NOP-patch segéd; nincs közvetlen call vagy statikus függőpointer-hivatkozás. | Magas (P) az írás, ismeretlen (U) a használat |

## 3. Fontos importok és közvetlen hívási helyek

| API | IAT RVA | Közvetlen hívási hely(ek) | Statikus cél/argumentum |
|---|---:|---|---|
| `OpenProcess` | `0x2E4D4C0` | `0xD7B86E` | PID = `buffer+0x28`; access `0x1000`; `bInheritHandle=FALSE`. |
| `OpenThread` | `0x2E4D4C8` | `0x1E0F4`, `0x1E473`, `0x1E526` | TID a belső szál-listából; access `0x5A`; öröklés nincs. |
| `CreateToolhelp32Snapshot` | `0x2E4D290` | `0x1E029`, közvetlen thunk `0x2BED400` | `TH32CS_SNAPTHREAD` (`4`), process ID `0`. |
| `Thread32First` | `0x2E4D5C8` | `0x1E04B` | `THREADENTRY32` méret `0x1C`. |
| `Thread32Next` | `0x2E4D5D0` | `0x1E1D7` | Ugyanaz a snapshot. |
| `SuspendThread` | `0x2E4D5A0` | `0x1E109` | A frissen megnyitott szál handle. |
| `GetThreadContext` | `0x2E4D400` | `0x1E11F` | `ContextFlags=0x100001`. |
| `SetThreadContext` | `0x2E4D570` | `0x1E214` | A módosított AMD64 `CONTEXT`. |
| `ResumeThread` | `0x2E4D538` | `0x1E484`, `0x1E537` | A korábban felsorolt szál handle. |
| `QueueUserAPC` | `0x2E4D4F8` | `0x1F907F4`, `0x1F90A17`, `0x1F91968`, `0x20668B5`, `0x2067DDB`, `0x20C0E25`, `0x20C0F33` | APC RVA `0x1170`, `dwData=0`; a szál handle belső thread-object mezőből jön. |
| `VirtualAlloc` | `0x2E4D618` | `0x1D3A2`, `0x1D43E`, `0x687356`, `0xC874E9` | Helyi allokáció; a részletesen vizsgált helyeken `MEM_COMMIT\|MEM_RESERVE`/`PAGE_EXECUTE_READWRITE`, illetve `MEM_COMMIT`/`PAGE_EXECUTE_READWRITE`. |
| `VirtualProtect` | `0x2E4D630` | `0x1E2D1`, `0x1E31B`, `0xC8CEF4`, `0x1754577`, `0x17545A0`, `0x2921505`, `0x2921526`, `0x2BEB8FB` | A vizsgált hookútvonalakon a saját processz kód- vagy adatterülete. |
| `VirtualQuery` | `0x2E4D638` | `0x1D34C`, `0x1D3DB`, `0x1DD5F`, `0x1DD95`, `0x1E922`, `0xC87508`, `0x2BEB812` | Helyi `MEMORY_BASIC_INFORMATION` lekérdezés; nincs processzhandle-argumentum. |
| `FlushInstructionCache` | `0x2E4D2E8` | `0x1E330` | `GetCurrentProcess`, a patchcím és a patchméret. |

Nem található statikus import `Process32First`, `Process32Next`, `VirtualAllocEx`, `VirtualProtectEx`, `ReadProcessMemory` vagy `WriteProcessMemory` névre. Ez nem zárja ki a direkt syscallos vagy dinamikusan feloldott megfelelőket. A táblázat közvetlen call-, thunk- és IAT-hívási helyeket felsorolja; a regiszteren átadott, kiszámított vagy egyéb közvetett hívások nem tekinthetők benne teljesnek.

## 4. Process ancestry és `OpenProcess`

### 4.1 ProcessBasicInformation lekérdezés

Három közvetlen inline syscall található:

- `RVA 0xD7B0AE`
- `RVA 0xD7B4B9`
- `RVA 0xD7C0AC`

Mindegyiknél az argumentumképzés azonos:

- `R10 = -1`: saját processz pseudo-handle;
- `EDX = 0`: `ProcessBasicInformation` osztály;
- `R8 = rbp`: kimeneti buffer;
- `R9D = 0x30`: `sizeof(PROCESS_BASIC_INFORMATION)`;
- az ötödik argumentum nulla.

A `syscall` számát (`EAX`) a kód futás közben, `KUSER_SHARED_DATA`, TEB/PEB és globális konstansok segítségében állítja elő. Emiatt a szolgáltatásszám nem olvasható közvetlenül statikusan, de az argumentumminta és a későbbi `buffer+0x28` használata erősen `NtQueryInformationProcess(ProcessBasicInformation)` műveletre utal.

### 4.2 Szülő PID és megnyitás

- `RVA 0xD7B863`: a `PROCESS_BASIC_INFORMATION.InheritedFromUniqueProcessId` mező, azaz `buffer+0x28`, bekerül az `OpenProcess` PID-argumentumába.
- `RVA 0xD7B86E`: `OpenProcess(0x1000, FALSE, parentPid)`; az x64 Win32 sorrend a kért jog, az öröklési flag és a PID.
- `0x1000` itt `PROCESS_QUERY_LIMITED_INFORMATION`, nem `PROCESS_VM_WRITE` vagy `PROCESS_VM_OPERATION`.
- Az eredmény a `RSP+0x60` által mutatott kimeneti helyre kerül.
- A callhelyen nincs azonnali `NULL`-ellenőrzés vagy `GetLastError`.
- Az átvizsgált blokkban nincs közvetlen `CloseHandle`; a handle további kezelése a hívóra vagy külső kódra marad.

**Bizonyosság:** magas a szülő PID kiolvasására és a `PROCESS_QUERY_LIMITED_INFORMATION` kérésre; futásidejű sikerre nincs bizonyíték.

### 4.3 A query-handle nem bizonyítottan a távoli írás handleje

A `0xC856C0` wrapper processzhandle-t használ memória-allokációra és feltételezett távoli írásra. A `0xD7B86E` hívás viszont csak query-limited jogú handle-t nyit. A statikus adatfolyamban nincs lánc, amely ezt a handle-t a wrapperhez kötné. Ezért:

- a query-handle önmagában nem alkalmas távoli allokációra/írásra;
- a wrapper végső handle-eredete ismeretlen;
- a „remote” jelleg a Nt argumentumszemantika alapján valószínű, de a handle tényleges tulajdonosa és célprocessze nem bizonyított.

## 5. Toolhelp-alapú szálkezelés

### 5.1 Snapshot és szűrés

Az `RVA 0x1DFF0` függvény:

1. `0x1E029`: `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)`.
2. `0x1E04B`: `Thread32First`.
3. `0x1E1D7`: `Thread32Next`.
4. A `THREADENTRY32.th32OwnerProcessID` mezőt összehasonlítja `GetCurrentProcessId()` eredményével.
5. Kizárja az aktuális `GetCurrentThreadId()` értékét.
6. Az átmaradó TID-kat dinamikus listában tárolja.

A `TH32CS_SNAPPROCESS`/`Process32First`/`Process32Next` útvonal nem látható; a process ancestry külön direkt syscallokon keresztül történik.

### 5.2 OpenThread, suspend és context

Mindhárom `OpenThread` call (`0x1E0F4`, `0x1E473`, `0x1E526`) a következő jogokat kéri:

- `THREAD_SUSPEND_RESUME` (`0x2`);
- `THREAD_GET_CONTEXT` (`0x8`);
- `THREAD_SET_CONTEXT` (`0x10`);
- `THREAD_QUERY_INFORMATION` (`0x40`).

Összesen `0x5A`.

Az első kontextusmódosító útvonal:

- `0x1E109`: `SuspendThread`;
- `0x1E11F`: `GetThreadContext`, `ContextFlags=CONTEXT_AMD64|CONTEXT_CONTROL` (`0x100001`);
- a `CONTEXT.Rip` a veremen `RSP+0x128` címen található;
- minden patch-rekordnál a `RIP` egyezését ellenőrzi a rekord `+0x28` bájtoffset-listája alapján;
- találatkor az új `RIP` értéke a rekord `+0x10` mezőjéből és a `+0x30` tárolt diszplacmentből képződik;
- `0x1E214`: `SetThreadContext`.

A rekord `0x38` bájt, és a következő statikus mezők használatosak:

- `+0x00`: patch/függvény alapcíme;
- `+0x08`: rel32 jump célcíme;
- `+0x10`: RIP-újraképzéshez használt bázis;
- `+0x20`: flag- és állapotbájt;
- `+0x24` alsó nibble: érvényes eltolások száma;
- `+0x28`: bájtoffsetek;
- `+0x30`: bájtos eltolás a RIP újraképzéséhez.

### 5.3 Resume- és hibakezelés

Az `RVA 0x1E360` általános hook-kezelő:

- `0x1E425` és `0x1E4FD`: meghívja az `RVA 0x1E270` patch-függvényt;
- `0x1E473`/`0x1E484`: egy ágon `OpenThread` + `ResumeThread`;
- `0x1E526`/`0x1E537`: másik ágon ugyanez.

Statikus hibaágak:

- `OpenThread` NULL esetén a szál kimarad;
- `GetThreadContext` sikertelenségekor a handle lezáródik, `SetThreadContext` nem történik;
- `SuspendThread`, `SetThreadContext` és `ResumeThread` visszatérési értékét nem ellenőrzi;
- a `0x1DFF0` context-módosító ágban nincs közvetlen `ResumeThread`; ebből nem következik biztos szállefagyás, de a helyi hibakezelés nem rendezi vissza a suspendet.

## 6. `QueueUserAPC`

Mind a hét közvetlen call azonos mintát követ:

- `RCX = RVA 0x1170`;
- `RDX = natív szálhandle`;
- `R8D = 0`.

Az `RVA 0x1170` egyetlen `ret` utasítás. Így az APC-cél statikailag nem hordoz shellcode-ot vagy adatot; feladata legfeljebb egy alertálható szál futásának felébresztése.

Mindegyik hívásnál:

- a globális `0x183254270` értéke `0`, akkor APC;
- nem nulla esetén `TerminateThread`, majd `WaitForSingleObject(..., INFINITE)` következik;
- a `QueueUserAPC` visszatérési értékét nem ellenőrzik;
- a szálhandle belső thread-object struktúrákból származik, nem az itt vizsgált `OpenThread` callokból.

**Bizonyosság:** magas. Az APC cél és hívási mód statikusan egyértelmű; az, hogy az APC fut-e és alertálható-e a szál, futásidőfüggő.

## 7. Modul enumeráció

### 7.1 Dinamikus feloldás

Két modulkereső segéd használja a következőket:

- `LoadLibraryW(L"KERNEL32.DLL")`;
- `GetProcAddress(..., "CreateToolhelp32Snapshot")`;
- `GetProcAddress(..., "Module32First")`;
- `GetProcAddress(..., "Module32Next")`;
- `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0)`.

Az első útvonal hívóhelyei:

- `0x2BD0FBE`: `LoadLibraryW`;
- `0x2BD1004`: snapshot-függvény feloldása;
- `0x2BD1058`: `Module32First` feloldása;
- `0x2BD106B`: `Module32Next` feloldása;
- `0x2BD1079`: snapshot;
- `0x2BD10C2`: `Module32First`;
- `0x2BD1120`: `Module32Next`.

A második útvonal:

- `0x2BD1206`: `LoadLibraryW`;
- `0x2BD124D`: snapshot-függvény feloldása;
- `0x2BD12AA`: `Module32First` feloldása;
- `0x2BD12BD`: `Module32Next` feloldása;
- `0x2BD12CB`: snapshot;
- `0x2BD1311`: `Module32First`;
- `0x2BD133E`: `Module32Next`.

Az első útvonal egy megadott címhez tartozó modult keres; a második a `GetProcAddress`-et ismételteti az enumerált bejegyzésekkel, ami exportkeresésre utal. Mindkét magasabb szintű célzási szemantika közepes bizonyosságú: az első több `MODULEENTRY32` mezőből számol tartományt, a második pedig a `GetProcAddress` első argumentumát egy szokatlan eltolásról olvassa. A `TH32CS_SNAPMODULE` és a processz ID `0` saját processz moduljaira utal, nem távoli processz moduljainak teljes körű enumerációjára.

A modulnév-rekordok `.rdata` címei:

- `Module32First`: `0x2E244C0`;
- `Module32Next`: `0x2E24418`;
- `CreateToolhelp32Snapshot`: `0x2E256C8`;
- `KERNEL32.DLL`: `0x2E490B0`.

Hibaágak:

- `LoadLibraryW` sikertelenségekor az első útvonal `0xFFFFFFFF`, a második `0` értékkel tér vissza;
- az első `GetProcAddress` sikertelenségekor `FreeLibrary` következik, majd a megfelelő hibaérték tér vissza;
- a `Module32First` és `Module32Next` feloldott pointereit a kód null-ellenőrzés nélkül használja;
- `INVALID_HANDLE_VALUE` snapshotnál mindkét útvonal `FreeLibrary` hívással kilép;
- `Module32First` hibájánál a snapshotot `CloseHandle`-lel, a `KERNEL32.DLL` modult `FreeLibrary`-val zárja; az első útvonal `0xFFFFFFFF`, a második `0` értéket ad vissza;
- a modulciklus végén, illetve találat után a snapshot és a modulhandle lezáródik.

### 7.2 `CreateToolhelp32Snapshot` inline hook

Az `RVA 0xC8CE70` segéd:

- `0xC8CEB5`: `GetModuleHandleA("kernel32.dll")`;
- `0xC8CEC5`: `GetProcAddress(..., "CreateToolhelp32Snapshot")`;
- `0xC8CEF4`: `VirtualProtect` az exportcím 16 bájtjára;
- elmenti az eredeti 16 bájtot egy hívó által adott bufferbe;
- az első 8 bájtot `INVALID_HANDLE_VALUE`-t visszaadó rövid stubbal írja felül.

Ez statikailag erős bizonyíték egy `KERNEL32!CreateToolhelp32Snapshot` inline hookra. Korlátok:

- nincs közvetlen call- vagy függőpointer-hivatkozás a telepítő `0xC8CE70` helperre;
- a célcím ASLR/runtime-feloldás miatt nem statikus;
- a `GetModuleHandleA`, `GetProcAddress` és `VirtualProtect` eredményét nem ellenőrzi;
- önmagában nem állítja vissza az eredeti védelmet;
- nem hív `FlushInstructionCache`-t;
- a sikeres felülírás után a `0x1DFF0` thread-snapshot és a modulkeresők `INVALID_HANDLE_VALUE` hibát kaphatnak.

A `0xC8F470` routine egy külön visszaállító pár:

- a hívó a telepítő által kitöltött struktúrát adja át: az első 16 bájt a mentett eredeti kód, a `+0x10` mező az eredeti oldalvédelem;
- `0xC8F47F`: újra feloldja a `KERNEL32!CreateToolhelp32Snapshot` címet;
- `0xC8F495`–`0xC8F498`: visszamásolja a mentett 16 bájtot;
- `0xC8F4B3`: tail-jump a `VirtualProtect` IAT-ra, a régi protection visszaállításával.

A visszaállító routine sem ellenőrzi a feloldási és `VirtualProtect` eredményét, és nem hív `FlushInstructionCache`-t. Nincs közvetlen call- vagy statikus függőpointer-hivatkozás hozzá, ezért hogy a telepítő és a visszaállító rutin fut-e, nem igazolható.

## 8. Helyi memória-API-k

### 8.1 `VirtualAlloc` és `VirtualQuery`

A részletesen vizsgált allokációs helyek a saját processzben allokálnak:

- `0x1D3A2` és `0x1D43E`: `VirtualAlloc(baseAddress, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)`, ahol az alapcím lehet egy korábbi `VirtualQuery` által talált szabad cím;
- `0xC874E9`: `VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)`;
- a `VirtualQuery` hívások `0x30` bájtos `MEMORY_BASIC_INFORMATION` struktúrát használnak;
- több helyen `State == MEM_COMMIT` és a protection magas nibble-ének vizsgálata történik;
- `0xC87508` után a frissen foglalt terület `0xCC` bájtokkal kitöltésre kerül.

Ezek a Win32 API-k nem processzhandle-t kapnak, ezért nem távoli memórialekérdezést bizonyítanak.

### 8.2 `VirtualProtect` és `FlushInstructionCache`

A `VirtualProtect` hívások többsége a saját processz hookcímét teszi ideiglenesen írhatóvá. A releváns visszatérési értékek kezelése:

- `RVA 0x1E270`: az első `VirtualProtect` hibája `0x0A` kóddal tér vissza;
- ugyanott a visszaállítás és a `FlushInstructionCache` eredménye nincs ellenőrizve;
- `RVA 0x1754520`: egyik `VirtualProtect` eredményét sem ellenőrzi;
- `RVA 0xC8CE70`: a `VirtualProtect` eredményét szintén figyelmen kívül hagyja.

Az egyetlen közvetlen `FlushInstructionCache` call `RVA 0x1E330`:

- közvetlenül `GetCurrentProcess()` után hívódik;
- az `RVA 0x1E270` által patchelt területet öblíti;
- sikert nem ellenőriz.

## 9. Távoli allokáció és feltételezett távoli írás: `RVA 0xC856C0`

### 9.1 Közvetlen hívó és bemenet

Az egyetlen közvetlen hívó:

- `RVA 0xC85681` → `RVA 0xC856C0`.

A hívó `RVA 0xC85650`:

- az első argumentumból egy eredmény-listát olvas;
- `outer+0x8` pointert olvas, majd ezt adja tovább;
- a string hosszát `2 * length + 2` bájtba számítja;
- a string SSO/heap mezőjéből választja a data pointert.

A `0xC856C0` wrapper ezután a kapott descriptor első qwordját processzhandle-ként használja (`[rcx]`, `0xC856F3`).

### 9.2 Allokációs útvonalak

A wrapper `RDTSC & 0xF` alapú, 16 ágú obfuszkált jump-táblát használ. Statikusan az alábbi allokációs útvonalak láthatók:

- `0xC85737` → `0x51D680`, ahol a syscall `0x51D84C`;
- `0xC8576D` → `0x51D880`, ahol a syscall `0x51DA7B`;
- közvetlen inline syscall `0xC86420`.

Az argumentumok egységes mintája:

1. processzhandle;
2. pointer a kezdetben nulla címhez;
3. `ZeroBits=0`;
4. pointer a kért bájtszámhoz;
5. `AllocationType=0x1000` (`MEM_COMMIT`);
6. `Protect=0x40` (`PAGE_EXECUTE_READWRITE`).

Ez statikailag erősen `NtAllocateVirtualMemory`-kompatibilis. A pontos syscall-szám futás közben képződik, ezért a szolgáltatásnév nem olvasható közvetlenül az `EAX` konstansából.

### 9.3 Írásnak látszó útvonalak

A sikeres allokáció után az alábbiak indulnak:

- `0xC86477` → `0xC8F650`, syscall `0xC8F84C`;
- `0xC864A0` → `0xC8F880`, syscall `0xC8FA6C`;
- közvetlen inline syscall `0xC870DB`.

Az argumentumrendezés:

1. processzhandle;
2. a remote processzben allokált cím;
3. helyi buffer;
4. bájtszám;
5. kiírt bájszám pointere.

Ez a `NtWriteVirtualMemory` és a `NtReadVirtualMemory` közös ötargumentumos formájával egyezik. A remote base adatkezelője és a hívási irány alapján a `NtWriteVirtualMemory` a valószínű cél, de az obfuscált szolgáltatásszám miatt ez nem abszolút bizonyított. A `NtReadVirtualMemory` formálisan nem zárható ki pusztán a syscall-szám ismerete nélkül.

### 9.4 Return és hibaág

- A wrapper a remote allokált címét adja vissza.
- Ha a base továbbra is nulla, `0xC8642B` körül nulla értékkel tér vissza, és az írás nem indul el.
- Az írás NTSTATUS-át a `0xC870DB` inline ág sem teszi a return értékévé.
- Sikertelen írás esetén nincs rollback vagy remote free.
- A hívó az allokált címet a kapott vectorba appendeli.

### 9.5 Ismeretlen handle-eredet

A közvetlen handle-adatfolyam:

```text
outer argumentum
  └─ [outer+0x8] → descriptor
       └─ [descriptor+0] → processzhandle
```

Az `0xC85650` hívónak nincs közvetlen statikus call- vagy qword-pointer-hivatkozása, ezért a descriptor létrehozása nem követhető vissza. A korábban azonosított parent-process handle `PROCESS_QUERY_LIMITED_INFORMATION` jogú, így nem bizonyított, sőt jogilag nem alkalmas a wrapper allokációs/írásigényeire.

**Következtetés:** a processzhandle-alapú távoli memória útvonal statikailag erős; a handle eredete, a célprocessz és a tényleges NtWrite-szolgáltatás bizonyossága alacsonyabb.

## 10. Futásidejű inline patch/trampoline útvonalak

### 10.1 `RVA 0x1E270` – táblavezérelt rel32 patch

Közvetlen hívók:

- `0x1E425`;
- `0x1E4FD`.

Statikus viselkedés:

- a `0x1830D44F8` globális táblából `index*0x38` rekordot választ;
- a patchcímet a rekord `+0x00` és flag bitei alapján számolja;
- a destination a rekord `+0x08` értéke;
- a célterületet `PAGE_EXECUTE_READWRITE` védelemmel írhatóvá teszi;
- rel32 jumpot helyez a számított címre;
- egy flag beállítása esetén külön rövid jump is készül a rekord alapcímén;
- visszaállítja a régi védelmet;
- `GetCurrentProcess` + `FlushInstructionCache` útvonalat használ;
- a rekord flag-jét `0x06` értékkel állapotba teszi.

Hibaágak:

- első `VirtualProtect` hiba → `0x0A`;
- a védelem visszaállításának hibája nincs rollbackként kezelve;
- `FlushInstructionCache` hiba nincs ellenőrizve;
- a rekord a cache-hívás után akkor is `0x06` jelre áll, ha a restore sikertelen;
- az 5/7 bájtos íráshoz itt nem látható explicit célméret- vagy oldalhatár-ellenőrzés.

A patch pontos célmoduljai és célfüggvényei futáskor a dinamikus rekordtáblából származnak; a statikus inicializálási állapot nélkül nem nevezhetők meg.

### 10.2 `RVA 0x1754520` – NOP-patch segéd

A két argumentum a célcím és a hossz; a normál user-mode címtartományban az első argumentumot használja célcímként. A függvény:

- a célterületet `PAGE_EXECUTE_READWRITE` védelemre váltja;
- a megadott hosszban egyetlen konstans bájt ismétlésével kitölt (NOP-fill); a kitöltő bájt értékét a `16` §7.2. szakasz adja meg, itt szándékosan nem reprodukálva;
- visszaállítja a régi védelmet;
- nem menti el az eredeti biteket;
- nem hív `FlushInstructionCache`-t;
- nem ad explicit siker-/hibaértéket;
- közvetlen call és statikus függőpointer-hivatkozás nincs hozzá.

Ez NOP-feltöltés. A hívási hely és a környező kód hiányában nem állítható, hogy trampolin-területként használják; önmagában a függvény nem bizonyít trampolin-szerű végrehajtást.

### 10.3 `RVA 0xC8CE70` – Toolhelp hook

A részletes leírás a modulfejezetben található. A `0xC8CE70` telepítő és a `0xC8F470` visszaállító pár ez az egyetlen különálló, név alapján azonosított inline hook.

## 11. Dinamikus Nt wrapper-ek

A releváns wrapper-ek nem importált `Nt*` szimbolumokra hivatkoznak. Hosszú, adatfüggő konstansláncot használnak a syscall-szám előállítására, többek között:

- `KUSER_SHARED_DATA` mezők;
- `gs:0x30` TEB és a PEB;
- titkosított `.data`/`.rdata` konstansok;
- különböző wrapper-változatok.

| Logikai művelet | Wrapper/syscall helyek | Bizonyosság |
|---|---|---:|
| `ProcessBasicInformation` lekérdezése | inline `0xD7B0AE`, `0xD7B4B9`, `0xD7C0AC` | Magas (P) |
| Folyamatmemória-allokáció | wrapper `0x51D680` / syscall `0x51D84C`; wrapper `0x51D880` / syscall `0x51DA7B`; inline `0xC86420` | Magas (P) |
| Távoli pufferírás | wrapper `0xC8F650` / syscall `0xC8F84C`; wrapper `0xC8F880` / syscall `0xC8FA6C`; inline `0xC870DB` | Közepes–magas (L–P) |

A `0x51D680` és `0x51D880` nem csak a `0xC856C0` wrapperből hívódik; több, egymástól távoli statikus call hely is látható. Az argumentumelőállítás egységes, ezért ezek statikailag ugyanazon allokációs sémát követő variánsok.

## 12. Jogosultsági és platformkorlátok

### Processz és memória

- A parent-process `OpenProcess` kérés `PROCESS_QUERY_LIMITED_INFORMATION` jogot kér.
- `NtAllocateVirtualMemory` processzhandle-hez `PROCESS_VM_OPERATION` szükséges.
- `NtWriteVirtualMemory` processzhandle-hez `PROCESS_VM_WRITE` és `PROCESS_VM_OPERATION` szükséges.
- A direkt syscall nem szünteti meg a kernel jogosultsági ellenőrzését.
- A binárisban nincs importált `AdjustTokenPrivileges`, token- vagy impersonációs művelet. Dinamikus kiváltság-módosítás nem zárható ki, de statikusan nem igazolható.
- Távoli processz kezeléséhez megfelelő processzobjektum-jog, a célprocessz megfelelő DACL-je és adott esetben `SeDebugPrivilege` szükséges. Ezek meglétét a minta nem garantálja.

### Szál és context

- Az `OpenThread(0x5A)` a saját processz szálaira általában elegendő lehet, de a thread object DACL-je, a thread időzített kilépése vagy védett végrehajtási környezet miatt hibázhat.
- `GetThreadContext` és `SetThreadContext` külön jogosultságot és érvényes, nem kilépő szálhandle-t igényel.
- A `SuspendThread` és `ResumeThread` előző suspend-számlálóval működik; ez a kód nem használja a visszatérési értéket a számláló kezelésére.

### APC

- `QueueUserAPC` sikeréhez érvényes szálhandle és `THREAD_SET_CONTEXT` jog szükséges.
- Az APC csak alertálható szálon fut le; a hívás sikusa önmagában nem jelenti az azonnali futást.
- A `RVA 0x1170` cél `ret`, ezért nem mutat APC-shellcode-ra.

### Toolhelp és modulok

- `TH32CS_SNAPMODULE` a saját processz moduljait listázza.
- Más processz és eltérő architektúrájú modulok teljes listázása további, jellemzően architektúrával egyező segédprocesszet igényelne; ilyen célprocessz nincs a dokumentált statikus útvonalon.
- A `C8CE70` hook sikertelen `VirtualProtect` vagy rossz feloldási eredmény esetén hibás utasításmódosítást okozhat.

## 13. Hibaágak összefoglalása

| Terület | Statikus kezelés |
|---|---|
| Toolhelp snapshot | `INVALID_HANDLE_VALUE` és `Thread32First` hiba külön ágra fut; a legtöbb ágon lezárja a snapshotot. |
| Szállista allokáció | Sikertelen heap-allokáció esetén a lista üres marad, majd a snapshot lezáródik. |
| `OpenThread` | NULL handle esetén a szál kimarad, nincs retry. |
| `GetThreadContext` | Hiba esetén nincs context-set és nincs explicit resume ugyanebben az ágban. |
| `Set/ResumeThread` | Return nincs ellenőrizve. |
| `QueueUserAPC` | Return nincs ellenőrizve; alternatív terminate ág van. |
| `VirtualProtect` | A `0x1E270` első hibáját `0x0A`-val adja vissza; restore és cache flush hibáját nem. A másik két patchhelper egyik hibát sem kezeli. |
| Távoli allokáció | Nulla base esetén nincs írás. |
| Távoli írás | Státusz nem kerül visszaadásra; nincs rollback vagy free. |
| Modulfeloldás | Load/feloldás/snapshot/első elem hibáinál takarítás és hibaérték vagy üres eredmény látható. |
| Hook célfeloldás | A `C8CE70` telepítő és a `C8F470` visszaállító egyaránt ellenőrizetlen handle-, proc-address- és protect-eredménnyel dolgozik. |

## 14. Nyitott kérdések

1. Melyik futásidejű objektum tölti be a `0xC856C0` wrapper descriptorét, és honnan származik a processzhandle?
2. A `0xC8F650/0xC8F880` wrapperek `NtWriteVirtualMemory`-t vagy `NtReadVirtualMemory`-t hívnak-e az adott Windows buildben?
3. Melyik `RVA 0x1E270` patch-rekordok aktiválódnak ténylegesen, és mely modulokat/exportokat céloznak?
4. Ki vagy mi hívja közvetetten az `RVA 0x1754520` NOP-patch segédet?
5. Mikor települ a `C8CE70` Toolhelp hook, és milyen globális inicializálási út vezet hozzá?
6. A három `ProcessBasicInformation` syscall mindegyike ugyanabban a logikai ágban fut-e, vagy az obfuszkáció csak párhuzamos másolatokat tartalmaz?

## 15. Korlát

Ez a dokumentáció statikus képesség- és hívási viselkedést ír le. Nem tartalmaz exploit-, bypass-, shellcode-kivitelezési vagy patchelési receptet, és nem állítja, hogy bármely import vagy syscall futásidőben sikeresen lefutott volna.

**Táblázat-formázási javítás (2026-09-26):** az API-hívási táblázat 60. sorában a `VirtualAlloc` sor `MEM_COMMIT|MEM_RESERVE` nem escapelt `|` karaktere `\|` alakra javítva, így a cellaszám egyezik a fejléccel; szám, RVA, finding és sortörés nem változott.
