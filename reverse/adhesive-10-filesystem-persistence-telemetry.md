# `adhesive.dll` – filesystem, perzisztencia és telemetry

**Vizsgált artifact:** `C:\Users\Admin\Desktop\Dumper - AllInOne\reverse\adhesive.dll`
**Vizsgálat dátuma:** `2026-09-25`
**Dokumentum nyelve:** magyar
**Vizsgálat típusa:** kizárólag statikus, fájlszintű elemzés

> A DLL-t nem töltöttem be, nem futtattam, nem patcheltem és nem monitoroztam. A dokumentáció nem tartalmaz persistence-bypass, exploit- vagy kézi végrehajtási receptet. Az import- és callsite-bizonyíték statikus képességjelenlétet jelent, nem garantált runtime-eseményt.

## 1. Artifact és módszertani határ

| Tulajdonság | Statikus érték |
|---|---|
| Fájlméret | `53 575 264` bájt (`0x3317E60`) |
| SHA-256 | `91CC0AA006D7315CB042C8FA8DCA6C1E074A307BBA7DCC9EB5509C8A7B81934E` |
| Formátum | PE32+ / AMD64 DLL |
| Image base | `0x180000000` |
| Entry point | `RVA=0x2AB2770`, `RAW=0x2AB1B70` |
| `.text` | `RVA=0x1000`, `RAW=0x400` |
| `.rdata` | `RVA=0x2BEF000`, `RAW=0x2BEDA00` |
| Import scope | 42 regular modul, 628 regular import, 1 delay-import |
| Export | `CreateComponent`, `RVA=0x101F80` |

Az `RVA` a PE-image relatív virtuális címe, a `RAW` a specimen fájlban mért offset. A nyers tárolt szekciórészben:

```text
raw = RVA - VirtualAddress + PointerToRawData
```

A `.text` és a `.rdata` gyakori deltaértékei rendre `RVA - RAW = 0xC00` és `0x1600`; a táblázatokban minden helyet külön ellenőriztem.

### Confidence

| Jelölés | Jelentés |
|---|---|
| `P` | Közvetlenül megfigyelt PE-, import-, string- vagy utasításbizonyíték. |
| `L` | Több statikus jelből erős, de nem közvetlen következtetés. |
| `U` | A jelen statikus vizsgálatból nem dönthető el. |

A callsite-sorok a `CONF:P` érték közvetlen utasítás- vagy IAT-bizonyítékára, az értelmezési sorok gyakran `CONF:L` értékre vonatkoznak.

## 2. Rövid eredmény

A specimenben erősen megfigyelhetők a következő, egymástól különálló rétegek:

- `CitizenFX.ini` olvasása, `Game` szekcióbeli `IVPath`, `PathCL2`, `DefaultBuild` és `ReplaceExecutable` kulcsok, valamint `FiveM.app` könyvtár létrehozása.
- `CitizenFX_SubProcess_%s.bin`, `cache\`, `subprocess\`, `data/server-cache-priv%s`, `citizen/release.txt`, `data\cache\crashometry` és `data\cache\error-pickup` artifactumok statikus előfordulásai.
- VFS-, resource-cache-, `RcdStream`-, `RcdBulkStream-` és `RagePackfile`-alapú erőforráskezelés.
- `CFX_%s_%s_SharedData_%s` alakú named shared-memory objektum létrehozása és leképezése.
- Egyetlen statikusan azonosított registry-olvasási útvonal: `RegGetValueW`, `HKEY_LOCAL_MACHINE` és `RRF_RT_REG_SZ` típusszűrő.
- Hálózati adapter-, eszközlista-, rendszerinformáció-, processz- és munkamenet-adatokat lekérő primitívák.
- OpenSSL klasszikus Event Log-diagnosztikai útvonal: `OpenSSL`, `OpenSSL: FATAL`, `RegisterEventSourceW`, `ReportEventW`, `DeregisterEventSource`.

A vizsgálat nem talált közvetlen, cleartext persistence-láncot: nincs service-manager API, Task Scheduler COM/API, `CurrentVersion\Run`, startup-mappa vagy registry-write bizonyíték, és a regular/delay importtáblában nincs Win32 `CreateRemoteThread`/`WriteProcessMemory`. Ez az importált Win32 API-k hiánya, nem process-memory-képesség-negatívum: a 06-os audit által igazolt közvetlen syscall process-memory útvonal statisztikusan pozitív. A named shared memory, a cache- és diagnosztikai fájlok önmagukban nem bizonyítják a perzisztenciát. Az adapter- és session-adatok fingerprint-képességet jeleznek, de a statikus kód nem bizonyítja, hogy milyen célra, milyen sémával továbbítják őket.

## 3. Win32 filesystem-API inventory

### 3.1 Natív fájl- és könyvtárhívások

| API | Callsite `RVA` | Callsite `RAW` | Funkcióhatár | Statikus szerep | Confidence |
|---|---:|---:|---|---|---|
| `CreateFileW` | `0x203AC04` | `0x203A004` | `0x2033690–0x2047B87` | Obfuszált, általános fájlmegnyitási útvonal; a konkrét útvonal nem statikusan nevezett. | `P` |
| `CreateFileW` | `0x203E938` | `0x203DD38` | `0x2033690–0x2047B87` | Második általános megnyitási callsite. | `P` |
| `CreateDirectoryW` | `0x47EA53` | `0x47DE53` | `0x47E760–0x47F668` | A subprocess/cache útvonal könyvtár-előállítása. | `P` |
| `CreateDirectoryW` | `0x47EAF0` | `0x47DEF0` | `0x47E760–0x47F668` | Ugyanazon lifecycle további könyvtárágai. | `P` |
| `CreateDirectoryW` | `0x47EB98` | `0x47DF98` | `0x47E760–0x47F668` | Ugyanazon lifecycle további könyvtárágai. | `P` |
| `CreateDirectoryW` | `0x2AA2F8C` | `0x2AA238C` | `0x2AA2C50–0x2AA325F` | `FiveM.app` könyvtár létrehozása. | `P` |
| `DeleteFileW` | `0x47F248` | `0x47E648` | `0x47E760–0x47F668` | Cache/subprocess fájl eltávolítása. | `P` |
| `DeleteFileW` | `0x47F38B` | `0x47E78B` | `0x47E760–0x47F668` | Második törlési ág. | `P` |
| `MoveFileW` | `0x47F3B9` | `0x47E7B9` | `0x47E760–0x47F668` | Cache/subprocess fájl áthelyezése. | `P` |
| `CopyFileW` | `0x47F42C` | `0x47E82C` | `0x47E760–0x47F668` | Cache/subprocess fájl másolása. | `P` |
| `MoveFileExW` | `0x2A6715B` | `0x2A6655B` | `0x2A66FC0–0x2A67290` | Általános fájl-áthelyezési primitív; a célútvonal nincs ehhez a callsite-hez kötve. | `P` |
| `GetFileAttributesExW` | `0x47F1C2` | `0x47E5C2` | `0x47E760–0x47F668` | Cache/subprocess attribútumellenőrzés. | `P` |
| `GetFileAttributesExW` | `0x47F1F4` | `0x47E5F4` | `0x47E760–0x47F668` | Második attribútumellenőrzési ág. | `P` |
| `GetFileAttributesW` | `0x47E94A` | `0x47DD4A` | `0x47E760–0x47F668` | Cache/subprocess útvonal-ellenőrzés. | `P` |
| `GetFileAttributesW` | `0x47F44C` | `0x47E84C` | `0x47E760–0x47F668` | Fájl- vagy könyvtárellátás ellenőrzése a copy/move ágban. | `P` |
| `GetFileAttributesW` | `0x2AA263F` | `0x2AA1A3F` | `0x2AA2490–0x2AA2823` | Konfigurációs útvonal ellenőrzése. | `P` |
| `GetFileAttributesW` | `0x2AA2F13` | `0x2AA2313` | `0x2AA2C50–0x2AA325F` | `CoreRT.dll`/`FiveM.app` ág előkészítése. | `P` |
| `GetFileAttributesW` | `0x2AA3015` | `0x2AA2415` | `0x2AA2C50–0x2AA325F` | Második `CoreRT.dll` ág ellenőrzése. | `P` |
| `GetFileAttributesW` | `0x2AA3091` | `0x2AA2491` | `0x2AA2C50–0x2AA325F` | `FiveM.app` ág ellenőrzése. | `P` |
| `GetFileAttributesW` | `0x2AA30B0` | `0x2AA24B0` | `0x2AA2C50–0x2AA325F` | Ugyanazon ág további attribútumlekérése. | `P` |
| `GetFileAttributesW` | `0x2AA380D` | `0x2AA2C0D` | `0x2AA3720–0x2AA38DC` | `CitizenFX.ini` második konfigurációs útvonalának ellenőrzése. | `P` |
| `GetFullPathNameW` | `0x2AA2D8D` | `0x2AA218D` | `0x2AA2C50–0x2AA325F` | Relatív konfigurációs/runtime útvonal feloldása. | `P` |
| `FindFirstFileW` | `0x2BA5D6C` | `0x2BA516C` | `0x2BA5A30–0x2BA5E4F` | Könyvtár- vagy wildcard-enumeráció. | `P` |
| `FindNextFileW` | `0x2BA5DA9` | `0x2BA51A9` | `0x2BA5A30–0x2BA5E4F` | Az enumeráció folytatása. | `P` |
| `FindClose` | `0x2BA5E6D` | `0x2BA526D` | `0x2BA5E50–0x2BA5EA2` | Find-handle lezárása. | `P` |
| `CreateFileMappingW` | `0x48F0A6` | `0x48E4A6` | `0x48EEB0–0x48F1D5` | Named shared-memory mapping létrehozása. | `P` |
| `MapViewOfFile` | `0x48F16F` | `0x48E56F` | `0x48EEB0–0x48F1D5` | A mapping nézetének leképezése. | `P` |
| `UnmapViewOfFile` | `0x48EE7D` | `0x48E27D` | `0x48EE60–0x48EEA6` | A nézet leválasztása a destruktorban. | `P` |
| `WriteFile` | `0x2AB6F93` | `0x2AB6393` | `0x2AB6EE0–0x2AB72D6` | Diagnosztikai/hibakezelési írási ág. | `P` |

A `FindFirstFileW` funkció a bemeneti útvonal végéhez wildcard-jelet épít, majd a visszaadott handle-t az objektum `+0x250` mezőjében tárolja. Ez közvetlenül könyvtár-/fájl-enumerációt bizonyít, de nem persistence-állandót.

A `ReadFile` nem szerepel a standard importtáblában, és a releváns, validált hívási táblázatban sincs közvetlen `ReadFile` callsite. A release- és crash/error-olvasási láncok ehelyett CRT `_wfopen`/`fgets`, illetve VFS stream API-kon keresztül olvasnak. Ez a bounded scan nem zárja ki dinamikus vagy companion-modulbeli `ReadFile` használatot. A `CreateFileW` callsite-ok nagy, erősen kevert/obfuszkált függvényben vannak; a konkrét célútvonal statikusan nem stabilizálható, ezért a jelentés nem kapcsol hozzájuk `AppData`, temp vagy startup-következtetést.

### 3.2 Fájl- és útvonal-stringek

| Literal | String `RVA` | String `RAW` | Közvetlen xref | Confidence és értelmezés |
|---|---:|---:|---|---|
| `CitizenFX.ini` | `0x2E48FE8` | `0x2E479E8` | `0x2AA258B/0x2AA198B`, `0x2AA3761/0x2AA2B61` | `P`: helyi INI-konfiguráció. |
| `IVPath` | `0x2E49008` | `0x2E47A08` | `0x2AA26DC/0x2AA19DC` | `P`: `[Game]` kulcs akkor, ha a CLI nem tartalmazza `PathCL2`-t. |
| `PathCL2` | `0x2E491F8` | `0x2E47BF8` | `0x2AA26E3/0x2AA19E3` | `P`: CLI-tartalomtól függő `[Game]` kulcs és a `GetPrivateProfileStringW` defaultja. |
| `Game` | `0x2E49018` | `0x2E47A18` | `0x2AA2719/0x2AA1B19`, `0x2AA3830/0x2AA2C30`, `0x2AA385B/0x2AA2C5B` | `P`: INI szekció. |
| `DefaultBuild` | `0x2E49080` | `0x2E47A80` | `0x2AA3829/0x2AA2C29` | `P`: integer konfigurációs kulcs. |
| `ReplaceExecutable` | `0x2E49028` | `0x2E47A28` | `0x2AA3854/0x2AA2C54` | `P`: integer konfigurációs kulcs. |
| `FiveM.app` | `0x2E48F70` | `0x2E47970` | `0x2AA2F69/0x2AA2369`, `0x2AA306B/0x2AA246B` | `P`: `CreateDirectoryW` argumentumaként használt könyvtárnév. |
| `CitizenFX_SubProcess_%s.bin` | `0x2E1F78E` | `0x2E1E18E` | `0x47E88E/0x47DC8E` | `P`: process-cache fájlnév-minta. |
| `cache\` | `0x2E1F8A6` | `0x2E1E2A6` | `0x47EABC/0x47DEBC` | `P`: cache-útvonalrész. |
| `subprocess\` | `0x2E1F88E` | `0x2E1E28E` | `0x47EB5D/0x47DF5D` | `P`: subprocess könyvtárrész. |
| `citizen/release.txt` | `0x2E1F6B8` | `0x2E1E0B8` | `0x101511/0x100911` | `P`: release/build marker olvasása. |
| `release.txt` (átfedő szuffix) | `0x2E1F6C8` | `0x2E1E0C8` | `0x101524/0x100924` | `P`: a teljes `citizen/release.txt` literál `+0x10` pontján kezdődő, null-terminált szuffix; a kód második 16 bájtos másolása. |
| `data/server-cache-priv%s` | `0x2E1F714` | `0x2E1E114` | — | `P` literal, `U` consumer; validált közvetlen xref nem adódott. |
| `data/server-cache-priv%s/` | `0x2E1F8F6` | `0x2E1E2F6` | — | `P` literal, `U` consumer; slash-változat. |
| `data\cache\crashometry` | `0x2E1F672` | `0x2E1E072` | `0x48C72E/0x48BB2E` | `P`: első példány, közvetlen teljes-literal xref. |
| `data\cache\crashometry` | `0x2E48F28` | `0x2E47928` | `0x2AA2863/0x2AA1C63`, `0x2AA2ABF/0x2AA1EBF` | `P`: két crash-report writer xref. |
| `ab` | `0x2E21BE8` | `0x2E205E8` | `0x2AA2896/0x2AA1C96`, `0x2AA2AE8/0x2AA1EE8` | `P`: append-binary mód. |
| `data\cache\error-pickup` | `0x2E1F75E` | `0x2E1E15E` | teljes kezdőxref: `0x539A/0x479A`, `0x5CF1/0x50F1`; átfedő `+0x10`/`+0x1E` komponensxref: `0x537C/0x477C`, `0x538F/0x478F`, `0x5CD3/0x50D3`, `0x5CE6/0x50E6` | `P`: error-pickup írófájl. |
| `wb` | `0x2E1F868` | `0x2E1E268` | `0x53C5/0x47C5`, `0x5D1C/0x511C` | `P`: write-binary mód. |
| `Fatal Error` | `0x2E1F746` | `0x2E1E146` | `0x54FA/0x48FA`, `0x5E51/0x5251` | `P`: hibadiagnosztikai üzenet. |
| `wtsapi32.dll` | `0x2E1F828` | `0x2E1E228` | `0x544F/0x484F`, `0x5DA6/0x51A6` | `P`: dinamikus WTS-modulbetöltés. |
| `WTSQuerySessionInformationW` | `0x2E160A3` | `0x2E14AA3` | `0x5464/0x4864`, `0x5DBB/0x51BB` | `P`: `WTSConnectState` lekérése. |
| `WTSFreeMemory` | `0x2E0B921` | `0x2E0A321` | `0x547B/0x487B`, `0x5DD2/0x51D2` | `P`: WTS-buffer felszabadítása. |
| `CFXGame` | `0x2E133FF` | `0x2E11DFF` | `0x48EF1C/0x48E31C` | `P`: shared-memory név összeállításának komponense. |
| `CFX_%s_%s_SharedData_%s` | `0x2E0E165` | `0x2E0CB65` | `0x48F02F/0x48E42F` | `P`: named mapping névformátuma. |
| `\\?\GLOBALROOT` | `0x2E1F8B4` | `0x2E1E2B4` | — | `P` literal, `U` felhasználási kör. |
| `privcache:/` | `0x2E1C1DA` | `0x2E1ABDA` | — | `P` VFS-scheme literal, `U` validált consumer. |
| `compcache:/` | `0x2E1C1E6` | `0x2E1ABE6` | — | `P` VFS-scheme literal, `U` validált consumer. |
| `compcache_nb:/` | `0x2E1C1F2` | `0x2E1ABF2` | — | `P` VFS-scheme literal, `U` validált consumer. |

A `data/server-cache-priv%s`, `\\?\GLOBALROOT` és a `compcache`/`privcache` scheme-ek jelenléte önmagában nem bizonyítja, hogy a DLL létrehozza, megnyitja vagy továbbítja azokat. A jelentésben ezért a string-presence és a callsite-bizonyíték külön van kezelve.

## 4. `CitizenFX.ini`, `FiveM.app` és a helyi konfiguráció

### 4.1 INI-konfiguráció

A `0x2AA2490–0x2AA2823` funkció a `CitizenFX.ini` literáljat használja, majd a környező kód `GetPrivateProfileStringW`-t hív. A közvetlen callsite:

```text
GetPrivateProfileStringW: RVA=0x2AA2720, RAW=0x2AA1B20
```

A `0x2AA26C7` `GetCommandLineW`, majd a `0x2AA26D7` `StrStrIW` a `PathCL2` literálra alapján választ kulcsot: találat esetén `PathCL2`, egyébként `IVPath`. A `0x2AA2720` `GetPrivateProfileStringW` hat argumentuma sorrendben `Game`, a kiválasztott kulcs, a `PathCL2` default, a kimeneti buffer, `0x200` méret és az előállított INI-útvonal. A kód a kapott értéket string-objektumokba továbbítja.

A `0x2AA3720–0x2AA38DC` funkció ugyanazt az INI-fájlt használja, és két lehetséges integer-lekérést tartalmaz:

| Lekérés | Callsite `RVA` | Callsite `RAW` | Szekció/kulcs |
|---|---:|---:|---|
| `GetPrivateProfileIntW` | `0x2AA3837` | `0x2AA2C37` | `[Game] DefaultBuild` |
| `GetPrivateProfileIntW` | `0x2AA3862` | `0x2AA2C62` | `[Game] ReplaceExecutable` |

A `DefaultBuild` eredménye pozitív érték esetén befejezi ezt a funkciót; a `ReplaceExecutable` hívás csak nem pozitív `DefaultBuild` eredmény után történik.

A `CitizenFX.ini` relatív literálja önmagában nem jelent `%LOCALAPPDATA%`, `AppData`, `ProgramData` vagy temp könyvtárat. A `GetFullPathNameW` callsite (`RVA=0x2AA2D8D`, `RAW=0x2AA218D`) egy közeli runtime-path ágban azt mutatja, hogy a teljes gyökérút futás közben készülhet.

### 4.2 `FiveM.app`

A `FiveM.app` literáljat a `0x2AA2C50–0x2AA325F` funkció használja. A közvetlen ágak:

- `FiveM.app` betöltése: `RVA=0x2AA2F69`, `RAW=0x2AA2369`;
- `CreateDirectoryW`: `RVA=0x2AA2F8C`, `RAW=0x2AA238C`;
- `FiveM.app` második betöltése: `RVA=0x2AA306B`, `RAW=0x2AA246B`;
- attribútumellenőrzés: `RVA=0x2AA3015`, `RAW=0x2AA2415`, illetve `RVA=0x2AA3091`, `RAW=0x2AA2491`.

A `CreateDirectoryW` közvetlenül a `FiveM.app` által előállított útvonalat kapja, ezért a literal itt könyvtárnévként viselkedik. Ez a runtime komponenskörnyezet előkészítésének statikus jele, nem Windows startup- vagy service-persistence bizonyítéka.

### 4.3 Subprocess- és cache-fájlok

A `0x47E760–0x47F668` funkció a következő literálokat használja:

- `CitizenFX_SubProcess_%s.bin`: `RVA=0x2E1F78E`, `RAW=0x2E1E18E`, xref `RVA=0x47E88E`, `RAW=0x47DC8E`;
- `cache\`: `RVA=0x2E1F8A6`, `RAW=0x2E1E2A6`, xref `RVA=0x47EABC`, `RAW=0x47DEBC`;
- `subprocess\`: `RVA=0x2E1F88E`, `RAW=0x2E1E28E`, xref `RVA=0x47EB5D`, `RAW=0x47DF5D`.

Ugyanebben a funkcióban található:

- `CreateDirectoryW`: `0x47EA53/0x47DE53`, `0x47EAF0/0x47DEF0`, `0x47EB98/0x47DF98`;
- `DeleteFileW`: `0x47F248/0x47E648`, `0x47F38B/0x47E78B`;
- `MoveFileW`: `0x47F3B9/0x47E7B9`;
- `CopyFileW`: `0x47F42C/0x47E82C`;
- `GetFileAttributesExW`: `0x47F1C2/0x47E5C2`, `0x47F1F4/0x47E5F4`;
- `GetFileAttributesW`: `0x47E94A/0x47DD4A`, `0x47F44C/0x47E84C`.

A név- és ág-összefüggés alapján a funkció process-cache könyvtárak létrehozását, másolását, mozgatását és törlését végzi. A pontos cache-kulcs és a hívó életciklusa `U`; a rendszerindítás utáni újrakezdés nem bizonyított.

### 4.4 Release/build marker

A `0x1014F0–0x101606` funkció a következő helyi olvasási láncot mutatja:

| Lépés | Callsite vagy xref `RVA` | `RAW` | Confidence |
|---|---:|---:|---|
| `citizen/release.txt` betöltése | `0x101511` | `0x100911` | `P` |
| `citizen/release.txt` `+0x10` részének második 16 bájtos másolása | `0x101524` | `0x100924` | `P` |
| `_wfopen` | `0x101575` | `0x100975` | `P` |
| `fgets` | `0x1015DB` | `0x1009DB` | `P` |
| `fclose` | `0x1015E4` | `0x1009E4` | `P` |
| `atoi` | `0x1015ED` | `0x1009ED` | `P` |

A `0x101524` xref a teljes `citizen/release.txt` UTF-16LE literál `+0x10` pontján kezdődő, önállóan null-terminált `release.txt` szuffixre mutat; nincs külön byte-kópia. A teljes útvonalat a kód `16 + 16 + 8` bájtos részletekből állítja össze.

A `_wfopen` módjára használt `r` literal: `RVA=0x2E1F75A`, `RAW=0x2E1E15A`, xref `RVA=0x10156B`, `RAW=0x10096B`. Ez release/build-jelv olvasása, nem write- vagy persistence-művelet.

### 4.5 Crashometry és error-pickup

Két duplikált, de egymástól külön futó writer-család látható:

| Writer | Path-xref | `_wfopen` | `fclose` | Mód |
|---|---:|---:|---:|---|
| `0x2AA2830–0x2AA29AD` | `0x2AA2863/0x2AA1C63` | `0x2AA28A0/0x2AA1CA0` | `0x2AA2987/0x2AA1D87` | `ab` |
| `0x2AA29B0–0x2AA2C42` | `0x2AA2ABF/0x2AA1EBF` | `0x2AA2AF2/0x2AA1EF2` | `0x2AA2BDA/0x2AA1FDA` | `ab` |

A `data\cache\crashometry` nagyobb példánya mindkét ágban `RVA=0x2E48F28`, `RAW=0x2E47928`; az `ab` mód `RVA=0x2E21BE8`, `RAW=0x2E205E8`. A közvetlen `fwrite`-hívások az első writerben `0x2AA2929`, `0x2AA2940`, `0x2AA295F`, `0x2AA297E`; a másodikban `0x2AA2B78`, `0x2AA2B8F`, `0x2AA2BAE`, `0x2AA2BD1` RVA-n. A relatív `data\cache\...` útvonal gyökérkönyvtára és a tartalom pontos sémája `U`.

Az error-pickup ág a `0x4D20–0x55F3` és `0x5BB0–0x5F17` duplikált függvényekben található:

- path-összeállítás: `0x537C/0x477C`, `0x538F/0x478F`, `0x539A/0x479A`, illetve `0x5CD3/0x50D3`, `0x5CE6/0x50E6`, `0x5CF1/0x50F1`;
- `wb` xref: `0x53C5/0x47C5`, `0x5D1C/0x511C`;
- `_wfopen`: `0x53CF/0x47CF`, `0x5D26/0x5126`;
- `fclose`: `0x543F/0x483F`, `0x5D96/0x5196`;
- `Fatal Error` xref: `0x54FA/0x48FA`, `0x5E51/0x5251`.

Ez lokális crash/error artifactumot bizonyít. A fájlnevek és az error-adatok továbbításáról a statikus rész nem állít semmit.

## 5. VFS és resource-cache

A specimen a `vfs-core.dll`, `citizen-resources-client.dll` és `citizen-resources-core.dll` importált API-kon keresztül erős VFS/resource-cache felületet mutat. A következő callsite-ok közvetlenül olvashatók:

| Importált művelet | Callsite `RVA` | `RAW` | Confidence |
|---|---:|---:|---|
| `vfs::Stream::GetLength` | `0x8C5E5` | `0x8B9E5` | `P` |
| `vfs::Stream::Seek` | `0x8C65E` | `0x8BA5E` | `P` |
| `vfs::Stream::Read` | `0x8C671` | `0x8BA71` | `P` |
| `vfs::GetDevice` | `0x91AD0` | `0x90ED0` | `P` |
| `vfs::Mount` | `0x91CB8` | `0x910B8` | `P` |
| `vfs::OpenRead` | `0xC223C` | `0xC163C` | `P` |
| `RcdBulkStream::OpenFile` | `0x7AA314` | `0x7A9714` | `P` |
| `RcdStream::OpenFile` | `0x7BAD58` | `0x7BA158` | `P` |
| `RcdStream::Read` | `0x7BB3CF` | `0x7BA7CF` | `P` |
| `ResourceCache` konstruktor | `0x84909A` | `0x84849A` | `P` |
| `ResourceCache::AddEntry` | `0x7B51DF` | `0x7B45DF` | `P` |
| `CachedResourceMounter` konstruktor | `0x848CED` | `0x8480ED` | `P` |
| `RagePackfile` konstruktor | `0x84CF64` | `0x84C364` | `P` |
| `RagePackfile::OpenArchive` | `0x84D51C` | `0x84C91C` | `P` |
| `vfs::Mount` resource-cache ág | `0x848984` | `0x847D84` | `P` |
| `vfs::GetDevice` resource-cache ág | `0x848D95` | `0x848195` | `P` |

A `privcache:/`, `compcache:/` és `compcache_nb:/` ASCII literálok jelen vannak a `.rdata` részben, de a validált közvetlen kódxref-vizsgálat nem adott egyértelmű fogyasztót számukra. A scheme-ek jelenléte `P`, a tényleges mount célpontja `U`.

A VFS-hívások erős bizonyítékai a resource- és packfile-olvasási képességet, nem a Windows-user profilhoz vagy service-hoz való perzisztenciát. A tényleges mount-útvonal, a gyökérkönyvtár és a hívó komponens futásidőben nem látható.

## 6. Named shared memory és IPC-jel

A `0x48EEB0–0x48F1D5` funkció a következő literálokat használja:

- `CFXGame`: `RVA=0x2E133FF`, `RAW=0x2E11DFF`, xref `RVA=0x48EF1C`, `RAW=0x48E31C`;
- `CFX_%s_%s_SharedData_%s`: `RVA=0x2E0E165`, `RAW=0x2E0CB65`, xref `RVA=0x48F02F`, `RAW=0x48E42F`.

A `CreateFileMappingW` callsite `RVA=0x48F0A6`, `RAW=0x48E4A6`. A közvetlen argumentumként látható értékek:

| Paraméter | Statikus érték |
|---|---|
| `hFile` | `INVALID_HANDLE_VALUE` (`0xFFFFFFFFFFFFFFFF`) |
| `lpFileAttributes` | `NULL` |
| `flProtect` | `PAGE_READWRITE` (`4`) |
| `dwMaximumSizeHigh` | `0` |
| `dwMaximumSizeLow` | `0x3058` |
| `lpName` | a `CFX_%s_%s_SharedData_%s` formátumból felépített pointer |

Ez tehát nem egy egyszerű, azonnal bezárt anonim mapping: a hívás named shared-memory objektumot kér. A `MapViewOfFile` callsite `RVA=0x48F16F`, `RAW=0x48E56F`; a látható access-maszk `0xF001F`, az offset `0`, a méret `0x3058`.

A destruktor `RVA=0x48EE7D`, `RAW=0x48E27D` meghívja az `UnmapViewOfFile`-ot, majd `RVA=0x48EE93`, `RAW=0x48E293` környezetében a mapping handle-t lezárja. A finding magas konfidenciájú shared-memory/IPC-képesség, de nem bizonyít disk persistence-t, hálózati telemetriát vagy service-létrehozást.

## 7. Registry

### 7.1 `RegGetValueW` adatfolyam

Az egyetlen releváns közvetlen registry-olvasási callsite:

```text
RegGetValueW: RVA=0x116618, RAW=0x115A18
Import IAT:   RVA=0x2E4D718, RAW=0x2E4C118
Funkcióhatár: 0x10FEB0–0x11FFF5
```

A hívás hét argumentuma a callsite-on: `RCX=0xFFFFFFFF80000002` (`HKEY_LOCAL_MACHINE`), `RDX=RBP+0xD0` (`lpSubKey`), `R8=RBP+0x1C0` (`lpValue`), `R9D=2` (`RRF_RT_REG_SZ`), `[RSP+0x20]=0` (`pdwType=NULL`), `[RSP+0x28]=RDI` (`pvData`) és `[RSP+0x30]=RBP+0x190` (`pcbData`). Az `RDI` egy közvetlenül korábbi obfuszkált indirect hívás eredménye. A subkey- és value-name pointerek stacken, futás közben összeállított obfuszkált széles karakteres adatot címznek; a konkrét registry útvonal és value neve nem olvasható plaintext stabil sztringként.

### 7.2 Registry-write és Win32 process-memory API-import negative finding

A regular és delay importtáblában nem található:

- `RegCreateKey*`, `RegSetValue*`, `RegSetKeyValue*`, `RegDeleteKey*`, `RegDeleteValue*`;
- `SHSetValue*`;
- `CreateService*`, `OpenSCManager*`, `StartService*`, `ChangeServiceConfig*`, `ControlService*`, `DeleteService*`, `OpenService*`;
- `WriteProcessMemory`, `CreateRemoteThread`.

A fenti negatívum a közvetlen registry-write/service-create és az importált Win32 `WriteProcessMemory`/`CreateRemoteThread` felület hiányára vonatkozik. Nem jelenti process-memory-képesség hiányát: a 06-os audit közvetlen syscall process-memory útvonalat, a `0xC86420` allokációs és a `0xC870DB` processzhandle-alapú írásargumentumú syscall-helyeket azonosít. A konkrét szolgáltatásnév, handle-eredet, célprocessz és runtime-végrehajtás továbbra is nyitott kérdés.

## 8. Session- és diagnosztikai adatgyűjtés

A `0x4D20–0x55F3` és `0x5BB0–0x5F17` duplikált hiba-/diagnosztikai függvények a `CoreRT.dll` opcionális exportjai között `GetErrorData`, `CoreGetGameWindow` és `CoreIsDebuggerPresent` opcionális export-hívásokat is végeznek. A filesystem/telemetry szempontból fontos WTS-ág statikusan egyértelmű:

| Lépés | Callsite `RVA` | `RAW` | Statikus adat |
|---|---:|---:|---|
| `LoadLibraryW(wtsapi32.dll)` | `0x5456` | `0x4856` | `wtsapi32.dll`, `RVA=0x2E1F828`, `RAW=0x2E1E228` |
| `GetProcAddress(WTSQuerySessionInformationW)` | `0x5475` | `0x4875` | név-string `RVA=0x2E160A3`, `RAW=0x2E14AA3` |
| `GetProcAddress(WTSFreeMemory)` | `0x5485` | `0x4885` | név-string `RVA=0x2E0B921`, `RAW=0x2E0A321` |
| WTS query | `0x54AA` | `0x48AA` | `hServer=0`, `SessionId=0xFFFFFFFF`, `WTSInfoClass=8` (`WTSConnectState`) |
| WTS-memory free | `0x54B8` | `0x48B8` | a WTS-kérés által kiosztott buffer felszabadítása |
| Duplikált WTS query | `0x5E01` | `0x5201` | ugyanaz a `WTSConnectState` lekérés |
| Duplikált WTS-memory free | `0x5E0F` | `0x520F` | ugyanaz a buffer-életciklus |

Ez session-kapcsolat állapotjel (`WTSConnectState`), amely diagnosztikai fingerprint-elem lehet. A vizsgált WTS-részben nincs hálózati kimeneti művelet vagy végpont, ezért ebből telemetry-küldés nem következik.

## 9. Fingerprint- és telemetry-jelöltek

### 9.1 Adapter-, eszköz- és rendszeradatok

| API | Callsite `RVA` | Callsite `RAW` | Funkcióhatár | Statikus értelmezés | Confidence |
|---|---:|---:|---|---|---|
| `GetAdaptersInfo` | `0x1F8C3C0` | `0x1F8B7C0` | `0x1F8BF10–0x1F8C81A` | Hálózati adapter-információ lekérése. | `P` képesség |
| `GetAdaptersInfo` | `0x1F8C6D5` | `0x1F8BAD5` | `0x1F8BF10–0x1F8C81A` | Adapter-buffer második méret/lekérdezési ága. | `P` képesség |
| `CM_Get_Device_Interface_ListW` | `0x1D9E222` | `0x1D9D622` | `0x1D9D370–0x1DA2556` | Eszközszerű interface-lista lekérése. | `P` képesség |
| `CM_Get_Device_Interface_List_SizeW` | `0x1DA11F6` | `0x1DA05F6` | `0x1D9D370–0x1DA2556` | Interface-lista méretlekérdezése. | `P` képesség |
| `GetNativeSystemInfo` | `0x2B16AF6` | `0x2B15EF6` | `0x2B16AB0–0x2B16B4E` | Natív processzor- és platforminformáció lekérése. | `P` képesség |
| `GetProcessAffinityMask` | `0x2B16B14` | `0x2B15F14` | `0x2B16AB0–0x2B16B4E` | Processz-CPU affinitási maszk lekérése. | `P` képesség |
| `GetCurrentProcess` | `0x2B16B01` | `0x2B15F01` | `0x2B16AB0–0x2B16B4E` | Aktuális processzhandle lekérése az affinity-ágban. | `P` képesség |
| `OpenProcess` | `0xD7B86E` | `0xD7AC6E` | `0xD7A400–0xD7CF5B` | Másik processz megnyitási primitíva; a célprocessz `U`. | `P` képesség |
| `QueryFullProcessImageNameW` | `0xD810A8` | `0xD804A8` | `0xD81040–0xD810BB` | Processzimage-path lekérése; a konkrét cél `U`. | `P` képesség |
| `UuidToStringA` | `0x10FBFB` | `0x10EFFB` | `0x10F190–0x10FDB5` | UUID-formázási primitíva; nem önmagában gépazonosító. | `P` képesség |
| `GetEnvironmentVariableW` | `0x2AB6DAB` | `0x2AB61AB` | `0x2AB6D71–0x2AB6EDA` | Környezeti változó lekérése egy szolgáltatás-/diagnosztikai ágban. | `P` képesség |
| `GetCommandLineW` | `0x2AA26C7` | `0x2AA1AC7` | `0x2AA2490–0x2AA2823` | Parancssor/config-feldolgozási környezet. | `P` képesség |
| `GetProcessWindowStation` | `0x2AB6C3E` | `0x2AB603E` | `0x2AB6BD0–0x2AB6D32` | Window-station információ lekérése. | `P` képesség |
| `GetUserObjectInformationW` | `0x2AB6C66` | `0x2AB6066` | `0x2AB6BD0–0x2AB6D32` | User-object/display környezet lekérése. | `P` képesség |

A `0x2B16AB0–0x2B16B4E` ágban a `Kernel32.dll` literal is látszik: `RVA=0x2E30270`, `RAW=0x2E2EC70`, xref `RVA=0x2B16AE1`, `RAW=0x2B15EE1`. A hívott processzor/platform- és adapteradatok fingerprint-jelölők, de a statikus ág nem mutat tárolási vagy kimenő sémát.

### 9.2 Telemetry-következtetés korlátai

A fenti primitívákból nem következik:

- hogy a teljes gépazonosító összeállításra kerül;
- hogy MAC-adapter, processzpath, WTS-kapcsolati állapot vagy CPU-affinitás továbbításra kerül;
- hogy a kimenő csatorna HTTP, WebSocket, Event Log vagy más protokoll lenne;
- hogy a DLL önállóan telemetry-szolgáltató.

A specimenben erős hálózati és fingerprint-képesség van, de a telemetry-cél, az adatminimalizálás, a retention és a hostkomponens-szintű továbbítás `U`.

## 10. OpenSSL Event Log

Az Event Log-ág nem ETW-provider, hanem klasszikus Windows Event Log API:

| Lépés | Callsite/xref `RVA` | `RAW` | Confidence |
|---|---:|---:|---|
| `_OPENSSL_isservice` feloldása | `0x2AB6C0A` | `0x2AB600A` | `P` |
| dinamikus `_OPENSSL_isservice` hívás | `0x2AB6C2C` | `0x2AB602C` | `P` |
| `RegisterEventSourceW` | `0x2AB71E8` | `0x2AB65E8` | `P` |
| `OpenSSL` source-string | `0x2AB71E1` | `0x2AB65E1` | `P`; string `RVA=0x2E490A0`, `RAW=0x2E47AA0` |
| `ReportEventW` | `0x2AB722A` | `0x2AB662A` | `P` |
| `OpenSSL: FATAL` message-string | `0x2AB7241` | `0x2AB6641` | `P`; string `RVA=0x2E490D0`, `RAW=0x2E47AD0` |
| `DeregisterEventSource` | `0x2AB7233` | `0x2AB6633` | `P` |
| `Service-0x` fallback literal | `0x2AB6CFD` | `0x2AB60FD` | `P`; string `RVA=0x2E48F58`, `RAW=0x2E47958` |

A `ReportEventW` környezetében a source `OpenSSL`, a hibaüzenet `OpenSSL: FATAL`; egy közeli `MessageBoxW` fallback is látszik. Ez diagnosztikai/eszközszintű hibajelzés. Az `Event Log` API-k használata nem ETW-telemetry és nem persistence.

## 11. Persistence, AppData, temp, ETW és WMI bounded negative findings

### N-01 – Közvetlen persistence-lánc nem látható

- **Scope:** a specimen statikus import-, delay-import-, string- és közvetlen kódxref-felülete; nem a host gép vagy companion DLL-ek állapota.
- **Kerest minták:** `CreateService`, `OpenSCManager`, `StartService`, `RegSetValue*`, `RegCreateKey*`, `schtasks`, `ITaskScheduler`, `CurrentVersion\Run`, startup-mappa, `CreateRemoteThread`, `WriteProcessMemory`.
- **Eredmény:** nincs importált vagy cleartext közvetlen persistence/API-lánc a DLL-ben; a Win32 `CreateRemoteThread`/`WriteProcessMemory` nevek sem importként, sem plaintext literálként nem találhatók.
- **Process-memory korrekció:** ez a Win32 import-API hiánya, nem általános process-memory capability-negatívum; a 06-os audit közvetlen syscall process-memory útvonalat igazolt.
- **Confidence:** `P` a közvetlen statikus hiányra, `U` a teljes runtime/komponensekészlet viselkedésére.
- **Korlát:** dinamikus resolver, más natív syscall-ok, COM/WMI, child process vagy másik FiveM-komponens nincs kizárva; a natív syscall-ok általános hiánya nem állítható, mert a process-memory útvonal pozitív.

### N-02 – AppData és programozott user-profile literal nem igazolt

A `SHGetKnownFolderPath` import jelen van:

- IAT: `RVA=0x2E4D700`, `RAW=0x2E4C100`.

A standard import-thunk- és közvetlen callsite-scan nem talált referenciát erre az IAT-ra; nincs validált `SHGetKnownFolderPath`-thunk. Az `AppData` ASCII találat nem folderpath:

- `ticket_appdata`: `RAW=0x2E3D988`, `RVA=0x2E3EF88`;
- az `AppData` részstring pontosan `RAW=0x2E3D98F`, `RVA=0x2E3EF8F`.

Ez az OpenSSL/TLS `ticket_appdata` bővítési azonosítója, nem `%APPDATA%` vagy LocalAppData. `LocalAppData`, `RoamingAppData` és `ProgramData` exact string nem található.

### N-03 – Temp-path és startup-false positive

- `GetTempPathW` nincs a közvetlen importtáblában.
- `TEMP` ASCII találatok szövegkörnyezete `attempted`, `template`, illetve beágyazott könyvtár-/protokollstringek; exact temp-útvonal nem látszik.
- `Startup` találatok a `WSAStartup`/`WSAstartup` részstringei:
  - `WSAStartup`: `RAW=0x2E2AE28`, `RVA=0x2E2C428`;
  - `WSAstartup`: `RAW=0x2E2AE18`, `RVA=0x2E2C418`.
- Ezek nem Windows startup-folder persistence-útvonalak.

### N-04 – Task Scheduler, ETW és WMI

- A `TBB failed to initialize task scheduler TLS` szöveg egy TBB/diagnosztikai library-kontextusban található: `RAW=0x2E47688`, `RVA=0x2E48C88`; nincs `ITaskScheduler`/`ITaskService` import.
- Nincs `StartTrace*`, `EnableTrace*`, `ControlTrace*`, `EventWrite*` vagy `TraceEvent*` közvetlen import.
- Az `ETW` ASCII/byte találatok nem standalone ETW provider/API nevek; egy példa `RAW=0x2E3F649`, `RVA=0x2E40C49`, ahol az egyezés beágyazott OpenSSL/PKCS-adatban található.
- A `WMI` byte-előfordulások, például `RAW=0x8FB383`, `RVA=0x8FBF83`, kódkonstansokban vannak; nincs `IWbem*`, `root\cimv2`, `Win32_Process` vagy WMI-query import/string.
- Következtetés: a DLL-ben nem igazolt egyértelmű ETW/WMI-felület. A host- vagy companion-modulviselkedés továbbra is `U`.

### N-05 – Fingerprint ≠ telemetry

A `GetAdaptersInfo`, `CM_Get_Device_Interface*`, `GetNativeSystemInfo`, `GetProcessAffinityMask`, `OpenProcess`, `QueryFullProcessImageNameW` és a `WTSConnectState` lekérése statikusan jelen van. Ebből fingerprint- és diagnosztikai adatgyűjtési képesség következik, de nem igazolt kimenő telemetry, adatbázis-írás vagy ismeretlen C2-cél.

## 12. Korlátok és nyitott kérdések

1. A DLL-t nem futtattuk, ezért nem láttuk a tényleges fájl- és registry-mutációkat.
2. A `CitizenFX.ini` teljes elérési útvonalát, a `data\cache` gyökérkönyvtárát és a `FiveM.app` létrehozási idejét a host futás környezete határozza meg.
3. A registry subkey/value neve a `RegGetValueW` hívás körüli stack- és objektumépítés miatt nem stabil plaintextként látható.
4. A named shared-memory nevet három, futás közben összeállított `%s` mező adja; a konkrét komponensazonosítók és az objektum életciklusa ismeretlen.
5. A `data/server-cache-priv%s` és a `compcache`/`privcache` literálokhoz nem találtunk egyértelmű, közvetlen consumer-xrefet a validált kódban.
6. A fingerprint-mezők összeállítása, retention és továbbítás nem látható; a hálózati végpont a specimen más részében vagy companion DLL-ben lehet.
7. Az Event Log-események runtime-célja és jogosultsági kontextusa nem vizsgálható statikusan.
8. A külső `citizen-*`, `gta-*`, `net-*`, `vfs-core.dll` és `v8` modulok nem részei ennek az artifact-only scope-nak.
9. A dinamikus API-feloldás, API-hashing, titkosított/runtime-generált string és natív syscall teljes kizárása nem lehetséges ebből a bounded statikus képből.
10. A dokumentum nem minősíti a DLL-t malware-nek, legitimnek vagy persistence-modulnak; a statikus jelek önmagukban nem bizonyítják az alkalmazói szándékot.

## 13. BRef-katalógus

A kanonikus forma:

```text
BRef = [RVA:<hex|N/A> | RAW:<hex|N/A> | CONF:<P|L|U> | STATUS:<OBSERVED|INFERRED|NEGATIVE|OPEN>]
```

- **B01 – Artifact:** `SHA-256=91CC0AA006D7315CB042C8FA8DCA6C1E074A307BBA7DCC9EB5509C8A7B81934E`, PE32+ AMD64, entry `RVA=0x2AB2770`, `RAW=0x2AB1B70`; `CONF:P`, `STATUS:OBSERVED`.
- **B02 – INI:** `CitizenFX.ini` `RVA=0x2E48FE8`, `RAW=0x2E479E8`; xref `RVA=0x2AA258B`, `RAW=0x2AA198B`; `CONF:P`, `STATUS:OBSERVED`.
- **B03 – INI-kulcsok:** `GetPrivateProfileStringW` `RVA=0x2AA2720`, `RAW=0x2AA1B20`; `GetPrivateProfileIntW` `RVA=0x2AA3837`, `RAW=0x2AA2C37` és `RVA=0x2AA3862`, `RAW=0x2AA2C62`; `CONF:P`, `STATUS:OBSERVED`.
- **B04 – Subprocess/cache:** `CitizenFX_SubProcess_%s.bin` xref `RVA=0x47E88E`, `RAW=0x47DC8E`; `DeleteFileW` `RVA=0x47F248`, `RAW=0x47E648`; `MoveFileW` `RVA=0x47F3B9`, `RAW=0x47E7B9`; `CONF:P`, `STATUS:OBSERVED`.
- **B05 – Release:** `citizen/release.txt` xref `RVA=0x101511`, `RAW=0x100911`; `_wfopen` `RVA=0x101575`, `RAW=0x100975`; `CONF:P`, `STATUS:OBSERVED`.
- **B06 – Diagnostics:** crashometry xref `RVA=0x2AA2863`, `RAW=0x2AA1C63`; error-pickup xref `RVA=0x539A`, `RAW=0x479A`; `CONF:P`, `STATUS:OBSERVED`.
- **B07 – VFS/resource:** `RcdStream::OpenFile` `RVA=0x7BAD58`, `RAW=0x7BA158`; `RagePackfile::OpenArchive` `RVA=0x84D51C`, `RAW=0x84C91C`; `CONF:P`, `STATUS:OBSERVED`.
- **B08 – Shared memory:** `CFX_%s_%s_SharedData_%s` xref `RVA=0x48F02F`, `RAW=0x48E42F`; `CreateFileMappingW` `RVA=0x48F0A6`, `RAW=0x48E4A6`; `CONF:P`, `STATUS:OBSERVED`.
- **B09 – Registry:** `RegGetValueW` `RVA=0x116618`, `RAW=0x115A18`, `RCX=0xFFFFFFFF80000002` (`HKEY_LOCAL_MACHINE`), `R9D=2` (`RRF_RT_REG_SZ`); `CONF:P`, `STATUS:OBSERVED`.
- **B10 – Fingerprint:** `GetAdaptersInfo` `RVA=0x1F8C3C0`, `RAW=0x1F8B7C0`; `GetNativeSystemInfo` `RVA=0x2B16AF6`, `RAW=0x2B15EF6`; `CONF:P` képesség, `STATUS:INFERRED` telemetry-célra.
- **B11 – Session:** WTS query `RVA=0x54AA`, `RAW=0x48AA`, `SessionId=0xFFFFFFFF`, class `8` (`WTSConnectState`); `CONF:P`, `STATUS:OBSERVED`.
- **B12 – Event Log:** `RegisterEventSourceW` `RVA=0x2AB71E8`, `RAW=0x2AB65E8`; `ReportEventW` `RVA=0x2AB722A`, `RAW=0x2AB662A`; `CONF:P`, `STATUS:OBSERVED`.
- **B13 – Negatív persistence és Win32 import:** a keresett service/task/Run/startup/registry-write API-k és exact stringek nem találhatók; Win32 `WriteProcessMemory`/`CreateRemoteThread` sincs importálva. Ez nem capability-negatívum: a 06-os közvetlen syscall process-memory útvonal pozitív; `CONF:P` a bounded scanre, `STATUS:NEGATIVE` a konkrét import/API-láncra.
- **B14 – False positives:** `ticket_appdata` `RVA=0x2E3EF88`, `RAW=0x2E3D988`; `WSAStartup` `RVA=0x2E2C428`, `RAW=0x2E2AE28`; `TBB failed to initialize task scheduler TLS` `RVA=0x2E48C88`, `RAW=0x2E47688`; `CONF:P`, `STATUS:NEGATIVE`.
- **B15 – Korlát:** nincs runtime config-, hálózat-, registry- vagy companion-DLL-megfigyelés; `CONF:U`, `STATUS:OPEN`.

## 14. Záró értékelés

**Magas statikus konfidencia:** helyi INI-konfiguráció, cache/subprocess-fájlműveletek, release-marker olvasása, crash/error artifactumok, VFS/resource-cache használat, named shared memory és az OpenSSL Event Log-diagnosztika.

**Közepes statikus konfidencia:** adapter-, process-, platform- és session-adatok fingerprint-jegyzete; a pontos adatmezők és a felhasználási cél nem látszik.

**Korroborált process-memory finding:** nincs importált Win32 `WriteProcessMemory`/`CreateRemoteThread`, de a 06-os audit közvetlen syscall process-memory útvonala pozitív statikus képesség; a pontos szolgáltatásnév, cél és runtime-végrehajtás nyitott.

**Korlátozott negatív eredmény:** a specimenben nincs közvetlen cleartext persistence-lánc, registry-write, ETW/WMI, AppData/temp vagy startup-folder bizonyíték. A fájl- és shared-memory-jelenlét önmagában nem persistence; a külső komponensek és a runtime viselkedése továbbra is nyitott kérdés.
