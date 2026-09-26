# `adhesive.dll` – PE layout, biztonsági és bináris szerkezeti dokumentáció

**Vizsgált fájl:** `C:\Users\Admin\Desktop\Dumper - AllInOne\reverse\adhesive.dll`
**Dokumentum nyelve:** magyar
**Vizsgálat típusa:** kizárólag statikus, byte-szintű PE-elemzés

> A DLL-t nem töltöttem be és nem futtattam bináris kódot. Az értékeket a fájl byte-jaiból, `pefile 2024.8.26`, `LIEF 1.0.0`, `Capstone` és `cryptography 50.0.1` statikus parsereivel, illetve független Authenticode-kivonatszámítással ellenőriztem.

## Confidence jelölés

| Jelölés | Jelentés |
|---|---|
| `[confidence: MAGAS]` | Közvetlenül a PE/COFF struktúrából vagy nyers payloadból olvasható, több parserrel egyező érték. |
| `[confidence: KÖZEPES]` | A mezőből erős szerkezeti következtetés vonható le, de a Windows loader/runtime működését nem bizonyítja. |
| `[confidence: ALACSONY]` | A statikus fáldból nem dönthető el egyértelműen; csak korlátozott következtetés adható. |

A teljes halmaz globális `P/L/U` jelölési szerződése az `adhesive-00-index.md` §6 bekezdésében van rögzítve. A fenti három fokozat a `P/L/U` szerződésnek felel meg, és a jelölés soronként, a sor tényleges kijelentésére alkalmazva került ki:

- `MAGAS` → `P` (`proven`): a kijelentés közvetlenül a PE/COFF struktúrából vagy a nyers payloadból olvasható; a közvetlen negatív megfigyelés is ide tartozik.
- `KÖZEPES` → `L` (`likely`): a mezőből erős szerkezeti, szerep- vagy viselkedés-következtetés vonható le.
- `ALACSONY` → `U` (`unknown`): a statikus fáldból nem dönthető el.

A `[confidence: …]` értékek változatlanok maradtak; a jelölés ugyanabban a cellában, közvetlenül utánuk szerepel. Ahol egy sor két, eltérő erősségű kijelentést tartalmaz, és a dokumentum ezt már két külön confidence-tel szétválasztotta, mindkét rész külön jelölést kapott.

## 1. Fájlazonosítás

| Tulajdonság | Érték | Confidence |
|---|---:|---|
| Fájl | `reverse\adhesive.dll` | `[confidence: MAGAS] [P]` |
| Fájlméret | `53 575 264` = `0x3317E60` | `[confidence: MAGAS] [P]` |
| MD5 | `2e24179cc01167e50190fdd3bcf6939a` | `[confidence: MAGAS] [P]` |
| SHA-256 | `91cc0aa006d7315cb042c8fa8dca6c1e074a307bba7dcc9eb5509c8a7b81934e` | `[confidence: MAGAS] [P]` |
| PE típus | PE32+ AMD64 DLL | `[confidence: MAGAS] [P]` |
| Image base | `0x180000000` | `[confidence: MAGAS] [P]` |
| Entry point RVA | `0x2AB2770`; preferált VA `0x182AB2770` | `[confidence: MAGAS] [P]` |
| PE checksum | `0x033207EE`; újraszámítva egyezik | `[confidence: MAGAS] [P]` |
| Rich header | nincs | `[confidence: MAGAS] [P]` |
| Overlay | `0x3315600`–`0x3317E60`, `0x2860` bájt | `[confidence: MAGAS] [P]` |

A `SizeOfCode` értéke pontosan a `.text` nyers mérete, a `SizeOfInitializedData` pedig a `CNT_INITIALIZED_DATA` jelű szekciók nyers méretösszege. A `SizeOfUninitializedData` nulla.

## 2. DOS header

A DOS header a fájl `[0x00, 0x40)` tartományában található.

| DOS mező | Decimális | Hex | Confidence |
|---|---:|---:|---|
| `e_magic` | `23117` | `0x5A4D` (`MZ`) | `[confidence: MAGAS] [P]` |
| `e_cblp` | `120` | `0x78` | `[confidence: MAGAS] [P]` |
| `e_cp` | `1` | `0x01` | `[confidence: MAGAS] [P]` |
| `e_crlc` | `0` | `0x00` | `[confidence: MAGAS] [P]` |
| `e_cparhdr` | `4` | `0x04` | `[confidence: MAGAS] [P]` |
| `e_minalloc` | `0` | `0x00` | `[confidence: MAGAS] [P]` |
| `e_maxalloc` | `0` | `0x00` | `[confidence: MAGAS] [P]` |
| `e_ss` | `0` | `0x00` | `[confidence: MAGAS] [P]` |
| `e_sp` | `0` | `0x00` | `[confidence: MAGAS] [P]` |
| `e_csum` | `0` | `0x00` | `[confidence: MAGAS] [P]` |
| `e_ip` | `0` | `0x00` | `[confidence: MAGAS] [P]` |
| `e_cs` | `0` | `0x00` | `[confidence: MAGAS] [P]` |
| `e_lfarlc` | `64` | `0x40` | `[confidence: MAGAS] [P]` |
| `e_ovno` | `0` | `0x00` | `[confidence: MAGAS] [P]` |
| `e_res[4]` | mind `0` | `00 00 00 00 00 00 00 00` | `[confidence: MAGAS] [P]` |
| `e_oemid` | `0` | `0x00` | `[confidence: MAGAS] [P]` |
| `e_oeminfo` | `0` | `0x00` | `[confidence: MAGAS] [P]` |
| `e_res2[10]` | mind `0` | 20 nulla bájt | `[confidence: MAGAS] [P]` |
| `e_lfanew` | `120` | `0x78` | `[confidence: MAGAS] [P]` |

### DOS stub

A `0x40`–`0x77` közötti 56 bájtos stub:

```text
0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21
54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61
6E 6E 6F 74 20 62 65 20 72 75 6E 20 69 6E 20
44 4F 53 20 6D 6F 64 65 2E 24 00 00
```

A stub SHA-256 értéke `6591a544dfff02dee1e814fa1bb72a220869d24ad6bb6d1e578e029c4e112b12`. A `0x78`–`0x7B` közötti PE signature `50 45 00 00`. A `0x78` előtti részben nincs Rich header. `[confidence: MAGAS] [P]`

## 3. PE signature és COFF/File header

| COFF mező | Érték | Hex | Confidence |
|---|---:|---:|---|
| `Machine` | `34404` | `0x8664` (`IMAGE_FILE_MACHINE_AMD64`) | `[confidence: MAGAS] [P]` |
| `NumberOfSections` | `7` | `0x07` | `[confidence: MAGAS] [P]` |
| `TimeDateStamp` | `1789139178` | `0x6AA418EA` | `[confidence: MAGAS] [P]` |
| `TimeDateStamp` UTC | `2026-09-11 15:06:18 UTC` | – | `[confidence: MAGAS] [P]` |
| `PointerToSymbolTable` | `0` | `0x00` | `[confidence: MAGAS] [P]` |
| `NumberOfSymbols` | `0` | `0x00` | `[confidence: MAGAS] [P]` |
| `SizeOfOptionalHeader` | `240` | `0xF0` | `[confidence: MAGAS] [P]` |
| `Characteristics` | `8226` | `0x2022` | `[confidence: MAGAS] [P]` |

A `0x2022` bitek:

| Bit | Név | Állapot |
|---:|---|---|
| `0x0002` | `IMAGE_FILE_EXECUTABLE_IMAGE` | be |
| `0x0020` | `IMAGE_FILE_LARGE_ADDRESS_AWARE` | be |
| `0x2000` | `IMAGE_FILE_DLL` | be |
| `0x0001` | `RELOCS_STRIPPED` | nincs |
| `0x0004` | `LINE_NUMS_STRIPPED` | nincs |
| `0x0008` | `LOCAL_SYMS_STRIPPED` | nincs |
| `0x0200` | `DEBUG_STRIPPED` | nincs |

A File header a `0x7C` fájl-eltoláson, az Optional header a `0x90` fájl-eltoláson kezdődik. A 7 darab 40 bájtos section header a `0x180` fájl-eltoláson kezdődik és a `0x180 + 7 × 0x28 = 0x298` fájl-eltoláson ér véget; a `SizeOfHeaders` `0x400`-ig tart.

## 4. PE32+ Optional header

| Optional header mező | Érték | Hex | Confidence |
|---|---:|---:|---|
| `Magic` | `523` | `0x020B` (`PE32+`) | `[confidence: MAGAS] [P]` |
| `MajorLinkerVersion` | `14` | `0x0E` | `[confidence: MAGAS] [P]` |
| `MinorLinkerVersion` | `0` | `0x00` | `[confidence: MAGAS] [P]` |
| `SizeOfCode` | `46 061 056` | `0x2BED600` | `[confidence: MAGAS] [P]` |
| `SizeOfInitializedData` | `7 502 336` | `0x727A00` | `[confidence: MAGAS] [P]` |
| `SizeOfUninitializedData` | `0` | `0x00` | `[confidence: MAGAS] [P]` |
| `AddressOfEntryPoint` | `44 771 184` | `0x2AB2770` | `[confidence: MAGAS] [P]` |
| `BaseOfCode` | `4096` | `0x1000` | `[confidence: MAGAS] [P]` |
| `ImageBase` | `6 442 450 944` | `0x180000000` | `[confidence: MAGAS] [P]` |
| `SectionAlignment` | `4096` | `0x1000` | `[confidence: MAGAS] [P]` |
| `FileAlignment` | `512` | `0x200` | `[confidence: MAGAS] [P]` |
| OS major/minor | `6.0` | `0x0006:0x0000` | `[confidence: MAGAS] [P]` |
| Image major/minor | `0.0` | `0x0000:0x0000` | `[confidence: MAGAS] [P]` |
| Subsystem version major/minor | `6.0` | `0x0006:0x0000` | `[confidence: MAGAS] [P]` |
| `Win32VersionValue` / `Reserved1` | `0` | `0x00` | `[confidence: MAGAS] [P]` |
| `SizeOfImage` | `53 600 256` | `0x331E000` | `[confidence: MAGAS] [P]` |
| `SizeOfHeaders` | `1024` | `0x400` | `[confidence: MAGAS] [P]` |
| `CheckSum` | `53 610 478` | `0x033207EE` | `[confidence: MAGAS] [P]` |
| `Subsystem` | `2` | `0x0002` (`WINDOWS_GUI`) | `[confidence: MAGAS] [P]` |
| `DllCharacteristics` | `352` | `0x0160` | `[confidence: MAGAS] [P]` |
| `SizeOfStackReserve` | `1 048 576` | `0x100000` | `[confidence: MAGAS] [P]` |
| `SizeOfStackCommit` | `4096` | `0x1000` | `[confidence: MAGAS] [P]` |
| `SizeOfHeapReserve` | `1 048 576` | `0x100000` | `[confidence: MAGAS] [P]` |
| `SizeOfHeapCommit` | `4096` | `0x1000` | `[confidence: MAGAS] [P]` |
| `LoaderFlags` | `0` | `0x00` | `[confidence: MAGAS] [P]` |
| `NumberOfRvaAndSizes` | `16` | `0x10` | `[confidence: MAGAS] [P]` |

PE32+ esetén nincs külön `BaseOfData` mező. Az `AddressOfEntryPoint` a `.text` szekción belül van, a `BaseOfCode` a `.text` kezdő RVA-jával egyezik.

### `DllCharacteristics = 0x0160`

| Bit | Név | Következmény a fájlban |
|---:|---|---|
| `0x0020` | `HIGH_ENTROPY_VA` | be; 64 bites, nagy VA-tér támogatott |
| `0x0040` | `DYNAMIC_BASE` | be; relokációval újra áthelyezhető |
| `0x0100` | `NX_COMPAT` | be; DEP/NX kompatibilitás kérhető |
| `0x0080` | `FORCE_INTEGRITY` | nincs |
| `0x0200` | `NO_ISOLATION` | nincs |
| `0x0400` | `NO_SEH` | nincs |
| `0x0800` | `NO_BIND` | nincs |
| `0x1000` | `APPCONTAINER` | nincs |
| `0x2000` | `WDM_DRIVER` | nincs |
| `0x4000` | `GUARD_CF` | nincs |
| `0x8000` | `TERMINAL_SERVER_AWARE` | nincs |

## 5. A hét szekció

Az entropy a `SizeOfRawData` bájtjaira, a szekció file alignment paddingjével együtt számítva értendő. A hex entropy hat tizedesjegyen megadva.

| # | Név | RVA | `VirtualSize` | `PointerToRawData` | `SizeOfRawData` | `Characteristics` | Dekódolt flags | Entropy | Confidence |
|---:|---|---:|---:|---:|---:|---:|---|---:|---|
| 0 | `.text` | `0x1000` | `0x2BED4B5` | `0x400` | `0x2BED600` | `0x60000020` | `CODE\|EXECUTE\|READ` | `6.354389118` | `[confidence: MAGAS] [P]` |
| 1 | `.rdata` | `0x2BEF000` | `0x4C9FDC` | `0x2BEDA00` | `0x4CA000` | `0x40000040` | `INITIALIZED_DATA\|READ` | `6.067496729` | `[confidence: MAGAS] [P]` |
| 2 | `.data` | `0x30B9000` | `0x252734` | `0x30B7A00` | `0x24E000` | `0xC0000040` | `INITIALIZED_DATA\|READ\|WRITE` | `3.837675197` | `[confidence: MAGAS] [P]` |
| 3 | `.retplne` | `0x330C000` | `0x5C` | `0x3305A00` | `0x200` | `0x00000000` | nincs explicit `MEM_*` flag | `0.845848782` | `[confidence: MAGAS] [P]` |
| 4 | `.tls` | `0x330D000` | `0x54A1` | `0x3305C00` | `0x5600` | `0xC0000040` | `INITIALIZED_DATA\|READ\|WRITE` | `0.006117656` | `[confidence: MAGAS] [P]` |
| 5 | `.rsrc` | `0x3313000` | `0x698` | `0x330B200` | `0x800` | `0x40000040` | `INITIALIZED_DATA\|READ` | `3.923277863` | `[confidence: MAGAS] [P]` |
| 6 | `.reloc` | `0x3314000` | `0x9AD0` | `0x330BA00` | `0x9C00` | `0x42000040` | `INITIALIZED_DATA\|DISCARDABLE\|READ` | `5.477351016` | `[confidence: MAGAS] [P]` |

A szekciónevek nyers 8 bájtos alakja rendre: `.text\0\0\0`, `.rdata\0\0`, `.data\0\0\0`, `.retplne` pontosan 8 karakter, `.tls\0\0\0\0`, `.rsrc\0\0\0`, `.reloc\0\0`.

### Szekció-ellenőrzések

- Mind a hét szekció RVA-ja `0x1000`-re, raw pointere `0x200`-re igazított; raw size-juk is `0x200`-es többszörös. `[confidence: MAGAS] [P]`
- A nyers szekciótartományok nem fedik egymást. `[confidence: MAGAS] [P]`
- A `.data`, `.tls` és a többi nem executable szekció sem alkot RWX szekciót. `[confidence: MAGAS] [P]`
- A statikus flags alapján egyetlen szekció sem `EXECUTE|READ|WRITE`; a legkisebb jogosultságú executable szekció a `.text` (`RX`). `[confidence: MAGAS] [P]`
- A `.retplne` flags értéke `0x00000000`, ezért nem RWX, és a név ellenére sem tartalmaz végrehajtható x86 utasításfolyamot. `[confidence: MAGAS] [P]`
- A `.data` és `.tls` írható; a `VirtualProtect` import miatt a futásidejű jogosultság-változtatás nem zárható ki. `[confidence: KÖZEPES] [L]`

## 6. RVA–raw mapping és virtuális padding

A szekción belüli, nyers fájlban tárolt részre a mapping:

```text
raw_offset = RVA - VirtualAddress + PointerToRawData
```

A `raw_offset` csak akkor érvényes, ha az RVA a szekció `SizeOfRawData` bájtjába esik. A `VirtualSize` és a következő 4 KiB-ra igazított szekció közti rész loader által biztosított virtuális zero-fill vagy ilyen padding, nem feltétlenül szerepel a fájlban.

| Terület | RVA / VA | Raw pointer | Raw end | `raw-RVA` delta | Virtuális end | Következő igazított RVA | Virtuális tail |
|---|---:|---:|---:|---:|---:|---:|---:|
| Header | `0x0` | `0x0` | `0x400` | `0` | `0x400` | `0x1000` | `0xC00` |
| `.text` | `0x1000` | `0x400` | `0x2BEDA00` | `-0xC00` | `0x2BEE4B5` | `0x2BEF000` | `0xB4B` |
| `.rdata` | `0x2BEF000` | `0x2BEDA00` | `0x30B7A00` | `-0x1600` | `0x30B8FDC` | `0x30B9000` | `0x24` |
| `.data` | `0x30B9000` | `0x30B7A00` | `0x3305A00` | `-0x1600` | `0x330B734` | `0x330C000` | `0x8CC` |
| `.retplne` | `0x330C000` | `0x3305A00` | `0x3305C00` | `-0x6600` | `0x330C05C` | `0x330D000` | `0xFA4` |
| `.tls` | `0x330D000` | `0x3305C00` | `0x330B200` | `-0x7400` | `0x33124A1` | `0x3313000` | `0xB5F` |
| `.rsrc` | `0x3313000` | `0x330B200` | `0x330BA00` | `-0x7E00` | `0x3313698` | `0x3314000` | `0x968` |
| `.reloc` | `0x3314000` | `0x330BA00` | `0x3315600` | `-0x8600` | `0x331DAD0` | `0x331E000` | `0x530` |

Ellenőrző példák:

| Jelenség | RVA | VA | Raw offset | Confidence |
|---|---:|---:|---:|---|
| Entry point | `0x2AB2770` | `0x182AB2770` | `0x2AB1B70` | `[confidence: MAGAS] [P]` |
| Export `CreateComponent` | `0x101F80` | `0x180101F80` | `0x101380` | `[confidence: MAGAS] [P]` |
| Import directory | `0x2E4B9B9` | `0x182E4B9B9` | `0x2E4A3B9` | `[confidence: MAGAS] [P]` |
| Exception directory | `0x2E54E3C` | `0x182E54E3C` | `0x2E5383C` | `[confidence: MAGAS] [P]` |
| Load Config | `0x2C594C0` | `0x182C594C0` | `0x2C57EC0` | `[confidence: MAGAS] [P]` |
| TLS callback table | `0x2E4B8B8` | `0x182E4B8B8` | `0x2E4A2B8` | `[confidence: MAGAS] [P]` |
| Security cookie | `0x30B9140` | `0x1830B9140` | `0x30B7B40` | `[confidence: MAGAS] [P]` |
| IAT start | `0x2E4D208` | `0x182E4D208` | `0x2E4BC08` | `[confidence: MAGAS] [P]` |
| Resource VERSION payload | `0x3313100` | `0x183313100` | `0x330B300` | `[confidence: MAGAS] [P]` |
| Resource MANIFEST payload | `0x3313550` | `0x183313550` | `0x330B750` | `[confidence: MAGAS] [P]` |
| Resource FXCOMPONENT payload | `0x33133E0` | `0x1833133E0` | `0x330B5E0` | `[confidence: MAGAS] [P]` |
| Delay-load IAT | `0x3306F60` | `0x183306F60` | `0x3305960` | `[confidence: MAGAS] [P]` |

A `SizeOfImage` `0x331E000`, vagyis az utolsó `.reloc` szekció 4 KiB-ra igazított virtuális vége. A `SizeOfHeaders` `0x400`, a szekciós nyers tartomány végpontja pedig `0x3315600`, ahol az overlay kezdődik.

## 7. Mind a 16 data directory

A `VirtualAddress` oszlop mindenütt RVA, kivéve a `SECURITY` direktóriumot: annak mezője a PE-specifikáció szerint fizikai file offset. A `Mapped raw` oszlop emiatt a security sornál nem RVA-mapping eredménye.

| Index | Directory | RVA / file offset | Size | Mapped raw / megjegyzés | Confidence |
|---:|---|---:|---:|---|---|
| 0 | `EXPORT` | `0x2E4B96A` | `0x4F` | `0x2E4A36A`, `.rdata` | `[confidence: MAGAS] [P]` |
| 1 | `IMPORT` | `0x2E4B9B9` | `0x35C` | `0x2E4A3B9`, 42 descriptor + null | `[confidence: MAGAS] [P]` |
| 2 | `RESOURCE` | `0x3313000` | `0x698` | `0x330B200`, `.rsrc` | `[confidence: MAGAS] [P]` |
| 3 | `EXCEPTION` | `0x2E54E3C` | `0x1A0070` | `0x2E5383C`, `.rdata` | `[confidence: MAGAS] [P]` |
| 4 | `SECURITY` | `0x3315600` file offset | `0x2860` | `0x3315600`, overlay certificate table | `[confidence: MAGAS] [P]` |
| 5 | `BASERELOC` | `0x3314000` | `0x9AD0` | `0x330BA00`, `.reloc` | `[confidence: MAGAS] [P]` |
| 6 | `DEBUG` | `0x2E4A9A8` | `0x1C` | `0x2E493A8`, egy CodeView rekord | `[confidence: MAGAS] [P]` |
| 7 | `COPYRIGHT` | `0x0` | `0x0` | nincs | `[confidence: MAGAS] [P]` |
| 8 | `GLOBALPTR` | `0x0` | `0x0` | nincs | `[confidence: MAGAS] [P]` |
| 9 | `TLS` | `0x2E0A1D0` | `0x28` | `0x2E08BD0`, `.rdata` | `[confidence: MAGAS] [P]` |
| 10 | `LOAD_CONFIG` | `0x2C594C0` | `0x140` | `0x2C57EC0`, `.rdata` | `[confidence: MAGAS] [P]` |
| 11 | `BOUND_IMPORT` | `0x0` | `0x0` | nincs bound import | `[confidence: MAGAS] [P]` |
| 12 | `IAT` | `0x2E4D208` | `0x14F0` | `0x2E4BC08`, vég `0x2E4E6F8` | `[confidence: MAGAS] [P]` |
| 13 | `DELAY_IMPORT` | `0x2E4B900` | `0x40` | `0x2E4A300`, egy descriptor | `[confidence: MAGAS] [P]` |
| 14 | `COM_DESCRIPTOR` | `0x0` | `0x0` | nincs .NET metadata | `[confidence: MAGAS] [P]` |
| 15 | `RESERVED` | `0x0` | `0x0` | nincs | `[confidence: MAGAS] [P]` |

## 8. Importok

### Import összegzés

| Tulajdonság | Érték | Confidence |
|---|---:|---|
| Standard import descriptor | `42` | `[confidence: MAGAS] [P]` |
| Standard import szimbólum | `628` | `[confidence: MAGAS] [P]` |
| Névvel importált | `604` | `[confidence: MAGAS] [P]` |
| Ordinal importált | `24`, mind a `WS2_32.dll`-ből | `[confidence: MAGAS] [P]` |
| Descriptor `TimeDateStamp` | mindenütt `0` | `[confidence: MAGAS] [P]` |
| Descriptor `ForwarderChain` | mindenütt `0` | `[confidence: MAGAS] [P]` |
| Standard IAT | `0x2E4D208`, méret `0x14F0` | `[confidence: MAGAS] [P]` |
| Bound import | nincs | `[confidence: MAGAS] [P]` |
| Delay import | `1` descriptor, `ole32.dll` | `[confidence: MAGAS] [P]` |
| Regular + delay összesen | `43` modul / `629` szimbólum | `[confidence: MAGAS] [P]` |
| Standard IAT tartalom | `628` slot + `42` null-terminátor | `[confidence: MAGAS] [P]` |
| Delay descriptor tartalom | `1` descriptor + `1` null-terminátor | `[confidence: MAGAS] [P]` |

A 42 standard descriptor teljes listája, a `OriginalFirstThunk` (OFT), `FirstThunk` (FT), DLL-nevek RVA-ja és szimbólumszám:

| DLL | Darab | OFT RVA | FT/IAT RVA | Name RVA |
|---|---:|---:|---:|---:|
| `KERNEL32.dll` | 142 | `0x2E4BD18` | `0x2E4D208` | `0x2E54AEE` |
| `USER32.dll` | 4 | `0x2E4C190` | `0x2E4D680` | `0x2E54AFB` |
| `libuv.dll` | 9 | `0x2E4C1B8` | `0x2E4D6A8` | `0x2E54B06` |
| `SHELL32.dll` | 2 | `0x2E4C208` | `0x2E4D6F8` | `0x2E54B10` |
| `ADVAPI32.dll` | 4 | `0x2E4C220` | `0x2E4D710` | `0x2E54B1C` |
| `v8-9.3.345.16.dll` | 48 | `0x2E4C248` | `0x2E4D738` | `0x2E54B29` |
| `CRYPT32.dll` | 13 | `0x2E4C3D0` | `0x2E4D8C0` | `0x2E54B3B` |
| `WS2_32.dll` | 41 | `0x2E4C440` | `0x2E4D930` | `0x2E54B47` |
| `SHLWAPI.dll` | 1 | `0x2E4C590` | `0x2E4DA80` | `0x2E54B52` |
| `WINMM.dll` | 1 | `0x2E4C5A0` | `0x2E4DA90` | `0x2E54B5E` |
| `citizen-resources-client.dll` | 52 | `0x2E4C5B0` | `0x2E4DAA0` | `0x2E54B68` |
| `rage-device-five.dll` | 1 | `0x2E4C758` | `0x2E4DC48` | `0x2E54B85` |
| `gta-core-five.dll` | 3 | `0x2E4C768` | `0x2E4DC58` | `0x2E54B9A` |
| `rage-nutsnbolts-five.dll` | 2 | `0x2E4C788` | `0x2E4DC78` | `0x2E54BAC` |
| `net.dll` | 3 | `0x2E4C7A0` | `0x2E4DC90` | `0x2E54BC5` |
| `legitimacy.dll` | 1 | `0x2E4C7C0` | `0x2E4DCB0` | `0x2E54BCD` |
| `net-tcp-server.dll` | 1 | `0x2E4C7D0` | `0x2E4DCC0` | `0x2E54BDC` |
| `net-base.dll` | 5 | `0x2E4C7E0` | `0x2E4DCD0` | `0x2E54BEF` |
| `citizen-resources-core.dll` | 5 | `0x2E4C810` | `0x2E4DD00` | `0x2E54BFC` |
| `vfs-core.dll` | 29 | `0x2E4C840` | `0x2E4DD30` | `0x2E54C17` |
| `scripting-gta.dll` | 2 | `0x2E4C930` | `0x2E4DE20` | `0x2E54C24` |
| `rage-scripting-five.dll` | 1 | `0x2E4C948` | `0x2E4DE38` | `0x2E54C36` |
| `MSVCP140.dll` | 110 | `0x2E4C958` | `0x2E4DE48` | `0x2E54C4E` |
| `CONCRT140.dll` | 1 | `0x2E4CCD0` | `0x2E4E1C0` | `0x2E54C5B` |
| `RPCRT4.dll` | 2 | `0x2E4CCE0` | `0x2E4E1D0` | `0x2E54C69` |
| `WINTRUST.dll` | 1 | `0x2E4CCF8` | `0x2E4E1E8` | `0x2E54C74` |
| `CFGMGR32.dll` | 2 | `0x2E4CD08` | `0x2E4E1F8` | `0x2E54C81` |
| `IPHLPAPI.DLL` | 1 | `0x2E4CD20` | `0x2E4E210` | `0x2E54C8E` |
| `VCRUNTIME140.dll` | 22 | `0x2E4CD30` | `0x2E4E220` | `0x2E54C9B` |
| `VCRUNTIME140_1.dll` | 1 | `0x2E4CDE8` | `0x2E4E2D8` | `0x2E54CAC` |
| `api-ms-win-crt-stdio-l1-1-0.dll` | 29 | `0x2E4CDF8` | `0x2E4E2E8` | `0x2E54CBF` |
| `api-ms-win-crt-locale-l1-1-0.dll` | 2 | `0x2E4CEE8` | `0x2E4E3D8` | `0x2E54CDF` |
| `api-ms-win-crt-heap-l1-1-0.dll` | 7 | `0x2E4CF00` | `0x2E4E3F0` | `0x2E54D00` |
| `api-ms-win-crt-runtime-l1-1-0.dll` | 23 | `0x2E4CF40` | `0x2E4E430` | `0x2E54D1F` |
| `api-ms-win-crt-math-l1-1-0.dll` | 15 | `0x2E4D000` | `0x2E4E4F0` | `0x2E54D41` |
| `api-ms-win-crt-time-l1-1-0.dll` | 4 | `0x2E4D080` | `0x2E4E570` | `0x2E54D60` |
| `api-ms-win-crt-string-l1-1-0.dll` | 19 | `0x2E4D0A8` | `0x2E4E598` | `0x2E54D7F` |
| `api-ms-win-crt-convert-l1-1-0.dll` | 9 | `0x2E4D148` | `0x2E4E638` | `0x2E54DA0` |
| `api-ms-win-crt-environment-l1-1-0.dll` | 1 | `0x2E4D198` | `0x2E4E688` | `0x2E54DC2` |
| `api-ms-win-crt-utility-l1-1-0.dll` | 2 | `0x2E4D1A8` | `0x2E4E698` | `0x2E54DE8` |
| `api-ms-win-crt-filesystem-l1-1-0.dll` | 6 | `0x2E4D1C0` | `0x2E4E6B0` | `0x2E54E0A` |
| `bcrypt.dll` | 1 | `0x2E4D1F8` | `0x2E4E6E8` | `0x2E54E2F` |

### Importkészlet funkciócsoportok szerint

A standard nevek közül a következő, rendszer- és viselkedésszempontból jellegzetes elemek láthatók:

| Csoport | Importált elemek példája | Statikus következtetés | Confidence |
|---|---|---|---|
| Process/thread | `CreateToolhelp32Snapshot`, `OpenThread`, `SuspendThread`, `ResumeThread`, `GetThreadContext`, `SetThreadContext`, `QueueUserAPC`, `TerminateThread` | több process- és thread-kezelő képesség importálva van | `[confidence: MAGAS] [P]` |
| Memória/page protection | `VirtualAlloc`, `VirtualFree`, `VirtualProtect`, `VirtualQuery`, `MapViewOfFile` | futásidejű oldaljogosultság-kezelés lehetséges | `[confidence: MAGAS] [P]` |
| Fiber/szinkron | `CreateFiber`, `ConvertFiberToThread`, `CreateWaitableTimerW`, `SleepConditionVariableSRW` | fiber és modern szinkron API-k használata lehetséges | `[confidence: MAGAS] [P]` |
| Hálózat | `WS2_32.dll`, `IPHLPAPI.DLL`, `CFGMGR32.dll`, `libuv.dll` | socket, adapter és eszközszerű hálózati API-k jelen vannak | `[confidence: MAGAS] [P]` |
| Kriptográfia/aláírás | `CRYPT32.dll`, `WINTRUST.dll`, `bcrypt.dll`, `BCryptGenRandom` | tanúsítvány-, trust- és véletlenszerűség-API-k importálva | `[confidence: MAGAS] [P]` |
| V8/Citizen FX | `v8-9.3.345.16.dll`, `citizen-resources-*.dll`, `rage-*.dll`, `gta-*.dll` | natív Citizen FX/FiveM komponens, V8 és resource-rendszer | `[confidence: MAGAS] [L]` |
| C++ runtime | `MSVCP140.dll`, `VCRUNTIME140.dll`, `VCRUNTIME140_1.dll`, `CONCRT140.dll` | MSVC runtime és Concurrency RT függőségek | `[confidence: MAGAS] [P]` |

A 24 ordinal import kizárólag a `WS2_32.dll`-ben található:

```text
116 WSACleanup
111 WSAGetLastError
112 WSASetLastError
115 WSAStartup
151 __WSAFDIsSet
1 accept
2 bind
3 closesocket
4 connect
5 getpeername
6 getsockname
7 getsockopt
8 htonl
9 htons
10 ioctlsocket
13 listen
14 ntohl
15 ntohs
16 recv
18 select
19 send
21 setsockopt
22 shutdown
23 socket
```

### Delay-load import

|mező | Érték |
|---|---:|
| Descriptor file offset | `0x2E4A300` |
| `grAttrs` | `0x1` (RVA-alapú descriptor) |
| `szName` RVA | `0x2E4B960` |
| DLL | `ole32.dll` |
| `phmod` RVA | `0x3306F58` |
| `pIAT` RVA | `0x3306F60` |
| `pINT` RVA | `0x2E4B940` |
| `pBoundIAT` | `0x0` |
| `pUnloadIAT` | `0x0` |
| `dwTimeStamp` | `0x0` |
| Szimbólum | `CoTaskMemFree` |
| IAT VA | `0x183306F60` |
| IAT raw | `0x3305960` |

## 9. Export

Az export directory `RVA=0x2E4B96A`, `Size=0x4F`, raw `0x2E4A36A`.

| Export mező | Érték | Hex |
|---|---:|---:|
| `Characteristics` | `0` | `0x0` |
| `TimeDateStamp` | `0` | `0x0` |
| `MajorVersion` | `0` | `0x0` |
| `MinorVersion` | `0` | `0x0` |
| Modulnév RVA | `adhesive.dll` | `0x2E4B992` |
| `Base` | `1` | `0x1` |
| `NumberOfFunctions` | `1` | `0x1` |
| `NumberOfNames` | `1` | `0x1` |
| `AddressOfFunctions` | `0x2E4B99F` | `0x2E4B99F` |
| `AddressOfNames` | `0x2E4B9A3` | `0x2E4B9A3` |
| `AddressOfNameOrdinals` | `0x2E4B9A7` | `0x2E4B9A7` |

| Ordinal | Név | Export RVA | Preferált VA | Raw offset | Forwarder |
|---:|---|---:|---:|---:|---|
| 1 | `CreateComponent` | `0x101F80` | `0x180101F80` | `0x101380` | nincs |

## 10. Resource-ek

A resource directory `RVA=0x3313000`, `Size=0x698`, raw `0x330B200`, szekció `.rsrc`. A fa `típus / név / nyelv / adat` szerkezetű; mindhárom levél nyelve `1033` (`0x0409`, angol US).

| Típus | Név | Lang ID | Adat RVA | Raw | Méret | CodePage | Payload SHA-256 | Confidence |
|---:|---|---:|---:|---:|---:|---:|---|---|
| `16` `RT_VERSION` | `1` | `1033` | `0x3313100` | `0x330B300` | `736` = `0x2E0` | `0` | `ff5386d98671bbe900a4e9771328cfb7b59b2b6025cbadee0c3f2042c223cda1` | `[confidence: MAGAS] [P]` |
| `24` `RT_MANIFEST` | `2` | `1033` | `0x3313550` | `0x330B750` | `323` = `0x143` | `0` | `6f88bc7cb02ccb2dbc26b5f4ce53e355b331e31bb920b2ba8cbbcd1b5d4cd5a0` | `[confidence: MAGAS] [P]` |
| `115` custom | `FXCOMPONENT` | `1033` | `0x33133E0` | `0x330B5E0` | `361` = `0x169` | `0` | `73c2ab07c65dc8a94faeaeb00f307bfb43773c32c8036f8420e873ed9affa05e` | `[confidence: MAGAS] [P]` |

Mindhárom `IMAGE_RESOURCE_DATA_ENTRY.Reserved` mezője `0`. A resource directory size `0x698`, a raw blokk `0x800`; a különbség file alignment padding.

### Manifest

A `RT_MANIFEST` payload statikus tartalma:

```xml
<?xml version="1.0" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1"
          manifestVersion="1.0">
  <trustInfo>
    <security>
      <requestedPrivileges>
         <requestedExecutionLevel level='asInvoker' uiAccess='false'/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
```

A manifest `asInvoker` és `uiAccess=false` értéket kér. `[confidence: MAGAS] [P]`

### `FXCOMPONENT` custom resource

A 361 bájtos, CRLF-es JSON-szerű tartalom:

```json
{
    "name": "adhesive",
    "version": "0.1.0",
    "dependencies": [
        "fx[2]",
        "rage:device",
        "gta:core",
        "gta:streaming",
        "vfs:core",
        "net",
        "citizen:scripting:core",
        "citizen:resources:gta",
        "citizen:legacy-net:resources",
        "scripting",
        "legitimacy",
        "glue",
        "vendor:openssl_ssl",
        "vendor:imgui"
    ],
    "provides": []
}
```

### VERSIONINFO

| Fixed vagy string mező | Érték | Hex / megjegyzés | Confidence |
|---|---:|---|---|
| `VS_FIXEDFILEINFO.Signature` | `0xFEEF04BD` | `0xFEEF04BD` | `[confidence: MAGAS] [P]` |
| `StrucVersion` | `1.0` | `0x00010000` | `[confidence: MAGAS] [P]` |
| `FileVersionMS` | `1.0` | `0x00010000` | `[confidence: MAGAS] [P]` |
| `FileVersionLS` | `36109` | `0x00008D0D` | `[confidence: MAGAS] [P]` |
| `ProductVersionMS` | `1.0` | `0x00010000` | `[confidence: MAGAS] [P]` |
| `ProductVersionLS` | `36109` | `0x00008D0D` | `[confidence: MAGAS] [P]` |
| `FileFlagsMask` | `0x3F` | `0x0000003F` | `[confidence: MAGAS] [P]` |
| `FileFlags` | `0` | `0x00000000` | `[confidence: MAGAS] [P]` |
| `FileOS` | `0x40004` | `VOS_NT_WINDOWS32` | `[confidence: KÖZEPES] [L]` |
| `FileType` | `1` | standard szerint `VFT_APP` | `[confidence: KÖZEPES] [L]` |
| `FileSubtype` | `0` | `0x00000000` | `[confidence: MAGAS] [P]` |
| `FileDateMS/LS` | `0/0` | `0x00000000/0x00000000` | `[confidence: MAGAS] [P]` |
| String table language | `040904B0` | angol US, Unicode | `[confidence: MAGAS] [P]` |
| `Translation` | `0x0409 0x04B0` | `1033/1200` | `[confidence: MAGAS] [P]` |

String table:

| Kulcs | Érték |
|---|---|
| `CompanyName` | `Cfx.re` |
| `FileDescription` | `adhesive for FiveM` |
| `FileVersion` | `1.0.0.36109` |
| `InternalName` | `adhesive` |
| `LegalCopyright` | `(C) 2015- CitizenFX Collective` |
| `OriginalFilename` | `adhesive.dll` |
| `ProductName` | `CitizenFX` |
| `ProductVersion` | `1.0.0.36109` |

A fixed és a string VERSIONINFO egyaránt `1.0.0.36109` értéket mutat, míg a custom resource `0.1.0`; ez nem bináris konfliktus, de verziómetadási anomália. A `FileType=1` (`VFT_APP`) sem a DLL COFF jelölését követi, ezért ezt nem tekintem megbízható végső azonosításnak.

## 11. TLS és a három TLS callback

### `IMAGE_TLS_DIRECTORY`

| TLS mező | VA | RVA | Raw | Hex / érték | Confidence |
|---|---:|---:|---:|---:|---|
| `StartAddressOfRawData` | `0x18330D000` | `0x330D000` | `0x3305C00` | TLS template kezdete | `[confidence: MAGAS] [P]` |
| `EndAddressOfRawData` | `0x1833124A0` | `0x33124A0` | `0x330B0A0` | `0x54A0` bájt template | `[confidence: MAGAS] [P]` |
| `AddressOfIndex` | `0x1833070EC` | `0x33070EC` | `0x3305AEC` | TLS index | `[confidence: MAGAS] [P]` |
| `AddressOfCallBacks` | `0x182E4B8B8` | `0x2E4B8B8` | `0x2E4A2B8` | callback tábla | `[confidence: MAGAS] [P]` |
| `SizeOfZeroFill` | `0` | – | – | `0x0` | `[confidence: MAGAS] [P]` |
| `Characteristics` | `0x00500000` | – | – | `IMAGE_SCN_ALIGN_16BYTES` | `[confidence: MAGAS] [P]` |

A `.tls` szekció a `0x330D000` RVA-n kezdődik, a template nyers adata `0x54A0` bájt, miközben a szekció `VirtualSize` értéke `0x54A1`. A callback lista négy 64 bites qwordből áll; a negyedik qword null.

### Callbackok

| Sorrend | VA | RVA | Raw | Kezdő bájtok | Statikus megfigyelés | Confidence |
|---:|---:|---:|---:|---|---|---|
| 1 | `0x182AB28D0` | `0x2AB28D0` | `0x2AB1CD0` | `83 FA 02 75 60 48 89 5C 24 08 57 48 83 EC 20 ...` | `cmp edx,2`; szál-attach ág | `[confidence: MAGAS] [P]` a kódra, `[confidence: KÖZEPES] [L]` a célzatos értelmezésre |
| 2 | `0x1800010D0` | `0x10D0` | `0x4D0` | `83 FA 03 0F 84 27 06 00 00 C3 ...` | `cmp edx,3`, majd `ret` | `[confidence: MAGAS] [P]` |
| 3 | `0x182AB2948` | `0x2AB2948` | `0x2AB1D48` | `48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 ...` | `cmp edx,3` egy későbbi ágban | `[confidence: MAGAS] [P]` a kódra, `[confidence: KÖZEPES] [L]` a célzatos értelmezésre |

A callbackok nem az RVA szerint rendezettek a táblában: a tényleges loader-hívási sorrend a fájlban a fenti sorrend. A standard `DLL_THREAD_ATTACH=2` és `DLL_THREAD_DETACH=3` értékekkel az első callback a 2-es, a második és harmadik a 3-as reason ágát vizsgálja.

## 12. Load Config

A load config `RVA=0x2C594C0`, `Size=0x140`, raw `0x2C57EC0`. A következő offszetek a load config kezdetéhez viszonyítottak.

| Offset | Mező | Érték | Confidence |
|---:|---|---:|---|
| `0x00` | `Size` | `0x140` | `[confidence: MAGAS] [P]` |
| `0x04` | `TimeDateStamp` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x08` | `MajorVersion` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x0A` | `MinorVersion` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x0C` | `GlobalFlagsClear` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x10` | `GlobalFlagsSet` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x14` | `CriticalSectionDefaultTimeout` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x18` | `DeCommitFreeBlockThreshold` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x20` | `DeCommitTotalFreeThreshold` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x28` | `LockPrefixTable` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x30` | `MaximumAllocationSize` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x38` | `VirtualMemoryThreshold` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x40` | `ProcessAffinityMask` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x48` | `ProcessHeapFlags` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x4C` | `CSDVersion` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x4E` | `DependentLoadFlags` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x50` | `EditList` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x58` | `SecurityCookie` | `0x1830B9140` | `[confidence: MAGAS] [P]` |
| `0x60` | `SEHandlerTable` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x68` | `SEHandlerCount` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x70` | `GuardCFCheckFunctionPointer` | `0x182E4AA28` | `[confidence: MAGAS] [P]` |
| `0x78` | `GuardCFDispatchFunctionPointer` | `0x182E4AA30` | `[confidence: MAGAS] [P]` |
| `0x80` | `GuardCFFunctionTable` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x88` | `GuardCFFunctionCount` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x90` | `GuardFlags` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x94` | `CodeIntegrityFlags` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x96` | `CodeIntegrityCatalog` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x98` | `CodeIntegrityCatalogOffset` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x9C` | `CodeIntegrityReserved` | `0x0` | `[confidence: MAGAS] [P]` |
| `0xA0` | `GuardAddressTakenIatEntryTable` | `0x0` | `[confidence: MAGAS] [P]` |
| `0xA8` | `GuardAddressTakenIatEntryCount` | `0x0` | `[confidence: MAGAS] [P]` |
| `0xB0` | `GuardLongJumpTargetTable` | `0x0` | `[confidence: MAGAS] [P]` |
| `0xB8` | `GuardLongJumpTargetCount` | `0x0` | `[confidence: MAGAS] [P]` |
| `0xC0` | `DynamicValueRelocTable` | `0x0` | `[confidence: MAGAS] [P]` |
| `0xC8` | `CHPEMetadataPointer` | `0x0` | `[confidence: MAGAS] [P]` |
| `0xD0` | `GuardRFFailureRoutine` | `0x0` | `[confidence: MAGAS] [P]` |
| `0xD8` | `GuardRFFailureRoutineFunctionPointer` | `0x0` | `[confidence: MAGAS] [P]` |
| `0xE0` | `DynamicValueRelocTableOffset` | `0x0` | `[confidence: MAGAS] [P]` |
| `0xE4` | `DynamicValueRelocTableSection` | `0x0` | `[confidence: MAGAS] [P]` |
| `0xE6` | `Reserved2` | `0x0` | `[confidence: MAGAS] [P]` |
| `0xE8` | `GuardRFVerifyStackPointerFunctionPointer` | `0x0` | `[confidence: MAGAS] [P]` |
| `0xF0` | `HotPatchTableOffset` | `0x0` | `[confidence: MAGAS] [P]` |
| `0xF4` | `Reserved3` | `0x0` | `[confidence: MAGAS] [P]` |
| `0xF8` | `EnclaveConfigurationPointer` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x100` | `VolatileMetadataPointer` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x108` | `GuardEHContinuationTable` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x110` | `GuardEHContinuationCount` | `0x0` | `[confidence: MAGAS] [P]` |
| `0x118` | `GuardXFGCheckFunctionPointer` | `0x182E4AA38` | `[confidence: MAGAS] [P]` |
| `0x120` | `GuardXFGDispatchFunctionPointer` | `0x182E4AA40` | `[confidence: MAGAS] [P]` |
| `0x128` | `GuardXFGTableDispatchFunctionPointer` | `0x182E4AA48` | `[confidence: MAGAS] [P]` |
| `0x130` | `CastGuardOsDeterminedFailureMode` | `0x182E4AA50` | `[confidence: MAGAS] [P]` |
| `0x138` | `GuardMemcpyFunctionPointer` | `0x182E4AA58` | `[confidence: MAGAS] [P]` |

A deklarált `0x140` méret a `GuardMemcpyFunctionPointer` mezővel zárul. A későbbi, `UmaFunctionPointers` mezőt nem tartalmazza ez a konkrét load config rekord; a parser ezt nem tekinti a `Size=0x140` részének. `[confidence: KÖZEPES] [L]`

A guard pointer-storage helyei a `.rdata` szekcióban vannak; a tárolt cél-RVA-k:

| Pointermező | Tároló RVA | Tárolt érték | Céltarget RVA |
|---|---:|---:|---:|
| CF check | `0x2E4AA28` | `0x182B1BA30` | `0x2B1BA30` |
| CF dispatch | `0x2E4AA30` | `0x182BEBD50` | `0x2BEBD50` |
| XFG check | `0x2E4AA38` | `0x182B1BA30` | `0x2B1BA30` |
| XFG dispatch | `0x2E4AA40` | `0x182BEBD70` | `0x2BEBD70` |
| XFG table dispatch | `0x2E4AA48` | `0x182BEBD70` | `0x2BEBD70` |
| CastGuard slot | `0x2E4AA50` | `0x0` | nincs |
| GuardMemcpy | `0x2E4AA58` | `0x182BEDED0` | `0x2BEDED0` |

A pointer_storage értékek nem azonosak a `DllCharacteristics` CFG bitjével: a `GuardFlags=0`, a CFG function table/count `0`, és a `DllCharacteristics` nem tartalmaz `0x4000` bitet. A helper pointerek tehát önmagukban nem bizonyítják a CFG engedélyezését.

## 13. Stack cookie

A Load Config `SecurityCookie` mezője egy 64 bites security cookie globális helyét mutatja.

| Tulajdonság | Érték | Confidence |
|---|---:|---|
| `SecurityCookie` VA | `0x1830B9140` | `[confidence: MAGAS] [P]` |
| Cookie RVA | `0x30B9140` | `[confidence: MAGAS] [P]` |
| Cookie raw | `0x30B7B40` | `[confidence: MAGAS] [P]` |
| File-ben tárolt kezdeti 64 bites érték | `0x00002B992DDFA232` | `[confidence: MAGAS] [P]` |
| Little-endian cookie bytes | `32 A2 DF 2D 99 2B 00 00` | `[confidence: MAGAS] [P]` |
| Cookie helyének szekciója | `.data`, `INITIALIZED_DATA\|READ\|WRITE` | `[confidence: MAGAS] [P]` |

A cookie pointer és a stack-cookie konvenció jelenléte erős `/GS`-szerű jel, de a konkrét runtime ellenőrzési útvonal és a processzerő kiterjesztése statikus PE-ből nem bizonyítható [U]. `[confidence: KÖZEPES] [L]`

## 14. Debug directory

A debug directory `RVA=0x2E4A9A8`, `Size=0x1C`, raw `0x2E493A8`; egyetlen `IMAGE_DEBUG_DIRECTORY` rekordot tartalmaz.

| Debug mező | Érték | Hex / megjegyzés | Confidence |
|---|---:|---|---|
| `Characteristics` | `0` | `0x0` | `[confidence: MAGAS] [P]` |
| `TimeDateStamp` | `0x6AA418EA` | megegyezik a COFF timestamppel | `[confidence: MAGAS] [P]` |
| `MajorVersion` | `0` | `0x0` | `[confidence: MAGAS] [P]` |
| `MinorVersion` | `0` | `0x0` | `[confidence: MAGAS] [P]` |
| `Type` | `2` | `IMAGE_DEBUG_TYPE_CODEVIEW` | `[confidence: MAGAS] [P]` |
| `SizeOfData` | `96` | `0x60` | `[confidence: MAGAS] [P]` |
| `AddressOfRawData` | `0x2E4A9C4` | RVA | `[confidence: MAGAS] [P]` |
| `PointerToRawData` | `0x2E493C4` | file offset | `[confidence: MAGAS] [P]` |
| CodeView signature | `RSDS` | `52 53 44 53` | `[confidence: MAGAS] [P]` |
| PDB GUID | `cb927e36-3f3d-8d77-4c4c-44205044422e` | canonical UUID | `[confidence: MAGAS] [P]` |
| PDB age | `1` | `0x00000001` | `[confidence: MAGAS] [P]` |
| PDB path | `C:\gl\builds\cfx-fivem-0\.build-cache\bin\five\release\dbg\adhesive.pdb` | 71 bájtos, nullterminált | `[confidence: MAGAS] [P]` |

A debug rekordban nincs `IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS` (`type=20`) bejegyzés. Ez különösen fontos a CET extended flag ellenőrzésénél.

## 15. Exception / x64 unwind directory

Az exception directory `RVA=0x2E54E3C`, `Size=0x1A0070`, raw `0x2E5383C`. A rekordok `IMAGE_RUNTIME_FUNCTION` szerkezetűek, minden rekord `12` bájt.

| Statisztika | Érték | Confidence |
|---|---:|---|
| `RUNTIME_FUNCTION` rekordok | `142 004` | `[confidence: MAGAS] [P]` |
| `Size / 12` | `142 004`, nincs maradék | `[confidence: MAGAS] [P]` |
| `BeginAddress` minimum | `0x1020` | `[confidence: MAGAS] [P]` |
| `EndAddress` maximum | `0x2BEE4B5` | `[confidence: MAGAS] [P]` |
| Kezdő RVA szerint rendezett | igen | `[confidence: MAGAS] [P]` |
| Duplikált rekord | `0` | `[confidence: MAGAS] [P]` |
| Overlap a szomszédos function range-ek között | `0` | `[confidence: MAGAS] [P]` |
| `UnwindInfoAddress=0` | `0` rekord | `[confidence: MAGAS] [P]` |
| Unwind RVA tartomány | `0x2E0B64C`–`0x30B89E0` | `[confidence: MAGAS] [P]` |
| Egyedi unwind info | `15 533` | `[confidence: MAGAS] [P]` |
| Unwind info szekciója | mind `.rdata` | `[confidence: MAGAS] [P]` |
| `UNWIND_INFO` version | mind `1` | `[confidence: MAGAS] [P]` |
| Hibás version/kódblokk/chain/handler határ | `0` | `[confidence: MAGAS] [P]` |

### Unwind flag-eloszlás

| `UNWIND_INFO` flag | Darab | Értelmezés | Confidence |
|---:|---:|---|---|
| `0` | `137 037` | nincs handler/chain | `[confidence: MAGAS] [P]` |
| `1` | `65` | `EHANDLER` | `[confidence: MAGAS] [P]` |
| `2` | `45` | `UHANDLER` | `[confidence: MAGAS] [P]` |
| `3` | `2 694` | `EHANDLER\|UHANDLER` | `[confidence: MAGAS] [P]` |
| `4` | `2 163` | `CHAININFO` | `[confidence: MAGAS] [P]` |

A `CHAININFO` rekordok száma `2 163`; handler flaget tartalmazó rekordok száma `2 804`. A handler RVA-k `0x2A740C0`–`0x2BEDE20` között vannak, mind a `.text` szekcióban. A kódszámok `0`–`31` között változnak, a teljes bounds-ellenőrzés hibátlan.

Első és utolsó rekordok:

| Index | `BeginAddress` | `EndAddress` | `UnwindInfoAddress` |
|---:|---:|---:|---:|
| 0 | `0x1020` | `0x1057` | `0x2FF7034` |
| 1 | `0x1060` | `0x10BC` | `0x2FF703C` |
| 2 | `0x10E0` | `0x10EF` | `0x2FFAC0C` |
| 142001 | `0x2BED264` | `0x2BED2BF` | `0x2FF52B8` |
| 142002 | `0x2BED320` | `0x2BED36D` | `0x2FFDC60` |
| 142003 | `0x2BEE462` | `0x2BEE4B5` | `0x2E0B64C` |

A nagy exception táblázat a hatalmas, `0x2BED4B5` méretű `.text` kódterület következménye; külön `.pdata` szekció nincs, az `.rdata` tartalmazza a teljes direktóriumot.

## 16. Base relocation

A base relocation directory `RVA=0x3314000`, `Size=0x9AD0`, raw `0x330BA00`, a `.reloc` szekcióban.

| Relocation statisztika | Érték | Confidence |
|---|---:|---|
| Blokkok | `171` | `[confidence: MAGAS] [P]` |
| Bejegyzések összesen | `19 132` | `[confidence: MAGAS] [P]` |
| `IMAGE_REL_BASED_ABSOLUTE` (`type=0`) | `91` | `[confidence: MAGAS] [P]` |
| `IMAGE_REL_BASED_DIR64` (`type=10`) | `19 041` | `[confidence: MAGAS] [P]` |
| `HIGHLOW` (`type=3`) | `0` | `[confidence: MAGAS] [P]` |
| Cél `.rdata` | `16 250` | `[confidence: MAGAS] [P]` |
| Cél `.data` | `2 882` | `[confidence: MAGAS] [P]` |
| Cél a `SizeOfImage` határán kívül | `0` | `[confidence: MAGAS] [P]` |
| Blokk méret minimuma | `0x0C` | `[confidence: MAGAS] [P]` |
| Blokk méret maximuma | `0x408` | `[confidence: MAGAS] [P]` |

| Blokk | Page RVA | `SizeOfBlock` | Entries |
|---:|---:|---:|---:|
| első | `0x2BEF000` | `0x4C` | `34` |
| második | `0x2BF0000` | `0x210` | `260` |
| harmadik | `0x2BF1000` | `0x60` | `44` |
| utolsó | `0x3306000` | `0x7C` | `58` |

A `DIR64` relokációk és a `DYNAMIC_BASE` bit együtt statikailag támogatják az ASLR-t. A tényleges betöltési cím a Windows betöltési és process-mitigation policyjától függ.

## 17. Overlay és Authenticode

### Overlay

| Tulajdonság | Érték | Confidence |
|---|---:|---|
| Legnagyobb raw section end | `0x3315600` | `[confidence: MAGAS] [P]` |
| Overlay kezdete | `0x3315600` | `[confidence: MAGAS] [P]` |
| Overlay mérete | `0x2860` = `10 336` | `[confidence: MAGAS] [P]` |
| Fájl vége | `0x3317E60` | `[confidence: MAGAS] [P]` |
| Overlay+security directory | pontosan a fájl vége | `[confidence: MAGAS] [P]` |
| Overlay tartalma | kizárólag `WIN_CERTIFICATE`/PKCS#7 | `[confidence: MAGAS] [P]` |

A security directory fizikai offsetje `0x3315600`, ezért nem szabad RVA-ként `.reloc` szekcióba mappingelni. A `WIN_CERTIFICATE` fejléce:

| `WIN_CERTIFICATE` mező | Érték | Hex |
|---|---:|---:|
| `dwLength` | `10 336` | `0x2860` |
| `wRevision` | `512` | `0x0200` (`WIN_CERT_REVISION_2_0`) |
| `wCertificateType` | `2` | `0x0002` (`WIN_CERT_TYPE_PKCS_SIGNED_DATA`) |
| `bCertificate` hossza | `10 328` | `0x2858` |
| PKCS#7 DER SHA-256 | `a429d46f0dc61647fb3d166b1cef17c150e33ad35aef230b2fbad77f72b60d17` | – |

### Authenticode digest és signer

A PE-specifikus Authenticode hash kiszámításakor a checksum mező (`0xD0`, 4 bájt), a security directory entry (`0x120`, 8 bájt) és a teljes certificate table (`0x3315600`–`0x3317E60`) kimarad. A független számítás és a LIEF eredménye egyezik:

| Authenticode adat | Érték | Confidence |
|---|---:|---|
| Authenticode SHA-256 | `82d63cbaf1ead1cc9e2b9fc871f4778e68c2adc06f0df7144e1892b38a1e575a` | `[confidence: MAGAS] [P]` |
| ContentInfo digest | `82:d6:3c:ba:f1:ea:d1:cc:9e:2b:9f:c8:71:f4:77:8e:68:c2:ad:c0:6f:0d:f7:14:4e:18:92:b3:8a:1e:57:5a` | `[confidence: MAGAS] [P]` |
| Signer digest | `SHA-256` | `[confidence: MAGAS] [P]` |
| Signer encryption | `RSA` | `[confidence: MAGAS] [P]` |
| Signer issuer | `DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1` | `[confidence: MAGAS] [P]` |
| Signer serial | `0x0B0AF411D651006A4562E07B6F086D75` | `[confidence: MAGAS] [P]` |
| Authenticated attributes | `SPC_SP_OPUS_INFO`, `CONTENT_TYPE`, `MS_SPC_STATEMENT_TYPE`, `PKCS9_MESSAGE_DIGEST` | `[confidence: MAGAS] [P]` |
| `CONTENT_TYPE` | `1.3.6.1.4.1.311.2.1.4` (`SPC_INDIRECT_DATA_CONTENT`) | `[confidence: MAGAS] [P]` |
| `MS_SPC_STATEMENT_TYPE` | `1.3.6.1.4.1.311.2.1.21` (`INDIVIDUAL_CODE_SIGNING`) | `[confidence: MAGAS] [P]` |
| `PKCS9_MESSAGE_DIGEST` | `39f1e1a1302a8b0e2761c2318f706728ae8709aece8a9e9c04f5c70aa9d01e5a` | `[confidence: MAGAS] [P]` |
| LIEF `verify_signature()` | `VERIFICATION_FLAGS.OK` | `[confidence: MAGAS] [P]` a kriptográfiai struktúrára |

Beágyazott kódaláíró tanúsítvány:

| Tanúsítvány | Subject | Issuer | Serial | Érvényesség UTC | Signature | Fingerprint SHA-256 |
|---|---|---|---|---|---|---|
| Leaf | `Rockstar Games, Inc.` | DigiCert Code Signing CA | `0xB0AF411D651006A4562E07B6F086D75` | `2026-07-21`–`2027-09-05 23:59:59` | `sha256RSA`, 3072-bit RSA | `65866007102ff66498c1ef739cf23dff71ae3d08da0d9d759b89d1a409c4208f` |
| Intermediate | `DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1` | DigiCert Trusted Root G4 | `0x08AD40B260D29C4C9F5ECDA9BD93AED9` | `2021-04-29`–`2036-04-28 23:59:59` | `sha384RSA`, 4096-bit RSA | `46011ede1c147eb2bc731a539b7c047b7ee93e48b9d3c3ba710ce132bbdfac6b` |

A gyökértanúsítvány nincs a PKCS#7 top-level `certificates` listájában; a root fingerprintjét ez a vizsgálat nem tekinti beágyazott tanúsítványnak.

### Időbélyeg counter-sign

| Tulajdonság | Érték | Confidence |
|---|---:|---|
| `MS_COUNTER_SIGN` | jelen | `[confidence: MAGAS] [P]` |
| Timestamp signer issuer | `DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1` | `[confidence: MAGAS] [P]` |
| Timestamp responder subject | `DigiCert SHA256 RSA4096 Timestamp Responder 2026 1` | `[confidence: MAGAS] [P]` |
| Timestamp algorithm | `SHA-256/RSA` | `[confidence: MAGAS] [P]` |
| Timestamp signing time | `2026-09-11 15:08:46 UTC` | `[confidence: MAGAS] [P]` |
| Timestamp responder serial | `0x084FDC334F7E454EDBC30F8FF9921835` | `[confidence: MAGAS] [P]` |
| Timestamp üzenetdigest | `d7d81197ff17b0ce831921281268db7682ffa37eac08fb99537648c4a41d0a90` | `[confidence: MAGAS] [P]` |
| Timestamp authenticált attribútumok | `5` | `[confidence: MAGAS] [P]` |
| Timestamp chain | responder + time-stamping intermediate + root | `[confidence: MAGAS] [P]` |

A `VERIFICATION_FLAGS.OK` és a két digest-ellenőrzés a PKCS#7 kriptográfiai konzisztenciáját igazolja. Nem helyettesíti a Windows trust provider, revocation/OCSP, tanúsítványlánc-policy vagy időbélyeg-szolgáltató állapotának ellenőrzését [U]. `[confidence: KÖZEPES] [L]`

## 18. ASLR, DEP, CFG, CET és stack-cookie állapot

| Védelem | Statikus állapot | Evidence | Következtetés | Confidence |
|---|---|---|---|---|
| ASLR / `DYNAMIC_BASE` | be | `DllCharacteristics&0x40`; 171 relocation blokk, 19 041 `DIR64` | a kép relokálható | `[confidence: MAGAS] [P]` |
| High-entropy VA | be | `DllCharacteristics&0x20` | 64 bites high-entropy VA támogatott | `[confidence: MAGAS] [P]` |
| DEP / NX | be | `DllCharacteristics&0x100`; nincs RWX | NX kompatibilis deklarálva | `[confidence: MAGAS] [P]` |
| Stack cookie / `/GS` jel | jelen | `SecurityCookie=0x1830B9140`, érték `0x00002B992DDFA232` | cookie-alapú stack védelem van konfigurálva | `[confidence: MAGAS] [P]` a pointerre, `[confidence: KÖZEPES] [L]` a teljes runtime útvonalra |
| CFG | nincs statikusan engedélyezve | `DllCharacteristics&0x4000=0`; `GuardFlags=0`; CFG table/count `0`; nincs CF function table | a PE nem hirdeti CFG támogatását | `[confidence: MAGAS] [P]` |
| XFG | nincs statikusan igazolva | XFG pointer mezők nem nullák, de `GuardFlags=0`, `XFG_ENABLED=false` | pointer mező önmagában nem XFG-engedélyezés | `[confidence: KÖZEPES] [L]` |
| CET shadow stack | nincs pozitív jel | nincs `IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS`; nincs `Ex CET=0x1`; EH continuation table/count `0` | a fájl nem tartalmaz statikus CET-compat jelölést | `[confidence: MAGAS] [P]` a jel hiányára, `[confidence: ALACSONY] [U]` a runtime állapotra |
| `FORCE_INTEGRITY` | nincs | `DllCharacteristics&0x80=0` | kényszerített kódintegritási flag nincs | `[confidence: MAGAS] [P]` |
| `NO_SEH` | nincs | `DllCharacteristics&0x400=0` | nincs tiltó NO_SEH jel | `[confidence: MAGAS] [P]` |
| RWX szekció | nincs | egyik section flags sem `E\|R\|W` | statikusan nincs RWX | `[confidence: MAGAS] [P]` |
| Runtime védelmi policy | nem megállapítható | nem történt loader/process execution | ASLR/CFG/DEP/CET tényleges bekapcsolása OS- és processzfüggő | `[confidence: ALACSONY] [U]` |

A `SecurityCookie`, CFG/XFG helper pointer és a stack cookie együttes jelenléte nem azonosítható automatikusan teljes `/GS` + CFG + CET védelemmel. A CFG-hez a header bit, a guard flagok és a valid guard metaadatok hiánya miatt a dokumentációban **nem állított CFG-t**, a CET-hez pedig **nem állított shadow-stack kompatibilitást**.

### Statikus runtime-RWX jel

A „nincs RWX szekció” kijelentés nem egyenlő azzal, hogy a kód nem kérhet futásidejű RWX memóriát. A `.text` statikus disasszemblálásában két közvetlen, IAT-on keresztüli `KERNEL32!VirtualAlloc` hívás található:

| Call site RVA | Raw | IAT-cél RVA | Statikus argumentumok | Értelmezés | Confidence |
|---:|---:|---:|---|---|---|
| `0x1D3A2` | `0x1C7A2` | `0x2E4D618` | `r8d=0x3000`, `r9d=0x40` | `MEM_COMMIT\|MEM_RESERVE`, `PAGE_EXECUTE_READWRITE` | `[confidence: MAGAS] [P]` |
| `0x1D43E` | `0x1C83E` | `0x2E4D618` | `r8d=0x3000`, `r9d=0x40` | `MEM_COMMIT\|MEM_RESERVE`, `PAGE_EXECUTE_READWRITE` | `[confidence: MAGAS] [P]` |

A hívási cél és az argumentumok statikusan bizonyítottak; azt, hogy a két út minden futáskor végigfut-e, nem állítom [U]. `[confidence: KÖZEPES] [L]`

## 19. `.retplne` jellemző

A `.retplne` a hét szekció közül szándékosan eltérő, `0x00000000` characteristics értékű szekció. A `0x5C` virtuális bájttartalom nem x86 `ret` opcode-sor: négy literál `RetpolineV1\0` marker található benne, amelyek közül az első 16 bájtos fejléc, a három további pedig linker-információs rekordként értelmezhető.

A 92 virtuális bájt nyers hexje:

```text
526574706F6C696E6556310000000000
526574706F6C696E65563100
10000000
03000000
04000000
10000000
526574706F6C696E655631000000000000000000
526574706F6C696E65563100
10000000
03000000
08000000
10000000
```

A `0x200` raw blokk fennmaradó `0x1A4` = 420 bájtja nullával kitöltött. A szekció flags `0`, tehát nincs `MEM_EXECUTE`, `MEM_READ` vagy `MEM_WRITE` bit; a `GuardFlags=0` miatt az `IMAGE_GUARD_RETPOLINE_PRESENT` sincs beállítva. A név alapján retpoline-kompatibilitást nem állítok. `[confidence: MAGAS] [P]` a tartalomra, `[confidence: KÖZEPES] [L]` a producer/linker szemantikájára.

## 20. Anomáliák és korlátok

1. **Nincs RWX szekció, de van statikus runtime-RWX kérés:** a `VirtualAlloc` két call site `0x40` (`PAGE_EXECUTE_READWRITE`) védelmet kér, miközben egyik section sem RWX. `[confidence: MAGAS] [P]` a call site-okra, `[confidence: KÖZEPES] [L]` a tényleges végrehajtási útra.
2. **Három TLS callback:** a callback tábla és mindhárom pointer érvényes; a tényleges callback-függvények viselkedését nem futtattam. `[confidence: MAGAS] [P]` a táblára, `[confidence: KÖZEPES] [L]` a célzatos branch értelmezésére.
3. **Nagy exception directory:** `142 004` unwind rekord, `0x1A0070` bájt, de minden bounds- és overlap-ellenőrzés hibátlan. A méret a nagy `.text` miatt nem önmagában anomália. `[confidence: MAGAS] [P]`
4. **Nincs külön `.pdata`:** az x64 runtime function táblázat `.rdata` részben van; ez PE-ben megengedett elrendezés. `[confidence: MAGAS] [P]`
5. **Különleges unwind flag-kombináció:** `2 694` `UNWIND_INFO` rekord nyers flag értéke `0x3`, vagyis a parser `EHANDLER|UHANDLER` kombinációt lát. Ez szokatlan/specifikus compiler- vagy adat-kombináció; statikusan a bounds-ellenőrzés hibátlan, de a loader/runtime értelmezését nem bizonyítottam [U]. `[confidence: KÖZEPES] [L]`
6. **Guard pointerek konfliktusa:** a Load Config pointer-storage értékei nem nullák, de a CFG/XFG flagok és táblák nullák. Ezt nem szabad CFG-engedélyezésként jelenteni. `[confidence: MAGAS] [P]`
7. **CET extended debug rekord hiánya:** csak `IMAGE_DEBUG_TYPE_CODEVIEW` van; `type=20` nincs. A CET runtime állapotát ezért nem lehet a statikus kompatibilitási bit alapján kijelenteni. `[confidence: MAGAS] [P]`
8. **Verzióeltérések:** a fixed és string VERSIONINFO `1.0.0.36109`, a custom component `0.1.0`; továbbá `FileType=1` egy DLL mellett. `[confidence: MAGAS] [P]` az eltérésekre, `[confidence: KÖZEPES] [L]` a szándékolt jelentésükre.
9. **Timestamp és PDB path nem bizonyítják az eredetet:** a PE timestamp `2026-09-11`, a PDB path egy build cache útvonalát tartalmazza. Ezek lehetnek build metadata-k, de nem tekinthetők független provenance-bizonyítéknak. `[confidence: KÖZEPES] [L]`
10. **Overlay tiszta:** az overlay pontosan a security certificate table, nincs utána külön adat vagy fájlfarok. `[confidence: MAGAS] [P]`
11. **Nincs Rich header:** a `0x40`–`0x78` DOS stub közvetlenül a PE signature előtt ér véget; Rich linker/compiler metadata nem található. `[confidence: MAGAS] [P]`
12. **Importok nem viselkedési bizonyíték:** a process-, thread-, memory-, network- és V8 importok statikus API-hivatkozások; tényleges meghívási sorrend és cél nem állapítható meg fájlfuttatás nélkül. `[confidence: MAGAS] [P]`
13. **Aláírás és trust külön kérdés:** a PKCS#7 strukturális/kriptográfiai ellenőrzése sikeres, de a Windows trust chain, revocation, geofencing és timestamp provider aktuális állapota nem lett futtatva [U]. `[confidence: KÖZEPES] [L]`
14. **Nem történt fuzzing, disasszem-semanticus teljes kódrekonstrukció vagy loader-szimuláció:** a dokumentáció a PE szerkezetet és a statikusan olvashó végrehajtási mintákat fedi le, nem a teljes program viselkedését. `[confidence: MAGAS] [P]`

## 21. Ellenőrzési összeg

A következő állítások statikusan, a fájl módosítása és bináris futtatása nélkül ellenőrizhetők:

- A fájl PE32+ AMD64 DLL, hét szekcióval.
- Az entry point `0x2AB2770`, image base `0x180000000`.
- A `DllCharacteristics=0x0160`: ASLR, high-entropy VA és NX/DEP kompatibilitás be van jelölve.
- Nincs RWX szekció.
- A TLS direktóriumban három callback van, a negyedik táblaelem null.
- A stack cookie pointer `0x1830B9140`, kezdeti értéke `0x00002B992DDFA232`.
- A Load Config `GuardFlags=0`, CFG function table/count `0`; CFG nincs statikusan hirdetve.
- Nincs CET extended debug bejegyzés; CET statikus kompatibilitási jel nincs.
- Az overlay `0x2860` bájt, és a teljes overlay Authenticode `WIN_CERTIFICATE`.
- A resource `VERSIONINFO`, `MANIFEST` és `FXCOMPONENT` payloadok statikusan validálhatók.
- Az Authenticode signer digest SHA-256; az embedded timestamp signer digestje szintén SHA-256.

**Végső confidence:** a fenti szerkezeti, mapping-, header-, directory-, relocation-, resource-, TLS-, debug- és overlayértékek `MAGAS` confidence-úak [P]. Az ASLR/CFG/CET tényleges runtime hatása, a callback-függvények teljes viselkedése és a tanúsítványlánc aktuális trust-állapota statikusan nem bizonyítható [U].

## 22. Jelöléskonformancia – záró blokk

Ez a blokk a `P/L/U` jelöléskonformancia-javítás eredményét rögzíti; nem visz új bizonyítékot, és nem módosít számot, hash-t, RVA-t, finding-szöveget vagy státuszt.

- **Kiinduló állapot:** a dokumentum `318` `[confidence: …]` értéket hordozott; ebből `3` a jelen fejezet skála-leírásának sora, így a finding/confidence értékek száma `315` volt.
- **Új jelölést kapott sorok:** `308` — a `315` finding/confidence érték `307` soron oszlik meg (`11` sor két értéket hordoz), továbbá `1` záró összefoglaló bekezdés.
- **Összesen hozzáadott jelölés:** `322`.
- **`P=proven`:** `295`
- **`L=likely`:** `19`
- **`U=unknown`:** `8`
- **Táblázat-javítás:** a `15.2` unwind-flag táblázat `3` jelű flag-sorában a kód-részlet nem escapelt `|` karaktere `\|`-re cserélődött, így a cellaszám egyezik a fejléccel; ez egyetlen cella-torzítás javítása volt, számérték és státusz nem változott.
- **A jelölés forrása és szabálya:** az `adhesive-00-index.md` §6 (`P=proven` / `L=likely` / `U=unknown`) globális szerződése, annak definícióival, soronként a sor tényleges kijelentésére alkalmazva. A `[confidence: …]` értékek változatlanok maradtak, a jelölés ugyanabban a cellában, közvetlenül utánuk került. Ahol a sor két, eltérő erősségű kijelentést tartalmazott és a dokumentum ezt már két confidence-tel szétválasztotta, mindkét rész külön jelölést kapott; ahol egy bekezdés proven állítást és explicit korlátot egyaránt tartalmazott, a korlát külön `U` jelölést kapott.
- **Nem jelölt tartalom:** a `[confidence: …]` oszlop nélküli táblázatok (delay-load mezők, exportmezők, string table, guard-pointer tárolók, `IMAGE_RUNTIME_FUNCTION` mintarekordok, relokációs blokkok, `WIN_CERTIFICATE`- és tanúsítványtáblázatok) nem finding/confidence sorok, ezért változatlanok maradtak.
