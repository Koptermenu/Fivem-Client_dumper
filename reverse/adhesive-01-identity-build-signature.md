# `adhesive.dll` — specimen identitás, build, provenance és aláírás

> **Vizsgálati határ:** kizárólag statikus elemzés történt. A DLL-t nem futtattam, nem töltöttem be, és nem hívtam meg belőle semmilyen belépési pontot. Az alábbi dokumentum identitási, build- és aláírásbizonyítékokat dokumentál; működési, credential-, exploit- vagy bypass-elemzést nem tartalmaz.
>
> **Elemzés ideje:** 2026-09-25 12:22:21 UTC körül.  
> **Specimen:** `C:\Users\Admin\Desktop\Dumper - AllInOne\reverse\adhesive.dll`

## 1. Bizonyítási szint és jelölés

- **Bizonyított (0,99):** közvetlenül a fájl bájtaiból vagy egy aláírásellenőrző láncból olvasható ki.
- **Magas (0,85–0,98):** több, egymást támogató közvetlen fingerprint alapján valószínű.
- **Közepes (0,65–0,84):** ésszerű következtetés, de nincs egyértelmű, közvetlen azonosító.
- **Alacsony (<0,65):** nyitott lehetőség vagy tiszta hipotézis.
- **Ismeretlen:** a specimenból nem állapítható meg biztonságosan.

A fenti skála a finding-következőkre használatos. A teljes halmaz globális `P/L/U` jelölési szerződése az `adhesive-00-index.md` §6 bekezdésében van rögzítve; a két skála külön réteg, a `P/L/U` nem helyettesíti a numerikus confidence-értéket:

- `P=proven` = a sor kijelentése közvetlenül a megadott fájl-, raw/RVA- vagy PE-mezőértékből olvasható vagy újraszámítható; a közvetlen negatív megfigyelés is ide tartozik.
- `L=likely` = a sor a fenti értékekből erős, de nem közvetlen szerep-, cél-, viselkedés- vagy toolchain-következtetést von le.
- `U=unknown` = a sor maga a megállapíthatatlanságot rögzíti.

Minden finding- és confidence-sor viseli a jelölést; több kijelentést tartalmazó sornál a jelölés a sor fő kijelentésére vonatkozik, kivéve ahol a dokumentum már eleve két eltérő confidence-tel szétválasztotta azokat.

A táblázatokban:

- az **RVA** a várt betöltési címből számított relatív virtuális cím;
- a **raw** a fizikai fájlon belüli null alapú bájteltolás;
- a `Security` data directory értéke PE-specifikáció szerint **nem RVA, hanem raw file offset**;
- minden bináris állításhoz hivatkozott tartomány vagy külön evidence/confidence szerepel.

## 2. Rövid identitási összefoglaló

| Állítás | Minősítés | Bizonyíték / RVA / raw | Confidence |
|---|---|---|---:|
| A specimen PE32+, AMD64, 64 bites Windows DLL. | Bizonyított | `Machine=0x8664` raw `0x7C`; `Magic=0x20B` raw `0x90`; `DLL` flag a raw `0x8E` értékében | 0,99 [P] |
| A belső termékazonosító `CitizenFX` / `adhesive for FiveM`, fájlnév `adhesive.dll`, verzió `1.0.0.36109`. | Bizonyított | Version resource RVA `0x3313100`, raw `[0x330B300,0x330B5E0)`; részletek a 8. fejezetben | 0,99 [P] |
| A specimen az FX komponensrendszer `adhesive` komponense. | Bizonyított | Export `CreateComponent`, RVA `0x101F80`, raw `0x101380`; FXCOMPONENT resource RVA `0x33133E0`, raw `[0x330B5E0,0x330B749)` | 0,99 [P] |
| A PE időbélyege `2026-09-11 15:06:18 UTC`. | Bizonyított | `TimeDateStamp=0x6AA418EA`, COFF raw `0x80`; Debug record raw `0x2E493AC` | 0,99 [P] |
| A kriptografikusan aláírt timestamp `2026-09-11 15:08:46 UTC`. | Bizonyított | PKCS#9 signing time raw `[0x331678C,0x33167A1)` | 0,99 [P] |
| Az Authenticode signer `Rockstar Games, Inc.`, DigiCert kódaláírási lánccal. | Bizonyított | Leaf certificate raw `[0x3315D49,0x3316436)`; PKCS#7 blob raw `[0x3315608,0x3317E60)` | 0,99 [P] |
| A Windows és az LIEF statikus ellenőrzése érvényes aláírást talált. | Bizonyított | `Get-AuthenticodeSignature: Valid`; LIEF: `VERIFICATION_FLAGS.OK`; digest raw `0x3315671` | 0,99 [P] |
| A specimen erősen összhangban van a FiveM/CitizenFX `adhesive` klienskomponensével. | Magas | Termékresource, FXCOMPONENT metadata, PDB build path, FiveM-specifikus importok és a Rockstar-aláírás együttesen; hivatkozott raw tartományok az 5., 7–11. fejezetben | 0,95 [L] |
| Nem állapítható meg, hogy a mintát pontosan ebből a repositoryból vagy a projekt buildéből származtatták. | Ismeretlen | A DLL és a teljes `reverse/` könyvtár gitben untracked; nincs history vagy közvetlen build/source hivatkozás | 0,99 [U] |
| Nem állapítható meg a build pontos LLVM LLD release-száma vagy pontos fordítóverziója. | Ismeretlen | A PE `14.0` linker mezője nem release-verzió; a resource raw `[0x0330B200,0x0330B898)` nem tartalmaz compiler-verziót, és nincs megmaradt build log | 0,99 [U] |

**Azonosítási következtetés:** a specimen kriptográfiailag érvényes, Rockstar Games által aláírt, a belső metadata alapján CitizenFX/FiveM `adhesive` DLL, PE-verzióval `1.0.0.36109`. Ez a mintaazonosítás nagyon erős [L]; az eredeti letöltési hely, a terjesztési lánc és a pontos buildgép azonban nem rekonstruálható egyértelműen [U].

## 3. Abszolút útvonal, fájlméret és fájlrendszer-provenance

| Tulajdonság | Érték | Evidence / raw | Confidence |
|---|---|---|---:|
| Abszolút útvonal | `C:\Users\Admin\Desktop\Dumper - AllInOne\reverse\adhesive.dll` | NTFS path; bináris tartomány `[0x00000000,0x03317E60)` | 0,99 [P] |
| Repository-relatív útvonal | `reverse/adhesive.dll` | Munkafájl; nincs git-tracked állapot | 0,99 [P] |
| Fájlméret | `53 575 264` bájt (`0x03317E60`, `51.093353 MiB`) | Teljes fájltartomány `[0x00000000,0x03317E60)` | 0,99 [P] |
| Fájlrendszer | `C:`, NTFS, `Windows` label, állapot `Healthy/OK` | Nem bináris fájlmetaadat | 0,99 [P] |
| Fájlattribútum | `Archive`; nincs symlink vagy reparse target | Nem bináris fájlmetaadat | 0,99 [P] |
| NTFS létrehozás | `2026-09-24T17:33:13.2773396Z` | Nem bináris fájlmetaadat | 0,99 [P] |
| NTFS last write | `2026-09-13T14:17:25.1851835Z` | Nem bináris fájlmetaadat; nem része a PE Authenticode digestnek | 0,99 [P] |
| NTFS last access – megfigyeléskor | `2026-09-25T12:22:21.1762449Z` | Változó, elemzést is befolyásoló metaadat; nem provenance-bizonyíték | 0,99 [P] |
| Tulajdonos | `DESKTOP-OE0NPNL\Admin` | Nem bináris ACL-metaadat | 0,99 [P] |
| Alternatív adatfolyam | Csak `:$DATA`, `53 575 264` bájt; nincs `Zone.Identifier` | Nem bináris NTFS-metaadat | 0,99 [P] |
| Hard link | Egyetlen hard link: maga a fenti útvonal | Nem bináris NTFS-metaadat | 0,99 [P] |

### Időzítési értelmezés

- Az Authenticode timestamp (`2026-09-11 15:08:46 UTC`) a PE timestamp (`15:06:18 UTC`) után **148 másodperccel** következik; ez konzisztens build–aláírás sorrend [L].
- Az NTFS last write a PE timestamp után körülbelül **47 óra 11 perc 07 másodperccel**, az aláírási timestamp után körülbelül **47 óra 08 perc 39 másodperccel** későbbi. Ez tipikusan másolás/export/post-build filesystem-időváltozás lehet, nem buildidő [U].
- Az NTFS creation time még későbbi, `2026-09-24`; ez összhangban van azzal, hogy a bináris később került a munkakönyvtárba.
- A PE `TimeDateStamp` reprodukálható buildnél felülírható; a jelen specimenben az aláírt timestamp a hitelesebb időbizonyíték.
- Mivel nincs `Zone.Identifier`, az eredeti letöltési URL vagy csomagolási folyamat nem rekonstruálható az NTFS metaadatból.

## 4. Hash- és azonosítóértékek

### 4.1 Teljes fájlhash-ek

| Algoritmus | Érték | Hatóterület | Confidence |
|---|---|---|---:|
| MD5 | `2E24179CC01167E50190FDD3BCF6939A` | `[0x00000000,0x03317E60)` | 0,99 [P] |
| SHA-1 | `AE5627C6AAB786095A816FC43F0E4CE04CEE8829` | `[0x00000000,0x03317E60)` | 0,99 [P] |
| **SHA-256** | **`91CC0AA006D7315CB042C8FA8DCA6C1E074A307BBA7DCC9EB5509C8A7B81934E`** | `[0x00000000,0x03317E60)` | 0,99 [P] |
| SHA-384 | `390527120F0333208DEA51AB2BFF66A50EBD2066A915979C8DD952F13DD117722724606FD8638BFC90F08AB2EAB02FEC` | `[0x00000000,0x03317E60)` | 0,99 [P] |
| SHA-512 | `922F3E50A1BB0F486A3DB21965DC9E3E68DCCB950B7C154305ADF6108A58BE8D8454BB8A256026F81AB42044952D3284337453AEF7260CBEC3E53D2AAB4ADD2D` | `[0x00000000,0x03317E60)` | 0,99 [P] |
| PE import hash / imphash | `e9c2e75385f3ebf50aa4426c22553747` | Import directory RVA `0x2E4B9B9`, raw `[0x2E4A3B9,0x2E4A715)` | 0,99 [P] |
| Git blob object ID | `0cc3ddb865ed1f8b9bf556ce148e01878becb8eb` | Git `blob <size>\0<content>` objektum; **nem azonos a nyers SHA-1 fájlhash-sel** | 0,99 [P] |

### 4.2 Authenticode image hash-ek

Az alábbi értékek az Authenticode szabály szerinti PE image hash-ek: a `Checksum` mező és a `Security` directory/tanúsítványzóna kivételével, de az ezek helyén lévő mezőértékeket is hashingelt formában számolva. A számított image a raw `[0x00000000,0x03315600)`; a kihagyott `Checksum` mező raw `[0xD0,0xD4)`, a `Security` directory entry raw `[0x120,0x128)`, a cert blob pedig raw `[0x03315600,0x03317E60)`.

| Algoritmus | Érték | Confidence |
|---|---|---:|
| MD5 image hash | `3f5ba96a2f5fe226a26fe32a1005a8be` | 0,99 [P] |
| SHA-1 image hash | `4ee1337e876cdc6542c24d4b89e6614db4849b95` | 0,99 [P] |
| **SHA-256 image hash – egyben az aláírt digest** | **`82d63cbaf1ead1cc9e2b9fc871f4778e68c2adc06f0df7144e1892b38a1e575a`** | 0,99 [P] |
| SHA-512 image hash | `ce12d0448bef3eca08ad6cd352cce11466074087e309988c2d6d914405a2c462f613394bd16b75fe305a1796cc8b670a2cb204c18f33b5d3b77737731dc56d69` | 0,99 [P] |

## 5. PE header és végrehajtási identitás

### 5.1 Header-elrendezés

| PE elem | Érték | RVA | Raw | Confidence |
|---|---:|---:|---:|---:|
| DOS signature | `MZ` | Nincs RVA | `0x00000000` | 0,99 [P] |
| `e_lfanew` | `0x78` | Nincs RVA | `0x0000003C` | 0,99 [P] |
| PE signature | `PE\0\0` | Nincs RVA | `0x00000078` | 0,99 [P] |
| COFF machine | `0x8664` / AMD64 | Nincs RVA | `0x0000007C` | 0,99 [P] |
| Szekciók száma | `7` | Nincs RVA | `0x0000007E` | 0,99 [P] |
| PE timestamp | `0x6AA418EA` = `2026-09-11T15:06:18Z` | Nincs RVA | `0x00000080` | 0,99 [P] |
| Optional header size | `0xF0` | Nincs RVA | `0x0000008C` | 0,99 [P] |
| File characteristics | `0x2022`: executable, large-address-aware, DLL | Nincs RVA | `0x0000008E` | 0,99 [P] |
| Optional header | `PE32+`, magic `0x20B` | Nincs RVA | `0x00000090` | 0,99 [P] |
| Linker version mező | `14.0` | Nincs RVA | `0x00000092` | 0,99 [P] |
| Entry point RVA | `0x02AB2770` | `0x02AB2770` | `0x02AB1B70` | 0,99 [P] |
| Entry point VA | `0x182AB2770` | `0x02AB2770` | `0x02AB1B70` | 0,99 [P] |
| ImageBase | `0x180000000` | Nincs RVA | `0x000000A8` | 0,99 [P] |
| Section/File alignment | `0x1000` / `0x200` | Nincs RVA | `0xB0` / `0xB4` | 0,99 [P] |
| OS és subsystem version | `6.0` / `6.0` | Nincs RVA | `0xB8–0xC3` | 0,99 [P] |
| SizeOfImage | `0x0331E000` | Nincs RVA | `0x000000C4` | 0,99 [P] |
| SizeOfHeaders | `0x400` | Nincs RVA | `0x000000CC` | 0,99 [P] |
| PE checksum | `0x033207EE`; újraszámítva is `0x033207EE` | Nincs RVA | `0x000000D0` | 0,99 [P] |
| Subsystem | `2`, Windows GUI | Nincs RVA | `0x000000D4` | 0,99 [P] |
| DllCharacteristics | `0x0160`: high-entropy ASLR, dynamic base, NX/DEP | Nincs RVA | `0x000000D6` | 0,99 [P] |
| Data directory kezdete | 16 bejegyzés | Nincs RVA | `0x00000100` | 0,99 [P] |
| Szekciós fejlécek kezdete | 7 darab | Nincs RVA | `0x00000180` | 0,99 [P] |

Az entrypoint első bájtjai:

```text
48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 49 8B F8
8B DA 48 8B F1 83 FA 01 75 05 E8 67 E6 02 00 ...
```

- **Evidence:** RVA `0x02AB2770`, raw `[0x02AB1B70,0x02AB1BB0)`.
- **Következtetés [L]:** a három argumentumot mentő, `fdwReason == 1` ágat tesztelő stub kompatibilis az MSVC-stílusú `DllMainCRTStartup` belépési mintával.
- **Confidence:** 0,90 [L].
- **Korlát [U]:** a név nem egy közvetlen symbol/export; az entrypoint-szimbólum nincs a PE-ben, ezért ez function-name következtetés, nem bizonyított nevű export.

### 5.2 Exporttábla

| Elem | Érték | RVA | Raw | Confidence |
|---|---|---:|---:|---:|
| Export directory | `IMAGE_EXPORT_DIRECTORY`, 1 funkció, 1 név, ordinal base 1 | `0x02E4B96A` | `0x02E4A36A` | 0,99 [P] |
| Export DLL neve | `adhesive.dll` | `0x02E4B992` | `0x02E4A392` | 0,99 [P] |
| Export név | `CreateComponent` | `0x02E4B9A9` | `0x02E4A3A9` | 0,99 [P] |
| Export célcím | `0x000101F80` | `0x00101F80` | `0x000101380` | 0,99 [P] |
| Export VA | `0x180101F80` | `0x00101F80` | `0x000101380` | 0,99 [P] |

### 5.3 Szekciók

| Szekció | Section header raw | RVA | Virtual size | Raw offset | Raw size | Characteristics | Confidence |
|---|---:|---:|---:|---:|---:|---:|---:|
| `.text` | `0x180` | `0x1000` | `0x02BED4B5` | `0x400` | `0x02BED600` | `0x60000020` | 0,99 [P] |
| `.rdata` | `0x1A8` | `0x02BEF000` | `0x004C9FDC` | `0x02BEDA00` | `0x004CA000` | `0x40000040` | 0,99 [P] |
| `.data` | `0x1D0` | `0x030B9000` | `0x00252734` | `0x030B7A00` | `0x0024E000` | `0xC0000040` | 0,99 [P] |
| `.retplne` | `0x1F8` | `0x0330C000` | `0x5C` | `0x03305A00` | `0x200` | `0x0` | 0,99 [P] |
| `.tls` | `0x220` | `0x0330D000` | `0x54A1` | `0x03305C00` | `0x5600` | `0xC0000040` | 0,99 [P] |
| `.rsrc` | `0x248` | `0x03313000` | `0x698` | `0x0330B200` | `0x800` | `0x40000040` | 0,99 [P] |
| `.reloc` | `0x270` | `0x03314000` | `0x9AD0` | `0x0330BA00` | `0x9C00` | `0x42000040` | 0,99 [P] |

A `.retplne` nyers tartalma három `RetpolineV1` link-info rekordot tartalmaz a raw `[0x03305A00,0x03305A5C)` tartományban. A szekció a végső image-ben `Characteristics=0`, és a raw `0x200` foglalásból csak `0x5C` bájt tartozik hozzá.

### 5.4 Data directories

| Index | Directory | Entry raw | Érték | Méret | Confidence |
|---:|---|---:|---:|---:|---:|
| 0 | Export | `0x100` | RVA `0x02E4B96A` / raw `0x02E4A36A` | `0x4F` | 0,99 [P] |
| 1 | Import | `0x108` | RVA `0x02E4B9B9` / raw `0x02E4A3B9` | `0x35C` | 0,99 [P] |
| 2 | Resource | `0x110` | RVA `0x03313000` / raw `0x0330B200` | `0x698` | 0,99 [P] |
| 3 | Exception / x64 unwind | `0x118` | RVA `0x02E54E3C` / raw `0x02E5383C` | `0x01A0070` | 0,99 [P] |
| 4 | Security | `0x120` | **raw file offset `0x03315600`**; nincs RVA | `0x2860` | 0,99 [P] |
| 5 | Base relocation | `0x128` | RVA `0x03314000` / raw `0x0330BA00` | `0x9AD0` | 0,99 [P] |
| 6 | Debug | `0x130` | RVA `0x02E4A9A8` / raw `0x02E493A8` | `0x1C` | 0,99 [P] |
| 7 | Architecture | `0x138` | `0` | `0` | 0,99 [P] |
| 8 | Global pointer | `0x140` | `0` | `0` | 0,99 [P] |
| 9 | TLS | `0x148` | RVA `0x02E0A1D0` / raw `0x02E08BD0` | `0x28` | 0,99 [P] |
| 10 | Load Config | `0x150` | RVA `0x02C594C0` / raw `0x02C57EC0` | `0x140` | 0,99 [P] |
| 11 | Bound import | `0x158` | `0` | `0` | 0,99 [P] |
| 12 | IAT | `0x160` | RVA `0x02E4D208` / raw `0x02E4BC08` | `0x14F0` | 0,99 [P] |
| 13 | Delay import | `0x168` | RVA `0x02E4B900` / raw `0x02E4A300` | `0x40` | 0,99 [P] |
| 14 | CLR/.NET | `0x170` | `0` | `0` | 0,99 [P] |
| 15 | Reserved | `0x178` | `0` | `0` | 0,99 [P] |

A `CLR` directory hiánya és a natív x64 unwind directory jelenléte együtt **natív, nem .NET** PE-t bizonyít. Evidence: directory entry raw `0x170`, illetve RVA `0x02E54E3C`, raw `0x02E5383C`; confidence `0,99` [P].

## 6. Debug, PDB és Rich header

### 6.1 CodeView / PDB

| Elem | Érték | RVA | Raw | Confidence |
|---|---|---:|---:|---:|
| Debug directory | Type `2`, `IMAGE_DEBUG_TYPE_CODEVIEW`; timestamp `0x6AA418EA`; size `0x60` | `0x02E4A9A8` | `0x02E493A8` | 0,99 [P] |
| CodeView signature | `RSDS` | `0x02E4A9C4` | `0x02E493C4` | 0,99 [P] |
| PDB GUID | `CB927E36-3F3D-8D77-4C4C-44205044422E` | `0x02E4A9C8` | `0x02E493C8` | 0,99 [P] |
| PDB age | `1` | `0x02E4A9D8` | `0x02E493D8` | 0,99 [P] |
| PDB path | `C:\gl\builds\cfx-fivem-0\.build-cache\bin\five\release\dbg\adhesive.pdb` | `0x02E4A9DC` | `0x02E493DC` | 0,99 [P] |
| PDB path nyers tartomány | 71 bájt + NUL | `0x02E4A9DC–0x02E4AA24` | `[0x02E493DC,0x02E49424)` | 0,99 [P] |

A PDB GUID és age együtt adja a build PDBazonosítóját. A beágyazott útvál kimutatja a `cfx-fivem-0`, `five`, `release\dbg` buildkontextust, de nem bizonyítja, hogy a fejlesztőgép vagy maga a PDB továbbra is létezik. A specimenben maga a PDB nincs; a projektben sincs ilyen nevű PDB. Confidence a kontextus közvetlen azonosítására: `0,99` [P]; a tényleges buildgép identitására: ismeretlen [U].

### 6.2 Rich header

- A lehetséges Rich-header terület a DOS stub és PE signature között, raw `[0x40,0x78)`.
- Ebben a tartományban nincs `DanS` és nincs `Rich` marker; a `pefile` `RICH_HEADER` értéke `None`, az LIEF `has_rich_header` értéke `False`.
- **Következtetés [P]:** a Rich header bizonyítottan hiányzik.
- **Confidence:** `0,99` [P].
- Emiatt nincs Rich build-ID, compiler/product tuple vagy az abból közvetlenül olvasható Visual Studio toolchain-verzió.

## 7. LLD, MSVC, CRT és linker feltételes azonosítása

| Állítás | Evidence | RVA / raw | Minősítés | Confidence |
|---|---|---|---|---:|
| A PE linker verziómezője `14.0`. | Optional header | raw `0x92–0x93` | Bizonyított mezőérték | 0,99 [P] |
| A `14.0` érték nem bizonyítja Visual Studio 2015-ot vagy LLD 14.0-t. | Az LLD COFF linker hosszú ideig `14.0`-ot írt a VS2015-kompatibilitás kedvéért; a mező felülírható. | raw `0x92–0x93` | Következtetett korlát | 0,99 [U] |
| A végső linker valószínűleg `lld-link`/LLVM COFF. | `14.0` linker fingerprint, Rich header hiánya, valamint a végső image-ben megmaradt `.retplne` link-info szekció, amely LLVM LLD COFF-viselkedésre utal. | linker raw `0x92`; Rich scan raw `[0x40,0x78)`; `.retplne` RVA `0x0330C000`, raw `[0x03305A00,0x03305C00)` | Magas | 0,85 [L] |
| A pontos LLD major/minor release nem állapítható meg. | Nincs linker build-id, version resource vagy build log. | Teljes PE, de nincs megkülönböztető linker-rekord | Ismeretlen | 0,99 [U] |
| A kód MSVC-kompatibilis x64 ABI-t használ. | `__CxxFrameHandler4`, MSVC mangled importok, security cookie és x64 SEH/unwind. | IAT RVA `0x02E4D208`, raw `0x02E4BC08`; load config RVA `0x02C594C0`, raw `0x02C57EC0`; exception RVA `0x02E54E3C` | Magas | 0,95 [L] |
| A fordító MSVC vagy clang-cl volt. | A fenti ABI/import fingerprint mindkettővel előállítható. | Ugyanazok, mint fent | Következtetett, nem megkülönböztethető | 0,55 [U] |
| Az MSVC runtime és az UCRT fő függőségei dinamikus importokon keresztül érhetők el. | Import descriptor és nevek: `MSVCP140.dll`, `CONCRT140.dll`, `VCRUNTIME140.dll`, `VCRUNTIME140_1.dll`, valamint `api-ms-win-crt-*.dll`. | Import raw `0x02E4A3B9–0x02E4A6FD`; nevek raw `0x02E5364E–0x02E53758` | Bizonyított | 0,99 [P] |
| A CRT pontos Visual Studio runtime buildje nem azonosítható. | A DLL-nevek nem tartalmaznak buildszámot; nincs PDB a CRT-hez. | Importnevek raw `[0x02E5364E,0x02E53759)` | Ismeretlen | 0,99 [U] |

A load config további közvetlen MSVC/LLD-kompatibilitási fingerprintjei:

| Elem | Érték | RVA | Raw | Confidence |
|---|---:|---:|---:|---:|
| `IMAGE_LOAD_CONFIG_DIRECTORY.Size` | `0x140` | `0x02C594C0` | `0x02C57EC0` | 0,99 [P] |
| `SecurityCookie` VA / RVA | `0x1830B9140` / `0x030B9140` | `0x030B9140` | `0x02C57EC0 + 0x58` | 0,99 [P] |
| `GuardCFCheckFunctionPointer` VA / RVA | `0x182E4AA28` / `0x02E4AA28` | `0x02E4AA28` | `0x02C57EC0 + 0x70` | 0,99 [P] |
| `GuardFlags` | `0` | Nincs önálló RVA | `0x02C57F50` | 0,99 [P] |
| `SEHandlerTable` / count | `0` / `0` | Nincs | `0x02C57F20` / `0x02C57F28` | 0,99 [P] |

**Feltételes végkövetkeztetés:** a legvalószínűbb toolchainkombináció egy LLVM/clang-cl vagy MSVC objektumokat MSVC ABI-val előállító, majd LLD-COFF-fel linkelt build, dinamikus MSVC/UCRT függőségekkel. Az LLD használata magas, de nem symbol-proven confidence-ú [L]; az MSVC ABI és a dinamikus CRT viszont közvetlen, magas bizonyosságú [P].

## 8. Verzióresource és manifestek

### 8.1 Resource-ek

| Resource | Type / name / language | RVA | Raw | Size | Confidence |
|---|---|---:|---:|---:|---:|
| Resource directory | — | `0x03313000` | `0x0330B200` | `0x698` | 0,99 [P] |
| Version | type `16`, name `1`, language `1033` (`0x409`) | `0x03313100` | `0x0330B300` | `0x2E0` | 0,99 [P] |
| Standard manifest | type `24` (`RT_MANIFEST`), name `2`, language `1033` | `0x03313550` | `0x0330B750` | `0x143` | 0,99 [P] |
| FX component manifest | type `115`, resource name `FXCOMPONENT`, language `1033` | `0x033133E0` | `0x0330B5E0` | `0x169` | 0,99 [P] |

### 8.2 `VS_VERSION_INFO`

A fixed file info RVA `0x03313328`, raw `0x0330B328`:

- FileVersionMS/LS: `0x00010000 / 0x00008D0D`, tehát `1.0.36109`;
- ProductVersionMS/LS: `0x00010000 / 0x00008D0D`, tehát `1.0.36109`;
- a StringTable által megjelenített verzió `1.0.0.36109`;
- FileOS `0x00040004`, FileType `1` (`VFT_APP`), FileFlags `0`;
- confidence `0,99` [P].

A StringTable minden értéke közvetlenül a version resource-en belül található:

| Kulcs | Érték | Value raw | Value RVA | Confidence |
|---|---|---:|---:|---:|
| `CompanyName` | `Cfx.re` | `0x0330B3B8` | `0x033131B8` | 0,99 [P] |
| `FileDescription` | `adhesive for FiveM` | `0x0330B3F0` | `0x033131F0` | 0,99 [P] |
| `FileVersion` | `1.0.0.36109` | `0x0330B438` | `0x03313238` | 0,99 [P] |
| `InternalName` | `adhesive` | `0x0330B470` | `0x03313270` | 0,99 [P] |
| `LegalCopyright` | `(C) 2015- CitizenFX Collective` | `0x0330B4A8` | `0x033132A8` | 0,99 [P] |
| `OriginalFilename` | `adhesive.dll` | `0x0330B510` | `0x03313310` | 0,99 [P] |
| `ProductName` | `CitizenFX` | `0x0330B54C` | `0x0331334C` | 0,99 [P] |
| `ProductVersion` | `1.0.0.36109` | `0x0330B584` | `0x03313384` | 0,99 [P] |

A vartranslation `0x00040024`: kódlap `1200` (`UTF-16`), nyelv `0x0409` (`en-US`). Evidence raw `0x0330B5BC`, RVA `0x033133BC`; confidence `0,99` [P].

### 8.3 Standard Windows manifest

A teljes payload RVA `0x03313550`, raw `[0x0330B750,0x0330B893)`:

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

**Bizonyított:** a beágyazott standard manifest `asInvoker` végrehajtási szintet kér; RVA `0x03313550`, raw `[0x0330B750,0x0330B893)`, confidence `0,99` [P].

### 8.4 `FXCOMPONENT` manifest

A teljes payload RVA `0x033133E0`, raw `[0x0330B5E0,0x0330B749)`:

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

**Következtetés [L]:** ez az FX komponens saját component manifestje. A `name=adhesive`, a `CreateComponent` export és a `vendor:openssl_ssl` dependency együtt magas confidence-zal azonosítja a specimen szerepét [L]. A manifest `0.1.0` verziója nem azonos a PE `1.0.0.36109` verziójával; a két érték külön semantikai rétegben tárolt, közvetlenül bizonyított adat [P].

## 9. OpenSSL, Botan, V8 és oneTBB azonosítók

| Technológia | Azonosító | Evidence RVA | Evidence raw | Minősítés | Confidence |
|---|---|---:|---:|---|---:|
| OpenSSL | `OpenSSL 1.1.1t  7 Feb 2023` | `0x02C29840` | `0x02C28240` | Bizonyított beágyazott verzióstring | 0,99 [P] |
| OpenSSL | `C:\gl\builds\cfx-fivem-0\vendor\openssl\...` forrásútvonalak, OpenSSL algoritmus- és hibaazonosítók | Több, például `0x02E31B50` | Több, például `0x02E30550` | Magas; statikus integráció | 0,98 [L] |
| Botan | `..\..\fivem-private\components\adhesive\src\botan\botan_all.cpp` | `0x02E102A6` | `0x02E0ECA6` | Bizonyított Botan forrásazonosító | 0,99 [P] |
| Botan | `..\..\fivem-private\components\adhesive\src\botan\botan_all.h` | `0x02E11BFB` | `0x02E105FB` | Bizonyított Botan headerazonosító | 0,99 [P] |
| Botan | `.?AVInvalid_Argument@Botan@@` RTTI | `0x0312AAF0` | `0x031294F0` | Magas; statikus Botan kód/RTTI | 0,98 [L] |
| V8 | Külső modulnév `v8-9.3.345.16.dll`; 48 importált V8 szimbólum | név RVA `0x02E54B29`; descriptor RVA `0x02E4B61D` | név raw `0x02E53529`; descriptor raw `0x02E4A41D` | Bizonyított külső verzióazonosító | 0,99 [P] |
| oneTBB | `oneTBB: VERSION` + `2021.7` | `0x02C08B43`, `0x02C08B54` | `0x02C07543`, `0x02C07554` | Bizonyított beágyazott verzió | 0,99 [P] |
| oneTBB | `oneTBB: INTERFACE VERSION` + `12070` | `0x02C08B5B`, `0x02C08B75` | `0x02C0755B`, `0x02C07575` | Bizonyított interface build | 0,99 [P] |
| oneTBB | `oneTBB: SPECIFICATION VERSION`, `tbbmalloc.dll` string és TBB scheduler hiba | RVA `0x02C08B21`, `0x02E30260`, `0x02E48C88` | raw `0x02C07521`, `0x02E2EC60`, `0x02E47688` | Magas; statikus oneTBB fingerprint | 0,98 [L] |

### Fontos különbségek

- Az **OpenSSL** nincs importált OpenSSL DLL-ként; az importtábla raw `[0x02E4A3B9,0x02E4A715)` nem tartalmaz ilyen modult, míg az `1.1.1t` verzióstring raw `0x02C28240`, RVA `0x02C29840` a DLL-en belül van. Confidence `0,99` [P].
- A **Botan** szintén beágyazott/statikus integrációra utal. A teljes fájlban nincs egyértelmű `Botan <major>.<minor>.<patch>` string; a közvetlen azonosítók raw `0x02E0ECA6`, `0x02E105FB` és `0x031294F0` helyeken vannak, ezért **a pontos Botan verzió ismeretlen** [U]. Confidence a negatív eredményre `0,95` [P].
- A **V8 nem a specimenbe ágyazott V8**: a DLL dinamikusan importálja a pontos `v8-9.3.345.16.dll` modult. Import descriptor raw `0x02E4A41D`, név raw `0x02E53529`; confidence `0,99` [P].
- A `tbbmalloc.dll` egy **string a DLL-ben**, nem a PE importtáblában. Az egyértelmű azonosító a `oneTBB 2021.7` és `12070` metadata; raw `0x02C07543–0x02C0757A`; confidence `0,99` [P].

## 10. Authenticode, signer és timestamp

### 10.1 `WIN_CERTIFICATE` és PKCS#7 konténer

| Elem | Érték | RVA / raw | Confidence |
|---|---|---|---:|
| Security directory entry | `0x120` | raw `0x120` | 0,99 [P] |
| Security directory file pointer | `0x03315600` | **raw only**, nincs RVA | 0,99 [P] |
| Security directory méret | `0x2860` = `10 336` bájt | raw `[0x03315600,0x03317E60)` | 0,99 [P] |
| `dwLength` | `0x2860` | raw `0x03315600` | 0,99 [P] |
| `wRevision` | `0x0200` | raw `0x03315604` | 0,99 [P] |
| `wCertificateType` | `0x0002`, PKCS signed data | raw `0x03315606` | 0,99 [P] |
| PKCS#7 SignedData blob | `0x2858` = `10 328` bájt | raw `[0x03315608,0x03317E60)` | 0,99 [P] |
| `WIN_CERTIFICATE` SHA-256 | `C670620DD04F80C823C66CC831D4481BD32D26E589DFBC3E57CFDC2EA0311951` | raw `[0x03315600,0x03317E60)` | 0,99 [P] |
| PKCS#7 SignedData blob SHA-256 | `A429D46F0DC61647FB3D166B1CEF17C150E33AD35AEF230B2FBAD77F72B60D17` | raw `[0x03315608,0x03317E60)` | 0,99 [P] |

A külső SignedData blokk BER-kompatibilis indefinite-length kódolást tartalmaz; ezért itt pontosan `SignedData blob`, nem szigorúan DER. A fenti tanúsítványláncban szereplő egyes X.509 tanúsítványok DER formátumúak. Evidence raw `[0x03315608,0x03317E60)`; confidence `0,98` [P].

### 10.2 Aláírt digest

| Elem | Érték | Evidence | Confidence |
|---|---|---|---:|
| Digest algoritmus | SHA-256 | Algoritmus-OID TLV raw `0x03315626` | 0,99 [P] |
| Az `SpcIndirectDataContent` által aláírt PE image digest | `82D63CBAF1EAD1CC9E2B9FC871F4778E68C2ADC06F0DF7144E1892B38A1E575A` | 32 bájtos érték raw `[0x03315671,0x03315691)` | 0,99 [P] |
| Függetlenül újraszámított Authenticode SHA-256 | `82D63CBAF1EAD1CC9E2B9FC871F4778E68C2ADC06F0DF7144E1892B38A1E575A` | PE image hash a 4.2 fejezet szerint | 0,99 [P] |
| SignerInfo digest- és titkosítási algoritmusa | `SHA_256/RSA` | PKCS#7 raw `[0x03315608,0x03317E60)` | 0,99 [P] |

Az aláírt digest és az újraszámított image hash byte-ra azonos. A Windows `Get-AuthenticodeSignature` eredménye `Valid`, az LIEF `check()` eredménye `VERIFICATION_FLAGS.OK`; confidence `0,99` [P].

### 10.3 Primer kódaláírási chain

A chain iránya: signer leaftől a bizalmi ankorig.

| Szerep | Subject / issuer | Serial | SHA-1 thumbprint | Validity | Key / cert signature | Raw / RVA | Confidence |
|---|---|---|---|---|---|---|---:|
| Code-signing leaf | Subject: `CN=Rockstar Games, Inc., O=Rockstar Games, Inc., L=New York, ST=New York, C=US`; issuer: DigiCert Code Signing CA | `0B0AF411D651006A4562E07B6F086D75` | `FF0EE06434B1695115A35FB077DE538FD1F66D9C` | `2026-07-21`–`2027-09-05` | RSA-3072; `sha256RSA`; EKU Code Signing | raw `[0x03315D49,0x03316436)`; nincs RVA | 0,99 [P] |
| Code-signing intermediate | `CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1, O=DigiCert, Inc., C=US`; issuer: `CN=DigiCert Trusted Root G4, OU=www.digicert.com, O=DigiCert Inc, C=US` | `08AD40B260D29C4C9F5ECDA9BD93AED9` | `7B0F360B775F76C94A12CA48445AA2D2A875701C` | `2021-04-29`–`2036-04-28` | RSA-4096; `sha384RSA`; CA | raw `[0x03315695,0x03315D49)`; nincs RVA | 0,99 [P] |
| Trust anchor | `CN=DigiCert Trusted Root G4, OU=www.digicert.com, O=DigiCert Inc, C=US` | `059B1B579E8E2132E23907BDA777755C` | `DDFB16CD4931C973A2037D3FC83A4D7D775D05E4` | `2013-08-01`–`2038-01-15` | A Windows Current User Root store-ból; **nem beágyazott** | Nincs specimen raw/RVA | 0,99 [P] |

A PKCS#7 primer cert setje csak a leafet és az intermediate-et tartalmazza: raw `[0x03315695,0x03316436)`. A self-signed root nem része a specimennek; a Windows trust store adja a chain zárását. A rootra vonatkozó állítás ezért **nem bináris mező, hanem az ellenőrző környezet trust-store eredménye**, confidence `0,99` [P].

A beágyazott primer tanúsítványok DER SHA-256 értékei:

- intermediate: `46011EDE1C147EB2BC731A539B7C047B7EE93E48B9D3C3BA710CE132BBDFAC6B`, raw `[0x03315695,0x03315D49)`;
- leaf: `65866007102FF66498C1EF739CF23DFF71AE3D08DA0D9D759B89D1A409C4208F`, raw `[0x03315D49,0x03316436)`.

Mindkét confidence `0,99` [P].

### 10.4 Timestamp chain és aláírási idő

A timestamp Microsoft Authenticode timestamp tokenként van beágyazva. A timestamp SignerInfo serialja megegyezik a timestamp leaf cert serialjával.

| Szerep | Subject / issuer | Serial | SHA-1 thumbprint | Validity | Key / cert signature | Raw | Confidence |
|---|---|---|---|---|---|---|---:|
| Timestamp responder leaf | `CN=DigiCert SHA256 RSA4096 Timestamp Responder 2026 1, O=DigiCert, Inc., C=US`; issuer: timestamp CA | `084FDC334F7E454EDBC30F8FF9921835` | `51D9ABDA034973D84F4266ACA48248E6B369C439` | `2026-08-05`–`2037-11-04` | RSA-4096; `sha256RSA`; EKU Time Stamping | `[0x033167A1,0x03316E92)` | 0,99 [P] |
| Timestamp intermediate | `CN=DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1, O=DigiCert, Inc., C=US`; issuer: `DigiCert Trusted Root G4` | `0DC7AC5705FF21992E4043220C3A4986` | `07894D00FC194A17DB273AEB5CF8FACEF14423A4` | `2025-05-07`–`2038-01-14` | RSA-4096; `sha256RSA`; CA | `[0x03316E92,0x0331754A)` | 0,99 [P] |
| Cross-signed root | Subject: `CN=DigiCert Trusted Root G4, OU=www.digicert.com, O=DigiCert Inc, C=US`; issuer: `CN=DigiCert Assured ID Root CA, ...` | `0E9B188EF9D02DE7EFDB50E20840185A` | `A99D5B79E9F1CDA59CDAB6373169D5353F5874C6` | `2022-08-01`–`2031-11-09` | RSA-4096; `sha384RSA`; CA | `[0x0331754A,0x03317ADB)` | 0,99 [P] |
| Trust anchor | `CN=DigiCert Assured ID Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US` | `0CE7E0E517D846FE8FE560FC1BF03039` | `0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43` | `2006-11-10`–`2031-11-10` | A Windows Current User Root store-ból; **nem beágyazott** | Nincs specimen raw/RVA | 0,99 [P] |

A timestamp `signingTime` GeneralizedTime TLV:

- teljes TLV: `18 0F 32 30 32 36 30 39 31 31 31 35 30 38 34 36 5A`;
- idő: **`2026-09-11 15:08:46 UTC`**;
- raw `[0x0331678C,0x033167A1)`, value raw `[0x0331678E,0x0331679D)`;
- confidence `0,99` [P].

A timestamp token három beágyazott certjének DER SHA-256:

- responder leaf: `2DA09DA7F4131F9FE72DB6C5E6E9C9656755AF043F1EA742CC0D2120E141EBFC`, raw `[0x033167A1,0x03316E92)`;
- intermediate: `CA0B1554ECD901EA19DCAD8749E9F2648C8D6DFCEA1ADD9D2C2109415BB82CCD`, raw `[0x03316E92,0x0331754A)`;
- cross-signed root: `33846B545A49C9BE4903C60E01713C1BD4E4EF31EA65CD95D69E62794F30B941`, raw `[0x0331754A,0x03317ADB)`.

Mindhárom confidence `0,99` [P].

### 10.5 Overlay és nem aláírt trailing adatok

- A PE-t általánosan parse-oló eszközök a `Security` directory file pointerénél, raw `0x03315600` jelölnek „overlay” kezdőpontot.
- Ez a tartomány azonban teljes egészében a `0x2860` bájtos Authenticode `WIN_CERTIFICATE`: raw `[0x03315600,0x03317E60)`.
- A certificate table vége pontosan egyezik a fájl végevel: `0x03315600 + 0x2860 = 0x03317E60`.
- **Következtetés:** nincs cert blobon kívüli, nem aláírt trailing overlay. Confidence `0,99` [P].

### 10.6 Aláírási státusz és korlátai

- Windows: `Status=Valid`, `SignatureType=Authenticode`, `IsOSBinary=False`.
- LIEF: `Signature.version=1`, `digest_algorithm=SHA_256`, `check=VERIFICATION_FLAGS.OK`.
- A signer és timestamp tanúsítványok a PKCS#7 konténerben csak nyilvános tanúsítványok; privát kulcs nincs a raw `[0x03315608,0x03317E60)` konténerben.
- Az ellenőrzés a vizsgálatkor használt Windows trust store és az Authenticode láncértékek alapján történt. Külön online CRL/OCSP frissességet, külső reputációadatbázist vagy timestamp authority online elérhetőségét nem külön teszteltem [U].
- A digitális aláírás a megadott kulcshoz és digesthez tartozó eredetiséget bizonyítja; önmagában nem mondja meg, melyik terjesztési csatornából származott ez a konkrét példány.

## 11. Projektbeli előfordulások és repository-provenance

| Vizsgálat | Eredmény | Confidence |
|---|---|---:|
| Fájlnév-előfordulás | Egyetlen bináris fájltalát: `reverse/adhesive.dll` | 0,99 [P] |
| Szöveges projekt-hivatkozás | Nincs `adhesive` vagy `adhesive.dll` előfordulás a forrás-, config-, manifest- és logfájlokban; a `reverse/` alatti elemző markdownok külön kategóriát jelentenek | 0,99 [P] |
| Markdown analitikai fájlok | Az elemzés során párhuzamosan további untracked `reverse/adhesive-*.md` fájlok jelentek meg, köztük a specimenre és erre a jelentésre hivatkozó `adhesive-00-index.md`; ezek analitikai navigációk, nem a specimen build-provenance-jének bizonyítékai | 0,99 [P] |
| Git tracked állapot | A célfájl nincs a `git ls-files` listában; a rövid git állapot a `reverse/` könyvtárat `??` jelöléssel mutatja | 0,99 [P] |
| Git history | Nincs commit a fájl útvonalára | 0,99 [P] |
| Git ignore | A `reverse/adhesive.dll` nincs ignorálva | 0,99 [P] |
| `.gitignore` | A szabályok `Bin/`, build-, archív-, log- és ideiglenes fájlokat fednek, nem a `reverse/` mintát; `.gitignore:1` | 0,99 [P] |
| CMake payload-kapcsolat | A projekt a `Bin/` alatti payloadot dolgozza fel, nem a `reverse/adhesive.dll`-t; `CMakeLists.txt:32`, `CMakeLists.txt:40` | 0,99 [P] |
| README kapcsolat | A leírás a FiveM Dumper payloadjáról szól, de nem hivatkozik erre a specimenre; `README.md:29` | 0,99 [P] |
| Beágyazott PDB path kapcsolat | A PDB path egy külső, nem a repositoryban található `C:\gl\builds\...` buildfához mutat; raw `[0x02E493DC,0x02E49424)` | 0,99 [P] |
| Eredeti URL | Nem rekonstruálható; nincs `Zone.Identifier` ADS és nincs build/source reference | 0,99 [P] |

**Provenance-következtetés:** a specimen a repository jelen állapotában untracked, és nincs közvetlen bizonyíték arra, hogy a jelenlegi projekt buildfolyamata hozta létre. A kiszámított Git blob objectum nincs a repository object store-ban; a pontos beszerzési és másolási előzmény ismeretlen [U]. Confidence `0,99` [P].

## 12. Beágyazott import/library kontextus

A specimen közvetlenül importálja több FiveM/CitizenFX modult, például `citizen-resources-client.dll`, `citizen-resources-core.dll`, `gta-core-five.dll`, `rage-device-five.dll`, `vfs-core.dll`, `net.dll`, `scripting-gta.dll` és `legitimacy.dll`. Az import directory RVA `0x02E4B9B9`, raw `[0x02E4A3B9,0x02E4A715)`; a konkrét descriptorok ugyanezen a tartományon belül találhatók. Confidence `0,99` [P].

Ezek a nevek plusz a CitizenFX verzió- és FXCOMPONENT-erőforrások (version raw `[0x0330B300,0x0330B5E0)`, FXCOMPONENT raw `[0x0330B5E0,0x0330B749)`) erős kontextust adnak, de önmagukban nem bizonyítják, hogy a fenti DLL-ek jelen voltak-e a vizsgálat környezetében; ezt a dokumentum nem futtatta vagy betöltötte.

## 13. Mit bizonyít és mit csak következtet a specimen?

### Bizonyított állítások

1. A fájl pontos mérete és minden felsorolt teljes fájlhash-e a 4. fejezetben.
2. [P] PE32+/AMD64 DLL, `ImageBase=0x180000000`, entrypoint RVA `0x02AB2770`; raw evidence a magic `0x90`, entrypoint `0xA0` és ImageBase `0xA8` fejléctermékeknél.
3. [P] PE timestamp `2026-09-11 15:06:18 UTC`; raw `0x80`.
4. [P] PDB GUID `CB927E36-3F3D-8D77-4C4C-44205044422E`, age `1` és a megadott `C:\gl\builds\...` PDB path; raw `[0x02E493C8,0x02E49424)`.
5. [P] Rich header hiányzik; raw `[0x40,0x78)`.
6. [P] Termék- és verziómetadata: CitizenFX / adhesive / `1.0.0.36109`; version resource raw `[0x0330B300,0x0330B5E0)`.
7. [P] FXCOMPONENT manifest `name=adhesive`, `version=0.1.0`; raw `[0x0330B5E0,0x0330B749)`.
8. [P] OpenSSL `1.1.1t`, Botan forrás/RTTI azonosítók, külső V8 `9.3.345.16`, beágyazott oneTBB `2021.7` interface `12070`; a 9. fejezet raw/RVA cellái.
9. [P] Authenticode SHA-256 aláírt digest és azzal egyező image hash; raw `0x03315671`.
10. [P] Rockstar Games signer, kétlépcsős beágyazott code-signing chain és a Windows trust anchor; cert raw tartományok a 10.3 fejezetben.
11. [P] Timestamp `2026-09-11 15:08:46 UTC` és a három beágyazott timestamp cert; raw `[0x0331678C,0x03317ADB)`.
12. [P] Nincs nem aláírt trailing overlay; a cert table pontosan a fájl végéig tart: security raw `[0x03315600,0x03317E60)`, fájlméret raw `0x03317E60`.

### Következtetett állítások

1. **Valószínű linker: LLD-COFF**, confidence `0,85` [L]; a `.retplne` + `14.0` + Rich hiány fingerprint ezt erősen sugallja, de nem symbol-proven.
2. **MSVC-kompatibilis ABI és dinamikus MSVC/UCRT**, confidence `0,95` [L]; közvetlen import- és EH-bizonyíték.
3. **A pontos fordító MSVC vagy clang-cl**, confidence csak `0,55` [U]; a specimen nem teszi lehetővével a megkülönböztetést.
4. **A specimen a FiveM/CitizenFX kliens `adhesive` komponense**, confidence `0,95` [L]; a belső azonosítók és aláírás együtt ezt erősen alátámasztják.
5. **A NTFS creation time egy későbbi másolást/elhelyezést tükröz**, confidence `0,80` [L]; tipikus, de nem közvetlenül bizonyított provenance-esemény.

### Ismeretlen vagy nem bizonyítható ebből a példányból

- [U] pontos LLD release;
- [U] pontos MSVC/clang-cl és UCRT build;
- [U] pontos Botan major/minor/patch;
- [U] a PDB tényleges buildgépének identitása;
- [U] a buildparancs, fordítási flag-ek és CI job;
- [U] az eredeti download URL, csomag és terjesztési chain;
- [U] a DLL futásidejű viselkedése vagy bármely végrehajtási eredménye.

## 14. Módszertan és korlátok

- Hash: `Get-FileHash` MD5, SHA-1, SHA-256, SHA-384 és SHA-512 algoritmusokkal.
- PE parse: `pefile 2024.8.26`, `LIEF 1.0.0-d05b3499b`, Python `3.14.7`; kizárólag fájlbájtokból.
- Authenticode: Windows PowerShell `5.1.26100.9444` `Get-AuthenticodeSignature`, valamint LIEF PKCS#7/chain parse.
- Környezet: Windows 11 Pro, build `26200`; NTFS.
- A vizsgálat nem végzett DLL-execute, processbe való betöltést, dinamikus instrumentációt vagy a specimen működését célzó hálózati megfigyelést. Az LLD értelmezéséhez végzett általános dokumentációkeresés nem érintkezett a specimenmel.
- A bináris claimek raw/RVA hivatkozásai a mintából újraszámíthatók; a confidence érték a közvetlenséget, nem a jogi vagy terjesztési eredetiséget jelenti.
- A feladatban végrehajtott fájlírás kizárólag ezt az egy markdown fájlt hozta létre; más projektfájlt nem módosítottam. Az elemzés közben párhuzamosan megjelenő további `reverse/adhesive-*.md` fájlokat nem módosítottam és nem használtam a specimen bizonyítékainak forrásaként.

## 15. Jelöléskonformancia – záró blokk

Ez a blokk a `P/L/U` jelöléskonformancia-javítás eredményét rögzíti; nem visz új bizonyítékot, és nem módosít számot, hash-t, RVA-t, finding-szöveget vagy státuszt.

- **Kiinduló állapot:** a dokumentum `184` numerikus confidence-értéket hordozott; ebből `6` az 1. fejezet skála-leírásának intervallumtokenje, így a finding/confidence értékek száma `178` volt, mindegyik külön sorban.
- **Új jelölést kapott sorok:** `205` — ebből `178` finding/confidence sor, `9` értelmezési, korlát- vagy összefoglaló bekezdés, `18` összefoglaló lista-elem a 13. fejezetben.
- **Összesen hozzáadott jelölés:** `212`.
- **`P=proven`:** `174`
- **`L=likely`:** `17`
- **`U=unknown`:** `21`
- **A jelölés forrása és szabálya:** az `adhesive-00-index.md` §6 (`P=proven` / `L=likely` / `U=unknown`) globális szerződése, annak definícióival, soronként a sor tényleges kijelentésére alkalmazva. A meglévő numerikus confidence-értékek változatlanul megmaradtak, a jelölés ugyanabban a cellában, közvetlenül utánuk került. Ahol `Minősítés` oszlop volt (`Bizonyított` / `Magas` / `Ismeretlen`), az szolgált a jelölés alapjául; a 13. fejezet listáinál a listafejléc címkéje (`Bizonyított állítások` → `P`, `Következtetett állítások` → `L`/`U`, `Ismeretlen vagy nem bizonyítható` → `U`).
- **Nem jelölt tartalom:** a confidence-érték nélküli `raw`/`RVA`-értékpár (például a 6. fejezet `PDB path nyers tartomány` sora) nem finding/confidence sor, ezért változatlan maradt; a skála-leíráshoz a `P`/`L`/`U` párt egyszer, az 1. fejezet skála-leírása után adtam meg.
