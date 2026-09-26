# `adhesive.dll` — string/config/path artifact inventory

## 1. Vizsgálati határ

- **Fájl:** `reverse/adhesive.dll`
- **SHA-256:** `91cc0aa006d7315cb042c8fa8dca6c1e074a307bba7dcc9eb5509c8a7b81934e`
- **Méret:** `53 575 264` byte (`0x3317E60`)
- **Formátum:** PE32+ x64, image base `0x180000000`, entry RVA `0x2AB2770`
- **Módszer:** kizárólag statikus fájl-, PE-, string- és objdump-elemzés. A DLL-t nem töltöttem be és nem futtattam.
- **Korlát:** az obfuszkált/kódolt bináris blokkokat nem dekódoltam, nem hajtottam végre és nem másoltam ki őket.

## 2. Rövid eredmény

A bináris erős FiveM/CitizenFX klienskomponens-jelzőket tartalmaz: `CitizenFX`, `FiveM`, `Cfx`, `GTA`, `rage`, `ResourceManager`, `legitimacy` és `v8-9.3.345.16.dll`. A konfigurációs részlet `CitizenFX.ini`-t használ, a `[Game]` szekcióban `DefaultBuild`, `ReplaceExecutable`, `IVPath`/`PathCL2` kulcsokkal. A `FiveM.app` itt könyvtárnévként jelenik meg egy `CreateDirectoryW`/attribútumellenőrzési ágban. A cache/crash/subprocess részlet `data\cache\crashometry`, `data\cache\error-pickup`, `CitizenFX_SubProcess_%s.bin`, `subprocess\` és `cache\` literálokat használ.

A hálózati réteg teljes, beágyazott cURL/Boost/HTTP/OpenSSL stacket tartalmaz. Az egyetlen nem-overlay, alkalmazásjellegű és közvetlenül xrefelt URL a `http://clients2.google.com/time/1/current`; a többi URL curl-dokumentáció, OpenSSL/CA-store vagy az Authenticode-tanúsítvány AIA/OCSP/CRL adata. Nem találtam plaintext FiveM/CitizenFX domaint, fix portot, JWT-t, PEM privát kulcsot vagy API-kulcsot.

## 3. Extrakciós elszámolás

A kanonikus teljes futások mindhárom encodinget lefedik, 4 karakteres minimummal:

| Futtatás | Módszer | Rekord | Egyedi szöveg | Megjegyzés |
|---|---|---:|---:|---|
| ASCII | `strings -a -n 4 -t x` | 368 220 | 83 486 | gépi kód, import-, RTTI- és beágyazott adat zaj is beleszámít |
| UTF-16LE | `strings -a -n 4 -e l -t x` | 123 | 114 | a valódi széles karakteres app/config literálok itt vannak |
| UTF-16BE | `strings -a -n 4 -e L -t x` | 0 | 0 | nincs találat |
| **Összes teljes extrakciós futás** |  | **368 343** |  |  |

**Teljes extrakciós futások száma: 3.**

Kiegészítő, nem kanonikus 3 karakteres ASCII/UTF-16LE célzott futás történt a HTTP metódusnevek (`GET`, `POST`, `PUT`, `HEAD`, `DELETE`, `TRACE`, `CONNECT`, `OPTIONS`) ellenőrzésére. A `3 karakteres` találat nem változtatja meg a fenti teljes extrakciós darabszámot.

## 4. Címképzés és bizonyítékhierarchia

- A `file offset` a nyers fájlban a literal első bájtjának offsetje.
- Az `RVA` a PE image base nélküli virtuális cím; a `.rdata` és `.data` szekciókban a raw offsethez `0x1600` hozzáadandó. A `.text` szekcióban a delta `0xC00`, a `.rsrc` szekcióban `0x7E00`.
- Az `xref` objdump Intel disasszemben látható közvetlen RIP-relative hivatkozás, IAT-hívás, pointer-table hivatkozás, illetve PE resource/debug kötés. A kód-xrefek RVA-ként, `0x...` formában vannak megadva.
- `—` azt jelenti, hogy nem találtam közvetlen literal-xrefet; ez nem bizonyítja, hogy az objektum futáskor nem használható.
- **Confidence:** `0,99` `[P]` közvetlen xref és erős kontextus; `0,90` `[L]` közvetlen xref vagy erős API-kontextus; `0,75` `[L]` közvetett pointer/string-pool használat; `0,50` `[L]` valószínű, de nem bizonyított szerep; `0,20` `[U]` alatt false positive.

## 5. PE- és erőforrás-metaadatok

| Artifact | File offset / RVA | Xref / értelmezés | Confidence |
|---|---|---|---:|
| `.text` | raw `0x400`, RVA `0x1000` | futtatható kód, delta `0xC00` | 1,00 `[P]` |
| `.rdata` | raw `0x2BEDA00`, RVA `0x2BEF000` | stringek, importnevek, konstanstáblák | 1,00 `[P]` |
| `.data` | raw `0x30B7A00`, RVA `0x30B9000` | inicializált adat és RTTI | 1,00 `[P]` |
| `.rsrc` | raw `0x330B200`, RVA `0x3313000` | `RT_VERSION`, `RT_MANIFEST`, `FXCOMPONENT` | 1,00 `[P]` |
| Authenticode overlay | raw `0x3315600`, méret `0x2860` | security directory; nem része a mapped PE image-nek | 1,00 `[P]` |
| `CreateComponent` | export RVA `0x101F80` | egyetlen export, nincs kódstrigens | 1,00 `[P]` |
| PDB CodeView rekord | raw `0x2E493C4`, RVA `0x2E4A9C4` | `IMAGE_DEBUG_TYPE_CODEVIEW`, méret `0x60` | 1,00 `[P]` |
| PDB path | raw `0x2E493DC`, RVA `0x2E4A9DC` | `C:\gl\builds\cfx-fivem-0\.build-cache\bin\five\release\dbg\adhesive.pdb` | 1,00 `[P]` |

## 6. FiveM/CitizenFX/GTA/V8/legitimacy/resource jelzők

| Literal / objektum | Enc. | File offset | RVA | Xref | Confidence | Minősítés |
|---|---|---:|---:|---|---:|---|
| `CitizenFX_SDK_Guest` | ASCII | `0x02E0B203` | `0x02E0C803` | `0x18009AB44`, `0x18009AD34` → `getenv` IAT `0x02E4E688` | 0,99 `[P]` | környezeti változó neve; vendég/tool mód jelzője |
| `CitizenFX_ToolMode` | ASCII | `0x02E12509` | `0x02E13B09` | közvetlen xref nincs; közeli string-pool | 0,65 `[L]` | custom tool/header/env jelző, a szerepe nem bizonyított |
| `CfxInitState` | ASCII | `0x02E1136C` | `0x02E1296C` | `0x1813387BB` | 0,98 `[P]` | inicializálási állapot/folyamatnév |
| `CfxInitState` | ASCII | `0x02E32040` | `0x02E33640` | `0x182AA222E`, `0x182AA24E9`, `0x182AA2CD1`, `0x182AA34F4` | 0,99 `[P]` | duplikált, vector-konstansban használt állapotnév |
| `CFXGame` | ASCII | `0x02E11DFF` | `0x02E133FF` | `0x18248EF1C` | 0,95 `[P]` | FiveM/game állapot jelző |
| `fx::ResourceManager` | ASCII | `0x02E0DD76` | `0x02E0F376` | `0x180053408`, `0x1800C71B7`, `0x180334958`, `0x18084FEA1`, `0x181109196` | 0,99 `[P]` | CitizenFX resource manager azonosító |
| `CFX_%s_%s_SharedData_%s` | ASCII | `0x02E0CB65` | `0x02E0E165` | `0x18248F02F`; ugyanott `CreateFileMappingW`/`MapViewOfFile` flow | 0,99 `[P]` | megosztott adat/név formázó |
| `Adhesive V8 error at %s: %s` | ASCII | `0x02E0CFBA` | `0x02E0E5BA` | `0x1804DDCF1` | 0,99 `[P]` | V8-integrációs hiba |
| `CfxInitSH` | ASCII | `0x0047DBA6` | `0x0047E7A6` | nincs közvetlen xref | 0,05 `[U]` | véletlen `.text` printable run, nem azonos a `CfxInitState`-tel |
| `GTA;` | ASCII | `0x02B16631` | `0x02B17231` | nincs közvetlen xref | 0,05 `[U]` | véletlen kódbeli mintázat |
| `v8-9.3.345.16.dll` | ASCII | `0x02E53529` | `0x02E54B29` | V8 import descriptor; IAT `0x02E4D738–0x02E4D8B0` | 1,00 `[P]` | V8 futtatómagva, `Compile`, `Run`, `JSON::Parse` és context API-k importálva |
| `citizen-resources-client.dll` | ASCII | `0x02E53568` | `0x02E54B68` | import descriptor; IAT `0x02E4DAA0–0x02E4DC40` | 1,00 `[P]` | resource cache/mounter |
| `rage-device-five.dll` | ASCII | `0x02E53585` | `0x02E54B85` | import descriptor; IAT `0x02E4DC48` | 1,00 `[P]` | rage device init |
| `gta-core-five.dll` | ASCII | `0x02E5359A` | `0x02E54B9A` | import descriptor; IAT `0x02E4DC58–0x02E4DC68` | 1,00 `[P]` | GTA core init/kill horgok |
| `rage-nutsnbolts-five.dll` | ASCII | `0x02E535AC` | `0x02E54BAC` | import descriptor; IAT `0x02E4DC78–0x02E4DC80` | 1,00 `[P]` | game frame horgok |
| `net.dll` | ASCII | `0x02E535C5` | `0x02E54BC5` | import descriptor; IAT `0x02E4DC90–0x02E4DCA0` | 1,00 `[P]` | hálózati library és GUID |
| `legitimacy.dll` | ASCII | `0x02E535CD` | `0x02E54BCD` | `?IDidntDoNothing` IAT `0x02E4DCB0`, hívás `0x1804DDD49` | 1,00 `[P]` | legitimacy komponens importja |
| `net-tcp-server.dll` | ASCII | `0x02E535DC` | `0x02E54BDC` | import descriptor | 1,00 `[P]` | TCP szerver wrapper |
| `net-base.dll` | ASCII | `0x02E535EF` | `0x02E54BEF` | import descriptor | 1,00 `[P]` | buffer/peer address |
| `citizen-resources-core.dll` | ASCII | `0x02E535FC` | `0x02E54BFC` | import descriptor; resource metadata/event IAT | 1,00 `[P]` | resource metadata és event manager |
| `vfs-core.dll` | ASCII | `0x02E53617` | `0x02E54C17` | import descriptor | 1,00 `[P]` | VFS, packfile, resource stream |
| `scripting-gta.dll` | ASCII | `0x02E53624` | `0x02E54C24` | import descriptor; native handler IAT | 1,00 `[P]` | GTA script handler |
| `rage-scripting-five.dll` | ASCII | `0x02E53636` | `0x02E54C36` | import descriptor | 1,00 `[P]` | script init callback |

### 6.1 `FXCOMPONENT` resource

A resource-adat raw tartománya `0x0330B5E0–0x0330B749` (RVA `0x033133E0–0x03313549`), `361` bájt. Az alábbi literálok mind a beágyazott resource-adatban vannak; kód-xrefjük nincs, az xref maga a `PE .rsrc/FXCOMPONENT` kötés.

| Literal | File offset | RVA | Confidence |
|---|---:|---:|---:|
| `"name": "adhesive"` | `0x0330B5E3` | `0x033133E3` | 1,00 `[P]` |
| `"version": "0.1.0"` | `0x0330B5F9` | `0x033133F9` | 1,00 `[P]` |
| `"fx[2]"` | `0x0330B623` | `0x03313423` | 1,00 `[P]` |
| `"rage:device"` | `0x0330B62F` | `0x0331342F` | 1,00 `[P]` |
| `"gta:core"` | `0x0330B641` | `0x03313441` | 1,00 `[P]` |
| `"gta:streaming"` | `0x0330B650` | `0x03313450` | 1,00 `[P]` |
| `"vfs:core"` | `0x0330B664` | `0x03313464` | 1,00 `[P]` |
| `"net"` | `0x0330B673` | `0x03313473` | 1,00 `[P]` |
| `"citizen:scripting:core"` | `0x0330B67D` | `0x0331347D` | 1,00 `[P]` |
| `"citizen:resources:gta"` | `0x0330B69A` | `0x0331349A` | 1,00 `[P]` |
| `"citizen:legacy-net:resources"` | `0x0330B6B6` | `0x033134B6` | 1,00 `[P]` |
| `"scripting"` | `0x0330B6D9` | `0x033134D9` | 1,00 `[P]` |
| `"legitimacy"` | `0x0330B6E9` | `0x033134E9` | 1,00 `[P]` |
| `"glue"` | `0x0330B6FA` | `0x033134FA` | 1,00 `[P]` |
| `"vendor:openssl_ssl"` | `0x0330B705` | `0x03313505` | 1,00 `[P]` |
| `"vendor:imgui"` | `0x0330B71E` | `0x0331351E` | 1,00 `[P]` |

A `RT_VERSION` resource raw `0x0330B300`, RVA `0x03313100`; az `RT_MANIFEST` resource raw `0x0330B750`, RVA `0x03313550`. A manifest `asInvoker` szövege raw `0x0330B804`, RVA `0x03313604`. A version metadata szerint a termék `CitizenFX`, a fájlleírás `adhesive for FiveM`, az eredeti fájlnév `adhesive.dll`, a verzió `1.0.0.36109`; ezek a resource-adatból származó public metadata, nem futásidejű config.

## 7. `CitizenFX.ini`, `FiveM.app` és config kulcsok

| Literal | Enc. | File offset | RVA | Xref | Confidence |
|---|---|---:|---:|---|---:|
| `CitizenFX.ini` | UTF-16LE | `0x02E479E8` | `0x02E48FE8` | `0x182AA258B`, `0x182AA3761`; közvetlenül egy path-buildernek adódik | 0,99 `[P]` |
| `FiveM.app` | UTF-16LE | `0x02E47970` | `0x02E48F70` | `0x182AA2F69`, `0x182AA306B`; könyvtárnév a létrehozási/ellenőrzési ágban | 0,99 `[P]` |
| `Game` | UTF-16LE | `0x02E47A18` | `0x02E49018` | `0x182AA2719`, `0x182AA3830`, `0x182AA385B` | 0,99 `[P]` |
| `IVPath` | UTF-16LE | `0x02E47A08` | `0x02E49008` | `0x182AA26DC`; akkor használt kulcs, ha a CLI nem tartalmazza `PathCL2`-t | 0,99 `[P]` |
| `PathCL2` | UTF-16LE | `0x02E47BF8` | `0x02E491F8` | `0x182AA26E3`; a CLI-ben szereplő `PathCL2` esetén használt kulcs | 0,99 `[P]` |
| `DefaultBuild` | UTF-16LE | `0x02E47A80` | `0x02E49080` | `0x182AA3829`; `GetPrivateProfileIntW` hívás `0x182AA3837` | 0,99 `[P]` |
| `ReplaceExecutable` | UTF-16LE | `0x02E47A28` | `0x02E49028` | `0x182AA3854`; `GetPrivateProfileIntW` hívás `0x182AA3862` | 0,99 `[P]` |
| `cl2` | UTF-16LE | `0x02E1E2DC` | `0x02E1F8DC` | `0x18009ABAF`, `0x18047EBE0`, `0x182370410` | 0,95 `[P]` |
| `!x-sys-default-locale` | UTF-16LE | `0x02E47A50` | `0x02E49050` | `0x182AB336D`; libcurl/locale opció | 0,90 `[L]` |
| `OPENSSL_ia32cap` | UTF-16LE | `0x02E47988` | `0x02E48F88` | `0x182AB6D76`; `GetEnvironmentVariableW` hívás `0x182AB6DAB` | 0,99 `[P]` |
| `OPENSSL_WIN32_UTF8` | UTF-16LE | `0x02E47B38` | `0x02E49138` | `0x182B8CDAB`; `GetEnvironmentVariableW` hívás `0x182B8CDB4` | 0,99 `[P]` |

A statikus hívási sorrend:

1. A `CitizenFX.ini` útvonalát a kód helper-függvénnyel állítja elő.
2. A `GetCommandLineW`/`StrStrIW` ág megvizsgálja, szerepel-e `PathCL2` a parancssorban; találat esetén a `PathCL2`, egyébként az `IVPath` kulcsot választja. Ez CLI-alapú kulcskiválasztás, nem egy sikertelen lookup utáni fallback.
3. A `GetPrivateProfileStringW` IAT-slot `0x02E4D3A8`, közvetlen hívás `0x182AA2720`; argumentumai sorrendben `Game`, a kiválasztott kulcs, a `PathCL2` default, a kimeneti buffer, `0x200` méret és az előállított INI-útvonal.
4. A `GetPrivateProfileIntW` IAT-slot `0x02E4D3A0` először a `DefaultBuild` értéket olvassa `0x182AA3837`-en; csak ha az eredmény nem pozitív, olvassa a `ReplaceExecutable` értéket `0x182AA3862`-en.
5. A `FiveM.app` két ágon könyvtárlétrehozási/attribútumellenőrzési útvonal jelenik meg, nem igazolt futtatható fájl fallbackjeként.

## 8. Cache, crashometry, subprocess és path artifactok

| Literal | Enc. | File offset | RVA | Xref | Confidence | Következtetés |
|---|---|---:|---:|---|---:|---|
| `data\cache\crashometry` | UTF-16LE | `0x02E1E072` | `0x02E1F672` | `0x18048C72E` | 0,99 `[P]` | crashometry cache path |
| `data\cache\crashometry` | UTF-16LE | `0x02E47928` | `0x02E48F28` | `0x182AA2863`, `0x182AA2ABF` | 0,99 `[P]` | duplikált, másik crash/config flow |
| `data\cache\error-pickup` | UTF-16LE | `0x02E1E15E` | `0x02E1F75E` | `0x18000539A`, `0x180005CF1` | 0,99 `[P]` | error pickup/cache artifact |
| `Fatal Error` | UTF-16LE | `0x02E1E146` | `0x02E1F746` | `0x1800054FA`, `0x180005E51` | 0,99 `[P]` | crash/fatal üzenet |
| `CitizenFX_SubProcess_%s.bin` | UTF-16LE | `0x02E1E18E` | `0x02E1F78E` | `0x18047E88E` | 0,99 `[P]` | subprocess bináris name format |
| `subprocess\` | UTF-16LE | `0x02E1E28E` | `0x02E1F88E` | `0x18047EB31`, `0x18047EB5D` | 0,99 `[P]` | subprocess könyvtár |
| `cache\` | UTF-16LE | `0x02E1E2A6` | `0x02E1F8A6` | `0x18047EABC` | 0,99 `[P]` | cache könyvtár |
| `citizen/release.txt` | UTF-16LE | `0x02E1E0B8` | `0x02E1F6B8` | `0x180101511` | 0,99 `[P]` | release metadata path |
| `release.txt` | UTF-16LE | `0x02E1E0C8` | `0x02E1F6C8` | `0x180101524` | 0,99 `[P]` | a teljes literál `+0x10` pontján kezdődő, null-terminált szuffix |
| `data/server-cache-priv%s` | UTF-16LE | `0x02E1E114` | `0x02E1F714` | nincs közvetlen xref | 0,85 `[L]` | privát server-cache path format |
| `data/server-cache-priv%s/` | UTF-16LE | `0x02E1E2F6` | `0x02E1F8F6` | nincs közvetlen xref | 0,85 `[L]` | ugyanannak a pathnek a slash-változata |
| `grcWindow` | UTF-16LE | `0x02E1E0A0` | `0x02E1F6A0` | `0x181B711D0` | 0,99 `[P]` | crash/GUI window-name getter |
| `\\?\GLOBALROOT` | UTF-16LE | `0x02E1E2B4` | `0x02E1F8B4` | nincs közvetlen xref | 0,80 `[L]` | hosszú útvonal-prefix, nem önmagában mapping-name |
| `fxdk` | UTF-16LE | `0x02E1E242` | `0x02E1F842` | `0x18009ACEA`, `0x18047EC6D` | 0,95 `[P]` | azonosító/prefix |
| `fxdk_` | UTF-16LE | `0x02E1E26E` | `0x02E1F86E` | `0x18047ECE3` | 0,95 `[P]` | generált prefix |
| `b%d_` | UTF-16LE | `0x02E1E27A` | `0x02E1F87A` | `0x18047EDEB` | 0,99 `[P]` | számozott process/cache prefix |
| `cl2_` | UTF-16LE | `0x02E1E284` | `0x02E1F884` | `0x18047EC4F` | 0,99 `[P]` | CL2 process/cache prefix |
| `Service-0x` | UTF-16LE | `0x02E47958` | `0x02E48F58` | `0x182AB6CFD` | 0,85 `[L]` | service-name format, OpenSSL/service-detection környezet |
| `privcache:/` | ASCII | `0x02E1ABDA` | `0x02E1F0DA` | nincs közvetlen xref | 0,80 `[L]` | priv cache séma |
| `compcache:/` | ASCII | `0x02E1ABE6` | `0x02E1F1E6` | nincs közvetlen xref | 0,80 `[L]` | compiler cache séma |
| `compcache_nb:/` | ASCII | `0x02E1ABF2` | `0x02E1F1F2` | nincs közvetlen xref | 0,80 `[L]` | non-builder cache séma |
| `CoreRT.dll` | UTF-16LE | `0x02E1E1FA` | `0x02E1F7FA` | `0x180004D58`, `0x180005287`, `0x1800052D3` és több | 0,99 `[P]` | dinamikus CoreRT betöltési próba |
| `CoreRT.dll` | UTF-16LE | `0x02E479D0` | `0x02E48FD0` | `0x182A9F5B8`, `0x182A9F600`, `0x182A9F6C5` | 0,99 `[P]` | duplikált CoreRT path |
| `security.dll` | UTF-16LE | `0x02E1E1C6` | `0x02E1F7C6` | `0x182A247EA`, `0x182A5F01A` | 0,99 `[P]` | dinamikus security provider |
| `secur32.dll` | UTF-16LE | `0x02E1E210` | `0x02E1F810` | `0x182A247F1`, `0x182A5F021` | 0,99 `[P]` | SSPI/security provider |
| `iphlpapi.dll` | UTF-16LE | `0x02E1E1E0` | `0x02E1F7E0` | `0x182A24836` | 0,99 `[P]` | adapter/IP helper |
| `wtsapi32.dll` | UTF-16LE | `0x02E1E228` | `0x02E1F828` | `0x18000544F`, `0x180005DA6` | 0,99 `[P]` | session API-k dinamikus betöltése |
| `kernel32` | UTF-16LE | `0x02E1E2E4` | `0x02E1F8E4` | `0x182A248CD` | 0,95 `[P]` | kisbetűs dinamikus modulnév |
| `ntdll.dll` | UTF-16LE | `0x02E479B8` | `0x02E48FB8` | `0x182AA062A` | 0,99 `[P]` | dinamikus NT API betöltés |
| `KERNEL32.DLL` | UTF-16LE | `0x02E47AB0` | `0x02E490B0` | `0x182BD0FB0`, `0x182BD11FF`, `0x182BEB6D8` | 0,99 `[P]` | OpenSSL provider/modulnév |
| `OpenSSL` | UTF-16LE | `0x02E47AA0` | `0x02E490A0` | `0x182AB71E1` | 0,95 `[P]` | provider/name |
| `OpenSSL: FATAL` | UTF-16LE | `0x02E47AD0` | `0x02E490D0` | `0x182AB7241` | 0,99 `[P]` | OpenSSL fatális hiba |
| `no stack?` | UTF-16LE | `0x02E47AF0` | `0x02E490F0` | `0x182AB6FE6` | 0,99 `[P]` | stack/diagnosztikai hiba |
| `C:\Program Files\Common Files\SSL/certs` | ASCII | `0x02E26028` | `0x02E27628` | `0x182B73C50` | 0,99 `[P]` | OpenSSL CA directory |
| `C:\Program Files\Common Files\SSL/cert.pem` | ASCII | `0x02E2E208` | `0x02E2F808` | `0x182B73C60` | 0,99 `[P]` | OpenSSL CA file fallback |
| `C:\Program Files\Common Files\SSL` | ASCII | `0x02E3FCC8` | `0x02E412C8` | `0x182B73C40` | 0,99 `[P]` | SSL root path |

## 9. PDB és source pathok

| Artifact | File offset | RVA | Xref | Confidence |
|---|---:|---:|---|---:|
| `C:\gl\builds\cfx-fivem-0\.build-cache\bin\five\release\dbg\adhesive.pdb` | `0x02E493DC` | `0x02E4A9DC` | CodeView debug rekord `0x02E493C4`, nem kód-xref | 1,00 `[P]` |
| `C:\gl\builds\cfx-fivem-0\code\client\shared\Utils.cpp` | `0x02E2B1C0` | `0x02E2C7C0` | `0x182AA01AA`, `0x182AA049E` | 0,99 `[P]` |
| `..\..\fivem-private\components\adhesive\src\botan\botan_all.cpp` | `0x02E0ECA6` | `0x02E102A6` | több `__FILE__`/assert xref, például `0x1805A7FCA` | 0,99 `[P]` |
| `..\..\fivem-private\components\adhesive\src\botan\botan_all.h` | `0x02E105FB` | `0x02E11BFB` | több xref, például `0x1805BA94D` | 0,99 `[P]` |
| Boost source path family | `0x02E0E079–0x02E0EC52` | `0x02E0F679–0x02E10252` | 34 literal; például `boost/asio/detail/impl/win_mutex.ipp` → `0x181F8DD49` | 0,99 `[P]` |
| `..\..\..\vendor\fmtlib\include\fmt/format.h` | `0x02E105CF` | `0x02E11BCF` | sok fmt-template xref | 0,99 `[P]` |
| `..\..\..\vendor\fmtlib\include\fmt/core.h` | `0x02E10639` | `0x02E11C39` | sok fmt-template xref | 0,99 `[P]` |
| `..\..\..\vendor\curl\lib\vtls\openssl.c` | `0x02E140A9` | `0x02E156A9` | `0x182A59044`, `0x182A59141` | 0,99 `[P]` |
| OpenSSL source path family | `0x02E30550–0x02E48E90` | `0x02E31B50–0x02E4A490` | 276 literal; library `__FILE__`/diagnosztikai xrefek | 0,99 `[P]` |

A 34 Boost-, 2 Botan-, 2 fmt-, 1 curl-, 276 OpenSSL- és 1 alkalmazás-source path is valódi, kurálható build metadata, de nem alkalmazáskonfiguráció. A report szándékosan csoportosítja őket, hogy a futásidejű string/config/path inventory olvasható maradjon; a csoport minden tagjára ugyanaz a delta, xref-kategória és confidence érvényes.

## 10. URL-, domain-, IP- és portartifactok

### 10.1 URL/domain

| Literal | Enc. | File offset | RVA | Xref | Confidence | Kontextus |
|---|---|---:|---:|---|---:|---|
| `http://clients2.google.com/time/1/current` | ASCII | `0x02C59AD0` | `0x02C5B0D0` | `0x180032569` | 0,90 `[L]` | egyetlen nem-overlay, közvetlenül xrefelt URL; time endpoint |
| `https://curl.se/docs/hsts.html` | ASCII | `0x02E1DA80` | `0x02E1F080` | `0x182A31136` | 0,99 `[P]` | curl HSTS-cache dokumentáció |
| `https://curl.se/docs/alt-svc.html` | ASCII | `0x02E1DAF0` | `0x02E1F0F0` | `0x182A322A5` | 0,99 `[P]` | curl alt-svc-cache dokumentáció |
| `https://curl.se/docs/http-cookies.html` | ASCII | `0x02E1DF03` | `0x02E1F503` | nincs közvetlen xref; cookie-file string-pool | 0,95 `[P]` | curl cookie-dokumentáció |
| `ftp@example.com` / `example.com` | ASCII | `0x02E0F922` | `0x02E10F22` | nincs közvetlen xref | 0,80 `[L]` | OpenSSL/cURL példahoszt, nem endpoint |
| `openssl.org` | ASCII | `0x02A73470`, `0x02A74BA0`, `0x02A79CA0`, `0x02A813E5`, `0x02A865E0`, `0x02A86FE6`, `0x02A8CB90`, `0x02A8DD50`, `0x02A8FE80`, `0x02A9223C`, `0x02A926D1`, `0x02A95700` | +`0x1600` minden offsethez | kreditszövegek, nincs alkalmazás-xref | 0,80 `[L]` | OpenSSL CRYPTOGAMS credits |
| `http://ocsp.digicert.com` | ASCII | `0x03315A77`, `0x033161A1`, `0x03316B84`, `0x03317910` | overlay, nincs RVA | Authenticode OCSP AIA | 1,00 `[P]` | tanúsítvány-metaadat |
| `http://cacerts.digicert.com/...` | ASCII | `0x03315A9C`, `0x033161C6`, `0x03316BA9`, `0x03317299`, `0x03317935` | overlay, nincs RVA | Authenticode AIA | 1,00 `[P]` | tanúsítvány-metaadat |
| `http://crl3.digicert.com/...` | ASCII | `0x03315AE4`, `0x033160DD`, `0x03316C0D`, `0x033172E1`, `0x0331797F` | overlay, nincs RVA | Authenticode CRL | 1,00 `[P]` | tanúsítvány-metaadat |
| `http://crl4.digicert.com/...` | ASCII | `0x03316132` | overlay, nincs RVA | Authenticode CRL | 1,00 `[P]` | tanúsítvány-metaadat |
| `http://www.digicert.com/CPS` | ASCII | `0x03316088` | overlay, nincs RVA | Authenticode CPS | 1,00 `[P]` | tanúsítvány-metaadat |

A teljes domain-regex találatok között nincs `fivem.*`, `cfx.*`, `citizenfx.*` vagy `rockstargames.com` domain. Az `ocsp/cacerts/crl` URL-ek ezért nem minősülnek FiveM backend endpointnak.

### 10.2 IP és port

| Literal | Enc. | File offset | RVA | Xref | Confidence | Minősítés |
|---|---|---:|---:|---|---:|---|
| `127.0.0.1` | ASCII | `0x02E1A3DC` | `0x02E1B9DC` | `0x182A44FCB`, `0x182A54697`, `0x182A56F26` | 0,99 `[P]` | OpenSSL/cURL loopback literal, nem FiveM szerver |
| `127.0.0.1/` | ASCII | `0x02E1AC01` | `0x02E1C201` | `0x182A610CA` | 0,99 `[P]` | loopback parser literal |
| `localhost/` | ASCII | `0x02E1ABB8` | `0x02E1C1B8` | `0x182A610B1` | 0,99 `[P]` | parser séma |
| `255.255.255.255` | ASCII | `0x02E1831D` | `0x02E1991D` | nincs közvetlen xref | 0,95 `[P]` | OpenSocket/host sentinel, nem hálózati cél |
| `2.5.29.19`, `2.5.29.18`, `2.5.29.17`, `2.5.4.65` és társai | ASCII | `0x02E172D6` környéke | `0x02E188D6` környéke | nincs alkalmazás-xref | 0,10 `[U]` | ASN.1 OID-ok, amelyek IP-regexre hasonlítanak |

A teljes ASCII/UTF-16 szűrésben **nincs fix numerikus port literal**. A portok dinamikusak: `%u`, `%d`, `%ld`, `%I64d` formátumok, `getaddrinfo`, `connect`, `bind`, `listen`, `WSA*` és a `Service-0x`/service-name flow használja őket.

## 11. HTTP metódusok

A 3 karakteres metóduskeresés 14 ASCII találatot adott; a táblában az azonos metódusok különböző előfordulásait csoportosítottam. A közvetlenül xrefelt táblabejegyzések a HTTP/parser implementációhoz tartoznak; a többi token library-táblázatban van.

| Literal | File offset | RVA | Xref | Confidence | Kontextus |
|---|---:|---:|---|---:|---|
| `GET` | `0x02E1FB4C` | `0x02E2174C` | `0x182AACD15` | 0,95 `[P]` | HTTP method token |
| `POST` | `0x02E1FB00` | `0x02E21700` | nincs közvetlen xref | 0,85 `[L]` | HTTP method token |
| `GET` | `0x02E204F4` | `0x02E21AF4` | `0x182BDD9A4` | 0,99 `[P]` | HTTP method table |
| `POST` | `0x02E204EC` | `0x02E21AEC` | `0x182BDD9C7` | 0,99 `[P]` | HTTP method table |
| `HEAD` | `0x02E204FC` | `0x02E21AFC` | `0x182BDD9E5` | 0,99 `[P]` | HTTP method table |
| `PUT` | `0x02E204E4` | `0x02E21AE4` | `0x182BDDA04` | 0,99 `[P]` | HTTP method table |
| `DELETE` | `0x02E15B7A` | `0x02E1717A` | `0x18206FE87` | 0,95 `[P]` | HTTP method table |
| `TRACE` | `0x02E15D67` | `0x02E17367` | `0x18206FC83` | 0,95 `[P]` | HTTP method table |
| `HEAD` | `0x02E16340` | `0x02E17940` | `0x18206FC2E`, `0x182A2BDB7`, `0x182A4A814`, `0x182A4DF56`, `0x182A5277C` | 0,99 `[P]` | HTTP method/parser |
| `CONNECT` | `0x02E3EBD0` | `0x02E401D0` | `0x182B66603` | 0,99 `[P]` | HTTP method table |
| `OPTIONS` | `0x02E3EE88` | `0x02E40488` | `0x182B6662C` | 0,99 `[P]` | HTTP method table |
| `CONNECT %s HTTP/%s` | `0x02E0CB1E` | `0x02E0E11E` | nincs közvetlen xref | 0,85 `[L]` | proxy CONNECT request |
| `HTTP/%s` | `0x02E0CAB4` | `0x02E0E0B4` | nincs közvetlen xref | 0,85 `[L]` | HTTP version parser |
| `%s %s %u %s %s %u "%d%02d%02d %02d:%02d:%02d" %u %d` | `0x02E1DA24` | `0x02E1F024` | nincs közvetlen xref | 0,85 `[L]` | proxy/request logging |
| `PRI * HTTP/2.0` | `0x02E47908` | `0x02E48F08` | nincs közvetlen xref | 0,85 `[L]` | HTTP/2 preface |

## 12. HTTP header, auth és cookie artifactok

| Literal | File offset | RVA | Xref | Confidence | Kontextus |
|---|---:|---:|---|---:|---|
| `HTTP/2` | `0x02E1D902` | `0x02E1EF02` | `0x182A38C4D` | 0,99 `[P]` | HTTP/2 |
| `:status:%u` | `0x02E1D913` | `0x02E1EF13` | `0x182A38C30` | 0,99 `[P]` | HTTP/2 pseudo-header |
| `content-type:%s` | `0x02E1D922` | `0x02E1EF22` | `0x182A6DD29` | 0,99 `[P]` | HTTP/2 header |
| `host:%s` | `0x02E1D932` | `0x02E1EF32` | `0x182A6DD7B` | 0,99 `[P]` | HTTP/2 header |
| `x-%s-date:%s` | `0x02E1D93A` | `0x02E1EF3A` | nincs közvetlen xref | 0,90 `[L]` | HTTP/2 request header |
| `Host: %s%s%s` | `0x02E1DBA9` | `0x02E1F1A9` | `0x182A4DBE9` | 0,99 `[P]` | request builder |
| `Range: bytes=%s` | `0x02E1DBB8` | `0x02E1F1B8` | `0x182A54C1E` | 0,99 `[P]` | resume/range |
| `Host: %s%s%s:%d` | `0x02E1DE69` | `0x02E1F469` | `0x182A4DDEB` | 0,99 `[P]` | host+port |
| `User-Agent: %s` | `0x02E1DC6E` | `0x02E1F26E` | `0x182A46B82`, `0x182A4A04C` | 0,99 `[P]` | request header |
| `Connection: Upgrade, HTTP2-Settings` | `0x02E1DC7F` | `0x02E1F27F` | `0x182A36756` | 0,99 `[P]` | HTTP/2 upgrade |
| `Referer: %s` | `0x02E1DCC6` | `0x02E1F2C6` | `0x182A4E21A` | 0,99 `[P]` | request header |
| `Accept-Encoding: %s` | `0x02E1DCD4` | `0x02E1F2D4` | `0x182A4E33F` | 0,99 `[P]` | request header |
| `%sAuthorization: Digest %s` | `0x02E1DBD4` | `0x02E1F1D4` | `0x182A336D0` | 0,99 `[P]` | auth, runtime credential placeholder |
| `Authorization: Bearer %s` | `0x02E1DBF1` | `0x02E1F1F1` | `0x182A503DD` | 0,99 `[P]` | auth, runtime token placeholder |
| `%sAuthorization: Negotiate %s` | `0x02E1DC0C` | `0x02E1F20C` | `0x182A5F628` | 0,99 `[P]` | SSPI auth |
| `%sAuthorization: Basic %s` | `0x02E1DC2C` | `0x02E1F22C` | `0x182A50266` | 0,99 `[P]` | basic auth |
| `%sAuthorization: NTLM %s` | `0x02E1DC48` | `0x02E1F248` | `0x182A5F167`, `0x182A5F222` | 0,99 `[P]` | NTLM auth |
| `Authorization: %s4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s` | `0x02E1DCEA` | `0x02E1F2EA` | `0x182A6E2C0` | 0,99 `[P]` | HMAC request signing |
| `Proxy-Connection: Keep-Alive` | `0x02E1DD62` | `0x02E1F362` | `0x182A46CA7`, `0x182A4EC3B` | 0,99 `[P]` | proxy header |
| `Expect: 100-continue` | `0x02E1DD81` | `0x02E1F381` | `0x182A52EB8`, `0x182A539D1`, `0x182A541CA` | 0,99 `[P]` | request header |
| `Transfer-Encoding: chunked` | `0x02E1DD98` | `0x02E1F398` | `0x182A4E7AC` | 0,99 `[P]` | response/request parser |
| `Content-Type: application/x-www-form-urlencoded` | `0x02E1DDB5` | `0x02E1F3B5` | `0x182A53750` | 0,99 `[P]` | POST body |
| `Content-Range: bytes %s/%I64d` | `0x02E1DDE7` | `0x02E1F3E7` | `0x182A54D80` | 0,99 `[P]` | range parser |
| `Content-Length: %I64d` | `0x02E1DE51` | `0x02E1F451` | `0x182A52DFD`, `0x182A530F7`, `0x182A53591` | 0,99 `[P]` | body parser |
| `Accept: */*` | `0x02E1DEBF` | `0x02E1F4BF` | `0x182A4E7B7` | 0,99 `[P]` | default accept |
| `Authorization:` | `0x02E16FF7` | `0x02E185F7` | `0x182A51FE8`, `0x182A52007` | 0,99 `[P]` | header parser |
| `Content-Type:` | `0x02E17095` | `0x02E18695` | `0x182A51BDD–0x182A51C99`, `0x182A566F0`, `0x182A568AE` | 0,99 `[P]` | header parser |
| `Content-Length:` | `0x02E1702A` | `0x02E1862A` | `0x182A4758F`, `0x182A475AE`, `0x182A51D58`, `0x182A56711` | 0,99 `[P]` | header parser |
| `Transfer-Encoding:` | `0x02E1704C` | `0x02E1864C` | `0x182A4772B`, `0x182A47771`, `0x182A51F1D`, `0x182A56B1E` | 0,99 `[P]` | header parser |
| `Content-Range:` | `0x02E170CD` | `0x02E186CD` | `0x182A56DF5` | 0,99 `[P]` | header parser |
| `WWW-Authenticate:` | `0x02E17073` | `0x02E18673` | `0x182A473C8`, `0x182A473E8`, `0x182A57096` | 0,99 `[P]` | auth challenge |
| `Proxy-Authorization:` | `0x02E16FE5` | `0x02E185E5` | `0x182A477E5`, `0x182A569AA`, `0x182A56A0C` | 0,99 `[P]` | proxy auth |
| `citizen:` | `0x02E17010` | `0x02E18610` | nincs közvetlen xref; auth/header pointer-pool | 0,75 `[L]` | custom auth scheme/token |
| `X-Device-Accept` | `0x02E0B479` | `0x02E0CA79` | pointer-table raw `0x02D8EB08`, RVA `0x02D90108`; nincs közvetlen literal-xref | 0,85 `[L]` | custom/default HTTP header |
| `X-Device-User-Agent` | `0x02E0B825` | `0x02E0CE25` | pointer-table raw `0x02D8EB48`, RVA `0x02D90148` | 0,85 `[L]` | custom/default HTTP header |
| `X-Device-Accept-Charset` | `0x02E0B9D1` | `0x02E0CFD1` | pointer-table raw `0x02D8EB18`, RVA `0x02D90118` | 0,85 `[L]` | custom/default HTTP header |
| `X-Device-Accept-Encoding` | `0x02E10A59` | `0x02E12059` | pointer-table raw `0x02D8EB28`, RVA `0x02D90128` | 0,85 `[L]` | custom/default HTTP header |
| `X-Device-Accept-Language` | `0x02E12314` | `0x02E13914` | pointer-table raw `0x02D8EB38`, RVA `0x02D90138` | 0,85 `[L]` | custom/default HTTP header |
| `Set-Cookie` / `Set-Cookie2` | `0x02E12039` / `0x02E1938B` | `0x02E13639` / `0x02E1A98B` | nincs közvetlen xref | 0,80 `[L]` | cookie parser |
| `Sec-WebSocket-Key` / `Sec-WebSocket-Accept` | `0x02E0A625` / `0x02E0B464` | `0x02E0BC25` / `0x02E0CA64` | nincs közvetlen xref | 0,80 `[L]` | WebSocket header |
| `Sec-WebSocket-Extensions` | `0x02E0C24D` | `0x02E0D84D` | nincs közvetlen xref | 0,80 `[L]` | WebSocket header |
| `ALPN: server accepted %.*s` | `0x02E0CA39` | `0x02E0E039` | `0x182A5B73F` | 0,99 `[P]` | TLS ALPN |

A `X-Device-*` és `Lock-Token` literálok nem a klasszikus, közvetlen `lea` xref formában használódnak; hosszú pointer/length adattáblákban vannak. Ezt a jelentés közvetett xrefként jelöli, nem tekinti bizonyított kérésfejlécnek minden hívásnál.

## 13. Registry és environment

| Artifact | File offset / IAT RVA | Xref | Confidence | Következtetés |
|---|---:|---|---:|---|
| `RegGetValueW` importnév | raw `0x02E4DD14`, RVA `0x02E4F314`; IAT RVA `0x02E4D718`, raw `0x02E4C118` | callsite RVA `0x00116618`, raw `0x00115A18` (`0x180116618`) | 0,99 `[P]` | registry-olvasás |
| `HKEY_LOCAL_MACHINE` | nincs plaintext literal; `RCX=0xFFFFFFFF80000002`, azaz sign-extended `0x80000002` | immediate RVA `0x0011660B`, raw `0x00115A0B`; call RVA `0x00116618` | 0,99 `[P]` | `HKEY_LOCAL_MACHINE` |
| `GetEnvironmentVariableA` | importnév raw `0x02E4D3D8`; IAT `0x02E4D338` | több, például `0x182A21A18` | 0,99 `[P]` | narrow environment API |
| `GetEnvironmentVariableW` | importnév raw `0x02E4D3F2`; IAT `0x02E4D340` | `0x182AB6DAB`, `0x182B8CDB4` | 0,99 `[P]` | wide environment API |
| `getenv` | importnév raw `0x02E5347C`; IAT `0x02E4E688` | `0x18009AB4B`, `0x18009AD3B`, `0x180EE6817` | 0,99 `[P]` | C runtime environment lookup |
| `CitizenFX_SDK_Guest` | `0x02E0B203` / `0x02E0C803` | `0x18009AB44`, `0x18009AD34` | 0,99 `[P]` | konkrét, `getenv`-hez adott env név |
| `CitizenFX_ToolMode` | `0x02E12509` / `0x02E13B09` | nincs közvetlen xref | 0,65 `[L]` | valószínű custom flag, de env/header szerepe nem bizonyított |
| `no conf or environment variable` | `0x02E34DC0` / `0x02E363C0` | nincs közvetlen xref | 0,80 `[L]` | OpenSSL konfigurációs hiba |
| `Software\`, `CurrentVersion` | nincs plaintext találat | — | 0,99 `[P]` | nincs látható registry subkey literal |

A `RegGetValueW` hét argumentuma a callsite-on: `RCX=0xFFFFFFFF80000002` (`HKEY_LOCAL_MACHINE`), `RDX=RBP+0xD0` (`lpSubKey`), `R8=RBP+0x1C0` (`lpValue`), `R9D=2` (`RRF_RT_REG_SZ`), `[RSP+0x20]=0` (`pdwType=NULL`), `[RSP+0x28]=RDI` (`pvData`) és `[RSP+0x30]=RBP+0x190` (`pcbData`). Az `RDI` egy közvetlenül korábbi obfuszkált indirect hívás eredménye. A subkey- és value-name pointerek obfuszkált, stacken felépített széles karakteres adatot címznek; a konkrét registry-nevek nem plaintext stabil literálként látszanak, ezért nem dekodoltam őket.

## 14. Event, shared memory és file mapping

| Artifact | File offset / IAT RVA | Xref | Confidence | Következtetés |
|---|---:|---|---:|---|
| `CFX_%s_%s_SharedData_%s` | `0x02E0CB65` / `0x02E0E165` | `0x18248F02F` | 0,99 `[P]` | shared-data name format |
| `CreateFileMappingW` | IAT `0x02E4D270` | `0x18248F0A6` | 0,99 `[P]` | file mapping létrehozás |
| `MapViewOfFile` | IAT `0x02E4D498` | `0x18248F16F` | 0,99 `[P]` | mapping megtekintése |
| `UnmapViewOfFile` | IAT `0x02E4D600` | `0x18247F626`, `0x18248EE7D`, `0x182AA23C5`, `0x182AA27E3`, `0x182AA3219`, `0x182AA3699` | 0,99 `[P]` | mapping lezárás |
| `Local\{C15730E2-145C-4c5e-B005-3BC753F42475}-once-flag` | `0x02C1D3E0` / `0x02C1E9E0` | `0x180002A97`, `0x180002C27` | 0,99 `[P]` | `Local\` named synchronization object/once-flag jelölő |
| `CreateEventA` | IAT `0x02E4D258` | `0x1800013E1`, `0x180002105` | 0,99 `[P]` | event API |
| `CreateEventW` | IAT `0x02E4D260` | `0x181F90AE5`, `0x181F90BC2` | 0,99 `[P]` | event API |
| `OpenEventA` | IAT `0x02E4D4B8` | `0x180002D85` | 0,99 `[P]` | event open |
| `SetEvent` | IAT `0x02E4D560` | `0x180001425`, `0x18000285B`, `0x181F90EBA`, `0x181F90EE2` | 0,99 `[P]` | event signal |
| `ResetEvent` | IAT `0x02E4D530` | `0x1800027F0` | 0,99 `[P]` | event reset |
| `\\?\GLOBALROOT` | `0x02E1E2B4` / `0x02E1F8B4` | nincs közvetlen xref | 0,80 `[L]` | path prefix, nem mapping-name bizonyíték |

Nincs `shared memory` vagy `Global\` plaintext literal, de a `CFX_*_SharedData_*` format és a `CreateFileMappingW`/`MapViewOfFile`/`UnmapViewOfFile` import-lánc erős, közvetlen shared-memory artifact.

## 15. Process, session és WTS

| Artifact | File offset / IAT RVA | Xref | Confidence | Következtetés |
|---|---:|---|---:|---|
| `WTSQuerySessionInformationW` | `0x02E14AA3` / `0x02E160A3` | `0x180005464`, `0x180005DBB` | 0,99 `[P]` | dinamikus session-query |
| `WTSFreeMemory` | `0x02E0A321` / `0x02E0B921` | `0x18000547B`, `0x180005DD2` | 0,99 `[P]` | WTS buffer felszabadítás |
| `wtsapi32.dll` | `0x02E1E228` / `0x02E1F828` | `0x18000544F`, `0x180005DA6` | 0,99 `[P]` | dinamikus WTS modul |
| `CreateToolhelp32Snapshot` | IAT `0x02E4D290` | jump thunk `0x182BED400` | 0,99 `[P]` | process/thread snapshot |
| `Thread32First` / `Thread32Next` | IAT `0x02E4D5C8` / `0x02E4D5D0` | jump thunks `0x182BED410`, `0x182BED420` | 0,99 `[P]` | thread enumeration |
| `OpenProcess` | IAT `0x02E4D4C0` | `0x180D7B86E` | 0,99 `[P]` | process handle |
| `QueryFullProcessImageNameW` | IAT `0x02E4D4E0` | `0x180D810A8` | 0,99 `[P]` | process image path |
| `OpenThread` | IAT `0x02E4D4C8` | `0x18001E0F4`, `0x18001E473`, `0x18001E526` | 0,99 `[P]` | thread handle |
| `SuspendThread` | IAT `0x02E4D5A0` | `0x18001E109` | 0,99 `[P]` | thread suspend |
| `GetThreadContext` / `SetThreadContext` | IAT `0x02E4D400` / `0x02E4D570` | `0x18001E11F`, `0x18001E214` | 0,99 `[P]` | context inspection/manipulation |
| `ResumeThread` | IAT `0x02E4D538` | `0x18001E484`, `0x18001E537` | 0,99 `[P]` | thread resume |
| `QueueUserAPC` | IAT `0x02E4D4F8` | `0x181F907F4`, `0x181F90A17`, `0x181F91968` és további | 0,99 `[P]` | APC-queue |
| `TerminateThread` | IAT `0x02E4D5C0` | `0x181F907E2`, `0x181F90A05`, `0x181F91956` és további | 0,99 `[P]` | thread termination |
| `GetCurrentProcessId` | IAT `0x02E4D320` | `0x180002B78`, `0x180002D08`, `0x18001E063` és sok más | 0,99 `[P]` | PID |
| `GetCurrentThreadId` | IAT `0x02E4D330` | `0x18001E075`, `0x180AB3B50` és további | 0,99 `[P]` | TID |
| `GetProcessWindowStation` | IAT `0x02E4D680` | `0x182AB6C3E` | 0,99 `[P]` | session/window-station ellenőrzés |
| `GetUserObjectInformationW` | IAT `0x02E4D688` | `0x182AB6C66`, `0x182AB6CDC` | 0,99 `[P]` | user-object/session metadata |
| `RegisterSuspendResumeNotification` | IAT `0x02E4D698` | `0x182936634` | 0,99 `[P]` | suspend/resume callback |
| `CitizenFX_SubProcess_%s.bin` | `0x02E1E18E` / `0x02E1F78E` | `0x18047E88E` | 0,99 `[P]` | subprocess artifact |

## 16. Hiba- és config-stringek

A teljes ASCII extrakcióban 1 483 hiba-/figyelmeztető-/állapotmintázat volt: 797 az OpenSSL- és license-tartományban, 452 a beágyazott hálózati/runtime részben, 119 a runtime/import részben és 115 máshol. Az alábbiak a FiveM/CitizenFX-környezethez vagy a futási döntési flow-hoz közvetlenül kapcsolódó jelentős literálok.

| Literal | File offset | RVA | Xref | Confidence |
|---|---:|---:|---|---:|
| `Adhesive V8 error at %s: %s` | `0x02E0CFBA` | `0x02E0E5BA` | `0x1804DDCF1` | 0,99 `[P]` |
| `Fatal Error` | `0x02E1E146` | `0x02E1F746` | `0x1800054FA`, `0x180005E51` | 0,99 `[P]` |
| `data\cache\error-pickup` | `0x02E1E15E` | `0x02E1F75E` | `0x18000539A`, `0x180005CF1` | 0,99 `[P]` |
| `Could not resolve host: %s` | `0x02E0CF10` | `0x02E0E510` | `0x182A2AD4B` | 0,99 `[P]` |
| `Failed to connect to %s port %u after %I64d ms: %s` | `0x02E0CF87` | `0x02E0E587` | `0x182A3B1CA` | 0,99 `[P]` |
| `connect to %s port %u failed: %s` | `0x02E0D271` | `0x02E0E871` | `0x182A3ACB8` | 0,99 `[P]` |
| `Failed sending PUT request` | `0x02E0B120` | `0x02E0C720` | `0x182A52FD4` | 0,99 `[P]` |
| `Failed sending POST request` | `0x02E0B13B` | `0x02E0C73B` | `0x182A5309E` | 0,99 `[P]` |
| `Failed sending HTTP POST request` | `0x02E0B157` | `0x02E0C757` | `0x182A53DBE` | 0,99 `[P]` |
| `Failed sending HTTP request` | `0x02E0B19C` | `0x02E0C79C` | `0x182A53E80` | 0,99 `[P]` |
| `Error setting ALPN` | `0x02E1501D` | `0x02E1661D` | `0x182A5A456` | 0,99 `[P]` |
| `Failed set SNI` | `0x02E1536E` | `0x02E1696E` | `0x182A5B10B` | 0,99 `[P]` |
| `No authentication method was acceptable.` | `0x02E1B703` | `0x02E1CD03` | `0x182A4CA15` | 0,99 `[P]` |
| `SSL certificate verify result: %s (%ld), continuing anyway.` | `0x02E1AC0C` | `0x02E1C20C` | `0x182A5CC8A` | 0,99 `[P]` |
| `invalid token supplied` | `0x02E138A2` | `0x02E14EA2` | `0x18002F4DA`, `0x18002F553` | 0,99 `[P]` |
| `unknown token` | `0x02E0F761` | `0x02E10D61` | `0x18045B4A`, `0x18045C32`, `0x1817751A4` | 0,99 `[P]` |
| `Access denied to remote resource` | `0x02E12588` | `0x02E13B88` | nincs közvetlen xref | 0,85 `[L]` |
| `URL using bad/illegal format or missing URL` | `0x02E1525E` | `0x02E1685E` | nincs közvetlen xref | 0,85 `[L]` |
| `bad method` | `0x02E1281A` | `0x02E13E1A` | nincs közvetlen xref | 0,80 `[L]` |
| `HTTP/3 error` | `0x02E0D906` | `0x02E0E506` | nincs közvetlen xref | 0,85 `[L]` |
| `no conf or environment variable` | `0x02E34DC0` | `0x02E363C0` | nincs közvetlen xref | 0,80 `[L]` |
| `OpenSSL: FATAL` | `0x02E47AD0` | `0x02E490D0` | `0x182AB7241` | 0,99 `[P]` |
| `no stack?` | `0x02E47AF0` | `0x02E490F0` | `0x182AB6FE6` | 0,99 `[P]` |
| `Failed to load PKCS12 client certificate, OpenSSL error %s` | `0x02E0CC98` | `0x02E0E298` | nincs közvetlen xref | 0,85 `[L]` |
| `failed to verify signature: Could not get key` | `0x02E0A49C` | `0x02E0B89C` | nincs közvetlen xref | 0,85 `[L]` |
| `Invalid authentication tag:` | `0x02E1D82A` | `0x02E1FE2A` | nincs közvetlen xref | 0,85 `[L]` |

A `OpenSSL`, `cURL`, `Boost.Beast`, `Botan` és `RTTI` hiba-/metadata-stringek nagyrészt a beágyazott könyvtárakhoz tartoznak, nem FiveM-specifikus konfiguráció. A `grants_token`, `Lock-Token`, `citizen:` és `CFX_*_SharedData_*` a FiveM/CitizenFX jelzők közé tartozik.

## 17. Érzékeny adatok és titkok

| Artifact | File offset / RVA | Xref / állapot | Confidence | Következtetés |
|---|---:|---|---:|---|
| `grants_token` | `0x02E0F754` / `0x02E10D54` | nincs közvetlen xref; mezőnév, nem érték | 0,85 `[L]` | runtime token/protocol key neve |
| `Lock-Token` | `0x02E0F76F` / `0x02E10D6F` | pointer-table raw `0x02D8E128`, RVA `0x02D8F728`; nincs közvetlen literal-xref | 0,85 `[L]` | lock/session token mező neve, nem token |
| `Authorization: ... %s` és HMAC credential/signature | `0x02E1DBD4–0x02E1DCEA` / `0x02E1F1D4–0x02E1F2EA` | közvetlen request-builder xrefek | 0,99 `[P]` | runtime credential-ek helye, plaintext érték nincs |
| `CryptUnprotectData` | importnév raw `0x02E4EB86`, RVA `0x02E50186`; IAT `0x02E4D920` | DPAPI capability, nem plaintext secret | 0,99 `[P]` | védett adatkezelés |
| `BCryptGenRandom` | importnév raw `0x02E534DE`, RVA `0x02E54ADE`; IAT `0x02E4E6E8` | random API, nem titok | 0,99 `[P]` | kriptográfiai véletlen |
| `PrivateKey`, `PEM_read_bio_PrivateKey`, `private key does not match...` | OpenSSL/Botan string-pool | API-nevek és hibák | 0,99 `[P]` | nincs beágyazott privát kulcs bizonyítva |
| `BEGIN PRIVATE KEY`, `BEGIN RSA PRIVATE KEY`, `BEGIN OPENSSH PRIVATE KEY` | nincs plaintext találat | — | 0,99 `[P]` | nincs PEM privát kulcs |
| `AKIA...`, `AIza...`, `ghp_...`, `sk-...`, `xox...` | nincs plaintext találat | — | 0,99 `[P]` | nincs felismerhető API-key |
| JWT-szerű `eyJ...` | nincs printable JWT | egyetlen nyers `eyJ` minta `0x0797544` nem volt string | 0,95 `[P]` | nem dekódoltam és nem tekintem tokennek |
| `Rockstar Games, Inc.` | overlay `0x03315E42`, `0x03315E61` | Authenticode subject metadata | 1,00 `[P]` | public certificate subject, nem secret |
| DigiCert OCSP/CRL/AIA URL-ek | overlay `0x03315A77–0x0331797F` | Authenticode metadata | 1,00 `[P]` | public tanúsítványlánc, nem alkalmazásadat |

A `grants_token` és `Lock-Token` nevek érzékeny *artifactok*, de a jelentés szándékosan nem tartalmaz runtime tokenértéket, cookie-t, credentialt vagy kódolt bináris titkot. A látható `Authorization` és HMAC stringek kizárólag `%s` placeholder-ek.

## 18. False positive-ok és zajcsökkentés

| Zajliteral / minta | File offset | RVA | Xref | Confidence | Ok |
|---|---:|---:|---|---:|---|
| `GTA;` | `0x02B16631` | `0x02B17231` | nincs | 0,05 `[U]` | `.text` bytecode printable szakasz |
| `CfxInitSH` | `0x0047DBA6` | `0x0047E7A6` | nincs | 0,05 `[U]` | bytecode hasonló karakterlánc |
| `d="GTAV` | `0x02CFE7D9` | `0x02CFFDD9` | nincs | 0,05 `[U]` | adat/kód mintázat, nem resource literal |
| `Five` | `0x0047DFC1` | `0x0047EBC1` | nincs | 0,05 `[U]` | UTF-16 futamidőben fellépő rövid minta |
| `data`, `cach`, `ess\`, `cl2_` | `0x0047DDED–0x0047E03E` | `0x0047E9ED–0x0047EC3E` | nincs | 0,05 `[U]` | UTF-16 false positive a `.text` belső bájtmintáiból |
| `123456`, `defghi`, `TUVWXYZ...` | `0x02C04D50`, `0x02C04D80`, `0x02C05000` | `0x02C06350`, `0x02C06380`, `0x02C06600` | nincs | 0,10 `[U]` | crypto/test alphabet, nem credential |
| `N.cN`, `ra.eU` | `0x021E6072`, `0x0316C213` | `0x021E7672`, `0x0316D813` | nincs | 0,05 `[U]` | domain-regexnek látszó véletlen bináris szöveg |
| ASN.1 OID-ok (`1.3.6.1...`, `2.5.29...`) | `0x02E16…–0x02E1A…` | `0x02E17…–0x02E1B…` | nincs | 0,05 `[U]` | OID, nem IP |
| `255.255.255.255` | `0x02E1831D` | `0x02E1991D` | nincs | 0,20 `[U]` | OpenSSL sentinel, nem FiveM endpoint |
| `A8RM`, `NBr8`, `ccpJ` és hasonló `.data` runok | `0x030D3D6C` környéke | `0x030D536C` környéke | nincs | 0,05 `[U]` | RTTI/binary data printable szeletek |
| `curl.se` docs URL-ek | `0x02E1DA80–0x02E1DF03` | `0x02E1F080–0x02E1F503` | library xref | 0,05 `[U]` | dokumentációs link, nem hálózati cél |
| `ocsp/cacerts/crl*.digicert.com` | overlay | nincs RVA | certificate metadata | 0,05 `[U]` | Authenticode chain |

A `strings` ASCII rekordok 83 486 egyedi értéke nem jelent 83 486 valódi runtime stringet. Az importnevek, C++ RTTI, OpenSSL/Boost hibagyűjtemény, kódban véletlenül olvasható bájtok és a 276 OpenSSL source path miatt a jelentés szándékosan kurál.

## 19. Statikus következtetés

1. A component identitása és a resource-manifest alapján ez a FiveM/CitizenFX `adhesive` runtime, V8 9.3.345.16 kompatibilitással, GTA/rage/resource/legitimacy komponensekkel.
2. A `CitizenFX.ini` séma statikusan rekonstruálható: `[Game]`, `DefaultBuild`, `ReplaceExecutable`, továbbá a CLI-tartalomtól függően `PathCL2`/`IVPath` kulcskiválasztás; a `FiveM.app` runtime komponenskönyvtár létrehozási/ellenőrzési ágához tartozik.
3. A process/session/cache részlet több windows API-t használ, mint amit egy egyszerű stringkonfiguráció sugall: Toolhelp process/thread snapshot, WTS session query, named event, file mapping és crashometry path.
4. A beágyazott hálózati stack széles HTTP-auth és transfer támogatást tartalmaz, de a statikus literálok nem adnak FiveM szervercímet vagy tokent.
5. A sensitive-data inventory szerint a binary public tanúsítványt és kriptográfiai constant/API-neveket tartalmaz, de nem találtam plaintext privát kulcsot, credentialt vagy fix API tokent.
6. A registry subkey/value és a `CitizenFX_ToolMode` pontos felhasználása obfuszkált/közvetett vagy nem bizonyítható; ezt a jelentés nem dekódolta és nem állítja teljes konfiguráció-rekonstrukciónak.

## 20. Jelölési összegző

A dokumentum minden finding- és confidence-sora a `00` §6 globális szerződése szerint explicit `P`/`L`/`U` jelölést visel. A meglévő confidence-számértékek változatlanok, és a jelölés nem vezetett be új bizonyítékot.

- **Összes jelölt confidence-érték: 269** — ebből 264 táblázati finding-sor és 5 érték a §4 bizonyítékhierarchia-magyarázatból.
- `P` = **210**: közvetlenül megfigyelhető statikus horgony (szó szerinti literal a megadott file offseten/RVAn, közvetlen kód-xref, IAT- vagy import-descriptor-kötés, PE resource/overlay/CodeView-kötés, illetve lezárt teljes extrakciós sweep eredménye). Lefedett sáv: `1,00`, `0,99`, `0,98`, `0,95`.
- `L` = **43**: erős, de nem közvetlen szerep-, cél- vagy viselkedés-következtetés (string-pool, pointer-table, `nincs közvetlen xref` mellett erős API-kontextus, csoportosított/family sor, korlátolt negatív sweep). Lefedett sáv: `0,90`, `0,85`, `0,80`, `0,75`, `0,65`, `0,50`.
- `U` = **16**: nem megalapozott finding; a dokumentum saját `0,20` alatti false positive sávja (`0,20`, `0,10`, `0,05`), ahol a finding eleve elutasított vagy nem állítható.
- A negatív soroknál (`nincs plaintext találat`, `nincs közvetlen xref`) a jelölés a megfigyelt sweep-eredményre vonatkozik. A §1 `Korlát` sora (obfuszkált/kódolt blokkok nem dekódolva) változatlanul érvényes korlát, és a `00` §7 szerinti negatív finding-scope megmarad.
- Minden sor pontosan egy `P`/`L`/`U` értéket kapott; vegyes kettős jelölés nincs.
- Fejezetszámozás: a korábban számozatlan 19 `##` és 3 `###` címsor számozott lett (`§1`–`§19`, alfejezetek `§6.1`, `§10.1`, `§10.2`), hogy a korpusz-szintű `05 §k.m` hivatkozások értelmezhetők legyenek. A címsorokon kívül a szövegtörzs változatlan: egyetlen szám, RVA, string, státusz és confidence-érték sem módosult.
