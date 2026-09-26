# `adhesive.dll` — teljes kriptográfiai fingerprint és trust-static audit

## 1. Vizsgálati keret

| Claim | RVA | raw | Confidence |
|---|---:|---:|---|
| A vizsgált fájl 53 575 264 bájt, SHA-256 `91CC0AA006D7315CB042C8FA8DCA6C1E074A307BBA7DCC9EB5509C8A7B81934E`. | — | `0x0–0x3317e5f`, teljes fájl | Nagy (P) |
| PE32+ x86-64 DLL, image base `0x180000000`, entry point `RVA 0x2ab2770`. | `0x2ab2770` | `0x2ab1b70` | Nagy (P) |
| A PE timestamp `2026-09-11 15:06:18 UTC`. | Fejléccím, nem image RVA | `0x80` | Nagy (P) |
| A fájlverzió `1.0.0.36109`. | `0x3313100` | `0x330b300` | Nagy (P) |
| Az `FXCOMPONENT` erőforrás `adhesive`, `0.1.0`, és `vendor:openssl_ssl` függőséget ír elő. | `0x33133e0`, a függőségi string `0x3313508` | `0x330b5e0`, a függőségi string `0x330b708` | Nagy (P) |
| A cert blob a PE security directoryben, a legnagyobb szekció nyers vége utáni overlayben található; ezért nincs rendes image RVA-ja. | — | `0x3315600–0x3317e5f` | Nagy (P) |

A vizsgálat kizárólag statikus: a DLL-t nem futtattam, betöltöttem vagy dinamikusan instrumentáltam. A megadott RVA-k a `0x180000000` image base-re relatívak; a raw értékek 0-alapú fájleltolások. Az Authenticode security directory PE-ben file offsetként, nem image RVA-ként szerepel. A negatív eredményeket a teljes fájl ascii, UTF-16LE és UTF-16BE sweepje, az IAT-, thunk- és közvetlen `rel32`/RIP-relative referenciaelemzés, továbbá PE/ASN.1/resource/signature-parser vizsgálat adja.

**Confidence-skála:** nagy = közvetlen szerkezeti, import-, byte- vagy tanúsítványbizonyíték; közepes = statikus elérhetőség vagy részleges szemantika; alacsony = csak konstans-, string-, entrópia- vagy kontextusalapú következtetés.

**Globális `P` / `L` / `U` jelölés (az `adhesive-00-index.md` 6. fejezete szerint):** `nagy` (és az azonos szintű `magas`) = **P** (közvetlenül statikusan bizonyított), `közepes` = **L** (erős indoklású, de nem közvetlen), `alacsony` = **U** (a jelen fájlos vizsgálatból nem dönthető el, futásidő- vagy konfigurációfüggő). A betűjelölés minden finding- és konfidenciasorban explicit módon, a eredeti szintszó után szerepel; több pontból álló findingnél pontonként, a pontot megnevező szöveg után. Hibrid szint (`közepes/alacsony`, `Közepes-nagy`) esetén az eredeti érték változatlan marad, és a gyengébb szinthez tartozó betű az irányadó. A szintszavak és minden szám, RVA, raw, kulcs és státusz változatlan.

> **Kritikus értelmezési korlát:** a beágyazott Botan/OpenSSL konstansok, cipher-katalógusok, X.509-táblák, opcode-ok és nagy entrópájú tartományok kizárólag azt bizonyítják, hogy a kód/statikus adat jelen van a binárisban. **Nem bizonyítják, hogy az `adhesive` alkalmazásszintű futási útvonalon használja az adott algoritmust, kulcsot, cipher-listát vagy konstanst.**

## 2. Vezetői összefoglaló

| Terület | Statikus eredmény | Fő bizonyíték — RVA / raw | Confidence |
|---|---|---|---|
| Botan | Botan amalgamált forrás- és RTTI-nyomok jelen vannak; pontos Botan verzió nem azonosítható biztonságosan. | `0x2e102a6` / `0x2e0eca6`; `0x312aaf0` / `0x31294f0` | Nagy (P) a jelenlétnél, alacsony (U) a pontos verziónál |
| OpenSSL | `OpenSSL 1.1.1t 7 Feb 2023` van beágyazva, a curl OpenSSL backend és az `FXCOMPONENT` függőség is jelen van. | `0x2c29840` / `0x2c28240`; `0x3313508` / `0x330b708` | Nagy (P) |
| V8 | Külső `v8-9.3.345.16.dll`, 48 importált V8 API. | IAT `0x2e4d738–0x2e4d8b0` / raw `0x2e4c138–0x2e4c2b0` | Nagy (P) |
| Windows RNG | `BCryptGenRandom(NULL, buffer, length, BCRYPT_USE_SYSTEM_PREFERRED_RNG)` alakú statikus wrapper-hívás. | hívás `0x2b4b41d` / `0x2b4a81d` | Nagy (P) a call formájára, közepes (L) a futási elérhetőségre |
| TLS | TLS 1.2 és TLS 1.3 statikus OpenSSL setup-lista, valamint cipher-katalógus jelen van; explicit adhesive-policy nem adható meg. | TLS 1.3 setup `0x2b4faf9` / `0x2b4eef9`; TLS 1.2 setup `0x2b4fb37` / `0x2b4ef37` | Nagy (P) a statikus setupra, közepes/alacsony (U) az aktív policyra |
| X.509 | OpenSSL Windows `ROOT` store-import útvonal és külön Authenticode/CryptoAPI call chain jelen van. | `0x2a59dc0` / `0x2a591c0`; `0xb9ecd0` / `0xb9e0d0` | Nagy (P) |
| Authenticode | A fájl aláírt PKCS#7-t tartalmaz; a rendszerbiztonsági szolgáltató az auditkor `Valid` eredményt adott. | `0x3315600–0x3317e5f` | Nagy (P) |
| `WinVerifyTrust` | Import és thunk létezik, de közvetlen rel32/RIP-reference hívást nem sikerült igazolni. | IAT `0x2e4e1e8`, thunk `0x2beddd0`; raw `0x2e4cbe8`, `0x2bed1d0` | Közepes (L) |
| DPAPI | `CryptUnprotectData` import/thunk jelen van; közvetlen hívás nincs. `CryptProtectData` nincs importálva. | IAT `0x2e4d920`, thunk `0x2bed750`; raw `0x2e4c320`, `0x2becb50` | Közepes (L) |
| UUID | `UuidToStringA` és `RpcStringFreeA` közvetlenül hívódik egy nagy, obfuszkált funkcióban. | `0x10fbfb`, `0x10f28b`; raw `0x10effb`, `0x10e68b` | Nagy (P) |
| Jelszó/kulcs/credential | Nincs teljes PEM private-key marker, `client_secret`, `api_key` vagy `access_token`; a password/private-key hitok generikus OpenSSL/curl/Botan diagnosztika. | teljes raw `0x0–0x3317e5f` | Közepes (L) |
| Constant-time | AES-NI/PCLMULQDQ/SHA-NI és rendszer-RNG statikus jelek vannak; `memcmp`- és egy `rand` call anti-pattern indikátor, de titokeredet nincs bizonyítva. | `0x5ab42f`, `0x6711cd`, `0x2e4e280`, `0xe488c4`; raw `0x5aa82f`, `0x6705cd`, `0x2e4cc80`, `0xe47cc4` | Nagy (P) a jelekre, alacsony közepesre (U) a biztonsági következményre |

## 3. Botan

| Claim | RVA | raw | Confidence |
|---|---:|---:|---|
| Beágyazott forrásnyom: `..\..\fivem-private\components\adhesive\src\botan\botan_all.cpp`. | `0x2e102a6` | `0x2e0eca6` | Nagy (P) |
| Beágyazott forrásnyom: `..\..\fivem-private\components\adhesive\src\botan\botan_all.h`. | `0x2e11bfb` | `0x2e105fb` | Nagy (P) |
| Botan RTTI: `.?AVInvalid_Argument@Botan@@`. | `0x312aaf0` | `0x31294f0` | Nagy (P) |
| Botan általános fingerprint: AES-GCM, ChaCha20Poly1305, HMAC_DRBG, PBKDF2, Scrypt, ECDH/ECDSA, Curve25519/Ed25519 és SystemFunction036 nyomok. | `0x2e167cd`, `0x2e19aad`, `0x2e16a89`, `0x2e1a9b3`, `0x2e0ca1e`, `0x2e169c0`, `0x2e18208`, `0x2e18873`, `0x2e18886`, `0x2e1951a` | `0x2e151cd`, `0x2e184ad`, `0x2e15489`, `0x2e193b3`, `0x2e0b41e`, `0x2e153c0`, `0x2e16c08`, `0x2e17273`, `0x2e17286`, `0x2e17f1a` | Nagy (P) a statikus tartalomra |
| Pontos Botan major/minor/patch/datestamp nincs a binárisban; `BOTAN_VERSION`, `version_string`, `version_major`, `version_minor`, `version_patch` keresés nulla eredményt adott. | — | teljes raw `0x0–0x3317e5f` | Nagy (P) a negatív szöveges keresésre, alacsony (U) egy nem kiírt verzió kizárására |

A Botan-nevű kód jelenléte nagy bizonyosságú (`RVA 0x2e102a6` / `raw 0x2e0eca6`; confidence: nagy (P)). Az, hogy egy adott Botan-algoritmus az `adhesive` saját logikájában ténylegesen meghívódik, ebből nem állapítható meg (RVA/raw: fenti Botan-táblázatok; confidence: alacsony (U)).

## 4. OpenSSL 1.1.1t és V8

### 4.1 OpenSSL

| Claim | RVA | raw | Confidence |
|---|---:|---:|---|
| Verzióstring: `OpenSSL 1.1.1t  7 Feb 2023`. | `0x2c29840` | `0x2c28240` | Nagy (P) |
| OpenSSL build path: `C:\gl\builds\cfx-fivem-0\vendor\openssl\ssl\packet_local.h`. | `0x2e31b50` | `0x2e30550` | Nagy (P) |
| X.509 verifier forráspath: `vendor\openssl\crypto\x509\x509_vfy.c`. | `0x2e3b250` | `0x2e39c50` | Nagy (P) |
| RNG forráspath: `vendor\openssl\crypto\rand\drbg_lib.c`. | `0x2e3d540` | `0x2e3c940` | Nagy (P) |
| libcurl OpenSSL backend forráspath: `..\..\..\vendor\curl\lib\vtls\openssl.c`. | `0x2e156a9` | `0x2e140a9` | Nagy (P) |
| Az `FXCOMPONENT` erőforrás `vendor:openssl_ssl` függőséget deklarál. | `0x3313508` | `0x330b708` | Nagy (P) |
| Az X.509, ASN.1, PKCS#12, CMS, RSA, ECDSA, ECDH, X25519/Ed25519 és DRBG statikus katalógusok jelen vannak. | `0x2e1f000–0x2e4b000` | `0x2e0da00–0x2e49a00` | Nagy (P) a tartalomra, alacsony (U) az alkalmazásszintű használatra |

### 4.2 V8

| Claim | RVA | raw | Confidence |
|---|---:|---:|---|
| Importált DLL-nev: `v8-9.3.345.16.dll`. | `0x2e54b29` | `0x2e53529` | Nagy (P) |
| A V8 importtábla 48 bejegyzést tartalmaz. | IAT `0x2e4d738–0x2e4d8b0` | `0x2e4c138–0x2e4c2b0` | Nagy (P) |
| A jellegzetes API-k között `Isolate`, `Context`, `Script::Compile`, `Script::Run`, `ArrayBuffer`, `Uint8Array` és `JSON::Parse` található. | `0x2e4d738`, `0x2e4d830`, `0x2e4d790`, `0x2e4d888`, `0x2e4d828`, `0x2e4d860`, `0x2e4d878` | `0x2e4c138`, `0x2e4c230`, `0x2e4c190`, `0x2e4c288`, `0x2e4c228`, `0x2e4c260`, `0x2e4c278` | Nagy (P) |
| Alkalmazási V8 hibaüzenet: `Adhesive V8 error at %s: %s`. | `0x2e0e5ba` | `0x2e0cfba` | Nagy (P) |

A V8 importok link-szintű használatot bizonyítanak; futásidejű végrehajtást nem (`RVA 0x2e4d738–0x2e4d8b0` / `raw 0x2e4c138–0x2e4c2b0`; confidence: nagy (P) az importra, közepes (L) a runtime-use-ra).

## 5. `BCryptGenRandom`

| Claim | RVA | raw | Confidence |
|---|---:|---:|---|
| A `bcrypt.dll` egyetlen importja `BCryptGenRandom`. | IAT `0x2e4e6e8` | `0x2e4d0e8` | Nagy (P) |
| Import-thunk: `jmp [BCryptGenRandom]`. | `0x2bee430` | `0x2bed830` | Nagy (P) |
| A wrapper `RVA 0x2b4b40a–0x2b4b44d` meghívja az importot `NULL` providerrel, a caller által átadott bufferral és hosszzal. | `0x2b4b40a–0x2b4b44d` | `0x2b4a80a–0x2b4a84d` | Nagy (P) |
| Az ötödik argumentum `2`, azaz `BCRYPT_USE_SYSTEM_PREFERRED_RNG`. | call `0x2b4b41d` | `0x2b4a81d` | Nagy (P) |
| A wrapperhez nem találtam közvetlen `call rel32` hívót; közvetett/function-pointer használat ettől még lehetséges. | keresési tartomány `0x1000–0x2bed4b5` | `0x400–0x2beda00` | Közepes (L) |
| Botan `SystemFunction036`, OpenSSL `RAND_DRBG*`, `RAND_bytes` és `HMAC_DRBG` stringek jelen vannak, de ezek önmagukban nem bizonyítják az alkalmazás RNG-útvonalát. | `0x2e1951a`, `0x2e16a89`, `0x2e292a8`, `0x2e1ea18` | `0x2e17f1a`, `0x2e15489`, `0x2e27ca8`, `0x2c1d418` | Nagy (P) a stringekre, alacsony (U) a runtime-use-ra |

## 6. TLS 1.2/1.3 statikus setup és cipher-stringek

### 6.1 Protokoll- és setup-nyomok

| Claim | RVA | raw | Confidence |
|---|---:|---:|---|
| `TLSv1.3` protokollnév jelen van. | `0x2e1a8bc` | `0x2e192bc` | Nagy (P) |
| `TLSv1.2` protokollnév jelen van. | `0x2e1af44` | `0x2e19944` | Nagy (P) |
| OpenSSL `max_protocol` és `min_protocol` konfigurációs kulcsok jelen vannak. | `0x2e300f8`, `0x2e30108` | `0x2e2eaf8`, `0x2e2eb08` | Nagy (P) |
| libcurl `CURLOPT_SSLVERSION` hibakezelési útvonala jelen van. | `0x2e16662` | `0x2e15062` | Nagy (P) |
| TLS 1.3 list: `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256`. | string `0x2e4a600`; code xref `0x2b4faf9` | string `0x2e49000`; xref `0x2b4eef9` | Nagy (P) |
| A TLS 1.3 listát egy SSL-context jellegű inicializáló függvény `0x2b4fa01–0x2b4fd1c` adja át a `0x2b582e0` setup-rutinak. | `0x2b4fa01–0x2b4fd1c`, hívás `0x2b4fb03` | `0x2b4ee01–0x2b4f11c`, raw `0x2b4ef03` | Közepes-nagy (L) |
| TLS 1.2 candidate string: `ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384`. | string `0x2e46450`; selector xref `0x2b58565` | string `0x2e44e50`; xref `0x2b57965` | Nagy (P) |
| A TLS 1.2 selector `0x2b58400–0x2b58595` közvetlenül meghívódik ugyanabban az SSL-context setupban `0x2b4fb37` címen. | `0x2b4fb37` | `0x2b4ef37` | Nagy (P) |
| A TLS 1.2/1.3 setupfüggvényekben vannak `failed setting cipher list`, `TLS 1.3 cipher selection` és `failed setting TLS 1.3 cipher suite` hibák. | `0x2a5a5a5`, `0x2a5a62a`, `0x2a5d1b9` | `0x2a599a5`, `0x2a59a2a`, `0x2a5c5b9` | Nagy (P) |
| Nem találtam egyértelmű, adhesive-specifikus literal `min=max=TLSv1.2` vagy kizárólag `TLSv1.2` policyt; a numerikus `CURLOPT_SSLVERSION` beállítás nem zárható ki. | — | teljes raw `0x0–0x3317e5f` | Közepes (L) |

### 6.2 Cipher-katalógus

| Claim | RVA | raw | Confidence |
|---|---:|---:|---|
| A bináris a teljes OpenSSL TLS suite-neveket tartalmazza, köztük AES-GCM, AES-CCM, ChaCha20-Poly1305, ECDHE, DHE, PSK, CBC és GCM neveket. | `0x2e3f550–0x2e469d0` körüli táblák | `0x2e2df50–0x2e453d0` körüli táblák | Nagy (P) a katalógusra, alacsony (U) az engedélyezésre |
| `TLS_RSA_WITH_NULL_MD5` definíció jelen van. | `0x2e459e0` | `0x2e443e0` | Nagy (P) a stringre, alacsony (U) a használatára |
| `RC4-HMAC-MD5` definíció jelen van. | `0x2e459a0` | `0x2e443a0` | Nagy (P) a stringre, alacsony (U) a használatára |
| `No SSLv2 support` és `No SSLv3 support` szöveg jelen van. | `0x2e0c89c`, `0x2e0c88b` | `0x2e0b29c`, `0x2e0b28b` | Nagy (P) a stringre, közepes (L) a policyra |

**Következtetés:** a statikus SSL-context setup mindkét modern protokollhoz tartozó listát kezeli (`RVA 0x2b4faf9` / `raw 0x2b4eef9`; `RVA 0x2b4fb37` / `raw 0x2b4ef37`; confidence: nagy (P)). A TLS 1.2/1.3 támogatás és a fenti cipher-lista nem egyezik bizonyítékkal arra, hogy egy adott hálózati kapcsolat ezt a listát használta (`RVA 0x2e4a600`, `0x2e46450` / `raw 0x2e49000`, `0x2e44e50`; confidence: alacsony (U)). Ehhez runtime trace vagy külön, célzott konfiguráció-elemzés kellene; a DLL-t ez az audit nem futtatta.

## 7. X.509 store

| Claim | RVA | raw | Confidence |
|---|---:|---:|---|
| Az OpenSSL Windows root-store loader `0x2a59dc0–0x2a5d1d1` a `ROOT` rendszerstore-t nyitja. | `0x2a59dc0–0x2a5d1d1` | `0x2a591c0–0x2a5c5d1` | Nagy (P) |
| A wide `ROOT` literal és a `CertOpenSystemStoreW` hívás. | string `0x2e1f8c8`, call `0x2a5a796` | string `0x2e1e2c8`, call `0x2a59b96` | Nagy (P) |
| A betöltő függvény két `CertEnumCertificatesInStore` hívást használ. | `0x2a5a7bf`, `0x2a5a813` | `0x2a59bbf`, `0x2a59c13` | Nagy (P) |
| A loader `CertGetIntendedKeyUsage` és `CertGetEnhancedKeyUsage` hívásokat használ. | `0x2a5a897`, `0x2a5a8d6` | `0x2a59c97`, `0x2a59cd6` | Nagy (P) |
| A ROOT store egy másik, ANSI belépési pontja. | store `0x2e1622e`, call `0x2a5ad72` | store `0x2e14c2e`, call `0x2a5a172` | Nagy (P) |
| Hibaüzenet: `error importing Windows CA store, continuing anyway`. | `0x2e0bd46` | `0x2e0a746` | Nagy (P) |
| Az X.509 store loadert két másik statikus OpenSSL-kódhely hívja. | calls `0x2a59751`, `0x2a5977c` | `0x2a58b51`, `0x2a58b7c` | Nagy (P) a belső statikus használatra, közepes (L) az alkalmazásszintű elérhetőségre |

A teljes releváns `CRYPT32.dll` IAT:

| API | IAT RVA | IAT raw | Confidence |
|---|---:|---:|---|
| `CertCloseStore` | `0x2e4d8c0` | `0x2e4c2c0` | Nagy (P) |
| `CertEnumCertificatesInStore` | `0x2e4d8c8` | `0x2e4c2c8` | Nagy (P) |
| `CertFindCertificateInStore` | `0x2e4d8d0` | `0x2e4c2d0` | Nagy (P) |
| `CertFreeCertificateContext` | `0x2e4d8d8` | `0x2e4c2d8` | Nagy (P) |
| `CertGetEnhancedKeyUsage` | `0x2e4d8e0` | `0x2e4c2e0` | Nagy (P) |
| `CertGetIntendedKeyUsage` | `0x2e4d8e8` | `0x2e4c2e8` | Nagy (P) |
| `CertGetNameStringW` | `0x2e4d8f0` | `0x2e4c2f0` | Nagy (P) |
| `CertOpenSystemStoreA` | `0x2e4d8f8` | `0x2e4c2f8` | Nagy (P) |
| `CertOpenSystemStoreW` | `0x2e4d900` | `0x2e4c300` | Nagy (P) |

## 8. Authenticode és trust

### 8.1 `CryptQueryObject` / `CryptMsg` call chain

| Claim | RVA | raw | Confidence |
|---|---:|---:|---|
| `CryptQueryObject` import és közvetlen hívás. | IAT `0x2e4d918`, call `0xb9edae` | IAT `0x2e4c318`, call `0xb9e1ae` | Nagy (P) |
| A `CryptQueryObject` hívás `objectType=1`, `expectedMsgType=0x400`, `expectedContentType=2` és `flags=0` értékeket állít be. | `0xb9ed9a–0xb9edae` | `0xb9e19a–0xb9e1ae` | Nagy (P) a közvetlen argumentumokra, közepes (L) a pontos content-policyra |
| A tartalmazó funkció `0xb9ecd0–0xb9ee0b` erősen obfuszkált, számításból előállított hívást használ. | `0xb9ecd0–0xb9ee0b` | `0xb9e0d0–0xb9e20b` | Nagy (P) |
| `CryptMsgGetParam` két közvetlen hívása `param=6` értékkel, azaz signer-info paraméter lekéréssel konzisztens. | `0xba0e1f`, `0xba2ee1` | `0xba021f`, `0xba22e1` | Nagy (P) |
| `CertFindCertificateInStore` közvetlen hívása `findFlags=0xb0000` értékkel. | `0xba3aa7` | `0xba2ea7` | Nagy (P) |
| `CertGetNameStringW` két közvetlen hívása `nameType=4` értékkel. | `0xba58c6`, `0xba6ebc` | `0xba4cc6`, `0xba62bc` | Nagy (P) |
| `CryptMsgClose` import és thunk jelen van. | IAT `0x2e4d908`, thunk `0xb75c3a` | IAT `0x2e4c308`, thunk `0xb7503a` | Nagy (P) az elérhetőségre |

A közvetlen `CryptQueryObject` → `CryptMsgGetParam(6)` → store-find/name útvonal erős statikus bizonyíték egy PKCS#7/Authenticode-alakú üzenet és signer információk feldolgozására (`RVA 0xb9edae`, `0xba0e1f`, `0xba2ee1`, `0xba3aa7` / `raw 0xb9e1ae`, `0xba021f`, `0xba22e1`, `0xba2ea7`; confidence: nagy (P)). A pontos elfogadási policy és a hívó objektum alkalmazási jelentősége a szimbolizálatlan, obfuszkált kód miatt csak közepesen adható meg (`RVA 0xb9ecd0–0xb9ee0b` / `raw 0xb9e0d0–0xb9e20b`; confidence: közepes (L)).

### 8.2 `WinVerifyTrust`

| Claim | RVA | raw | Confidence |
|---|---:|---:|---|
| `WINTRUST.dll!WinVerifyTrust` importálva. | IAT `0x2e4e1e8` | `0x2e4cbe8` | Nagy (P) |
| Import-thunk: `jmp [WinVerifyTrust]`. | `0x2beddd0` | `0x2bed1d0` | Nagy (P) |
| A teljes `.text` tartományban nem találtam közvetlen `call rel32`-t a WinVerifyTrust thunkra, és a gyakori RIP-relative `LEA/MOV` hivatkozási mintát sem. | keresés `0x1000–0x2bed4b5` | `0x400–0x2beda00` | Közepes (L) |
| `WINTRUST_ACTION_GENERIC_VERIFY_V2`, `WINTRUST_DATA` és `WTD_UI_NONE` ASCII/UTF-16 literal nincs. | — | teljes raw `0x0–0x3317e5f` | Nagy (P) a negatív literalkeresésre, közepes (L) a policy-következtetésre |

A bináris obfuszkált, számított célcímeket használ, ezért a negatív xref-scan nem zárja ki a közvetett vagy adatból felépített hívást (`RVA 0x2beddd0` / `raw 0x2bed1d0`; keresési tartomány `RVA 0x1000–0x2bed4b5` / `raw 0x400–0x2beda00`; confidence: közepes (L)).

### 8.3 A beágyazott Authenticode

| Claim | RVA | raw | Confidence |
|---|---:|---:|---|
| `WIN_CERTIFICATE`: `dwLength=0x2860`, `wRevision=0x200`, `wCertificateType=2` (`PKCS_SIGNED_DATA`). | —, overlay | header `0x3315600–0x3315607` | Nagy (P) |
| PKCS#7 kezdet és hossz. | —, overlay | `0x3315608`, length `0x2858`, vég `0x3317e5f` | Nagy (P) |
| A security blob SHA-256 `C670620DD04F80C823C66CC831D4481BD32D26E589DFBC3E57CFDC2EA0311951`. | —, overlay | `0x3315600–0x3317e5f` | Nagy (P) |
| A Windows Authenticode-ellenőrzés az auditkor `Valid`, `Signature verified` eredményt adott. | —, overlay | `0x3315600–0x3317e5f` | Nagy (P) |
| A signer `Rockstar Games, Inc.`, RSA-3072, sha256WithRSAEncryption, Code Signing EKU, Digital Signature key usage. | —, overlay | cert `0x3315d49–0x3316435` | Nagy (P) |
| Signer certificate SHA-256 `65866007102FF66498C1EF739CF23DFF71AE3D08DA0D9D759B89D1A409C4208F`; SHA-1 thumbprint `FF0EE06434B1695115A35FB077DE538FD1F66D9C`. | —, overlay | `0x3315d49–0x3316435` | Nagy (P) |
| Signer érvényesség UTC: `2026-07-21 00:00:00`–`2027-09-05 23:59:59`. | —, overlay | `0x3315d49–0x3316435` | Nagy (P) |
| A timestamp signer `DigiCert SHA256 RSA4096 Timestamp Responder 2026 1`, RSA-4096. | —, overlay | `0x33167a1–0x3316e91` | Nagy (P) |
| Timestamp signer SHA-1 thumbprint `51D9ABDA034973D84F4266ACA48248E6B369C439`. | —, overlay | `0x33167a1–0x3316e91` | Nagy (P) |

A blobban található X.509 DER-ek:

| Tanúsítvány | raw | Fingerprint / algoritmus | Confidence |
|---|---:|---|---|
| `DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1` | `0x3315695–0x3315d48` | SHA-256 `46011EDE1C147EB2BC731A539B7C047B7EE93E48B9D3C3BA710CE132BBDFAC6B`; sha384RSA; RSA-4096 | Nagy (P) |
| `Rockstar Games, Inc.` code signer | `0x3315d49–0x3316435` | SHA-256 `65866007102FF66498C1EF739CF23DFF71AE3D08DA0D9D759B89D1A409C4208F`; sha256RSA; RSA-3072 | Nagy (P) |
| `DigiCert SHA256 RSA4096 Timestamp Responder 2026 1` | `0x33167a1–0x3316e91` | SHA-256 `2DA09DA7F4131F9FE72DB6C5E6E9C9656755AF043F1EA742CC0D2120E141EBFC`; sha256RSA; RSA-4096 | Nagy (P) |
| `DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1` | `0x3316e92–0x3317549` | SHA-256 `CA0B1554ECD901EA19DCAD8749E9F2648C8D6DFCEA1ADD9D2C2109415BB82CCD`; sha256RSA; RSA-4096 | Nagy (P) |
| `DigiCert Trusted Root G4` cross-certificate | `0x331754a–0x3317ada` | SHA-256 `33846B545A49C9BE4903C60E01713C1BD4E4EF31EA65CD95D69E62794F30B941`; sha384RSA; RSA-4096 | Nagy (P) |

A blob tartalmaz kód-aláíró és RFC3161 timestamp láncot (`raw 0x3315608–0x3317e5f`; RVA nincs, overlay; confidence: nagy (P)). A `Valid` eredmény a vizsgálatkor telepített Windows trust store állapotát is tükrözi; nem állítás arról, hogy minden korábbi vagy jövőbeli Windows konfigurációban érvényes lesz (`raw 0x3315600–0x3317e5f`; RVA nincs; confidence: nagy (P) az aktuális eredményre, közepes (L) a jövőbeli konfigurációkra).

## 9. DPAPI és `CryptUnprotectData`

| Claim | RVA | raw | Confidence |
|---|---:|---:|---|
| `CryptUnprotectData` importálva. | IAT `0x2e4d920` | `0x2e4c320` | Nagy (P) |
| Import-thunk: `jmp [CryptUnprotectData]`. | `0x2bed750` | `0x2becb50` | Nagy (P) |
| A teljes `.text` tartományban nem találtam közvetlen rel32 vagy gyakori RIP-relative `LEA/MOV` referenciát a thunkra. | `0x1000–0x2bed4b5` | `0x400–0x2beda00` | Közepes (L) |
| `CryptProtectData` és `CryptProtectMemory` nincs importálva vagy ASCII/UTF-16 néven jelen. | — | teljes raw `0x0–0x3317e5f` | Nagy (P) a negatív névkeresésre |
| `DPAPI` literal nincs. | — | teljes raw `0x0–0x3317e5f` | Nagy (P) |

**Következtetés:** DPAPI-képesség statikusan importálva van (`RVA 0x2e4d920`, thunk `0x2bed750` / `raw 0x2e4c320`, `0x2becb50`; confidence: nagy (P)), de alkalmazásszintű DPAPI-használat nincs bizonyítva (keresési tartomány `RVA 0x1000–0x2bed4b5` / `raw 0x400–0x2beda00`; confidence: közepes (L)). Az obfuszkáció miatt ez nem kizárólagos negatív eredmény.

## 10. UUID

| Claim | RVA | raw | Confidence |
|---|---:|---:|---|
| `UuidToStringA` import és közvetlen hívás; a hívás output bufferbe ír. | IAT `0x2e4e1d8`, call `0x10fbfb` | IAT `0x2e4cbd8`, call `0x10effb` | Nagy (P) |
| `RpcStringFreeA` import és közvetlen hívás ugyanabban a `0x10f190–0x10fdb5` funkcióban. | IAT `0x2e4e1d0`, call `0x10f28b` | IAT `0x2e4cbd0`, call `0x10e68b` | Nagy (P) |
| Az UUID-függvény `RPCRT4.dll`-ből importál; `UuidCreate` és `UuidCreateEx` nincs importálva/literal. | IAT `0x2e4e1d0–0x2e4e1d8` | `0x2e4cbd0–0x2e4cbd8`; teljes fájlkeresés `0x0–0x3317e5f` | Nagy (P) |

Ez a formázási útvonal statikosan elérhető (`RVA 0x10fbfb`, `0x10f28b` / `raw 0x10effb`, `0x10e68b`; confidence: nagy (P)); az, hogy egy adott runtime folyamat UUID-t formáz, nem bizonyított (ugyanaz az evidence; confidence: közepes (L)).

## 11. Jelszó-, private-key- és credential-keresések

| Keresés | Eredmény | RVA | raw | Confidence |
|---|---:|---:|---:|---|
| `-----BEGIN PRIVATE KEY-----` | 0 ASCII, 0 UTF-16LE, 0 UTF-16BE | — | teljes `0x0–0x3317e5f` | Nagy (P) |
| `-----BEGIN RSA PRIVATE KEY-----` | 0 / 0 / 0 | — | teljes `0x0–0x3317e5f` | Nagy (P) |
| `-----BEGIN EC PRIVATE KEY-----` | 0 / 0 / 0 | — | teljes `0x0–0x3317e5f` | Nagy (P) |
| `-----BEGIN OPENSSH PRIVATE KEY-----` | 0 / 0 / 0 | — | teljes `0x0–0x3317e5f` | Nagy (P) |
| `-----BEGIN ENCRYPTED PRIVATE KEY-----` | 0 / 0 / 0 | — | teljes `0x0–0x3317e5f` | Nagy (P) |
| `client_secret`, `api_key`, `access_token` | 0 találat | — | teljes `0x0–0x3317e5f` | Nagy (P) |
| `passwd` | 0 | — | teljes `0x0–0x3317e5f` | Nagy (P) |
| `password` | 12 pontos lowercase byte-előfordulás | — | `0x2e0ccf6`, `0x2e1026c`, `0x2e237f0`, `0x2e362b3–0x2e36351`, `0x2e392c4`, `0x2e41270` | Nagy (P) |
| `passphrase` | 2 pontos előfordulás | `0x2e1237c`, `0x2e2a228` | `0x2e10d7c`, `0x2e29628` | Nagy (P) |
| `credential` | 1 pontos előfordulás | `0x2e1f274` | `0x2e1af74` | Nagy (P) |
| `private key` és kapcsolódó API-nevek | 70 string | jellemzően `0x2e0a000–0x2e480000` | `0x2e09000–0x2e470000` | Nagy (P) a szövegre |

A hitok minta:

- `could not parse PKCS12 file, check password` — `RVA 0x2e0e5d3`, raw `0x2e0ccd3`; confidence: nagy (P).
- `could not load PEM client certificate ... wrong pass phrase` — `RVA 0x2e1d819`, raw `0x2e1c219`; confidence: nagy (P).
- `Authorization: ... Credential=%s/%s ...` — `RVA 0x2e1f2ea`, raw `0x2e1dcea`; confidence: nagy (P).
- `PKCS12 import password` — `RVA 0x2e37900`, raw `0x2e36300`; `PEM_write_PrivateKey` — `RVA 0x2e22e08`, raw `0x2e21808`; `X509_check_private_key` — `RVA 0x2e22940`, raw `0x2e21340`; confidence: nagy (P) a statikus katalógus-stringekre, alacsony (U) az alkalmazásszintű használatra.

**Negatív eredmény:** nem találtam beágyazott jelszóértéket, credential tokent vagy teljes PEM private key blokkot (teljes raw `0x0–0x3317e5f`; RVA a mapped és overlay tartományokra együttesen; confidence: nagy (P) a literálkeresésre). Ez nem zárja ki obfuszkált, DER/bináris, később letöltött vagy runtime-ból származó kulcsokat; a bizonyíték erőssége közepes (ugyanaz a raw sweep; confidence: közepes (L)).

## 12. Kriptográfiai konstansok és táblák

### 12.1 Közvetlenül azonosított konstans-/táblanyomok

| Fingerprint | RVA | raw | Azonosítás | Confidence |
|---|---:|---:|---|---|
| AES inverse S-box kezdete `52 09 6a d5 30 36 a5 38 ...` | `0x2c45950` | `0x2c44350` | 256 bájtos, szabványos AES inverse S-box | Nagy (P) |
| SHA-256 K-tábla eleje: `0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5`, majd ismétlődő lane-értékek. | `0x2a75540` | `0x2a74940` | K256 lookup | Nagy (P) |
| SHA-512 K0 `0x23ef65cd428a2f98` és az azt követő 64 bites konstanssor. | `0x2a7a384` | `0x2a79784` | K512 lookup | Nagy (P) |
| ChaCha/Salsa konstans `expand 32-byte k`. | `0x2a932c0` | `0x2a926c0` | 32 bájtos szókonstans | Nagy (P) |
| NIST P-256 prime `FFFFFFFF00000001...FFFFFFFF`. | `0x2c0c4e4` | `0x2c0aee4` | Duplikált 32 bájtos prímkonstans | Nagy (P) |
| NIST P-256 order `FFFFFFFF00000000FFFFFFFF...FC632551`. | `0x2c0c584` | `0x2c0af84` | Csoport-rend lookup | Nagy (P) |
| `09 00...00`, azaz standard X25519 basepoint kezdete. | `0x2c657c4` | `0x2c641c4` | 32 bájtos basepoint | Nagy (P) |
| CRC-32 table kezdete `00000000 77073096 ee0e612e 990951ba ...`. | `0x2c9b5d0` | `0x2c99fd0` | 256 × 32 bites CRC lookup | Nagy (P) |
| `AESENC` opcode: 363 statikus előfordulás. | első `0x5ab42f` | első `0x5aa82f` | x86 AES-NI kód | Nagy (P) |
| `PCLMULQDQ` opcode: 42 statikus előfordulás. | első `0x6711cd` | első `0x6705cd` | Carry-less multiply/GCM-jelű kód | Nagy (P) |
| `SHA256MSG1` opcode: 13 statikus előfordulás. | első `0x2a758c9` | első `0x2a74cc9` | SHA-NI kód | Nagy (P) |
| A kanonikus AES forward S-box 32 bájtos prefixe nincs teljes fájlszinten megtalálható; ez nem zárja ki generált/transzformált táblát. | — | teljes `0x0–0x3317e5f` | Negatív pontos keresés | Nagy (P) |
| A standard Ed25519 `d` 32 bájtos prefixe nincs megtalálva, miközben Ed25519/Curve25519 stringek vannak. | — | teljes `0x0–0x3317e5f` | Negatív konstanskeresés | Közepes (L) |

### 12.2 Szekció- és 4 KiB-oldal entrópia

| Tartomány | Shannon entrópia | Confidence |
|---|---:|---|
| `.text` `RVA 0x1000`, raw `0x400`, raw hossz `0x2bed600` | `6.354389` bit/bájt | Nagy (P) |
| `.rdata` `RVA 0x2bef000`, raw `0x2beda00`, raw hossz `0x4ca000` | `6.067497` bit/bájt | Nagy (P) |
| `.data` `RVA 0x30b9000`, raw `0x30b7a00`, raw hossz `0x24e000` | `3.837675` bit/bájt | Nagy (P) |
| `.reloc` `RVA 0x3314000`, raw `0x330ba00`, raw hossz `0x9c00` | `5.477351` bit/bájt | Nagy (P) |

A `>= 7,5` bit/bájt küszöböt elérő 4 KiB-os, összefüggő raw oldalak:

| raw | RVA | Csúcs entrópia | Statikus megjelenés | Confidence |
|---:|---:|---:|---|---|
| `0x2a96000–0x2a97000` | `0x2a96c00–0x2a97c00` | `7.965173` | A kezdet érvényes x86-64 kód; ez önmagában nem zárja ki a titkot, de a magas entrópia sem bizonyít titkot. | Nagy (P) az entrópia, magas (P) az x86-kód, alacsony (U) a szemantika |
| `0x2c3d000–0x2c44000` | `0x2c3e600–0x2c45600` | `7.996695` | Descriptor/table-szerű tartalom; RIP-reference a `0x2b1fcbf` címen. | Nagy (P) az entrópia/xref, közepes (L) a táblajelleg |
| `0x2c4c000–0x2c4f000` | `0x2c4d600–0x2c50600` | `7.948239` | Szétszórt, sok nulla bájttal kevert lookup-szerű értékek. | Nagy (P) az entrópia, alacsony (U) a szemantika |
| `0x2c50000–0x2c51000` | `0x2c51600–0x2c52600` | `7.760299` | Több 64/128 bites nagyságrendű érték és ismétlődő nulla-terminusok. | Nagy (P) az entrópia, alacsony (U) a szemantika |
| `0x2c98000–0x2c99000` | `0x2c99600–0x2c9a600` | `7.923134` | Kis egész- és descriptor-szerű értékek. | Nagy (P) az entrópia, közepes (L) a táblajelleg |
| `0x2ca9000–0x2cb4000` | `0x2caa600–0x2cb5600` | `8.000000` | Sűrű 16 bites lookup-szerű értéktáblák. | Nagy (P) az entrópia, közepes (L) a kriptográfiai eredet |
| `0x2cbb000–0x2cbc000` | `0x2cbc600–0x2cbd600` | `7.526747` | Ismétlődő 16 bites értékpárok. | Nagy (P) az entrópia, alacsony (U) a szemantika |
| `0x2cbf000–0x2cc0000` | `0x2cc0600–0x2cc1600` | `7.686464` | 16 bites lookup-szerű értékek. | Nagy (P) az entrópia, alacsony (U) a szemantika |
| `0x3316000–0x3317000` | —, overlay | `7.500109` | Az Authenticode blob része; nyilvános tanúsítványi és aláírási adat. | Nagy (P) |

A fenti, `.text`beli tartományok (`RVA 0x2a96c00–0x2cc1600` / `raw 0x2a96000–0x2cc0000`; confidence: nagy (P) az elhelyezkedésre) pusztán magas entrópia alapján nem nevezhetők titkos kulcsnak, kódolásnak vagy exploit-payloadnak (confidence: nagy (P)). A dokumentum nem tartalmaz kulcsletörési vagy exploit-receptet.

## 13. Constant-time és anti-pattern statikus jelek

| Jel | RVA | raw | Értékelés | Confidence |
|---|---:|---:|---|---|
| `BCryptGenRandom` system-preferred wrapper | `0x2b4b41d` | `0x2b4a81d` | Pozitív RNG-jel; a hívó elérhetősége külön kérdés. | Nagy (P) a wrapperre, közepes (L) a runtime-use-ra |
| AES-NI, PCLMULQDQ és SHA-NI opcode-ok | `0x5ab42f`, `0x6711cd`, `0x2a758c9` | `0x5aa82f`, `0x6705cd`, `0x2a74cc9` | Fixed-latency végrehajtásra alkalmas implementációs jel, nem alkalmazási policy-bizonyíték. | Nagy (P) |
| C `memcmp` import/thunk és 110 közvetlen rel32 call a `.text`ben. | IAT `0x2e4e280`, thunk `0x2bedec0`; példa call `0x2b943ac` | IAT `0x2e4cc80`, thunk `0x2bed2c0`; példa `0x2b37bac` | Nem constant-time-garancia; időzítési anti-pattern csak titokfüggő, korai kilépéssel használt összehasonlításnál lenne. Data-flow nincs igazolva. | Nagy (P) a jelenlétre, alacsony (U) a biztonsági hatásra |
| C `rand` import és egyetlen közvetlen hívás `0xe48840–0xe48977` funkcióban. | IAT `0x2e4e6a0`, call `0xe488c4` | IAT `0x2e4d0a0`, call `0xe47cc4` | A visszatérés `% 5` szerint két ötágú dispatchhez használódik. Nem kriptográfiai PRNG; titok/nonceeredet nincs bizonyítva. | Nagy (P) a callra, alacsony (U) a kockázatosságra |
| `strcmp`: 85 közvetlen rel32 call; `strstr`: 4. | thunks `0x2bee3b0`, `0x2bee420` | thunks `0x2bed7b0`, `0x2bed820` | Általános nem constant-time string API-k; érzékeny adatú használat nincs bizonyítva. | Nagy (P) a számokra, alacsony (U) a kockázatra |
| `CRYPTO_memcmp`, `constant_time`, `timing_safe` név nincs a statikus stringkatalógusban. | — | teljes `0x0–0x3317e5f` | Negatív jel; inlining és symbol stripping miatt nem zárja ki constant-time kódot. | Közepes (L) |
| Számításból előállított, obfuszkált hívások és adatfolyamok. | példa `0xb9ecd0–0xb9ee0b`, `0x10f190–0x10fdb5` | `0xb9e0d0–0xb9e20b`, `0x10e590–0x10efb5` | A teljes constant-time/adatfolyam-audit korlátozott. | Nagy (P) |

**Következtetés:** a binárisban vannak modern, rendszer-RNG-t és hardveres kriptográfiai műveleteket használó statikus implementációs jelek (`RVA 0x2b4b41d`, `0x5ab42f`, `0x6711cd`, `0x2a758c9` / `raw 0x2b4a81d`, `0x5aa82f`, `0x6705cd`, `0x2a74cc9`; confidence: nagy (P)), de ebből nem állapítható meg, hogy minden releváns összehasonlítás vagy kriptográfiai útvonal constant-time (`RVA 0xb9ecd0–0xb9ee0b` / `raw 0xb9e0d0–0xb9e20b`; confidence: közepes (L)). A `memcmp`, `strcmp` és `rand` előfordulások auditálható anti-pattern jelek (`RVA 0x2bedec0`, `0x2bee3b0`, `0xe488c4` / `raw 0x2bed2c0`, `0x2bed7b0`, `0xe47cc4`; confidence: nagy (P)), de a titokeredet hiánya miatt önmagukban sebezhetőség-bizonyítékok sem (confidence: alacsony (U)).

## 14. Végső értékelés

| Claim | Evidence — RVA / raw | Confidence |
|---|---|---|
| A statikus kriptográfiai felszín széles: Botan, OpenSSL 1.1.1t, V8, Windows BCrypt, TLS 1.2/1.3, X.509, Authenticode és DPAPI import egyaránt jelen van. | `0x2e102a6`/`0x2e0eca6`; `0x2c29840`/`0x2c28240`; `0x2e4d738`/`0x2e4c138`; `0x2e4e6e8`/`0x2e4d0e8`; `0x2e4a600`/`0x2e49000`; `0x2e4d8c0–0x2e4d920`/`0x2e4c2c0–0x2e4c320` | Nagy (P) a statikus felületre |
| Az OpenSSL Windows root-store loader a `ROOT` store-t nyitja; ez nem általánosítja az állítást a teljes DLL trust-folyamatára. A signer blob ténylegesen Rockstar Games CA-lánccal és timestamp-tel aláírt. | `0x2a5a796`/`0x2a59b96`; `0x3315600–0x3317e5f` | Nagy (P) |
| `WinVerifyTrust` és `CryptUnprotectData` import/thunk tényleges alkalmazásszintű meghívása nincs statikailag igazolva. | `0x2beddd0`/`0x2bed1d0`; `0x2bed750`/`0x2becb50` | Közepes (L) |
| Nincs pozitív embedded password/private-key/credential finding; a hitok library diagnostics. | teljes raw `0x0–0x3317e5f`; reprezentatív `0x2e0ccd3`, `0x2e1c219`, `0x2e1dcea` | Közepes (L) |
| A kriptográfiai konstansok és high-entropy tartományok nem önmagukban bizonyítják az alkalmazásszintű használatot, és nem bizonyítanak sebezhetőséget. | például `0x2c45950`/`0x2c44350`; `0x2caa600`/`0x2ca9000` | Nagy (P) |

**Végső confidence:** nagy (P) a fingerprint-importok, stringek, opcode-ok, tanúsítványok és közvetlen call site-ok azonosítására (`RVA 0x2e102a6`, `0x2c29840`, `0x2e4d738`, `0x2e4e6e8`, `0xb9edae` / `raw 0x2e0eca6`, `0x2c28240`, `0x2e4c138`, `0x2e4d0e8`, `0xb9e1ae`; confidence: nagy (P)); közepes (L) a közvetett runtime-elérhetőségre és a negatív titokkeresésre (`RVA 0x2beddd0`, `0x2bed750` / `raw 0x2bed1d0`, `0x2becb50`; teljes raw `0x0–0x3317e5f`; confidence: közepes (L)); alacsony (U) minden olyan állításra, amely kizárólag konstans-, entrópia- vagy cipher-katalógus-tartalomból vezet le alkalmazásszintű viselkedést (`RVA 0x2c45950`, `0x2e4a600` / `raw 0x2c44350`, `0x2e49000`; confidence: alacsony (U)).

## 15. `P` / `L` / `U` jelölési összegzés

Ez a blokk a dokumentum confidence-jelölésének konformancia-javítását rögzíti, nem új evidence-ot ad hozzá.

- **Hatókör:** a dokumentum összes `152` konfidenciát hordozó táblázati sora és `16` prose confidence-állítása, összesen `168` jelölt tétel. Az 1. fejezet scale-definíciója és a 18. sor kritikai értelmezési korlátja nem finding, ezért változatlan.
- **Alkalmazott megfeleltetés:** `nagy` (és az azonos szintű `magas`) = `P`, `közepes` = `L`, `alacsony` = `U`, az `adhesive-00-index.md` 6. fejezetének globális szerződése szerint.
- **Elhelyezés:** a betűjelölés az eredeti szintszó után, zárójelben szerepel (`Nagy (P)`, `közepes (L) a futási elérhetőségre`); több pontból álló findingnél pontonként, a pontot megnevező szöveg után. Hibrid szintnél (`közepes/alacsony`, `Közepes-nagy`) a gyengébb szint betűje az irányadó.
- **Darabszám:** `P` = `160`, `L` = `31`, `U` = `23` betűjelölés, összesen `214` jelölés a `168` tételen; `46` tétel több pontot is külön jelöl. A darabszám a finding-sorokra vonatkozik, az 1. és a 15. fejezet jelölési magyarázata nem finding, ezért nem számít bele.
- **Változatlanul maradt:** minden eredeti szintszó és hibrid érték, minden szám, RVA, raw, IAT-címsor, kulcsliteral, tanúsítvány-adat és a dokumentum 18. soros értelmezési korlátja. A vizsgálati keret változatlan: a DLL-t ez a blokk sem futtatta, betöltötte vagy dinamikusan instrumentálta; új evidence-fájl nem keletkezett, és nincs benne exploit-, bypass-, patch- vagy credential-recovery recept.
