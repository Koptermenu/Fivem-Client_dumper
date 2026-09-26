# adhesive.dll – 09. hálózati és IPC-statikus jelentés

## 1. Vizsgálati keret

- **Célfájl:** `C:\Users\Admin\Desktop\Dumper - AllInOne\reverse\adhesive.dll`
- **SHA-256:** `91CC0AA006D7315CB042C8FA8DCA6C1E074A307BBA7DCC9EB5509C8A7B81934E`
- **Fájlméret:** `53 575 264` byte
- **Vizsgálat:** kizárólag statikus PE-, import-, string- és disassemble-elemzés.
- A DLL-t nem futtattam, hálózati kapcsolatot nem nyitottam, és nem végeztem dinamikus vagy interaktív tesztet.
- A belső függvénynevek inferált nevek; nincs PDB, exportált alkalmazói szimbolumnév vagy használható map.
- A `RVA` a képfájlbeli virtuális cím, a `raw` a fájlon belüli eltolás. Az alábbi kódhívásoknál `RVA / raw` sorrendet használok.
- `.text` konverzió: `raw = RVA - 0xC00`.
- `.rdata` konverzió: `RVA = raw + 0x1600`.

### Bizonyítéki szintek

| Jelölés | Jelentés |
|---|---|
| Magas `[P]` | Közvetlen importált IAT-hívás, pontos argumentum/konstans vagy közvetlenül visszafejtett objektum-művelet. |
| Közepes `[L]` | Statikus library-string/source-path és részben rejtett, de kontextusból azonosítható kódút. |
| Alacsony `[U]` | Csak capability-string vagy import látható; a tényleges runtime-hívás nem bizonyított. |

## 2. Vezetői összegzés

1. A bináris közvetlen Winsock-képesége magas `[P]`: TCP socket, bind/listen/connect/accept, stream/datagram küldés-fogadás, DNS-feloldás, socket-event multiplexing és IPv6 datagram probe található.
2. Két külön, magas bizonyosságú `[P]` IPv4 loopback önteszt-tranzakció azonosítható. A `127.0.0.1` cím, az ephemeral port, a listener, a connector és az `accept` mind közvetlenül látszanak.
3. A binárisban statikusan linkelt vagy beágyazott hálózati/HTTP-könyvtárkészlet található: Boost.Asio, Boost.Beast, cPR/cURL, nghttp2, OpenSSL és TLS/ALPN-kezelés. Ez capability, nem automatikusan bizonyított runtime-használat.
4. A HTTP-funkciók között HTTP/1.1, HTTP/2 és egy HTTP/3-runtime-ág statikus nyomai vannak. HTTP/3 backendet nem sikerült azonosítani; `ngtcp2`, `nghttp3` és `quiche` string nem található.
5. A proxyképesség statikusan egyértelmű: `http_proxy`, `no_proxy`, `all_proxy`, HTTP CONNECT, SOCKS4/5 és proxy-HTTP/2 hibakezelési kód van. Konfigurált proxy vagy célproxy nincs bizonyítva.
6. A legfontosabb IPC-képesség a `CFX_%s_%s_SharedData_%s` névvel létrehozott, `0x3058` méretű shared-memory mapping és a `Local\{...}-once-flag` mintát használó, generált nevű named local event; a mapping namespace és a TBB-jelű objektum tulajdonosa statikusan nem azonosított.
7. Az adapter/device oldalon közvetlen `GetAdaptersInfo` és `CM_Get_Device_Interface_ListW` hívások vannak. Az `X-Device-*` header-literalek jelen vannak, de a teljes literal pontos kódxrefje és a kimenő header összeállítása nem bizonyított.
8. A teljes cleartext URL/host sweepben az egyetlen releváns, nem-metaadat fix alkalmazási URL a `http://clients2.google.com/time/1/current`. A cURL dokumentációs URL-ek és a DigiCert/Authenticode URL-ek könyvtár-, illetve tanúsítvány-metaadatok, nem alkalmazási végpontok.
9. Statikus bizonyíték alapján nincs indokolt C2-minősítés. A hálózati és fingerprint-képesség önmagában nem azonosít C2-kiszolgálót.

## 3. PE-metaadatok és szekciók

| Tulajdonság | Érték |
|---|---|
| Machine | `0x8664` (`AMD64`) |
| ImageBase | `0x180000000` |
| Entry RVA | `0x2AB2770` |
| Entry raw | `0x2AB1B70` |
| SizeOfImage | `0x331E000` |
| PE timestamp | `0x6AA418EA` |
| Import descriptorok | `42` |
| Importált nevek | `628` |

| Szekció | RVA | Virtual size | Raw | Raw size |
|---|---:|---:|---:|---:|
| `.text` | `0x1000` | `0x2BED4B5` | `0x400` | `0x2BED600` |
| `.rdata` | `0x2BEF000` | `0x4C9FDC` | `0x2BEDA00` | `0x4CA000` |
| `.data` | `0x30B9000` | `0x252734` | `0x30B7A00` | `0x24E000` |
| `.retplne` | `0x330C000` | `0x5C` | `0x3305A00` | `0x200` |
| `.tls` | `0x330D000` | `0x54A1` | `0x3305C00` | `0x5600` |
| `.rsrc` | `0x3313000` | `0x698` | `0x330B200` | `0x800` |
| `.reloc` | `0x3314000` | `0x9AD0` | `0x330BA00` | `0x9C00` |

A releváns importok: `WS2_32.dll` 41, `libuv.dll` 9, `net.dll` 3, `net-tcp-server.dll` 1, `net-base.dll` 5, `IPHLPAPI.DLL` 1, `CFGMGR32.dll` 2, `RPCRT4.dll` 2, `bcrypt.dll` 1, `CRYPT32.dll` 13, `KERNEL32.dll` 142, valamint delay-import `ole32.dll!CoTaskMemFree`. Közvetlen `WinHTTP`, `WinINet` vagy `URLMON` import nincs.

## 4. WS2_32: importok és közvetlen hívások

### 4.1 Importált API-k

A WS2_32 IAT 41 nyolcbájtos bejegyzésből áll, `RVA 0x2E4D930–0x2E4DA70`, raw `0x2E4C330–0x2E4C470` tartományban. A pontos sorrend:

```text
WSAAddressToStringW
WSACleanup
WSACloseEvent
WSACreateEvent
WSAEnumNetworkEvents
WSAEventSelect
WSAGetLastError
WSAIoctl
WSARecv
WSARecvFrom
WSAResetEvent
WSASend
WSASendTo
WSASetLastError
WSASocketW
WSAStartup
WSAStringToAddressW
WSAWaitForMultipleEvents
__WSAFDIsSet
accept
bind
closesocket
connect
freeaddrinfo
getaddrinfo
getnameinfo
getpeername
getsockname
getsockopt
htonl
htons
ioctlsocket
listen
ntohl
ntohs
recv
select
send
setsockopt
shutdown
socket
```

A pontosan importált készletben nincs `WSARecvMsg`, `WSASendMsg` vagy `WSASocketA`; az ezekre vonatkozó korábbi feltételezés nem igazolható.

### 4.2 Fontosabb közvetlen callsite-ok

| API | IAT RVA / raw | Közvetlen callsite-ok RVA / raw | Inferált szerep |
|---|---|---|---|
| `socket` | `0x2E4DA70 / 0x2E4C470` | `0x2A19EDD / 0x2A192DD`; `0x2A3BD93 / 0x2A3B193`; `0x2A5E539 / 0x2A5D939`; `0x2A5E612 / 0x2A5DA12`; `0x2AE2BA7 / 0x2AE1FA7` | Stream, datagram és IPv6 socket-létrehozás. |
| `WSASocketW` | `0x2E4D9A0 / 0x2E4C3A0` | `0x2063136 / 0x2062536`; `0x2066AD9 / 0x2065ED9`; `0x2067024 / 0x2066424` | Widesocket-alapú TCP round-trip útvonal. |
| `bind` | `0x2E4D9D0 / 0x2E4C3D0` | `0x205ED37 / 0x205E137`; `0x2066D97 / 0x2066197`; `0x20C553B / 0x20C493B`; `0x2A3C527 / 0x2A3B927`; `0x2A5E5B8 / 0x2A5D9B8` | Listener, ephemeral port és általános socket-service. |
| `listen` | `0x2E4DA30 / 0x2E4C430` | `0x2066FE8 / 0x20663E8`; `0x2A5E5F6 / 0x2A5D9F6` | TCP listener. |
| `connect` | `0x2E4D9E0 / 0x2E4C3E0` | `0x205F16B / 0x205E56B`; `0x2067215 / 0x2066615`; `0x2A3C701 / 0x2A3BB01`; `0x2A5E633 / 0x2A5DA33`; `0x2AE2D95 / 0x2AE2195` | Kliens- és önteszt-kapcsolat. |
| `accept` | `0x2E4D9C8 / 0x2E4C3C8` | `0x2067346 / 0x2066746`; `0x2A5E68F / 0x2A5DA8F` | TCP szerver-elfogadás. |
| `WSASend` | `0x2E4D988 / 0x2E4C388` | `0x205F914 / 0x205ED14`; `0x2061F0F / 0x206130F`; `0x2065C86 / 0x2065086`; `0x20667C5 / 0x2065BC5`; `0x207A040 / 0x2079440` | Több stream-küldési útvonal. |
| `WSARecv` | `0x2E4D970 / 0x2E4C370` | `0x206874C / 0x2067B4C`; `0x20A2015 / 0x20A1415` | Stream fogadás. |
| `WSASendTo` | `0x2E4D990 / 0x2E4C390` | `0x20CCF0B / 0x20CC30B` | Datagram célcímkéző küldés. |
| `WSARecvFrom` | `0x2E4D978 / 0x2E4C378` | `0x20D37E9 / 0x20D2BE9` | Datagram fogadás forráscímmel. |
| `WSAIoctl` | `0x2E4D968 / 0x2E4C368` | `0x205EC6B / 0x205E06B`; `0x2A3BFE0 / 0x2A3B3E0`; `0x2A497BB / 0x2A48BBB` | Socket extension/keepalive/állapotkezelés. |
| `ioctlsocket` | `0x2E4DA28 / 0x2E4C428` | `0x205F059 / 0x205E459`; `0x2061D00 / 0x2061100`; `0x2067473 / 0x2066873`; `0x2067698 / 0x2066A98`; `0x2A3BDD0 / 0x2A3B1D0`; `0x2A3C1A8 / 0x2A3B5A8`; `0x2A5E657 / 0x2A5DA57`; `0x2A6B6F0 / 0x2A6AAF0`; `0x2A6C3FD / 0x2A6B7FD`; `0x2AB5DC7 / 0x2AB51C7` | Nem blokkoló I/O és socket-állapot. |
| `getsockname` | `0x2E4DA08 / 0x2E4C408` | `0x2066DC6 / 0x20661C6`; `0x2A3A6A1 / 0x2A39AA1`; `0x2A3C590 / 0x2A3B990`; `0x2A5E5D4 / 0x2A5D9D4`; `0x2A5E6B4 / 0x2A5DAB4` | Local/remote endpoint és ephemeral port. |
| `getpeername` | `0x2E4DA00 / 0x2E4C400` | `0x2A3A57D / 0x2A3997D`; `0x2A5E6DC / 0x2A5DADC` | Peer-ellenőrzés. |
| `setsockopt` | `0x2E4DA60 / 0x2E4C460` | `0x2061B50 / 0x2060F50`; `0x20631AC / 0x20625AC`; `0x2064C25 / 0x2064025`; `0x2066C1D / 0x206601D`; `0x20675BE / 0x20669BE`; `0x20677E3 / 0x2066BE3`; `0x20C5163 / 0x20C4563`; `0x20C538F / 0x20C478F`; `0x2A3B885 / 0x2A3AC85`; `0x2A3BECF / 0x2A3B2CF`; `0x2A3BF44 / 0x2A3B344`; `0x2A497E0 / 0x2A48BE0`; `0x2A5E59B / 0x2A5D99B`; `0x2AE2CA7 / 0x2AE20A7`; `0x2AE2D2C / 0x2AE212C` | Reuse, keepalive, buffer és socket-opciók. |
| `getaddrinfo` | `0x2E4D9F0 / 0x2E4C3F0` | `0x2A5DFAB / 0x2A5D3AB`; `0x2AB633E / 0x2AB573E`; `0x2AB637F / 0x2AB577F` | Hostnév- és szolgáltatásfeloldás. |
| `freeaddrinfo` | `0x2E4D9E8 / 0x2E4C3E8` | `0x2A5E0EA / 0x2A5D4EA`; `0x2A5E113 / 0x2A5D513`; thunk `0x2AB5FF6 / 0x2AB53F6` | Feloldási memória felszabadítása. |
| `getnameinfo` | `0x2E4D9F8 / 0x2E4C3F8` | `0x2AB651E / 0x2AB591E` | Visszafordítás host-/servicename-re. |
| `WSAStringToAddressW` | `0x2E4D9B0 / 0x2E4C3B0` | `0x1F98FEE / 0x1F983EE` | Szöveges cím konvertálása. |
| `WSAEventSelect` | `0x2E4D958 / 0x2E4C358` | `0x2A1C3D4 / 0x2A1B7D4`; `0x2A1C485 / 0x2A1B885`; `0x2A1C63C / 0x2A1BA3C`; `0x2A1C72B / 0x2A1BB2B`; `0x2A1C783 / 0x2A1BB83`; `0x2A1C7DB / 0x2A1BBDB`; `0x2A1C833 / 0x2A1BC33`; `0x2A1C887 / 0x2A1BC87` | Socket-eseményekhez társítás. |
| `WSAEnumNetworkEvents` | `0x2E4D950 / 0x2E4C350` | `0x2A1C5ED / 0x2A1B9ED`; `0x2A1C6FD / 0x2A1BAFD`; `0x2A1C755 / 0x2A1BB55`; `0x2A1C7AD / 0x2A1BBAD`; `0x2A1C805 / 0x2A1BC05`; `0x2A1C859 / 0x2A1BC59` | Readiness és hibaesemények kiértékelése. |
| `WSAWaitForMultipleEvents` | `0x2E4D9B8 / 0x2E4C3B8` | `0x2A1C582 / 0x2A1B982` | Több socket-esemény megvárása. |
| `WSACreateEvent` | `0x2E4D948 / 0x2E4C348` | `0x2A19F00 / 0x2A19300` | WSA-esemény létrehozása. |
| `WSACloseEvent` | `0x2E4D940 / 0x2E4C340` | `0x2A1F61B / 0x2A1EA1B` | WSA-esemény lezárása. |
| `WSAResetEvent` | `0x2E4D980 / 0x2E4C380` | `0x2A1C8A1 / 0x2A1BCA1` | Esemény-állapot alaphelyzetbe állítása. |
| `select` | `0x2E4DA50 / 0x2E4C450` | `0x2065808 / 0x2064C08`; `0x2068686 / 0x2067A86`; `0x2A4D768 / 0x2A4CB68` | Készenléti várakozás. |
| `send` | `0x2E4DA58 / 0x2E4C458` | `0x2A1C3A2 / 0x2A1B7A2`; `0x2A1C472 / 0x2A1B872`; `0x2A2472B / 0x2A23B2B`; `0x2A39981 / 0x2A38D81`; `0x2AE27AD / 0x2AE1BAD`; `0x2AE28EB / 0x2AE1CEB`; `0x2BADD3F / 0x2BAD13F`; `0x2BADE9D / 0x2BAD29D` | Stream-küldés. |
| `recv` | `0x2E4DA48 / 0x2E4C448` | `0x2A37A52 / 0x2A36E52`; `0x2A3995E / 0x2A38D5E`; `0x2A39B19 / 0x2A38F19`; `0x2A4BC7E / 0x2A4B07E`; `0x2A4C2E4 / 0x2A4B6E4`; `0x2A4C853 / 0x2A4BC53`; `0x2A4CB7A / 0x2A4BF7A`; `0x2A4D17B / 0x2A4C57B`; `0x2A4D2C6 / 0x2A4C6C6`; `0x2A59381 / 0x2A58781`; `0x2AE2822 / 0x2AE1C22`; `0x2BADDDD / 0x2BAD1DD` | Stream-fogadás. |
| `shutdown` | `0x2E4DA68 / 0x2E4C468` | `0x2BAE40F / 0x2BAD80F`; `0x2BAE920 / 0x2BADD20` | Graceful lezárás. |
| `htonl` / `ntohl` | `0x2E4DA18 / 0x2E4C418`; `0x2E4DA38 / 0x2E4C438` | Például `htonl(0x7F000001)` a loopback-címekhez; több IPv4/IPv6 konverziós útvonal. | Hálózati bájtsorrend. |
| `htons` / `ntohs` | `0x2E4DA20 / 0x2E4C420`; `0x2E4DA40 / 0x2E4C440` | Több port- és endpoint-kezelő hívás. | Hálózati bájtsorrend. |

A teljes egymenetes IAT-scan további darabszámokat is kimutatott: `WSAGetLastError` 75, `WSASetLastError` 13, `WSAIoctl` 3, `htonl` 8, `htons` 11, `recv` 12, `send` 8, `select` 3, `setsockopt` 15, `closesocket` 11, `socket` 5. Ezek is közvetlen, közvetlenül visszafejtett IAT-hivatkozások; a `WSAGetLastError` és `WSASetLastError` callsite-lista nagyrészt hibakezelési ismétlődés.

### 4.3 TCP stream és event-alapú kliens/szerver

- **`fn 0x2A1BFC0–0x2A1C934`**: `WSAEventSelect` és `WSAEnumNetworkEvents` hívások, `WSAWaitForMultipleEvents`, `send`, `WSAResetEvent`. Magas `[P]` bizonyosságú, event-driven socket-szolgáltatás.
- **`fn 0x205DC70–0x205FA34`**: `WSAIoctl` `0x205EC6B / 0x205E06B`, `bind` `0x205ED37 / 0x205E137`, `connect` `0x205F16B / 0x205E56B`, `WSASend` `0x205F914 / 0x205ED14`; stream socket-szolgáltatás.
- **`fn 0x2063070–0x20633AA`**: `WSASocketW` `0x2063136 / 0x2062536`, `setsockopt` `0x20631AC / 0x20625AC`; TCP socket előkészítése.
- **`fn 0x2067F60–0x2068E2A`**: `WSARecv` `0x206874C / 0x2067B4C`, `select` `0x2068686 / 0x2067A86`; stream fogadási útvonal.
- **`fn 0x20A19F0–0x20A20F0`**: `WSARecv` `0x20A2015 / 0x20A1415`; további fogadási útvonal.

### 4.4 Magas bizonyosságú loopback öntesztek

#### Önteszt A

Funkció: `fn 0x2A5E500–0x2A5E74C`, raw start `0x2A5D900`.

- `socket(AF_INET=2, SOCK_STREAM=1, IPPROTO_TCP=6)`:
  - `RVA 0x2A5E539 / raw 0x2A5D939`
  - második socket: `0x2A5E612 / 0x2A5DA12`
- `setsockopt(SOL_SOCKET=0xFFFF, SO_REUSEADDR=4, 1)`:
  - `0x2A5E59B / 0x2A5D99B`
- `htonl(0x7F000001)`:
  - `0x2A5E567 / 0x2A5D967`
- `bind`:
  - `0x2A5E5B8 / 0x2A5D9B8`
- `getsockname`:
  - `0x2A5E5D4 / 0x2A5D9D4`
- `listen`:
  - `0x2A5E5F6 / 0x2A5D9F6`
- `ioctlsocket(FIONBIO=0x8004667E)`:
  - `0x2A5E657 / 0x2A5DA57`
- `connect`:
  - `0x2A5E633 / 0x2A5DA33`
- `accept`:
  - `0x2A5E68F / 0x2A5DA8F`
- `getsockname` és `getpeername`:
  - `0x2A5E6B4 / 0x2A5DAB4`
  - `0x2A5E6DC / 0x2A5DADC`
- `closesocket`:
  - `0x2A5E72F / 0x2A5DB2F`

A port kezdetben `0`, ezért az OS ephemeral portot választ. A cím `127.0.0.1`; a kód a bound portot használja a connectorhoz, majd listeneren fogad és peer/local címet hasonlít. A közvetlen hívó `fn 0x2A24290–0x2A245F3` a tesztet `0x2A24466 / 0x2A23866` címon hívja. Következtetés: magas bizonyosságú `[P]` helyi TCP round-trip/functional test, nem külső cél.

#### Önteszt B

Funkció: `fn 0x2066A90–0x20678BF`, raw start `0x2065E90`.

- `WSASocketW(AF_INET=2, SOCK_STREAM=1, IPPROTO_TCP=6, 0)`:
  - `0x2066AD9 / 0x2065ED9`
  - `0x2067024 / 0x2066424`
- `htonl(0x7F000001)`:
  - `0x2066CA2 / 0x20660A2`
  - `0x2066DEC / 0x20661EC`
  - `0x2066DFB / 0x20661FB`
- `setsockopt`, `bind`, `getsockname`, `listen`, `connect`, `accept`:
  - `bind 0x2066D97 / 0x2066197`
  - `getsockname 0x2066DC6 / 0x20661C6`
  - `listen 0x2066FE8 / 0x20663E8`
  - `connect 0x2067215 / 0x2066615`
  - `accept 0x2067346 / 0x2066746`
- További `setsockopt`: `0x2066C1D / 0x206601D`, `0x20675BE / 0x20669BE`, `0x20677E3 / 0x2066BE3`.

Ez egy második, közvetlenül visszafejtett loopback TCP round-trip. A pontos célnév nem ismert, de a loopback-optimalizálás nem runtime-feltételezésen alapul.

### 4.5 Datagram és IPv6

- **`fn 0x2A3BC70–0x2A3C7E7`**:
  - default protokollág `0x11` (`IPPROTO_UDP`): `0x2A3BCD2 / 0x2A3B0D2`
  - `socket` `0x2A3BD93 / 0x2A3B193`
  - `WSAIoctl` `0x2A3BFE0 / 0x2A3B3E0`
  - `bind` `0x2A3C527 / 0x2A3B927`
  - `connect` `0x2A3C701 / 0x2A3BB01`
  - `getsockname` `0x2A3C590 / 0x2A3B990`
  - `ioctlsocket` `0x2A3BDD0 / 0x2A3B1D0` és `0x2A3C1A8 / 0x2A3B5A8`
  - Magas `[P]` bizonyosságú socket-szolgáltatás; a `0x11` ág datagram képességet jelez.
- **`fn 0x20CCBC0–0x20CCFEF`**: `WSASendTo` `0x20CCF0B / 0x20CC30B`, `WSAGetLastError` `0x20CCF13 / 0x20CC313`. Közvetlen datagram küldési útvonal.
- **`fn 0x20D3400–0x20D38FF`**: `WSARecvFrom` `0x20D37E9 / 0x20D2BE9`, `WSAGetLastError` `0x20D37F1 / 0x20D2BF1`. Közvetlen datagram fogadási útvonal.
- **`fn 0x2A19D80–0x2A1A11D`**:
  - `socket(AF_INET6=23, SOCK_DGRAM=2, 0)` `0x2A19EDD / 0x2A192DD`
  - `WSACreateEvent` `0x2A19F00 / 0x2A19300`
  - `closesocket` `0x2A19EEF / 0x2A192EF`
  - IPv6 UDP socket-pröbe; nem igazolt külső IPv6-kommunikáció.

### 4.6 DNS és WSAStartup

- `WSAStartup` közvetlen hívások: `0x1F884DC / 0x1F878DC`, `0x1FA0134 / 0x1F9F534`, `0x20C10A1 / 0x20C04A1`, `0x2A24798 / 0x2A23B98`, `0x2AB5E4B / 0x2AB524B`.
- `WSACleanup` közvetlen hívások: `0x1F8CED8 / 0x1F8C2D8`, `0x1F8DBFC / 0x1F8CFFC`, `0x2A247AE / 0x2A23BAE`; thunkok: `0x1F8861B / 0x1F87A1B`, `0x2AB5EC4 / 0x2AB52C4`.
- A `getaddrinfo`/`getnameinfo` útvonalak DNS-feloldási és visszafordítási képességet igazolnak; konkrét runtime hostname nincs a fix Google URL mellett.

## 5. libuv és játék-hálózati komponensek

### 5.1 libuv

Az importok és közvetlen callsite-ok:

| API | IAT RVA / raw | Callsite-ok RVA / raw |
|---|---|---|
| `uv_async_init` | `0x2E4D6A8 / 0x2E4C0A8` | `0x1C34C / 0x1B74C` |
| `uv_async_send` | `0x2E4D6B0 / 0x2E4C0B0` | `0x13A6C / 0x12E6C`; `0x1A06E / 0x1946E`; `0x1A374 / 0x19774`; `0x1A7F7 / 0x19BF7` |
| `uv_poll_init_socket` | `0x2E4D6C0 / 0x2E4C0C0` | `0x13ED5 / 0x132D5` |
| `uv_poll_start` | `0x2E4D6C8 / 0x2E4C0C8` | `0x13F74 / 0x13374` |
| `uv_poll_stop` | `0x2E4D6D0 / 0x2E4C0D0` | `0x13E58 / 0x13258` |
| `uv_close` | `0x2E4D6B8 / 0x2E4C0B8` | `0x13E67 / 0x13267` |
| `uv_timer_init` | `0x2E4D6D8 / 0x2E4C0D8` | `0x1BBB8 / 0x1AFB8` |
| `uv_timer_start` | `0x2E4D6E0 / 0x2E4C0E0` | `0x1400E / 0x1340E` |
| `uv_timer_stop` | `0x2E4D6E8 / 0x2E4C0E8` | `0x13FEF / 0x133EF` |

- `fn 0x13E10–0x13FD1` socket-handle leállítása, `uv_poll_init_socket`, majd `uv_poll_start` környezetében socket-file-descriptor figyelést állít be.
- `fn 0x13480–0x13AD8` a TCP-server/uv-loop inicializálási és peer-state útvonal; `net-tcp-server!GetOrCreate` közvetlen hívása `0x1393F / 0x12D3F`.
- Az `uv_async_send` hívások event-loop wakeup/értesítési képességet mutatnak.
- Következtetés: magas bizonyosságú `[P]` libuv socket-event és timer infrastruktúra; konkrét távoli peer nem azonosítható statikusan.

### 5.2 net.dll, net-base.dll és net-tcp-server.dll

| DLL / API | IAT RVA / raw | Közvetlen vagy közvetett callsite |
|---|---|---|
| `net.dll!AddReliableHandler` | `0x2E4DC90 / 0x2E4C690` | Csak thunk `0x2BED9B0 / 0x2BECDB0`; közvetlen `E8` callsite nem talált. |
| `net.dll!GetGUID` | `0x2E4DC98 / 0x2E4C698` | Thunk `0x2BED9C0 / 0x2BECDC0`; hívás `0x1B29F1 / 0x1B1DF1`, `fn 0x19A3E0–0x1C753D`. |
| `net.dll!OnNetLibraryCreate` | `0x2E4DCA0 / 0x2E4C6A0` | Globális event-objektum betöltések (`mov` xrefek, nem közvetlen API-hívás): `0x101262 / 0x100662`, `0x1F84C3 / 0x1F78C3`, `0x333E10 / 0x333210`, `0x1720112 / 0x171F512`, `0x176D18A / 0x176C58A`. |
| `net-tcp-server.dll!UvLoopManager::GetOrCreate` | `0x2E4DCC0 / 0x2E4C6C0` | `0x1393F / 0x12D3F`. |
| `net-base.dll!Buffer` konstruktor | `0x2E4DCD0 / 0x2E4C6D0` | `0x173477 / 0x172877`. |
| `net-base.dll!Buffer` destruktor | `0x2E4DCD8 / 0x2E4C6D8` | `0x1726DB / 0x171ADB`; `0x173B00 / 0x172F00`. |
| `net-base.dll!Buffer::GetBuffer` | `0x2E4DCE0 / 0x2E4C6E0` | `0x17254E / 0x17194E`. |
| `net-base.dll!Buffer::Write` | `0x2E4DCF0 / 0x2E4C6F0` | `0x172540 / 0x171940`. |
| `net-base.dll!PeerAddress::ToString` | `0x2E4DCE8 / 0x2E4C6E8` | Thunk `0x2BED9D0 / 0x2BECDD0`; közvetlen hívás nem talált. |

A `net.dll` és `net-tcp-server.dll` import- és callsite-együttese játék-TCP/reliable-handler infrastruktúrát jelez. Ez nem önálló C2-csatorna bizonyítéka.

## 6. cURL, HTTP, TLS, proxy és WebSocket

### 6.1 Statikus library-nyomok

| Evidencia | Raw / RVA | Következtetés |
|---|---|---|
| `boost-submodules\boost-asio\...` forrásstring | `0x2E0E089 / 0x2E0F689` és környezete | Boost.Asio statikus forrás-/diagnosztikai nyom. |
| `boost.beast` | `0x2E0B265 / 0x2E0C865` | Boost.Beast jelenléte; pontos kódxref `0x2063FD0 / 0x20633D0`. |
| `beast.http` | `0x2E0D760 / 0x2E0ED60`; `0x2E0E065 / 0x2E0F665` | HTTP parser/field implementáció. |
| `HttpClient` | `0x2E0B800 / 0x2E0CE00` | Pontos LEA-xrefek: `0x1D22C / 0x1C62C`; `0x53442 / 0x52842`; cPR/HTTP kliens-adatstruktúra. |
| `cpr::Timeout` | `0x2E47190 / 0x2E48790` | cPR timeout-kezelés; pontos xref `0x2AD61A2 / 0x2AD55A2`. |
| `curl/` | `0x2E20408 / 0x2E21A08` | cURL user-agent/library azonosító; pontos xref `0x2AAC898 / 0x2AABC98`, `fn 0x2AAC660–0x2AACB32`. |
| `..\..\..\vendor\curl\lib\vtls\openssl.c` | `0x2E140A9 / 0x2E156A9` | cURL OpenSSL backend source-path; xref `0x2A59044 / 0x2A58444` és `0x2A59141 / 0x2A58541`, `fn 0x2A58D00–0x2A59173`. |
| `OpenSSL 1.1.1t  7 Feb 2023` | `0x2C28240 / 0x2C29840` | Beágyazott OpenSSL pontos verziója. |
| `nghttp2_session_mem_recv` hiba- és implementációs stringek | `0x2E0CB91 / 0x2E0E191` környezete | HTTP/2/nghttp2 kód; pontos xref `0x2A368D6 / 0x2A35CD6`, `fn 0x2A36890–0x2A369BB`. |
| `PRI * HTTP/2.0` | `0x2E47908 / 0x2E48F08` | HTTP/2 prior-knowledge kód; pontos xref `0x2B1329D / 0x2B1269D`, `fn 0x2B12D10–0x2B132F0`. |
| `HTTP/3 requested for non-HTTPS URL` | `0x2E1528A / 0x2E1688A` | HTTP/3 kiválasztási/hibaág; pontos xref `0x2A4D903 / 0x2A4CD03`. |
| `HTTP/3 error` | `0x2E0D906 / 0x2E0EF06` | HTTP/3 hibakód-capability; pontos teljes xref nem igazolt. |

A cURL pontos verziója nem állapítható meg biztonságosan: a `curl/` marker és a `1.20.0` közeli adat nem önmagában bizonyítja a libcurl build verzióját.

### 6.2 HTTP/1.1, HTTP/2 és HTTP/3

- A cURL-függvényekben `HTTP/1.0`, `HTTP/1.1`, `HTTP/1.%d %d`, `HTTP/2` és `nghttp2` hibakódok vannak.
- `fn 0x2A36890–0x2A369BB` konkrét nghttp2 session-input feldolgozási hibaútvonalat tartalmaz; ez nem csak import- vagy string-capability.
- `fn 0x2B12D10–0x2B132F0` a `PRI * HTTP/2.0` prior-knowledge folyamatot használja.
- `fn 0x2A4D880–0x2A4D97F`:
  - konfigurációs bitet olvas;
  - `RVA 0x2A4D8F7` körül HTTP/3 állapotot állít `5` értékre;
  - `RVA 0x2A4D903 / raw 0x2A4CD03` a `HTTP/3 requested for non-HTTPS URL` stringet adja tovább.
- HTTP/3 backendre nincs `ngtcp2`, `nghttp3` vagy `quiche` statikus string; az HTTP/3 kód jelenléte capability, működő QUIC backend nem bizonyított.

### 6.3 Proxy- és URL-feldolgozás

A `fn 0x2A269B0–0x2A289B3` cURL-szerű URL/proxy-feldolgozást mutat:

| String / ág | String raw / RVA | Kódxref RVA / raw |
|---|---|---|
| `no_proxy` | `0x2E0A0BD / 0x2E0B6BD` | `0x2A27B26 / 0x2A26F26` |
| `NO_PROXY` | `0x2E149C9 / 0x2E15FC9` | `0x2A27B42 / 0x2A26F42` |
| `http_proxy` | `0x2E0A0B2 / 0x2E0B6B2` | `0x2A27D85 / 0x2A27185` |
| `all_proxy` | `0x2E0A0C6 / 0x2E0B6C6` | `0x2A27DE8 / 0x2A271E8` |
| `ALL_PROXY` | `0x2E149D2 / 0x2E15FD2` | `0x2A27E04 / 0x2A27204` |
| `http`, `https`, `file`, `mqtt` | `http`: `0x2E0E06B / 0x2E0F66B`; `https`: `0x2E0C1A5 / 0x2E0D7A5`; `file`: `0x2E11F1F / 0x2E1351F`; `mqtt`: `0x2E0AFD6 / 0x2E0C5D6` | `0x2A2731F–0x2A27530` környéke |

A SOCKS-képességhez több explicit literal és cURL hiba-/protokolltábla-entry található: `SOCKS4 communication to %s:%d` raw `0x2E13C93 / RVA 0x2E15293`, `SOCKS5: connecting to HTTP proxy %s port %d` raw `0x2E13D1C / RVA 0x2E1531C`, `SOCKS5 request granted.` raw `0x2E1B7FB / RVA 0x2E1CDFB`, valamint `socks5` raw `0x2E18197 / RVA 0x2E19797`. Ezek közvetlen kódxrefje nem különül el a táblázatos referencia miatt; a SOCKS-következtetés ezért közepes–magas `[L]` statikus capability, nem igazolt runtime-proxy.

A `fn 0x2A464E0–0x2A47CBC` HTTP CONNECT proxy-tunnel kódot tartalmaz; jellemző stringek:

- `Establish HTTP proxy tunnel to %s:%d`: `raw 0x2E13CB1 / RVA 0x2E152B1`, xref `0x2A46768 / 0x2A45B68`.
- `Proxy CONNECT aborted due to timeout`: `raw 0x2E0AEF4 / RVA 0x2E0C0F4`, xref `0x2A46D7F / 0x2A4617F`.
- `User-Agent` suffix: kódxref `0x2A46A75 / 0x2A45E75`.
- `Proxy-Connection` header: xref `0x2A46BE6 / 0x2A45FE6` és `0x2A46C02 / 0x2A46002`.

A `fn 0x2A4D980–0x2A4F0B1` a proxy és HTTP/2 prior-knowledge interakciót is kezeli; az `Ignoring HTTP/2 prior knowledge due to proxy` pontos xref `0x2A4DA0A / 0x2A4CE0A`.

Következtetés: HTTP CONNECT és environment-alapú proxyképesség magas `[P]`; SOCKS4/5 közepes–magas `[L]` statikus capability; konkrét proxy-URL, proxy-konfiguráció vagy külső proxycím nincs statikusan bizonyítva.

### 6.4 TLS és tanúsítványlánc

A `fn 0x2A59DC0–0x2A5D1D1` cURL/OpenSSL kódban a következő közvetlen Windows cert-store hívások vannak:

| API | IAT RVA / raw | Callsite RVA / raw |
|---|---|---|
| `CertOpenSystemStoreW` | `0x2E4D900 / 0x2E4C300` | `0x2A5A796 / 0x2A59B96` |
| `CertEnumCertificatesInStore` | `0x2E4D8C8 / 0x2E4C2C8` | `0x2A5A7BF / 0x2A59BBF`; `0x2A5A813 / 0x2A59C13`; `0x2A5AD9C / 0x2A5A19C`; `0x2A5ADE4 / 0x2A5A1E4` |
| `CertGetEnhancedKeyUsage` | `0x2E4D8E0 / 0x2E4C2E0` | `0x2A5A8D6 / 0x2A59CD6`; `0x2A5AA7A / 0x2A59E7A` |
| `CertGetIntendedKeyUsage` | `0x2E4D8E8 / 0x2E4C2E8` | `0x2A5A897 / 0x2A59C97` |
| `CertGetNameStringW` | `0x2E4D8F0 / 0x2E4C2F0` | `0x2BA58C6 / 0x2BA4CC6`; `0x2BA6EBC / 0x2BA62BC` |
| `CertCloseStore` | `0x2E4D8C0 / 0x2E4C2C0` | `0x2A5A96A / 0x2A59D6A` |
| `CertFreeCertificateContext` | `0x2E4D8D8 / 0x2E4C2D8` | `0x2A5A95D / 0x2A59D5D` |

Az ALPN, TLS 1.3 cipher, SNI, peer certificate, CRL és OCSP hibakódok szintén ebben a statikus OpenSSL/cURL részben vannak. Ez magas `[P]` TLS-képesség, nem konkrét távoli TLS-kapcsolat bizonyítéka.

### 6.5 WebSocket

A statikus header-szótár tartalmazza:

| Header | Raw / RVA |
|---|---|
| `Sec-WebSocket-Key` | `0x2E0A625 / 0x2E0BC25` |
| `Sec-WebSocket-Accept` | `0x2E0B464 / 0x2E0CA64` |
| `Sec-WebSocket-Extensions` | `0x2E0C24D / 0x2E0D84D` |
| `Sec-WebSocket-Version` | `0x2E0F59B / 0x2E10B9B` |
| `Sec-WebSocket-Protocol` | `0x2E0FC11 / 0x2E11211` |

A közvetlen, teljes literálra mutató PC-relative xref scan nem talált pontosan minden teljes WebSocket-literalhoz tartozó hívást. A kód több helyen a suffixekre hivatkozik, például `Version`/`Key`/`Accept` összehasonlításra; ez összhangban van a Boost.Beast header-field implementációval, de nem bizonyítja, hogy a bináris ténylegesen WebSocket-handshake-et indít. Következtetés: közepes `[L]` WebSocket capability, alacsonyabb `[U]` runtime-callsite-bizonyíték.

## 7. Adapter- és device-fingerprint képesség

### 7.1 Adapterek

| API | IAT RVA / raw | Közvetlen callsite-ok RVA / raw | Funckció |
|---|---|---|---|
| `IPHLPAPI.DLL!GetAdaptersInfo` | `0x2E4E210 / 0x2E4CC10` | `0x1F8C3C0 / 0x1F8B7C0`; `0x1F8C6D5 / 0x1F8BAD5` | `fn 0x1F8BF10–0x1F8C81A`; adapterlista lekérése és további feldolgozása. |

A két hívás buffer- és méretpointert használ; a környező kód `0x2C0` méretű struktúrával dolgozik, majd erősen obfuszkált transzformációkat végez. Magas `[P]` bizonyosságú adapter-enumeráció; közepes `[L]` bizonyosságú konkrét fingerprint-mezők kiválasztása.

### 7.2 Device interface-ek

| API | IAT RVA / raw | Közvetlen callsite-ok RVA / raw |
|---|---|---|
| `CM_Get_Device_Interface_ListW` | `0x2E4E1F8 / 0x2E4CBF8` | `0x1D9E222 / 0x1D9D622` |
| `CM_Get_Device_Interface_List_SizeW` | `0x2E4E200 / 0x2E4CC00` | `0x1DA11F6 / 0x1DA05F6` |

Mindkettő a `fn 0x1D9D370–0x1DA2556` nagy, obfuszkált funkcióban van. A két hívás size/list.sequence-t alkot; magas `[P]` bizonyosságú Windows device-interface enumeráció. A pontos interface-osztály és a későbbi felhasználási mód nem olvasható egyértelműen.

### 7.3 UUID és random

- `RPCRT4.dll!UuidToStringA`: IAT `0x2E4E1D8 / 0x2E4CBD8`, call `0x10FBFB / 0x10EFFB`.
- `RPCRT4.dll!RpcStringFreeA`: IAT `0x2E4E1D0 / 0x2E4CBD0`, call `0x10F28B / 0x10E68B`.
- A `fn 0x10F190–0x10FDB5` kódja egy UUID-szerű 16 bájtos értéket stringgé alakít, majd felszabadítja a stringet. `UuidCreate` nincs importálva és nincs statikus `UuidCreate` string.
- `bcrypt.dll!BCryptGenRandom`: IAT `0x2E4E6E8 / 0x2E4D0E8`; thunk `0x2BEE430 / 0x2BED830`; közvetlen hívó `0x2B4B41D / 0x2B4A81D`, a `fn 0x2B4B40A–0x2B4B44D` random-buffer helperben. A helpernek nincs közvetlen statikus hívója ebből a funkcióból, ezért a fingerprinthez való kötése nem bizonyított.

### 7.4 `X-Device-*` header-literalok

A teljes, pontosan elkülönített literalok:

| Literal | Raw / RVA |
|---|---|
| `X-Device-Accept` | `0x2E0B479 / 0x2E0CA79` |
| `X-Device-Accept-Charset` | `0x2E0B9D1 / 0x2E0CFD1` |
| `X-Device-Accept-Encoding` | `0x2E10A59 / 0x2E12059` |
| `X-Device-Accept-Language` | `0x2E12314 / 0x2E13914` |
| `X-Device-User-Agent` | `0x2E0B825 / 0x2E0CE25` |
| `X-Trasporto` | `0x2E0ED59 / 0x2E10359` |

A suffix-alapú, közvetlen kódhivatkozások között például:

- `User-Agent` suffix: `0x2A46A75 / 0x2A45E75`;
- `Accept-Encoding` suffix: `0x2A4E256 / 0x2A4D656` és `0x2A4E275 / 0x2A4D675`;
- `Accept` suffix: `0x2A4E7D1 / 0x2A4DBD1` és további, `0x2A4E831 / 0x2A4DC31`, `0x2A4E866 / 0x2A4DC66`, `0x2A4E89B / 0x2A4DC9B`, `0x2A4E8CF / 0x2A4DCCF`, `0x2A4E903 / 0x2A4DD03` környezete.

Ezek a targetek a teljes `X-Device-*` literal kezdete utáni suffixekre mutatnak, nem a teljes custom header literál pontos kezdetére. Következtetés: a custom header-névkészlet statikusan jelen van, és a kód is kezel standard header-suffixeket; az `X-Device-*` tényleges kimenő használata és a hozzájuk tartozó értékek forrása nem igazolt.

## 8. IPC-mechanizmusok

### 8.1 CFX shared-memory mapping

A pozitív mapping-formátum:

- `CFX_%s_%s_SharedData_%s`: raw `0x2E0CB65`, RVA `0x2E0E165`.
- `CFXGame`: raw `0x2E11DFF`, RVA `0x2E133FF`; xref a mapping-builderben `0x48EF1C / 0x48E31C`.
- Builder: `fn 0x48EEB0–0x48F1D5`, raw start `0x48E2B0`.
- Format-string xref: `0x48F02F / 0x48E42F`.

A builder visszafejtett hívásai:

| Művelet | Callsite RVA / raw | Argumentum-megfigyelés |
|---|---|---|
| `CreateFileMappingW` | `0x48F0A6 / 0x48E4A6` | `hFile=INVALID_HANDLE_VALUE`, `lpFileMappingAttributes=NULL`, `PAGE_READWRITE=4`, low size `0x3058`, runtime-formázott név. |
| `GetLastError` | `0x48F150 / 0x48E550` | Mapping/view hibakezelés. |
| `MapViewOfFile` | `0x48F16F / 0x48E56F` | `FILE_MAP_ALL_ACCESS=0xF001F`, low size `0x3058`, offset `0`. |

A view inicializálása:

- `[view+0x00] = 0`;
- `[view+0x10] = 0x100`;
- `[view+0x08] = 0x3040`;
- `[view+0x14..0x3053]` zero-feltöltés;
- `[view+0x3054] = 0`.

Ez magas `[P]` bizonyosságú, pagefile-backed, `0x3058` méretű named shared-memory IPC-képesség. A névben nincs explicit `Global\` vagy `Local\` prefix; ezért a mapping namespace nem állapítható meg statikusan.

A builder közvetlen hívói:

- `0x47E7C4 / 0x47DBC4`
- `0x87F2BE / 0x87E6BE`
- `0x13387D7 / 0x1337BD7`
- `0x2AA2255 / 0x2AA1655`
- `0x2AA250C / 0x2AA190C`
- `0x2AA2CF8 / 0x2AA20F8`
- `0x2AA351B / 0x2AA291B`

A `UnmapViewOfFile` IAT `0x2E4D600 / 0x2E4C000`, közvetlen hívások:

- `0x47F626 / 0x47EA26`
- `0x48EE7D / 0x48E27D`
- `0x87F331 / 0x87E731`
- `0xC81D2C / 0xC8112C`
- `0x1338938 / 0x1337D38`
- `0x2AA23C5 / 0x2AA17C5`
- `0x2AA27E3 / 0x2AA1BE3`
- `0x2AA3219 / 0x2AA2619`
- `0x2AA3699 / 0x2AA2A99`

### 8.2 TBB-jelű once-flag named event

A fix prefix:

- `Local\{C15730E2-145C-4c5e-B005-3BC753F42475}-once-flag`
- raw `0x2C1D3E0`, RVA `0x2C1E9E0`.

A `fn 0x2A70–0x2BFF`:

- a prefixet egy bufferbe másolja;
- egy 32 bites seed hexadecimális értékét 16 karakterként hozzáfűzi;
- `GetCurrentProcessId` IAT `0x2E4D320 / 0x2E4BD20`, hívás `0x2B78 / 0x1F78`;
- a process-ID nyolc hex karakterként kerül a végére;
- `CreateEventA` IAT `0x2E4D258 / 0x2E4BC58`, tail-jump thunk `0x2BF8 / 0x1FF8`;
- argumentumok: `NULL`, `TRUE` manual reset, `FALSE` initial state, generált buffer név.

Ez magas `[P]` bizonyosságú named local event. A GUID-os `once-flag` név összhangban van TBB-jelű vagy stabilizáló szinkronizációval, de az objektum tulajdonosa és pontos célja statikusan nem azonosított; ez nem bizonyított CFX hálózati IPC.

További event-hívások:

- `CreateEventW` IAT `0x2E4D260 / 0x2E4BC60`; `0x1F90AE5 / 0x1F8FEE5` és `0x1F90BC2 / 0x1F8FFC2`; `NULL` névvel anonim manual-reset eventek.
- `CreateEventA` IAT `0x2E4D258 / 0x2E4BC58`; `0x13E1 / 0x7E1` és `0x2105 / 0x1505`; `NULL` névvel anonim eventek.
- `SetEvent` IAT `0x2E4D560 / 0x2E4BF60`; `0x1F90EBA / 0x1F902BA` és `0x1F90EE2 / 0x1F902E2`; anonim lifecycle-event jelzések.
- `ResetEvent` IAT `0x2E4D530 / 0x2E4BF30`; `0x27F0 / 0x1BF0`.
- `OpenEventA` IAT `0x2E4D4B8 / 0x2E4BEB8`; thunk `0x2D86 / 0x2186`, de közvetlen `E8` callsite nem található. Az open-pár konkrét célja ezért nem igazolt.

### 8.3 RPC, COM és egyéb IPC-negatívumok

- Az `RPCRT4.dll` két importja kizárólag `UuidToStringA` és `RpcStringFreeA`; nincs `RpcServerListen`, `RpcBinding`, `NdrClientCall`, `NdrServer` vagy RPC endpoint-string.
- Az `ole32.dll` egyetlen delay-importja `CoTaskMemFree`, IAT RVA `0x3306F60`, raw `0x3305960`; közvetlen hívás `0x10FB79 / 0x10EF79`, az UUID-kezelő funkcióban. Nincs `CoInitialize`, `CoCreateInstance`, `CoGetClassObject` vagy CLSID/IID-string.
- Import- és ASCII/UTF-16-scan nem talált `CreateNamedPipeW/A`, `ConnectNamedPipe`, `DisconnectNamedPipe`, `TransactNamedPipe`, `CreateMailslot`, `NtAlpc*` vagy `ALPC` előfordulást.
- Nincs közvetlen pipe/mailslot/ALPC API-hívás. Dinamikus `GetProcAddress`-os vagy obfuszkált betöltés teljes kizárása statikusan nem lehetséges, ezért ezek a negatívumok közepes-magas `[L]` bizonyosságúak.
- A `Local\{...}-once-flag` string TBB-jellegű objektum, nem CFX network channel.
- A CFX mapping és a TBB-jelű event egymástól külön mechanizmus; a statikus adat nem mutat közvetlen, runtime bizonyított IPC-párt.

## 9. URL- és host/config-összegzés

### Alkalmazási URL

| URL | Raw / RVA | Statikus xref | Minősítés |
|---|---|---|---|
| `http://clients2.google.com/time/1/current` | `0x2C59AD0 / 0x2C5B0D0` | `0x32569 / 0x31969`; `fn 0x30D50–0x3299D` | Egyetlen talált fix, nem-metaadat Google time URL. A path időszinkronra utal, de runtime cél vagy C2 nem bizonyított. |

A `RVA 0x32569` (`raw 0x31969`) utasítás közvetlenül a URL-literal elejére számoló RIP-relative `LEA`. A `fn 0x30D50` közvetlen, közönséges `E8` hívója nem található; lehet inicializálási vagy callbacken keresztül elért kód. A statikus xref önmagában nem aktivitásbizonyíték.

### Kizárt URL- és metadata-nyomok

- `https://curl.se/docs/hsts.html`: raw `0x2E1DA93 / RVA 0x2E1F093`.
- `https://curl.se/docs/alt-svc.html`: raw `0x2E1DB06 / RVA 0x2E1F106`.
- `https://curl.se/docs/http-cookies.html`: raw `0x2E1DF05 / RVA 0x2E1F505`.
- A DigiCert OCSP/CRL URL-ek a tanúsítványi erőforrásban, a szekciótáblázat mögötti cert/metaadatban találhatók; nem alkalmazási végpontok.

A scan további alkalmazási domain/host literalt nem talált. A `localhost`, `127.0.0.1` és `[::1]` előfordulások cURL/Boost parser- és loopback-útvonalakhoz tartoznak, nem távoli konfigurációhoz.

## 10. Végső findings és confidence

| Finding | Confidence | Korlát |
|---|---|---|
| Közvetlen TCP/UDP socket-képesség | Magas `[P]` | Közvetlen IAT-hívások és visszafejtett konstansok. |
| Loopback TCP önteszt | Magas `[P]` | `127.0.0.1`, bind/listen/connect/accept és peer-összevetés. |
| libuv/net TCP-event infrastruktúra | Magas `[P]` | Közvetlen libuv és net DLL-hívások; távoli cél nincs. |
| cURL HTTP/1.1 + TLS | Magas `[P]` | Statikus cURL/OpenSSL kód és közvetlen cert-store hívások. |
| HTTP/2 | Magas `[P]` | nghttp2 source/error code és `PRI * HTTP/2.0` xref. |
| HTTP/3 | Közepes `[L]` | Runtime-ág és hiba-string; backend nincs azonosítva. |
| WebSocket | Közepes `[L]` | Header-szótár és Boost.Beast; handshake callsite nem teljesen bizonyított. |
| Adapter enumeration | Magas `[P]` | Közvetlen `GetAdaptersInfo`. |
| Device-interface enumeration | Magas `[P]` | Közvetlen `CM_Get_Device_Interface_List*`. |
| `X-Device-*` tényleges fingerprint-kibocsátás | Alacsony–közepes `[U]` | Custom literalok jelen vannak, de a teljes literal/kimenő összeállítás nem igazolt. |
| CFX shared-memory IPC | Magas `[P]` | Közvetlen mapping/view inicializálás és ismert méret. |
| TBB-jelű named local event | Magas az event létrehozására, közepes a TBB-jelű célra `[L]` | Közvetlen `CreateEventA` és generált név; a TBB tulajdonosi kapcsolat nem statikusan azonosított. |
| RPC endpoint / COM / ALPC / named pipe / mailslot | Közepes–magas negatív `[L]` | Nincs import vagy statikus API/string; dinamikus betöltés nem zárható ki. |
| Fix Google time URL | Magas statikus jelenlét `[P]` | Runtime használat és C2-jelleg nem bizonyított. |
| C2-kiszolgáló azonosítása | Nem indokolt `[U]` | A statikus hálózati/fingerprint-képesség önmagában nem elég. |

## 11. Következtetés

A statikus elemzés bizonyítja, hogy az `adhesive.dll` erős általános hálózati és játék-hálózati képességeket tartalmaz, és van pagefile-backed named shared-memory mapping, named local event, adapter/device enumeráció, valamint cURL/HTTP/TLS/proxy statikus implementáció. A két loopback tranzakció inkább önteszt/funkcionális ellenőrzés, nem külső kommunikáció. A `clients2.google.com/time/1/current` a statikus sweepben azonosított releváns fix alkalmazási URL, de nincs bizonyíték arra, hogy C2, parancs- és vezérlőcsatorna lenne. A jelentés ezért nem tartalmaz C2-minősítést.

## 12. Jelölési összegző

A jelentés minden confidence-minősítése a `00` §6 globális szerződése szerint explicit `P`/`L`/`U` jelölést visel. A magyar szintszavak változatlanul megmaradtak, és a jelölés nem vezetett be új bizonyítékot.

- **Összes jelölés: 36** — ebből 3 a §1 `Bizonyítéki szintek` legendában, 15 a §10 finding-táblázatban és 18 a szövegtörzs confidence-állításaiban.
- `P` = **22**: `Magas` — közvetlen importált IAT-hívás, pontos argumentum/konstans vagy közvetlenül visszafejtett objektum-művelet.
- `L` = **10**: `Közepes` — statikus library-string/source-path és részben rejtett, de kontextusból azonosítható kódút.
- `U` = **4**: `Alacsony` — csak capability-string vagy import látható, a tényleges runtime-hívás nem bizonyított.
- A vegyes szintű minősítéseknél a gyengébb szint szerinti jelölés az irányadó: `Közepes–magas` → `L`, `Alacsony–közepes` → `U`, `Magas az event létrehozására, közepes a TBB-jelű célra` → `L`. A `Magas statikus jelenlét` → `P`, mert a literal statikus létezése közvetlenül megfigyelhető.
- A `Nem indokolt` minősítés (C2-kiszolgáló azonosítása) `U`: a kérdés a jelen fájlos vizsgálatból nem dönthető el.
- A számozás változatlan: a dokumentum fejezetei `§1`–`§11`, az új blokk `§12`. Egyetlen szám, RVA, raw, string, importnév, IAT- vagy callsite-érték, és egyetlen magyar confidence-szint sem módosult.
