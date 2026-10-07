# Central configuration store

A dumper kozponti, IP-alapu konfiguracios tara. Egy sikeres dump utan minden
szerver `/client` valasza ide kerul, es innentol a szerver **jatek-csatlakozas
es token nelkul** ujra dumpolhato.

## Futtatas

```
bun install        # nincs fuggoseg, de ha valaki sertoseged…
bun run start      # default port 8920
PORT=9000 bun run start
```

Az adat a `store/data/<key>.json` fajlokba kerul (key = `safeName("http://ip:port")`).

## API

| Vegpont | Mire jo |
|---|---|
| `GET /v1/servers/<key>` | a tarolt `/client` valasz (`200`), vagy `404`; a valaszba a backend beleirja a `storeSavedAt` idobélyeget |
| `POST /v1/servers/<key>` | torzsben a `/client` valasz JSON; csak akkor fogadja el, ha van benne `resources` tomb |

## A dumper oldali beallitas

```
set DUMPER_STORE_URL=http://a-te-szervered:8920   # alapertelmezes: grantsclk.ckcloud.de5.net
set DUMPER_STORE_URL=off                          # kikapcsolas
```

## Uj resource-ok esete

A dumper **eloszor** mindig az elo `/client`-et hivja, es siker eseten azonnal
frissiti a tarat — tehat aki friss tokennel dumpol, az automatikusan frissiti a
tarolt listat. Ha valaki a tarbol dumpol (offline mod), az a pillanatnyi
pillanatfelvetelt latja: az utana felfejtett uj resource-okat csak egy friss
(clientes) dump hozza be. A dumper a `storeSavedAt` alapjan figyelmeztet, ha a
tarolt konfiguracio 24 oranak regebbi.
