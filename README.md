# FiveM Dumper - AllInOne (C++)

Native C++ FiveM resource dumper and decoder. No external dependencies: HTTP, AES and
memory reading use the built-in Windows APIs, the rest (SHA-256, ChaCha20, JSON) is in
`src/`.

## Build

```
build.bat
build\Release\fivem_dumper.exe
```

`build.bat` asks `vswhere` which Visual Studio has the C++ x64/x86 tools and configures
with it, so VS 2019, 2022 and 2026 all work. Override with
`DUMPER_GENERATOR="Visual Studio 16 2019" build.bat`, or run CMake by hand:

```
cmake -B build -G "Visual Studio 18 2026"
cmake --build build --config Release --parallel
```

Do not skip the configure step: the embedded payload and its SHA-256 manifest are built
at configure time. The build tree caches its generator and CMake refuses to reuse a tree
across Visual Studio versions, which `build.bat` handles by deleting the stale one.

`Bin/` is not in the repository (2.4 GB), but the build packs it into an RCDATA payload.
It needs the FXServer components (`Bin/citizen/`, `Bin/*.dll`, `Bin/Unpacker.exe`) and
`Bin/vertex-fixer/` (`FivemDecryptFixer.Cli`, `CodeWalker.Core`, `SharpDX`,
`CK.VertexBridge`). Without the vertex fixer the repair step is skipped silently, and
the decompiled Lua still works.

## Use

1. Start FiveM and join a server
2. Run `fivem_dumper.exe`; the token and the IPs are picked up from the game's memory
3. Pick a server from the list, or type the IP
4. Pick resources: index (`1,3`), range (`5-8`), names (`pma-voice, ox_lib`), `all`, or
   `q` to quit

The exe needs nothing else on the machine: `Bin/` and the VC++ runtime DLLs are unpacked
to `%LOCALAPPDATA%\FiveMDumper\payload` on first run, verified by size and SHA256, and
repacked if something deletes them.

Output lands in `Servers/<name>/Output/<resource>/`. `checkpoint.json` makes an
interrupted run resumable, and warnings go to `dumper.log` rather than the console.

The server name comes from the `hostname` field of `GET /dynamic.json`, with FX color
markup stripped. If the server stops answering, the first successful `/client` response
is reused from `Servers/<name>/config.json`, and successful configurations are also
uploaded to a central store under `DUMPER_STORE_URL` (default
`http://188.97.125.55:8920`). Those two together mean a dump can run with no game
connection at all, as long as the IP is known.

## Environment

| Variable | Meaning |
|---|---|
| `DUMPER_TOKEN` | token, skips the memory scan |
| `DUMPER_SERVER_IP` | fixed server, no interactive question |
| `DUMPER_SERVER_NAME` | fixed folder and server name |
| `DUMPER_RESOURCE` | this one resource only |
| `DUMPER_WORKERS` | parallel downloads (1-64, default 24) |
| `DUMPER_KEEP_TEMP` | keeps `Temp`, `TempCompiled` and `Unpacked` for debugging; any value counts, deleted by default |
| `DUMPER_TEST_MODE=1` | non-interactive mode |
| `DUMPER_CONFIG` | path to a `config.json`, for dumping without a token or a game connection |
| `CK_CLIENT_KEY_API_URL` | client key service (default `https://grantsclk.ckcloud.de5.net`; `CK_GRANTS_CLK_API_URL` also accepted); `off` = fully offline |

To run without network, start the store locally and turn the key service off:

```
set DUMPER_STORE_URL=http://127.0.0.1:8920
set CK_CLIENT_KEY_API_URL=off
```

The client key is the one thing that cannot be done offline, because the service holds a
key *table* in a Cloudflare Workers KV rather than computing it. `off` also interrupts
the query, which matters when a real server has 969 `grants_clk` entries and a connect
timeout on each would add up to about eight hours. Only the server-keyed files decrypt
this way; the rest stay encrypted.

## Decryption

An encrypted resource has two layers. The outer one is the `FXAP` header: 12 nonce bytes
at offset 74, ciphertext from byte 86, fixed key. The inner one holds a variable-length
meta block (the file's SHA-256 and original path), then the 12 byte nonce, then the
ciphertext. That meta block is 74-105 bytes on real data, so the nonce offset has to be
read from the `uint16` length field instead of assumed.

The header also holds the resource identifier, which selects between two keys: `grants`
from the token, or `client` from the key service via `grants_clk`. Both are tried on
every file, since files of the same resource can come with either, and the first valid
result wins. Stream files (`.yft`, `.ymap`, `.ytd` and the rest) are only written once
their `RSC7`/`RSC8` header checks out.

With the service enabled, the 64 byte `grants_clk` found in 78% of cases cannot be
resolved: it only accepts the canonical 48 byte form, which the token's value contains
neither as a prefix nor as a suffix. Those resources keep their server-side files
decoded, and the client-side `.lua` stays on disk as `<file>.raw`.

## Notes

- The `unluac` jar is embedded (`v1.2.3.511`), but Lua decompilation needs a runnable
  Java on the machine. If decompilation fails, the dumper retries with
  `--disassemble`/`--assemble` to repair broken labels, and failing that keeps the
  bytecode as `<file>.luac` with the listing as `<file>.asm`.
- The payload is about 215 MB, so the exe lands around 217 MB.
- Servers without encryption need none of the above; everything just falls out.