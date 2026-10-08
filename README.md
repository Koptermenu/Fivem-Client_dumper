# FiveM Dumper - AllInOne (C++)

Native C++ FiveM resource dumper and decoder. No external dependencies: HTTP, AES and
memory reading come from Windows' own APIs, the rest (SHA-256, ChaCha20, JSON) is
implemented in this repository.

## Building

```
build.bat
build\Release\fivem_dumper.exe
```

`build.bat` runs `vswhere` to find the installed Visual Studio that has the C++ x64/x86
tools and configures with it. VS 2019, 2022 and 2026 all work, there is no version to
hardcode.

```
DUMPER_GENERATOR="Visual Studio 16 2019" build.bat   # override the generator
cmake -B build -DCMAKE_CXX_STANDARD=17                # older toolset, if C++20 is unavailable
```

By hand:

```
cmake -B build -G "Visual Studio 18 2026"
cmake --build build --config Release --parallel
```

Do not skip the configure step. The embedded payload and its SHA-256 manifest are
produced at configure time, so it has to re-run even in an existing build tree. The tree
caches its generator, and CMake refuses to reuse a tree created by a different Visual
Studio. `build.bat` detects that and deletes the old tree, so you never have to clear
`build\` by hand.

### The `Bin/` folder

`Bin/` is not in the repository (2.4 GB of build input), but the build assembles it into
an RCDATA payload that the program unpacks at runtime:

| input | what it has to contain |
|---|---|
| `Bin/citizen/`, `Bin/*.dll`, `Bin/Unpacker.exe` | the FXServer components |
| `Bin/vertex-fixer/` | the vertex fixer and its .NET dependencies (9 files, 9.2 MB) |

`Bin/vertex-fixer/` is `FivemDecryptFixer.Cli`, `CodeWalker.Core`, `SharpDX` and
`CK.VertexBridge`. If it is missing, the program silently skips the vertex repair, and the
decompiled Lua works either way.

| component | source |
|---|---|
| HTTP | WinHTTP (built into Windows) |
| AES-256-CBC | BCrypt (built into Windows) |
| SHA256 / HMAC-SHA256 | own implementation (`src/crypto/Sha256.cpp`) |
| ChaCha20 (8/12 byte nonce) | own implementation (`src/crypto/ChaCha20.cpp`) |
| JSON parser | own implementation (`src/utils/Json.cpp`) |
| memory scan | Toolhelp32 + VirtualQueryEx + ReadProcessMemory |

## Usage

1. Start FiveM and join a server
2. `fivem_dumper.exe`, where the token and the IPs are picked up from the game's memory
   automatically
3. Pick a server from the list, or type the IP
4. Pick resources: index (`1,3`), range (`5-8`), names (`pma-voice, ox_lib`), all
   (`all`), or `q` to quit

### What the dumper does

The exe stands on its own. The whole `Bin/` folder and the VC++ runtime DLLs are embedded
as RCDATA resources; on first run they are unpacked into
`%LOCALAPPDATA%\FiveMDumper\payload`, verified by size and SHA256. If an antivirus
deletes or touches them, they are packed again automatically. The finished exe runs on
any machine with no extra files, and it deliberately ignores the `Bin/` folder next to
the project root.

- Server name comes automatically from the `hostname` field of `GET /dynamic.json`
  (`sv_hostname`), so there is nothing to type. FX color markup (`^0`-`^9`, `^^`, `^s`)
  is stripped, and the `default FXServer` / `FXServer, but unconfigured` placeholder
  names are rejected
- Name cache in `server_name.txt`: the list shows the name, and if `dynamic.json` fails
  this is the fallback, ahead of the prompt
- Progress bar for both the download and the decryption
- Checkpoint (`checkpoint.json`): after Ctrl-C, a kick or a timeout it resumes where it
  stopped. It is only deleted once every selected resource is finished
- Warnings go to `dumper.log` only, the console stays clean
- Encrypted (`.fxap`) resources: FXAP -> ChaCha20 -> Lua decompilation, in two layers
  (see below)
- Connection reset and timeout: 5 retries with exponential backoff (2/4/8/16 s), which
  also survives a server restart window
- Decryption is skipped when a resource has no `.fxap`: the second phase closes right
  away with a rename, no grants load, no per-file work
- Manifest backfill: if the RPF unpack produces no fxmanifest, it is fetched separately
  from the `/files` endpoint; if the unpack fails outright, the raw `.rpf` is kept
- **Config cache and server restart tolerance**: the first successful `/client` response
  is stored in `Servers/<name>/config.json`. If the server stops answering later (it
  restarted) or rejects the token, the dumper loads that cache and carries on; the game
  connection is only needed for a fresh token, not for the whole dump
- **Central store, keyed by IP**: every successful configuration is uploaded to the store
  under `DUMPER_STORE_URL` (default `http://188.97.125.55:8920`) at
  `GET/POST /v1/servers/<safeName(baseUrl)>`. The dumper always tries the server first
  and the store second. If the IP's configuration is already there, the dump works with
  no game connection and no token. If there is data nowhere, the dumper asks for a
  one-time login and uploads the config at that point

### Environment variables

| Variable | Meaning |
|---|---|
| `DUMPER_TOKEN` | token, skips the memory scan |
| `DUMPER_SERVER_IP` | fixed server, no interactive question |
| `DUMPER_SERVER_NAME` | fixed folder and server name |
| `DUMPER_RESOURCE` | this one resource only |
| `DUMPER_WORKERS` | parallel downloads (1-64, default 24) |
| `DUMPER_KEEP_TEMP` | keeps the `Temp`, `TempCompiled` and `Unpacked` folders for debugging. Any value counts, the empty string too; deleted by default |
| `DUMPER_TEST_MODE=1` | non-interactive mode |
| `DUMPER_CONFIG` | path to a `config.json` for dumping without a token or a game connection (e.g. copied from another machine; `DUMPER_SERVER_IP` supplies the IP) |
| `CK_CLIENT_KEY_API_URL` | address of the client key service (default `https://grantsclk.ckcloud.de5.net`); `CK_GRANTS_CLK_API_URL` is accepted as well. **`off` = fully offline** |

### Running without network

| dependency | status |
|---|---|
| `Grants.txt` key token | **local**, from `Servers/<name>/Resources/Grants.txt` |
| `grants` server key | **local**, derived from the token |
| central store (`Servers/`) | **local**, the `store/` folder; it answers on `http://127.0.0.1:8920` |
| client key (`/v1/derive`) | **needs network**, see below |

```
set DUMPER_STORE_URL=http://127.0.0.1:8920
set CK_CLIENT_KEY_API_URL=off
```

The **client key is the only one** that is not local. The service holds a key *table* in
a Cloudflare Workers KV (`/health` reports `workers-kv-read-only`), not a computed
algorithm, so it cannot be reproduced locally from `grants_clk`. If you only need the
**server-keyed** files, those two variables are enough and you need no network at all;
everything else stays encrypted.

`CK_CLIENT_KEY_API_URL=off` does not just switch off that one value, it **interrupts** the
query: if the service is unreachable (no answer, DNS or connect error), the dumper does
not retry it for the remaining resources. That matters because a real server has 969
`grants_clk` entries and the connect timeout would run again on every single one: the
first call takes 30 s, the rest 0 ms, so without the interrupt a full pass would have
taken roughly 8 hours.

The interrupt triggers on a **transport error** (no HTTP status at all). If the service
**does answer** but does not know the given resource (`HTTP 400`), that does **not**
switch it off: the service is alive, it just has no entry for that value.

## Resource decryption

For an encrypted resource the dumper takes apart two layers:

1. **Outer FXAP layer**: the file starts with the `FXAP` header; the nonce is the 12
   bytes read from byte 74, the encrypted content starts at byte 86. The key is fixed.
2. **Inner layer**: the unwrapped block holds a variable-length meta block (the file's
   SHA-256 and its original path), **then** the 12 byte nonce, then the encrypted
   content. The meta block length changes per file (74-105 bytes on real data), so the
   nonce position cannot be computed from a fixed offset and has to be read from the
   `uint16` length field. The old fixed 80/92 offsets would only be correct for 74 byte
   meta blocks.

The `.fxap` header holds the resource identifier, which gives two possible keys:

| key | source | what it opens |
|-------|--------|---------------|
| grants | the `grants` field of the grants token | server-side files |
| client | returned by the key service from `grants_clk` | client-side `.lua` |

**The key that belongs to the file is always the one that opens it.** It is not decided
per resource: some files come with the grants key, others with the client key, so both
are tried on every file and the first valid result wins.

Stream files (`.awc .ybn .ydd .ydr .yft .ymap .ymf .ytd .ytyp`) are only written after
their `RSC7`/`RSC8` header has been checked, so an unverified entity cannot end up there.

With the client key service, the 64 byte `grants_clk` found in 78% of cases cannot be
resolved: the service only accepts the canonical 48 byte form, and the token's 64 byte
value contains it neither as a prefix nor as a suffix. For those resources the
server-side files decrypt, and the client-side `.lua` stays on disk under `<file>.raw` as
the encrypted original.

## Directory layout

```
Servers/<server name>/
  Resources/Grants.txt
  Output/<resource>/...      <- the finished, decoded files
%LOCALAPPDATA%/FiveMDumper/payload/   <- Bin/ and the jar, unpacked from the exe
                                        (standalone exe: nothing else to download)
```

## Notes

- The `unluac` jar is in the exe (`v1.2.3.511`), but decompiling Lua needs a runnable
  **Java** on the machine, the jar is not an executable by itself. If decompilation
  fails, the program tries the `--disassemble` / `--assemble` round trip to repair the
  broken labels; if that fails too, the bytecode is kept as `<file>.luac` and the listing
  as `<file>.asm`.
- The embedded payload is roughly 215 MB, so the finished exe comes to roughly 217 MB.
  The exact size depends on the current contents of `Bin/` (which is not part of the git
  repository).
- From a server without encryption everything simply falls out. For `.fxap` resources the
  grants token decides which key is needed.