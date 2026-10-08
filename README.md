# FiveM Dumper - AllInOne

Native C++ FiveM resource dumper. No dependencies beyond Windows itself: HTTP, AES and
process memory reading use the built-in APIs, SHA-256, ChaCha20 and the JSON parser are
in `src/`.

## Build

```
build.bat
```

The exe lands in `build\Release\fivem_dumper.exe`. `build.bat` picks the installed Visual
Studio with `vswhere`, so VS 2019, 2022 and 2026 all work.

`Bin/` is not in the repository (2.4 GB), but the build packs it into the exe as an RCDATA
payload. It needs the FXServer components (`Bin/citizen/`, `Bin/*.dll`,
`Bin/Unpacker.exe`) and `Bin/vertex-fixer/`.

## Use

1. Start FiveM and join a server
2. Run `fivem_dumper.exe`. The token and the IPs come from the game's memory
3. Pick a server, then resources: `1,3` by index, `5-8` for a range, names like
   `pma-voice, ox_lib`, `all`, or `q` to quit

Output goes to `Servers\<name>\Output\<resource>\`. Interrupted runs continue from
`checkpoint.json`, and warnings go to `dumper.log` instead of the console.

The server name is read from `GET /dynamic.json`, so there is nothing to type. The first
successful `/client` response is cached in `Servers\<name>\config.json` and uploaded to a
store under `DUMPER_STORE_URL`, which lets a later dump run without the game.

## Environment

| Variable | Meaning |
|---|---|
| `DUMPER_TOKEN` | token, skips the memory scan |
| `DUMPER_SERVER_IP` | fixed server, no prompt |
| `DUMPER_RESOURCE` | one resource only |
| `DUMPER_WORKERS` | parallel downloads (1-64, default 24) |
| `DUMPER_KEEP_TEMP` | keeps `Temp`, `TempCompiled` and `Unpacked` for debugging |
| `DUMPER_CONFIG` | `config.json` to dump without a token or the game |
| `CK_CLIENT_KEY_API_URL` | client key service; `off` = fully offline |

## Notes

- The `unluac` jar is in the exe, but a runnable Java is needed to decompile the Lua.
- Encrypted resources have two layers: an `FXAP` header with a fixed key, then a variable
  length meta block ahead of the nonce, so the nonce offset is read from the `uint16`
  length field. Both the `grants` and the client key are tried on every file.
- The exe is about 217 MB, payload included.