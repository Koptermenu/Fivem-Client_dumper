# Naming model

    ai\deploy\build_model.bat [adapterDir]

Builds the deployable model: LoRA merged into the base weights, then f16 GGUF, then Q4_K_M.

    ai\rl\out_v2\final  ->  ai\deploy\model\merged  ->  qwen_lua_namer_f16.gguf  ->  qwen_lua_namer_q4km.gguf

`ai\rl\out_v2\final` is the default adapter because it scored best on complete maps, which
matters more than the raw exact-match count. The candidates were 331 to 338 correct out of 806,
a spread of 7 names over 25 files, so they are within noise of each other on accuracy. What
separates them is that 23 of 25 files got a well formed complete map against 22, and an
incomplete map leaves the remaining registers as garbage, which no later stage recovers.

The f16 GGUF is an intermediate and can be deleted after quantisation; the Q4_K_M is the one to
ship.

## Running it

    llama-cli.exe -m model\qwen_lua_namer_q4km.gguf -f prompt.txt -n 300 -st -c 4096

**`-st` is not optional.** Without `--single-turn`, llama-cli runs as an interactive REPL. If
stdin stays open it never exits and accumulates the conversation in its context, and because
`-c` defaults to loading from the model, that context is 32768 tokens. Measured on this machine
with a 379 MB model and a 2,376 byte prompt: RAM climbed 898 MB to 4,597 MB in 19 seconds while
generating **five** tokens, and reached 13 GB before it was killed. With `-st -c 4096` the same
prompt peaks at **564 MB** and exits cleanly in 6 seconds.

Bounding `-c` alone does not help. The 32768-token default was measured at 5,746 MB peak, still
climbing; the growth is the REPL loop, not the context reservation.

The model only ever answers with names. It is given cleaned Lua and replies with one
`register=readableName` line per register, and must never be allowed to write code: a measured
attempt to have it rewrite the files produced output that compiled about half the time and
dropped or merged function arguments.

## Provenance

- base: `Qwen2.5-Coder-0.5B`, from `%LOCALAPPDATA%\Temp\opencode\base`. 953 MB, and the build
  needs it. It is the one thing in the temp tree that cannot simply be deleted.
- quantiser: the CPU build of the pinned llama.cpp `b11146` in this directory. The CUDA build's
  `llama-quantize.exe` fails on a missing DLL, and adding ~600 MB of CUDA runtime to requantise a
  0.5B model is not worth it. Inference still uses the GPU through the engine's CUDA build.
- held-out scores for every candidate are in `ai\rl\eval_sweep.txt` and `ai\rl\result_rl.json`,
  both scored on 25 files and 806 names with input digest `8035f83da374`.