# Verification gate for the deterministic Lua cleanup pass

    powershell -NoProfile -ExecutionPolicy Bypass -File check.ps1

One command, one verdict, non-zero exit on failure. Nothing outside this
directory is written to; the corpora are only ever read.

## Why this exists

The pass rewrites thousands of decompiled Lua files. Three times it produced
output that looked fine and was quietly wrong: a live store deleted, the
author's own comments removed along with the decompiler banners, every newline
of a rebuilt file collapsed. Each was caught by reading, never by measuring. A
change that looks cleaner is not evidence.

## What runs

| step | what | file |
| --- | --- | --- |
| 1 | build `bin\pass.exe` from the project's current `src\ai\Cleanup.cpp` | `build_pass.bat`, `passdrv.cpp` |
| 2 | decrypt every Macho `.fxap` directory into decompiler output and run the pass over it | `build_macho_corpus.js` |
| 3 | prove the four historical failures are detectable | `selfcheck.py` |
| 4 | measure both corpora | `gate.py` |

Step 1 rebuilds only when a source is newer than the binary. The pass is edited
in place while the gate runs, so measuring a stale binary would be measuring the
wrong thing.

## The checks

1. **luac** on every file before and after. Only a file luac accepted before and
   rejects after is a regression. Files the decompiler already emitted invalid
   are listed by relative path and are explicitly not counted against the pass.
2. **Comments**, split into decompiler banners (the marker list mirrors
   `isBannerLine()` in `Cleanup.cpp`) and the author's own. Target: zero of the
   author's lost.
3. **String literals** as a per-file multiset of decoded values, from a real
   lexer. A cleaned file that holds a literal the decompiler never produced is a
   rewritten string and fails. Literals that only disappear are reported
   separately, because removing a dead store legitimately removes one. CRLF
   against LF is normalised first so a line-ending rewrite is not mistaken for a
   changed string.
4. **Readability**: the whole pattern
   `\b(SHX\d*_\d+|text\d+|num\d+|table\d+|L\d+_\d+)\b`, reported over all files
   *and* excluding `rtx_themepark/client/paths.lua`, which is called out because
   it holds ~85% of what is left and a previous report on this project quoted
   only the other figure.
5. **Runtime**, one pass run per file, with a 30s flag and a 300s hard kill so a
   quadratic regression is caught by a clock and not by memory.

Plus two checks the history demanded:

6. **Line structure**, so a rebuild that drops newlines is caught even though
   luac is perfectly happy with a one line file.
7. **Live stores**: a name assigned before, still read after, never assigned
   after. Known limit: the comparison is by name, so where the pass also renames
   the variable the check is blind.

`selfcheck.py` builds a deliberately broken copy of a small real file for each of
those four historical failures and asserts the matching check fires, plus a
control pair that must come out clean. Cases 6 and 7 are proven undetectable by
`luac`: the selfcheck asserts `luac` accepts the broken file too.

## Notes

- `lualex.py` is a real Lua 5.4 lexer, not a regex over source. `luaparser` 4.2
  is installed and was tried as an independent cross-check; it parses 1 of 18
  files in the second corpus and 0 of 329 in the first (the `FXAP` payloads and
  the decompiler's `goto ::label::` output), so it cannot be the extractor of
  record here.
- No JSON is read by PowerShell. `ConvertFrom-Json` throws on these corpora
  because identifiers such as `Framework` and `framework` collide in its
  case-insensitive hashtable; the JSON is produced and consumed in Python.
- `luac` runs with `-p -o NUL`, which parses without writing output.
- `Get-ChildItem -Recurse` is used throughout; PowerShell's `**` does not
  recurse.