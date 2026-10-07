"""Decides which proposed names may be written into a file, and writes the result.

This is the only code here allowed to touch Lua text, and it only ever rewrites an
identifier that is already a synthetic register. Every proposal must clear every check below
or the original register name stays exactly where it was; there is no partial application and
no fallback rename. Accepted and rejected proposals are written to separate files so the
rejection rate can be measured rather than assumed.

The checks, in the fixed order they are evaluated:

  empty               the value is not a non-empty string
  invalid_identifier  the value is not [A-Za-z_][A-Za-z0-9_]*
  lua_keyword         the value is one of Lua's reserved words
  self_rename         the value equals the register's own name, so nothing would change
  not_a_register      the key is not a synthetic register present in this file
  collision_local     the value is bound by a `local` statement in this file, so the
                      register would collide with another local
  shadow_local        the value is a parameter or loop variable name declared in this file,
                      which a rename at file scope would shadow
  collision_global    the value is a global the file already reads or writes, so renaming
                      would shadow it inside the register's scope
  duplicate_name      an earlier accepted proposal in this file already took that value, so
                      two distinct registers would collapse onto one name
"""

import argparse
import collections
import io
import json
import os
import re
import sys

import extract

IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# `local a, b, c` and `local function a`, and the loop variables of a numeric for.
LOCAL_DECL_RE = re.compile(
    r"\blocal\s+(function\s+)?([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*)")
PARAM_DECL_RE = re.compile(r"\bfunction\b[^\n]*?\(([^()]*)\)")


def declared_locals(code):
    """Names introduced by a `local` statement anywhere in the code."""
    names = set()
    for m in LOCAL_DECL_RE.finditer(code):
        for ident in m.group(2).split(","):
            ident = ident.strip()
            if IDENT_RE.match(ident) and ident not in extract.KEYWORDS:
                names.add(ident)
    return names


def declared_params(code):
    """Names in a parameter list, which a register of the same name would shadow."""
    names = set()
    for m in PARAM_DECL_RE.finditer(code):
        for ident in m.group(1).split(","):
            ident = ident.strip()
            if IDENT_RE.match(ident) and ident not in extract.KEYWORDS:
                names.add(ident)
    return names


def classify(key, value, file_idents, locals_, params_, taken):
    if not isinstance(value, str) or value == "":
        return False, "empty"
    if not IDENT_RE.match(value):
        return False, "invalid_identifier"
    if value in extract.KEYWORDS:
        return False, "lua_keyword"
    if value == key:
        return False, "self_rename"
    if key not in file_idents:
        return False, "not_a_register"
    if value in locals_:
        return False, "collision_local"
    if value in params_:
        return False, "shadow_local"
    if value in file_idents:
        return False, "collision_global"
    if value in taken:
        return False, "duplicate_name"
    return True, "ok"


FIELD_RE = re.compile(r"[.:]\s*(" + extract.SYNTH_RE.pattern + r")\b")
KEY_RE = re.compile(r"[{,]\s*(" + extract.SYNTH_RE.pattern + r")\s*=(?!=)")


def protected_spans(code):
    """Line ranges holding a register used as a field or a table key, not as a variable.

    A register written as `.text2` or `{ SHX16_1 = 1 }` is part of that table's shape.
    Rewriting those positions would change what the program computes, so they are skipped
    even when the register is renamed elsewhere.
    """
    noise = extract.strip_noise(code)
    n = len(code)
    skip = bytearray(n)
    for m in list(FIELD_RE.finditer(noise)) + list(KEY_RE.finditer(noise)):
        s = noise.rfind("\n", 0, m.start(1))
        s = 0 if s < 0 else s + 1
        e = noise.find("\n", m.end(1))
        e = n if e < 0 else e
        for i in range(s, e):
            skip[i] = 1
    return skip


def rename(code, accepted):
    """Applies accepted renames to whole-register positions only."""
    if not accepted:
        return code
    skip = protected_spans(code)
    pieces = []
    pos = 0
    for m in extract.SYNTH_RE.finditer(code):
        new = accepted.get(m.group(0))
        if new is None:
            continue
        s = m.start()
        if skip[s]:
            continue
        head = code[:s].rstrip()
        if head.endswith(".") or head.endswith(":"):
            continue
        pieces.append(code[pos:s])
        pieces.append(new)
        pos = m.end()
    if not pieces:
        return code
    pieces.append(code[pos:])
    return "".join(pieces)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--proposals", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--accepted", required=True)
    ap.add_argument("--rejected", required=True)
    ap.add_argument("--exclude", default=os.path.join("rtx_themepark", "client", "paths.lua"))
    args = ap.parse_args()

    exclude = os.path.normcase(args.exclude)
    acc_fh = io.open(args.accepted, "w", encoding="utf-8")
    rej_fh = io.open(args.rejected, "w", encoding="utf-8")

    reasons = collections.Counter()
    totals = collections.Counter()
    for line in io.open(args.proposals, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        rel = rec["file"]
        if os.path.normcase(rel) == exclude:
            continue
        code = extract.read(os.path.join(args.root, rel))
        bare = extract.strip_noise(code)
        regs = extract.register_set(code)
        file_idents = extract.identifiers(code) | regs
        locals_ = declared_locals(bare)
        params_ = declared_params(bare) - regs

        taken = set()
        accepted_map = {}
        for key, value in rec["proposals"]:
            totals["proposed"] += 1
            ok, reason = classify(key, value, file_idents, locals_, params_, taken)
            if ok:
                taken.add(value)
                accepted_map[key] = value
                reasons["accepted"] += 1
                acc_fh.write(json.dumps({"file": rel, "register": key, "name": value},
                                        ensure_ascii=False) + "\n")
            else:
                reasons[reason] += 1
                rej_fh.write(json.dumps({"file": rel, "register": key, "name": value,
                                         "reason": reason}, ensure_ascii=False) + "\n")
        totals["registers_offered"] += rec["registers"]
        totals["unique_registers"] += rec["unique"]
        totals["files"] += 1
        totals["seconds"] += rec.get("seconds", 0.0)
        totals["dropped"] += sum(rec.get("dropped", {}).values())

        new_code = rename(code, accepted_map)
        out_path = os.path.join(args.out, rel)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with io.open(out_path, "w", encoding="utf-8", newline="") as fh:
            fh.write(new_code)

    acc_fh.close()
    rej_fh.close()

    proposed = totals["proposed"]
    accepted = reasons["accepted"]
    print("files processed      :", totals["files"])
    print("registers offered    :", totals["registers_offered"])
    print("unique registers     :", totals["unique_registers"])
    print("proposals received   :", proposed)
    print("dropped while parsing:", totals["dropped"])
    print("accepted             :", accepted)
    print("rejected             :", proposed - accepted)
    for r, n in sorted(reasons.items(), key=lambda kv: -kv[1]):
        if r != "accepted":
            print(f"  {r:20s}: {n}")
    if proposed:
        print(f"acceptance rate      : {accepted / proposed * 100:.1f}%")
        print(f"rejection rate       : {(proposed - accepted) / proposed * 100:.1f}%")
    print(f"inference seconds    : {totals['seconds']:.1f}")
    print(f"seconds per file     : {totals['seconds'] / max(1, totals['files']):.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())