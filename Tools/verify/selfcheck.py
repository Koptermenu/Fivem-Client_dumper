"""Proves the gate can fail.

A gate that has never rejected anything is decoration. This builds four
deliberately broken copies of small real files, one for each failure this
project has actually shipped, and asserts the matching check fires on each.

  1. newlines removed from a rebuilt file
  2. the author's own comment deleted along with the decompiler banner
  3. a string literal altered
  4. a live store deleted

Cases 1 and 4 are the interesting ones: luac accepts both broken files, so the
compiler check alone would wave them through. The script asserts that too.

usage: python selfcheck.py
"""

from __future__ import annotations

import os
import sys
import shutil
import collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gate
import lualex

HERE = os.path.dirname(os.path.abspath(__file__))
# Corpora live under this directory, not at an absolute scratch path: the gate has to work
# from a checkout, and it previously reported "no pairs" on any machine but the one it was
# written on.
YES = os.path.join(HERE, "work", "yes", "Servers", "yes")
MACHO = os.path.join(HERE, "work", "macho")

WORK = os.path.join(HERE, "work", "selfcheck")

# Small, clean, and known to satisfy luac on both sides.
SIMPLE = "0r_lib/modules/client/events.lua"

# A real resource that carries the author's own comments in the cleaned output.
AUTHOR = None


def log(*a):
    print(*a)


def pick_author_fixture():
    """A small macho file whose cleaned output still holds an author comment.

    Returns (size, corpus_relative_path) where the path is the one the gate
    uses as the relative key, so it can be paired back up.
    """
    if not os.path.isdir(MACHO):
        return None
    best = None
    for dirpath, _dirs, files in os.walk(MACHO):
        for fn in files:
            if not fn.endswith(".lua"):
                continue
            ap = os.path.join(dirpath, fn)
            size = os.path.getsize(ap)
            if size > 20000:
                continue
            a = lualex.read_lua(ap)
            authors = [body for _k, body, _r in lualex.comments(a)
                       if body and not lualex.is_banner(body) and len(body) > 20]
            if not authors:
                continue
            marker = os.sep + "Output_gate" + os.sep
            if marker not in ap:
                continue
            rel = ap.split(marker, 1)[1].replace("\\", "/")
            if best is None or size < best[0]:
                best = (size, rel, authors[0])
    return best


def pairs_for(before_root, after_root, wanted=None):
    before = gate.lua_files(before_root)
    after = gate.lua_files(after_root)
    if wanted is None:
        rels = sorted(set(before) & set(after))
    else:
        rels = [r for r in sorted(set(before) & set(after)) if r.endswith(wanted)]
    return [(r, before[r], after[r]) for r in rels]


def make_case(name, rel, before_path, clean_path):
    root = os.path.join(WORK, name)
    shutil.rmtree(root, ignore_errors=True)
    out = os.path.join(root, "cleaned")
    os.makedirs(out)
    shutil.copyfile(clean_path, os.path.join(out, os.path.basename(rel)))
    return root, os.path.join(out, os.path.basename(rel))


def run(name, rel, before_path, after_path):
    res = gate.analyze_corpus(name, [(rel, before_path, after_path)], timing=False)
    gate.corpus_verdict(res)
    return res


# ----------------------------------------------------------------- the mutations


def mutate_drop_newlines(src):
    """Every newline gone. Comments would swallow the rest of the file, so this
    mutation is only applied to a file that has none."""
    if lualex.comments(src):
        return None, "file has comments; collapsing newlines would change more than newlines"
    return src.replace("\r\n", " ").replace("\n", " ").replace("\r", " "), "ok"


def mutate_delete_author_comment(src):
    picked = None
    for _kind, text, _raw in lualex.comments(src):
        if text and not lualex.is_banner(text):
            picked = text
            break
    if picked is None:
        return None, "no author comment in the cleaned file"
    for line in src.splitlines(keepends=True):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("--") and stripped[2:].strip() == picked:
            if line.endswith(("\n", "\r")):
                return src.replace(line, "", 1), "deleted the comment line"
            continue
        # trailing comment: drop the comment, keep the code
        idx = line.find("--")
        if idx != -1 and line[idx + 2:].strip() == picked:
            return src.replace(line, line[:idx], 1), "deleted the trailing comment"
    return None, "author comment %r not found as a line or a trailing comment" % picked[:60]


def mutate_alter_string(src):
    picked = None
    for value, closed in lualex.strings(src):
        if closed and value and "\n" not in value and len(value) > 3:
            picked = value
            break
    if picked is None:
        return None, "no single line string literal"
    for quote in ("'", '"'):
        needle = quote + picked + quote
        if needle in src:
            return src.replace(needle, quote + picked + "_ALTERED" + quote, 1), "ok"
    return None, "literal %r only reachable as a long string" % picked[:40]


def mutate_delete_live_store(src):
    """Delete one assignment whose target is still read afterwards and is never
    written again. Removing it leaves the name read but never assigned, which is
    exactly the shape of the bug that shipped once."""
    code = lualex._code_tokens(src)
    write_idx, _names = lualex._write_map(code)
    n = len(code)
    counts = collections.Counter()
    for i, t in enumerate(code):
        if t.kind == lualex.SYMBOL and t.text == "=":
            for k in lualex._lhs_indices(code, i):
                counts[code[k].text] += 1
    for i, t in enumerate(code):
        if t.kind != lualex.SYMBOL or t.text != "=":
            continue
        lhs = lualex._lhs_indices(code, i)
        if len(lhs) != 1:
            continue
        name = code[lhs[0]].text
        # the whole point: this is the only place the name is ever assigned, so
        # removing the store leaves it read but never assigned
        if name in lualex.KEYWORDS or counts[name] != 1:
            continue
        # end of this statement: next token that starts a new line and is not
        # a continuation of the current expression
        end = i + 1
        depth = 0
        while end < n:
            c = code[end]
            if c.kind == lualex.SYMBOL and c.text in "([{":
                depth += 1
            elif c.kind == lualex.SYMBOL and c.text in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and c.kind == lualex.SYMBOL and c.text in (",", ";", "="):
                break
            end += 1
        # the whole statement must sit on one line
        start = src.rfind("\n", 0, t.begin) + 1
        line_end = src.find("\n", t.end)
        line_end = len(src) if line_end == -1 else line_end + 1
        if src.count("\n", code[end - 1].end, line_end) > 0:
            continue
        read_later = any(
            code[k].kind == lualex.NAME and code[k].text == name and k not in write_idx
            for k in range(end, n))
        written_later = any(
            code[k].kind == lualex.NAME and code[k].text == name and k in write_idx
            for k in range(end, n))
        if not read_later or written_later:
            continue
        return src[:start] + src[line_end:], "deleted the store to %s" % name
    return None, "no single line store to a name that is still read"


# ------------------------------------------------------------------------ cases

def _macho_dirs():
    if not os.path.isdir(MACHO):
        return []
    import json
    slots = None
    idx = os.path.join(MACHO, "index.json")
    if os.path.isfile(idx):
        with open(idx, encoding="utf-8") as fh:
            slots = [r["slot"] for r in json.load(fh).get("resources", [])]
    if slots is None:
        slots = os.listdir(MACHO)
    return [(os.path.join(MACHO, s, "Servers", s),
             s) for s in slots
            if os.path.isdir(os.path.join(MACHO, s, "Servers", s))]


def pick_live_store_fixture():
    """A small file the store mutation applies to.

    Taken from the second corpus on purpose. The store check compares names
    across before and after, and the first corpus renames every decompiler
    register, so a deleted store there changes the name at the same time and the
    comparison cannot see it. In the second corpus the identifiers are the
    author's own and survive the pass untouched, which is the situation the check
    is meant to police.
    """
    best = None
    for base, slot in _macho_dirs():
        clean_root = os.path.join(base, "Output_gate")
        if not os.path.isdir(clean_root):
            continue
        for rel, path in gate.lua_files(clean_root).items():
            size = os.path.getsize(path)
            if size > 15000 or (best is not None and size >= best[0]):
                continue
            src = lualex.read_lua(path)
            if lualex.comments(src):
                continue
            ok, _err = gate.luac_ok(path)
            if not ok:
                continue
            if mutate_delete_live_store(src)[0] is None:
                continue
            if not os.path.exists(os.path.join(base, "Output",
                                               rel.replace("/", os.sep))):
                continue
            best = (size, "%s/%s" % (slot, rel), path)
            break
        if best is not None:
            break
    return best


CASES = [
    ("newlines-removed", SIMPLE, "lines", mutate_drop_newlines,
     "the newlines of a rebuilt file are collapsed"),
    ("author-comment-deleted", None, "comments", mutate_delete_author_comment,
     "the author's own comment is deleted with the banner"),
    ("string-altered", SIMPLE, "strings", mutate_alter_string,
     "a string literal is rewritten"),
    ("live-store-deleted", "AUTO", "live_stores", mutate_delete_live_store,
     "a store that is still read afterwards is deleted"),
]


def main():
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK, exist_ok=True)

    author = pick_author_fixture()
    if author is None:
        log("FATAL no cleaned file with an author comment was found; "
            "build the second corpus first (node build_macho_corpus.js)")
        return 2
    log("author-comment fixture: %s (%d bytes)" % (author[1], author[0]))

    store = pick_live_store_fixture()
    if store is None:
        log("FATAL no cleaned file with a deletable live store was found")
        return 2
    log("live-store fixture   : %s (%d bytes, store to %s)"
        % (store[1], store[0],
           (mutate_delete_live_store(lualex.read_lua(store[2]))[1] or "-").split()[-1]))

    results = []

    # control: the untouched pair must satisfy every check the mutations target
    pairs = pairs_for(os.path.join(YES, "Output"), os.path.join(YES, "Output_gate"),
                      wanted=SIMPLE)
    control = run("control", SIMPLE, pairs[0][1], pairs[0][2])
    clean_signals = {
        "lines": len(control["lines"]["violations"]),
        "comments": control["comments"]["removed_author"],
        "strings": len(control["strings"]["mutated_files"]),
        "live_stores": len(control["live_stores"]["violations"]),
    }
    control_ok = all(v == 0 for v in clean_signals.values())
    results.append(("control (unmodified pair must be clean)", control_ok,
                    "signals %s" % clean_signals))
    log("\ncontrol pair %s: luac before=%s after=%s, signals %s -> %s"
        % (SIMPLE, control["per_file"][SIMPLE]["luac_before"],
           control["per_file"][SIMPLE]["luac_after"], clean_signals,
           "clean" if control_ok else "DIRTY"))

    for name, rel, signal, mutate, description in CASES:
        if rel == "AUTO":
            rel = store[1]
            slot = rel.split("/")[0]
            before_path = os.path.join(MACHO, slot, "Servers", slot, "Output",
                                       *rel.split("/")[1:])
            after_path = store[2]
        elif rel is None:
            rel = author[1]
            before_path = None
            after_path = None
            for _k, b, a in _macho_pairs(rel):
                before_path, after_path = b, a
            if before_path is None:
                log("\n%-22s SKIP (fixture not found)" % name)
                results.append((description, False, "fixture not found"))
                continue
        else:
            before_path = os.path.join(YES, "Output", rel.replace("/", os.sep))
            after_path = os.path.join(YES, "Output_gate", rel.replace("/", os.sep))

        _root, mutated = make_case(name, rel, before_path, after_path)
        src = lualex.read_lua(after_path)
        broken, note = mutate(src)
        if broken is None:
            log("\n%-22s SKIP (%s)" % (name, note))
            results.append((description, False, "mutation not applicable: " + note))
            continue
        with open(mutated, "wb") as fh:
            fh.write(broken.encode("latin-1"))

        res = run(name, rel, before_path, mutated)
        if signal == "comments":
            count = res["comments"]["removed_author"]
        elif signal == "strings":
            count = len(res["strings"]["mutated_files"])
        elif signal == "lines":
            count = len(res["lines"]["violations"])
        else:
            count = len(res["live_stores"]["violations"])
        fired = count > 0
        gate_failed = not res["pass"]

        detail = "%s=%s" % (signal, count)
        if signal == "comments":
            ex = res["comments"]["author_examples"]
            detail += " (e.g. %s)" % (ex[0][1][:70] if ex else "-")
        elif signal == "strings":
            ex = res["strings"]["examples"]
            detail += " (e.g. %s)" % (ex[0]["gained"] if ex else "-")
        elif signal == "live_stores":
            ex = res["live_stores"]["violations"]
            detail += " (e.g. %s)" % (ex[0][1] if ex else "-")
        elif signal == "lines":
            ex = res["lines"]["violations"]
            detail += " (e.g. %s)" % (ex[0] if ex else "-")

        # For the two cases luac cannot see, prove that explicitly.
        luac_note = ""
        if signal in ("lines", "live_stores"):
            ok_before, _ = gate.luac_ok(before_path)
            ok_broken, err = gate.luac_ok(mutated)
            luac_note = " | luac accepts the broken file: %s%s" % (
                ok_broken, "" if ok_broken else " (%s)" % err.splitlines()[-1][:80])

        log("\n%-22s %s" % (name, description))
        log("   mutation        : %s" % note)
        log("   check fired     : %s -> %s" % (fired, detail))
        log("   gate verdict    : %s%s" % ("FAIL" if gate_failed else "PASS", luac_note))
        ok = fired and gate_failed
        results.append((description, ok, detail))

    log("\n================ selfcheck ================")
    bad = 0
    for description, ok, detail in results:
        log("  %-6s %-58s %s" % ("PASS" if ok else "FAIL", description, detail))
        if not ok:
            bad += 1
    log("  %d/%d checks behaved as required" % (len(results) - bad, len(results)))
    return 1 if bad else 0


def _macho_pairs(wanted):
    root = MACHO
    if not os.path.isdir(root):
        return []
    import json
    slots = None
    idx = os.path.join(root, "index.json")
    if os.path.isfile(idx):
        with open(idx, encoding="utf-8") as fh:
            slots = [r["slot"] for r in json.load(fh).get("resources", [])]
    if slots is None:
        slots = os.listdir(root)
    out = []
    for slot in slots:
        base = os.path.join(root, slot, "Servers", slot)
        for rel, b, a in gate.collect_pairs(os.path.join(base, "Output"),
                                            os.path.join(base, "Output_gate")):
            if rel.endswith(wanted):
                out.append((slot + "/" + rel, b, a))
    return out


if __name__ == "__main__":
    sys.exit(main())