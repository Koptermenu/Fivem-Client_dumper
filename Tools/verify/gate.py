"""Verification gate for the deterministic Lua cleanup pass.

Five kinds of evidence, all measured rather than read off a diff:

  1. luac -p on every file before and after; only a file luac accepted before and
     rejects after is a regression. Files the decompiler already emitted invalid
     are identified by relative path and are not counted against the pass.
  2. Comment preservation, split into decompiler banners and the author's own
     comments. Only the author's comments are load bearing.
  3. String literal multiset equality, from a real lexer, per file.
  4. Readability: the whole synthetic-register pattern, reported with and
     without the one file that holds almost all of the leftovers.
  5. Wall clock time of the pass per file, with a hard limit.

Two further checks exist because the historical failures demanded them: newline
structure and live stores. Each of those was noticed once by reading a diff.

JSON is produced and consumed with Python's json module only: these corpora
contain identifiers that differ only in case and PowerShell's ConvertFrom-Json
throws on them.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lualex

LUAC = r"C:\Users\Admin\AppData\Local\Programs\Lua\bin\luac.exe"




NAME_RE = re.compile(r"\b(SHX\d*_\d+|text\d+|num\d+|table\d+|L\d+_\d+)\b")


READABILITY_EXCLUDE = "rtx_themepark/client/paths.lua"


BASELINE_BEFORE = 398346
BASELINE_AFTER = 158871






LINE_RATIO_MIN = 0.02
LINE_COLLAPSE_AFTER = 2
LINE_COLLAPSE_BEFORE = 10

SECOND_LIMIT = 30.0
HARD_TIMEOUT = 300.0

MAX_EXAMPLES = 10


def norm_eol(text):
    """CRLF to LF.

    The pass rewrites the whole file with LF endings. That changes bytes on
    every line but is not a lost comment and not, on its own, a changed string.
    Anything still different after this normalisation really did change.
    """
    return text.replace("\r\n", "\n").replace("\r", "\n")





def read_text(path):
    with open(path, "rb") as fh:
        return fh.read().decode("latin-1")


def lua_files(root):
    """relative path (forward slashes) -> absolute path, for every .lua under root."""
    found = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if not name.lower().endswith(".lua"):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace("\\", "/")
            found[rel] = full
    return found


def luac_ok(path):
    try:
        proc = subprocess.run(
            [LUAC, "-p", "-o", "NUL", path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=HARD_TIMEOUT,
        )
        return proc.returncode == 0, proc.stderr.decode("utf-8", "replace").strip()
    except subprocess.TimeoutExpired:
        return False, "luac timed out"
    except OSError as exc:
        return False, "luac could not run: %s" % exc





def time_pass(pass_exe, scratch, before_path, limit):
    """Run the pass on a single file. Returns (seconds, over_limit, killed, stats)."""
    in_dir = os.path.join(scratch, "in")
    out_dir = os.path.join(scratch, "out")
    shutil.rmtree(in_dir, ignore_errors=True)
    shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(in_dir, exist_ok=True)
    shutil.copyfile(before_path, os.path.join(in_dir, "unit.lua"))
    started = time.perf_counter()
    killed = False
    proc = None
    try:
        proc = subprocess.run(
            [pass_exe, in_dir, out_dir],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=HARD_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        killed = True
    elapsed = time.perf_counter() - started
    stats = None
    if proc is not None and proc.stdout:
        try:
            stats = json.loads(proc.stdout.decode("utf-8", "replace").strip().splitlines()[-1])
        except (ValueError, IndexError):
            stats = None
    return elapsed, elapsed > limit, killed, stats





def _empty_result(name, pairs):
    return {
        "corpus": name,
        "files": len(pairs),
        "files_compared": 0,
        "luac": {
            "invalid_before": [], "invalid_after": [], "new_invalid": [],
            "missing_after": [], "errors": {},
        },
        "comments": {
            "before": 0, "after": 0, "removed": 0, "removed_banner": 0,
            "removed_author": 0, "author_examples": [], "banner_examples": [],
            "added": 0,
        },
        "strings": {
            "before": 0, "after": 0, "changed_files": [], "mutated_files": [],
            "dropped_only_files": [], "dropped_examples": [], "examples": [],
            "eol_only_files": [], "lost_count": 0, "unterminated": 0,
        },
        "readability": {
            "before": 0, "after": 0, "before_excl": 0, "after_excl": 0,
            "files_incl": 0, "files_excl": 0, "excluded": [],
            "worst": [], "baseline_before": BASELINE_BEFORE,
            "baseline_after": BASELINE_AFTER, "baseline_applies": False,
        },
        "lines": {"violations": [], "min_ratio": 1.0, "min_ratio_rel": None},
        "live_stores": {"violations": []},
        "timing": {"measured": 0, "outliers": [], "max": 0.0, "max_rel": None,
                   "total": 0.0, "killed": [], "limit": SECOND_LIMIT},
        "per_file": {},
    }


def analyze_corpus(name, pairs, pass_exe=None, scratch=None, limit=SECOND_LIMIT,
                   jobs=8, timing=True):
    """pairs: iterable of (relative_key, before_path, after_path_or_None)."""
    pairs = list(pairs)
    res = _empty_result(name, pairs)
    if not pairs:
        return res


    jobspec = []
    for rel, bpath, apath in pairs:
        jobspec.append((rel, "before", bpath))
        if apath:
            jobspec.append((rel, "after", apath))
        else:
            res["luac"]["missing_after"].append(rel)
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        outcomes = list(pool.map(lambda s: luac_ok(s[2]), jobspec))
    verdicts = {}
    for (rel, side, _p), (ok, err) in zip(jobspec, outcomes):
        verdicts[(rel, side)] = (ok, err)

    ratios = []
    stats_sum = collections.Counter()
    any_stats = False

    for rel, bpath, apath in pairs:
        b_ok, b_err = verdicts[(rel, "before")]
        if not b_ok:
            res["luac"]["invalid_before"].append(rel)
            res["luac"]["errors"][rel] = b_err
        if apath:
            a_ok, a_err = verdicts[(rel, "after")]
            if not a_ok:
                res["luac"]["invalid_after"].append(rel)
                res["luac"]["errors"][rel + " [after]"] = a_err
                if b_ok:
                    res["luac"]["new_invalid"].append(rel)
            if b_ok and a_ok:
                res["files_compared"] += 1

        entry = {
            "luac_before": b_ok, "luac_after": bool(apath) and verdicts[(rel, "after")][0],
            "before_bytes": os.path.getsize(bpath),
        }
        if not apath:
            res["per_file"][rel] = entry
            continue

        bsrc = read_text(bpath)
        asrc = read_text(apath)


        cb = collections.Counter(norm_eol(body) for _k, body, _raw in lualex.comments(bsrc))
        ca = collections.Counter(norm_eol(body) for _k, body, _raw in lualex.comments(asrc))
        removed = cb - ca
        author = [body for body, n in removed.items() for _ in range(n)
                  if body and not lualex.is_banner(body)]
        banner = [body for body, n in removed.items() for _ in range(n)
                  if body and lualex.is_banner(body)]
        blank = sum(n for body, n in removed.items() if not body)
        res["comments"]["before"] += sum(cb.values())
        res["comments"]["after"] += sum(ca.values())
        res["comments"]["removed"] += sum(removed.values())
        res["comments"]["removed_banner"] += len(banner)
        res["comments"]["removed_author"] += len(author)
        res["comments"]["added"] += sum((ca - cb).values())
        for body in author[:max(0, MAX_EXAMPLES - len(res["comments"]["author_examples"]))]:
            res["comments"]["author_examples"].append([rel, body[:160]])
        for body in banner[:max(0, MAX_EXAMPLES - len(res["comments"]["banner_examples"]))]:
            res["comments"]["banner_examples"].append([rel, body[:160]])
        entry["comments_removed"] = sum(removed.values())
        entry["comments_author_removed"] = len(author)


        sb = collections.Counter(v for v, closed in lualex.strings(bsrc) if closed)
        sa = collections.Counter(v for v, closed in lualex.strings(asrc) if closed)
        res["strings"]["before"] += sum(sb.values())
        res["strings"]["after"] += sum(sa.values())
        res["strings"]["unterminated"] += sum(
            1 for _v, closed in lualex.strings(bsrc) if not closed)
        lost = sb - sa
        gained = sa - sb
        sbn = collections.Counter(norm_eol(v) for v, c in sb.items() for _ in range(c))
        san = collections.Counter(norm_eol(v) for v, c in sa.items() for _ in range(c))
        lost_n = sbn - san
        gained_n = san - sbn
        if lost or gained:
            res["strings"]["changed_files"].append(rel)
            res["strings"]["lost_count"] += sum(lost.values())
            if gained_n:



                res["strings"]["mutated_files"].append(rel)
                res["strings"]["examples"].append({
                    "rel": rel, "kind": "value rewritten",
                    "lost": lost_n.most_common(3), "gained": gained_n.most_common(3),
                })
            elif gained:
                res["strings"]["eol_only_files"].append(rel)
            else:
                res["strings"]["dropped_only_files"].append(rel)
                res["strings"]["dropped_examples"].append(
                    [rel, lost.most_common(3)])
        entry["strings_before"] = sum(sb.values())
        entry["strings_after"] = sum(sa.values())


        lb = lualex.line_count(bsrc)
        la = lualex.line_count(asrc)
        ratio = (la / lb) if lb else 1.0
        ratios.append((ratio, rel))
        collapsed = lb >= LINE_COLLAPSE_BEFORE and la <= LINE_COLLAPSE_AFTER
        shrunk = lb >= 5 and ratio < LINE_RATIO_MIN
        if collapsed or shrunk:
            res["lines"]["violations"].append(
                [rel, lb, la, round(ratio, 4), "newlines collapsed" if collapsed else "line count collapsed"])
        entry["lines_before"] = lb
        entry["lines_after"] = la



        assigned_before = lualex.names_assigned(bsrc)
        assigned_after = lualex.names_assigned(asrc)
        read_after = lualex.names_read(asrc)
        orphan = sorted(n for n in assigned_before
                        if n in read_after and n not in assigned_after)
        if orphan:
            res["live_stores"]["violations"].append([rel, orphan[:8]])
        entry["live_store_orphans"] = len(orphan)


        rb = len(NAME_RE.findall(bsrc))
        ra = len(NAME_RE.findall(asrc))
        res["readability"]["before"] += rb
        res["readability"]["after"] += ra
        res["readability"]["files_incl"] += 1
        if rel == READABILITY_EXCLUDE or rel.endswith("/" + READABILITY_EXCLUDE):
            res["readability"]["excluded"].append([rel, rb, ra])
        else:
            res["readability"]["files_excl"] += 1
            res["readability"]["before_excl"] += rb
            res["readability"]["after_excl"] += ra
            entry["reg_before"] = rb
            entry["reg_after"] = ra

        entry["bytes_after"] = os.path.getsize(apath)
        res["per_file"][rel] = entry

    if ratios:
        ratios.sort()
        res["lines"]["min_ratio"] = round(ratios[0][0], 4)
        res["lines"]["min_ratio_rel"] = ratios[0][1]


    worst = [(e["reg_after"], rel) for rel, e in res["per_file"].items() if "reg_after" in e]
    worst.sort(reverse=True)
    res["readability"]["worst"] = [[rel, n] for n, rel in worst[:10]]
    res["readability"]["baseline_applies"] = res["readability"]["files_excl"] == 328


    if timing and pass_exe:
        scratch = scratch or os.path.join(os.path.dirname(os.path.abspath(__file__)), "scratch", "time")
        os.makedirs(scratch, exist_ok=True)
        for rel, bpath, _apath in pairs:
            elapsed, over, killed, st = time_pass(pass_exe, scratch, bpath, limit)
            res["timing"]["measured"] += 1
            res["timing"]["total"] += elapsed
            if elapsed > res["timing"]["max"]:
                res["timing"]["max"] = elapsed
                res["timing"]["max_rel"] = rel
            if over:
                res["timing"]["outliers"].append([rel, round(elapsed, 3)])
            if killed:
                res["timing"]["killed"].append([rel, round(elapsed, 3)])
            if st:
                any_stats = True
                for k, v in st.items():
                    if isinstance(v, int):
                        stats_sum[k] += v
        res["timing"]["limit"] = limit
        if any_stats:
            res["timing"]["stats_sum"] = dict(stats_sum)
    return res





def corpus_verdict(r):
    fails = []
    if r["luac"]["new_invalid"]:
        fails.append("luac: %d file(s) luac accepted before and rejects after" % len(r["luac"]["new_invalid"]))
    if r["luac"]["missing_after"]:
        fails.append("luac: %d file(s) missing from the cleaned output" % len(r["luac"]["missing_after"]))
    if r["comments"]["removed_author"]:
        fails.append("comments: %d of the author's own comments were removed" % r["comments"]["removed_author"])
    if r["strings"]["mutated_files"]:
        fails.append("strings: %d file(s) rewrote a string literal value" % len(r["strings"]["mutated_files"]))
    if r["strings"]["dropped_only_files"]:
        fails.append("strings: %d file(s) lost %d string literal(s) with no replacement "
                     "(expected only from removed dead statements, verify each)"
                     % (len(r["strings"]["dropped_only_files"]), r["strings"]["lost_count"]))
    if r["lines"]["violations"]:
        fails.append("newlines: %d file(s) collapsed their line structure" % len(r["lines"]["violations"]))
    if r["live_stores"]["violations"]:
        fails.append("live stores: %d file(s) read a local that is never assigned" % len(r["live_stores"]["violations"]))
    if r["timing"]["outliers"]:
        fails.append("runtime: %d file(s) over %.0fs" % (len(r["timing"]["outliers"]), r["timing"]["limit"]))
    if r["timing"]["killed"]:
        fails.append("runtime: %d file(s) did not finish inside the hard timeout" % len(r["timing"]["killed"]))
    rd = r["readability"]
    if rd["files_excl"] and rd["after_excl"] >= rd["before_excl"]:
        fails.append("readability: synthetic register count did not fall")
    r["failures"] = fails
    r["pass"] = not fails
    return r["pass"]





def collect_pairs(before_root, after_root):
    before = lua_files(before_root)
    after = lua_files(after_root)
    keys = sorted(set(before) | set(after))
    pairs = []
    for k in keys:
        pairs.append((k, before.get(k), after.get(k)))
    return pairs


def macho_pairs(work_root):
    """verify\\work\\macho\\<slot>\\Servers\\<slot>\\{Output,Output_gate}"""
    pairs = []
    if not os.path.isdir(work_root):
        return pairs
    index = os.path.join(work_root, "index.json")
    slots = None
    if os.path.isfile(index):
        try:
            with open(index, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            slots = [r["slot"] for r in data.get("resources", [])]
        except ValueError:
            slots = None
    if slots is None:
        slots = [d for d in sorted(os.listdir(work_root))
                 if os.path.isdir(os.path.join(work_root, d))]
    for slot in slots:
        base = os.path.join(work_root, slot, "Servers", slot)
        out = os.path.join(base, "Output")
        clean = os.path.join(base, "Output_gate")
        if not os.path.isdir(out) and not os.path.isdir(clean):
            continue
        for rel, b, a in collect_pairs(out, clean):
            pairs.append(("%s/%s" % (slot, rel), b, a))
    return pairs


def load_manifest(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, sort_keys=True, default=str)





def report(r, out):
    w = out.write
    rd = r["readability"]
    w("\n=== corpus %s: %d file(s), %d compared by luac on both sides\n"
      % (r["corpus"], r["files"], r["files_compared"]))

    w("\n[1] luac -p before and after (keys are relative paths, not full paths)\n")
    w("    valid before                       : %d\n" % (r["files"] - len(r["luac"]["invalid_before"])))
    w("    invalid before (decompiler's own)  : %d\n" % len(r["luac"]["invalid_before"]))
    w("    invalid after                      : %d\n" % len(r["luac"]["invalid_after"]))
    w("    missing from cleaned output        : %d\n" % len(r["luac"]["missing_after"]))
    w("    NEW invalid (regressions)          : %d\n" % len(r["luac"]["new_invalid"]))
    if r["luac"]["invalid_before"]:
        w("    already-invalid before cleanup, by relative path (NOT regressions):\n")
        for rel in sorted(r["luac"]["invalid_before"])[:MAX_EXAMPLES]:
            err = r["luac"]["errors"].get(rel, "").splitlines()[:1]
            w("      %s%s\n" % (rel, ("   <- " + err[0]) if err else ""))
        if len(r["luac"]["invalid_before"]) > MAX_EXAMPLES:
            w("      ... and %d more\n" % (len(r["luac"]["invalid_before"]) - MAX_EXAMPLES))
    for rel in sorted(r["luac"]["new_invalid"])[:MAX_EXAMPLES]:
        w("    REGRESSION %s\n" % rel)
    for rel in sorted(r["luac"]["missing_after"])[:MAX_EXAMPLES]:
        w("    MISSING    %s\n" % rel)

    c = r["comments"]
    w("\n[2] comments (real lexer)\n")
    w("    before %d, after %d, removed %d, added %d\n"
      % (c["before"], c["after"], c["removed"], c["added"]))
    w("    of those removed: %d decompiler banner line(s), %d of the author's own\n"
      % (c["removed_banner"], c["removed_author"]))
    for rel, body in c["author_examples"]:
        w("    AUTHOR LOST  %s  --%s\n" % (rel, body))
    for rel, body in c["banner_examples"][:4]:
        w("    banner ok    %s  --%s\n" % (rel, body))

    s = r["strings"]
    w("\n[3] string literals (real lexer, multiset of decoded values, per file)\n")
    w("    before %d, after %d; files whose multiset changed: %d\n"
      % (s["before"], s["after"], len(s["changed_files"])))
    w("      of those, value rewritten (cleaned file holds a literal the decompiler never\n")
    w("      produced, even ignoring CRLF normalisation): %d   -> hard failure, a string changed\n"
      % len(s["mutated_files"]))
    w("      of those, differing only in CRLF vs LF: %d\n" % len(s["eol_only_files"]))
    w("      of those, literals only dropped, no replacement: %d (%d literal(s)), the\n"
      % (len(s["dropped_only_files"]), s["lost_count"]))
    w("      signature of a dead assignment or a collapsed table being removed\n")
    w("    unterminated string literals in the before set: %d\n" % s["unterminated"])
    for ex in s["examples"][:5]:
        w("    REWRITTEN %s\n        lost   %s\n        gained %s\n"
          % (ex["rel"], ex["lost"], ex["gained"]))
    for rel, lost in s["dropped_examples"][:4]:
        w("    dropped  %s  %s\n" % (rel, lost))

    w("\n[4] readability: synthetic registers, whole pattern "
      r"\b(SHX\d*_\d+|text\d+|num\d+|table\d+|L\d+_\d+)\b" "\n")
    w("    ALL %d files        : %d -> %d\n"
      % (rd["files_incl"], rd["before"], rd["after"]))
    w("    EXCLUDING %s\n" % READABILITY_EXCLUDE)
    w("                    : %d -> %d  over %d file(s)\n"
      % (rd["before_excl"], rd["after_excl"], rd["files_excl"]))
    for rel, rb, ra in rd["excluded"]:
        w("    excluded file      : %s  %d -> %d  (%.1f%% of all remaining matches)\n"
          % (rel, rb, ra, 100.0 * ra / rd["after"] if rd["after"] else 0.0))
    if rd["baseline_applies"]:
        w("    baseline to beat   : %d -> %d over 328 files\n"
          % (rd["baseline_before"], rd["baseline_after"]))
        w("    verdict            : %s\n"
          % ("meets baseline" if rd["after_excl"] <= rd["baseline_after"]
             else "MISSES baseline by %d" % (rd["after_excl"] - rd["baseline_after"])))
    else:
        w("    baseline (%d -> %d over 328 files) does not apply: this corpus has %d non-excluded files\n"
          % (rd["baseline_before"], rd["baseline_after"], rd["files_excl"]))
    w("    heaviest leftovers (excluding the excluded file):\n")
    for rel, n in rd["worst"][:5]:
        w("      %8d  %s\n" % (n, rel))

    ln = r["lines"]
    w("\n[5] line structure\n")
    w("    smallest after/before line ratio: %.4f (%s)\n" % (ln["min_ratio"], ln["min_ratio_rel"]))
    w("    files that lost their line structure: %d\n" % len(ln["violations"]))
    for rel, lb, la, ratio, why in ln["violations"][:MAX_EXAMPLES]:
        w("      %s  %d -> %d (%.4f)  %s\n" % (rel, lb, la, ratio, why))

    lv = r["live_stores"]
    w("\n[6] live stores: names assigned before, still read after, never assigned after\n")
    w("    files with an orphaned name: %d\n" % len(lv["violations"]))
    w("    limit: the comparison is by name, so a deleted store is only visible when\n")
    w("    the pass left that name alone. Where it also renames the variable the\n")
    w("    check is blind; that is a known gap, not a clean result.\n")
    for rel, names in lv["violations"][:MAX_EXAMPLES]:
        w("      %s  %s\n" % (rel, ", ".join(names)))

    t = r["timing"]
    w("\n[7] runtime of the pass, per file (limit %.0fs, hard kill %.0fs)\n"
      % (t["limit"], HARD_TIMEOUT))
    if t["measured"]:
        w("    measured %d file(s), total %.1fs, slowest %.3fs (%s)\n"
          % (t["measured"], t["total"], t["max"], t["max_rel"]))
        w("    outliers over the limit: %d\n" % len(t["outliers"]))
        for rel, sec in t["outliers"][:MAX_EXAMPLES]:
            w("      %8.3fs  %s\n" % (sec, rel))
        w("    files that had to be killed: %d\n" % len(t["killed"]))
        if t.get("stats_sum"):
            w("    pass stats over the corpus: %s\n" % json.dumps(t["stats_sum"], sort_keys=True))
    else:
        w("    not measured (no pass binary supplied)\n")

    w("\n--- corpus %s: %s\n" % (r["corpus"], "PASS" if r["pass"] else "FAIL"))
    for f in r["failures"]:
        w("    FAIL %s\n" % f)





def main(argv=None):

    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--yes-root", default=None, help="dir holding Output/ and Output_gate/")
    ap.add_argument("--macho-work", default=None, help="verify\\work\\macho")
    ap.add_argument("--json", default=None)
    ap.add_argument("--pass-exe", dest="pass_exe", default=None,
                    help="pass.exe used for the runtime check")
    ap.add_argument("--scratch", default=None)
    ap.add_argument("--limit", type=float, default=SECOND_LIMIT)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--no-timing", action="store_true")
    ap.add_argument("--skip", default="", help="comma separated corpus names to skip")
    args = ap.parse_args(argv)

    here = os.path.dirname(os.path.abspath(__file__))
    tmp = os.path.abspath(os.path.join(here, ".."))
    yes_root = args.yes_root or os.path.join(tmp, "yes", "Servers", "yes")
    macho_work = args.macho_work or os.path.join(here, "work", "macho")
    scratch = args.scratch or os.path.join(here, "scratch", "time")
    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    pass_exe = args.pass_exe

    corpora = []
    results = []
    notes = []

    if "yes" not in skip:
        b = os.path.join(yes_root, "Output")
        a = os.path.join(yes_root, "Output_gate")
        if os.path.isdir(b):
            pairs = collect_pairs(b, a)
            results.append(analyze_corpus("yes", pairs, pass_exe, scratch,
                                          args.limit, args.jobs, not args.no_timing))
        else:
            notes.append("corpus yes skipped: %s not found" % b)

    if "macho" not in skip:
        pairs = macho_pairs(macho_work)
        if pairs:
            results.append(analyze_corpus("macho", pairs, pass_exe, scratch,
                                          args.limit, args.jobs, not args.no_timing))
        else:
            notes.append("corpus macho skipped: no built resources under %s "
                         "(run build_macho_corpus.js)" % macho_work)

    for r in results:
        corpus_verdict(r)
        corpora.append(r)

    ok = bool(results) and all(r["pass"] for r in results) and not notes
    summary = {
        "pass": ok,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "notes": notes,
        "corpora": corpora,
    }
    if args.json:
        write_json(args.json, summary)

    for note in notes:
        print("NOTE: " + note)
    for r in results:
        report(r, sys.stdout)

    timing_outliers = sum(len(r["timing"]["outliers"]) for r in results)
    print("\n================ GATE %s ================" % ("PASS" if ok else "FAIL"))
    for r in results:
        print("  %-8s files=%-5d luac_new_invalid=%-3d author_comments_lost=%-3d "
              "string_files_changed=%-3d newline_collapsed=%-3d live_store_lost=%-3d "
              "slow(>%.0fs)=%d  readability %d->%d (all) / %d->%d (excl %s)"
              % (r["corpus"], r["files"], len(r["luac"]["new_invalid"]),
                 r["comments"]["removed_author"], len(r["strings"]["changed_files"]),
                 len(r["lines"]["violations"]), len(r["live_stores"]["violations"]),
                 r["timing"]["limit"], len(r["timing"]["outliers"]),
                 r["readability"]["before"], r["readability"]["after"],
                 r["readability"]["before_excl"], r["readability"]["after_excl"],
                 READABILITY_EXCLUDE))
        for f in r["failures"]:
            print("           FAIL %s" % f)
    print("  per-file timing outliers: %d" % timing_outliers)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())