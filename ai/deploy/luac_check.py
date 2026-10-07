"""Counts files luac rejects, and the synthetic registers left in a tree."""

import argparse
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

SYNTH = re.compile(r"\b(SHX\d*_\d+|text\d+|num\d+|table\d+|L\d+_\d+)\b")
LUAC = r"C:\Users\Admin\AppData\Local\Programs\Lua\bin\luac.exe"


def luac_ok(path, outdir):
    """luac -p parses only; -o points the (never written) dump at the scratch dir."""
    dst = os.path.join(outdir, os.path.basename(path) + ".luac")
    r = subprocess.run([LUAC, "-p", "-o", dst, path],
                       capture_output=True, text=True)
    if os.path.exists(dst):
        os.remove(dst)
    return r.returncode == 0, (r.stderr or r.stdout or "").strip().splitlines()[:1]


def walk(root, exclude):
    ex = os.path.normcase(exclude)
    out = []
    for base, _, names in os.walk(root):
        for n in sorted(names):
            if not n.endswith(".lua"):
                continue
            p = os.path.join(base, n)
            if os.path.normcase(os.path.relpath(p, root)) == ex:
                continue
            out.append(p)
    return sorted(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--exclude", default=os.path.join("rtx_themepark", "client", "paths.lua"))
    ap.add_argument("--label", default="")
    ap.add_argument("--scratch", default=os.path.dirname(os.path.abspath(__file__)))
    args = ap.parse_args()

    files = walk(args.root, args.exclude)
    bad = []
    total = 0
    for p in files:
        with open(p, encoding="utf-8", errors="replace") as fh:
            total += len(SYNTH.findall(fh.read()))
    with ThreadPoolExecutor(max_workers=8) as pool:
        for path, (ok, msg) in zip(files, pool.map(
                lambda p: (p, luac_ok(p, args.scratch)), files)):
            if not ok:
                bad.append((os.path.relpath(path, args.root), msg))
    print(f"[{args.label or args.root}] files={len(files)} "
          f"luac_invalid={len(bad)} synthetic={total}")
    for rel, msg in bad[:10]:
        print("   invalid:", rel, msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())