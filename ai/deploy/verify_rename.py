"""Proves the rename step changed identifiers and nothing else.

The renamed tree must differ from the original only in whole-register identifier positions.
Comparing the two files token by token and finding every difference is the check: if any
difference is not a register identifier becoming a proposed name, the step changed more than
it was allowed to.
"""

import argparse
import collections
import io
import json
import os
import re
import sys

TOKEN_RE = re.compile(r"""
    (?P<ws>\s+)
  | (?P<str>'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")
  | (?P<longstr>\[(=*)\[)
  | (?P<num>\d+\.?\d*(?:[eE][-+]?\d+)?)
  | (?P<name>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op>[^\sA-Za-z0-9_])
""", re.X | re.S)


def tokens(src):
    out = []
    i = 0
    n = len(src)
    while i < n:
        m = TOKEN_RE.match(src, i)
        if not m:
            out.append(("raw", src[i]))
            i += 1
            continue
        kind = m.lastgroup
        text = m.group()
        if kind == "longstr":
            close = "]" + m.group("longstr")[2:-1] + "]"
            j = src.find(close, m.end())
            j = n if j < 0 else j + len(close)
            out.append(("longstr", src[i:j]))
            i = j
            continue
        out.append((kind, text))
        i = m.end()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--renamed", required=True)
    ap.add_argument("--accepted", required=True)
    args = ap.parse_args()

    acc = collections.defaultdict(dict)
    for line in io.open(args.accepted, encoding="utf-8"):
        line = line.strip()
        if line:
            r = json.loads(line)
            acc[r["file"]][r["register"]] = r["name"]

    checked = diffs = bad = 0
    for rel, mapping in sorted(acc.items()):
        a = tokens(io.open(os.path.join(args.root, rel), encoding="utf-8",
                           errors="replace", newline="").read())
        b = tokens(io.open(os.path.join(args.renamed, rel), encoding="utf-8",
                           errors="replace", newline="").read())
        checked += 1
        if len(a) != len(b):
            bad += 1
            print(f"TOKEN COUNT CHANGED in {rel}: {len(a)} -> {len(b)}")
            continue
        used = {}
        for ta, tb in zip(a, b):
            if ta == tb:
                continue
            diffs += 1
            if ta[0] != "name":
                bad += 1
                print(f"NON-IDENTIFIER CHANGE in {rel}: {ta} -> {tb}")
                continue
            if ta[1] not in mapping:
                bad += 1
                print(f"UNPROPOSED IDENTIFIER in {rel}: {ta[1]}")
                continue
            if tb[1] != mapping[ta[1]]:
                bad += 1
                print(f"WRONG NAME in {rel}: {ta[1]} -> {tb[1]} "
                      f"(expected {mapping[ta[1]]})")
                continue
            used[ta[1]] = used.get(ta[1], 0) + 1
    print(f"files checked        : {checked}")
    print(f"identifier changes   : {diffs}")
    print(f"violations           : {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())