"""Samples a few renames with the line each one came from, so the result can be read."""

import argparse
import io
import json
import os
import random

import extract


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--accepted", required=True)
    ap.add_argument("--sample", type=int, default=12)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    rows = [json.loads(l) for l in io.open(args.accepted, encoding="utf-8") if l.strip()]
    by_file = {}
    for r in rows:
        by_file.setdefault(r["file"], []).append(r)

    rng = random.Random(args.seed)
    files = sorted(by_file)
    picked = []
    for f in files:
        n = len(by_file[f])
        take = max(1, round(n * args.sample / max(1, len(rows)) * len(rows) / len(files) / 4))
        picks = rng.sample(by_file[f], min(n, take))
        for p in picks:
            picked.append(p)

    out = []
    for r in picked:
        src = extract.read(os.path.join(args.root, r["file"]))
        code = extract.strip_noise(src)
        idx = code.find(r["register"])
        if idx < 0:
            continue
        s = src.rfind("\n", 0, idx) + 1
        e = src.find("\n", idx)
        e = len(src) if e < 0 else e
        line = src[s:e].strip()
        out.append({"file": r["file"], "before": r["register"], "after": r["name"],
                    "line": line[:220]})

    with io.open(args.out, "w", encoding="utf-8") as fh:
        for r in out:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
            print(f"{r['file']}\n  {r['before']} -> {r['after']}\n  {r['line']}")
    print(f"\nsampled {len(out)}")


if __name__ == "__main__":
    main()