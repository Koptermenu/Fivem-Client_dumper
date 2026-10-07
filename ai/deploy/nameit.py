"""Asks the naming model what to call each register in a file, and records what it said.

The model is never allowed to write code. It is shown a slice of the cleaned file, followed
by the exact header it was trained on, and it answers with a list of `register=name` lines.
Nothing here is written back to any Lua file: the output is a proposal file that apply.py
validates on its own.

Files are larger than the context window, so they are cut at statement boundaries that leave
bracket nesting at zero. Every cut is a line boundary, and the cut position is verified, so a
chunk can never split a token or a string.
"""

import argparse
import io
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request

import extract

HEADER = "\n\n=== rename map ===\n"
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def chunk_bounds(src, budget):
    """Line-start offsets where the brace depth seen so far is zero.

    Lua has no block brace: every `{` opens a table constructor, so depth zero is exactly a
    position that cannot be inside a table, a call, or an index. Splitting there means each
    chunk is a run of whole top-level statements.
    """
    code = extract.strip_noise(src)
    depth_at_line_start = {}
    depth = 0
    for i, ch in enumerate(code):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
        if ch == "\n":
            depth_at_line_start[i + 1] = depth

    bounds = [0]
    start = 0
    for off in sorted(depth_at_line_start):
        if off - start > budget and depth_at_line_start[off] == 0:
            bounds.append(off)
            start = off
    if bounds[-1] != len(src) and src.strip():
        bounds.append(len(src))
    return bounds


def chunk_registers(src, start, end):
    return extract.SYNTH_RE.findall(extract.strip_noise(src[start:end]))


def parse_map(text, offered):
    """Turns model text into proposals.

    Stops at the first repeated key: the map is a bijection, so a key appearing twice means
    generation has left the format. Only `key=value` lines whose value is a Lua identifier
    are taken; anything else is counted and dropped.
    """
    proposals = []
    dropped = {"repeated_key": 0, "not_identifier": 0, "malformed": 0, "not_a_register": 0,
               "key_equals_value": 0}
    seen = set()
    stopped = "eos"
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if "=" not in line:
            if line.startswith("=="):
                continue
            dropped["malformed"] += 1
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if key in seen:
            dropped["repeated_key"] += 1
            stopped = "repeated_key"
            break
        if not IDENT_RE.match(key):
            dropped["malformed"] += 1
            continue
        seen.add(key)
        if not value:
            dropped["not_identifier"] += 1
            continue
        if not IDENT_RE.match(value):
            dropped["not_identifier"] += 1
            continue
        if key == value:
            dropped["key_equals_value"] += 1
            continue
        if offered is not None and key not in offered:
            dropped["not_a_register"] += 1
            continue
        proposals.append((key, value))
    return proposals, dropped, stopped


def request(url, prompt, n_predict, retries=3):
    body = json.dumps({
        "prompt": prompt,
        "n_predict": n_predict,
        "temperature": 0.0,
        "top_k": 1,
        "seed": 1234,
        "cache_prompt": False,
        "stop": ["\n\n", "==="],
    }).encode()
    last = None
    for _ in range(retries):
        try:
            req = urllib.request.Request(url, data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=900) as r:
                return json.loads(r.read())
        except (urllib.error.URLError, OSError, ValueError) as e:
            last = e
            time.sleep(2)
    raise RuntimeError(f"request failed after {retries} attempts: {last}")


def list_files(root, exclude_rel):
    out = []
    for base, _, names in os.walk(root):
        for n in sorted(names):
            if not n.endswith(".lua"):
                continue
            p = os.path.join(base, n)
            rel = os.path.relpath(p, root)
            if os.path.normcase(rel) == exclude_rel:
                continue
            out.append(p)
    return sorted(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--url", default="")
    ap.add_argument("--exclude", default=os.path.join("rtx_themepark", "client", "paths.lua"))
    ap.add_argument("--chunk-bytes", type=int, default=9000)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--port", type=int, default=8731)
    args = ap.parse_args()
    if not args.url:
        args.url = f"http://127.0.0.1:{args.port}/completion"

    files = list_files(args.root, os.path.normcase(args.exclude))
    if args.limit:
        files = files[:args.limit]
    print(f"files: {len(files)}", flush=True)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    fh = io.open(args.out, "w", encoding="utf-8")
    lock = threading.Lock()
    progress = [0]

    def work(path):
        src = extract.read(path)
        regs = extract.registers(src)
        bounds = chunk_bounds(src, args.chunk_bytes)
        chunks = []
        for a, b in zip(bounds, bounds[1:]):
            offered = chunk_registers(src, a, b)
            if offered:
                chunks.append((a, b, offered))
        rel = os.path.relpath(path, args.root)
        if not chunks:
            rec = {"file": rel, "registers": len(regs), "unique": len(set(regs)),
                   "chunks": 0, "proposals": [], "dropped": {}, "seconds": 0.0}
            with lock:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                fh.flush()
                progress[0] += 1
                print(f"[{progress[0]}/{len(files)}] {rel}: no registers", flush=True)
            return

        t0 = time.time()
        per_key = {}
        dropped = {"repeated_key": 0, "not_identifier": 0, "malformed": 0,
                   "not_a_register": 0, "key_equals_value": 0}
        stops = []
        chunk_rows = []
        for a, b, offered in chunks:
            text = src[a:b].strip()
            n_predict = min(1024, 16 + 10 * len(set(offered)))
            res = request(args.url, text + HEADER, n_predict)
            props, drop, stopped = parse_map(res.get("content", ""), set(offered))
            for k, v in props:
                if k in per_key and per_key[k] != v:
                    drop["repeated_key"] += 1
                    continue
                per_key.setdefault(k, v)
            for key_name, n in drop.items():
                dropped[key_name] += n
            stops.append(stopped)
            chunk_rows.append({"start": a, "end": b, "offered": len(set(offered)),
                               "proposed": len(props), "stop": stopped,
                               "text": res.get("content", "")})
        elapsed = time.time() - t0
        rec = {"file": rel, "registers": len(regs), "unique": len(set(regs)),
               "chunks": len(chunks), "proposals": [[k, v] for k, v in per_key.items()],
               "dropped": dropped, "seconds": round(elapsed, 3), "chunk_rows": chunk_rows}
        with lock:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            fh.flush()
            progress[0] += 1
            print(f"[{progress[0]}/{len(files)}] {rel}: {len(regs)} regs, "
                  f"{len(chunks)} chunks, {len(per_key)} proposals, {elapsed:.1f}s", flush=True)

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        list(pool.map(work, files))
    fh.close()
    print("done", flush=True)


if __name__ == "__main__":
    sys.exit(main())