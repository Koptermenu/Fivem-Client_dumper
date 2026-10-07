"""Scores the naming model on held-out files.

Generating code was never the point, so this does not look at code at all. It checks the two
things the pipeline actually depends on: that the reply is a well formed rename map covering
the registers it was asked about, and how many of the names it chose match the original.

The deterministic renamer in the dumper is the baseline to beat. A model only earns its place
if it names registers the rule-based pass leaves as SHX garbage.

Three things this reports that the previous version did not, each because a number looked
wrong and turned out to be measuring the harness instead of the model:

*   The generation budget was 320 tokens. A rename line is roughly ten tokens, so the model
    was cut off at about 32 entries no matter how long the file's map was. Measured against
    the 25 held out files, coverage saturated at 32-34 entries on every file with more names
    than that, and the long files held most of the 806 names. The budget is now derived from
    the file and the run is also stopped the moment a line stops looking like a map entry, so
    "coverage" measures the model rather than the token limit.
*   Identifiers. The old parser threw away any value that was not a Lua identifier before
    counting, so a run that emitted prose still scored as if it had emitted nothing.
    Validity and distinctness are counted over everything the model actually wrote.
*   Whether the scored files were in the training set. Pass --pairs to have that checked by
    hashing the code, so a run cannot quietly be scored on its own training data.
"""

import argparse
import hashlib
import io
import json
import os
import re

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, StoppingCriteria, StoppingCriteriaList

BASE = r"C:\Users\Admin\AppData\Local\Temp\opencode\base\Qwen2.5-Coder-0.5B"
HEADER = "\n\n=== rename map ===\n"
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# The decompiler emits four register shapes, not one: SHXn_m, SHXn_mFnk for a register it saw
# called, and numN / textN / tableN for a register typed by its first assignment. Measured over
# a cleaned resource, only 11.4% are plain SHXn_m. A parser that accepts only SHX silently
# discards every other answer and reports near zero, which looks like a broken model.
REGISTER = re.compile(r"SHX\d+_\d+(?:Fn\d+)?|L\d+_\d+|num\d+|text\d+|table\d+")
ENTRY = re.compile(r"^(" + REGISTER.pattern + r")=[A-Za-z_][A-Za-z0-9_]*$")


def parse_map(text):
    """Parses the rename map, stopping at the first repeated key.

    The model learns the mapping and then keeps going, echoing the last entry for registers
    it has no name left for. Cutting there is not a fudge: the map is a bijection, so a
    key cannot legitimately appear twice.
    """
    got = {}
    for line in text.split("\n"):
        line = line.strip()
        if not line or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip()
        if k in got:
            break
        if k and v and IDENT.match(v):
            got[k] = v
    return got


def raw_entries(text):
    """Every register=value line the model wrote, in order, before generation stopped.

    Nothing is filtered here. This is what the validity and distinctness figures are
    computed over, so a model cannot improve them by emitting fewer entries.
    """
    out = []
    for line in text.split("\n"):
        line = line.strip()
        if not line or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip()
        if k and v:
            out.append((k, v))
    return out


class MapEnded(StoppingCriteria):
    """Stops generation at the end of the map, whether or not the EOS was emitted.

    Three things end a map and none of them is "we hit the token budget":

    *   a line that is not a map entry, which is prose or code;
    *   a register that has already been named, because the map is a bijection;
    *   a register that does not occur in the file. This one is not a guess about the
        format. The ground truth was checked against the files and covers exactly the
        registers the code mentions, 806 of 806 over the held out set, so a register that
        is not in the code is by definition past the end rather than part of the answer.
        Without this the model runs on: two files answered with 71 and 113 entries against
        maps of 51 and 73, inventing register labels as it went, and the register labels
        are numbered in source order so it can keep guessing them.
    """

    def __init__(self, tok, prompt_len, allowed):
        self.tok = tok
        self.prompt_len = prompt_len
        self.allowed = allowed
        self.done = False

    def __call__(self, input_ids, scores, **kwargs):
        if self.done:
            return True
        new = input_ids[0][self.prompt_len:]
        text = self.tok.decode(new, skip_special_tokens=True)
        lines = text.split("\n")
        # Only the lines before the last one are finished. The tail is a half written token
        # and judging it would stop generation on the very first step.
        seen = set()
        for line in lines[:-1]:
            line = line.strip()
            if not line:
                continue
            if not ENTRY.match(line):
                self.done = True
                return True
            key = line.split("=", 1)[0]
            if key in seen or (self.allowed and key not in self.allowed):
                self.done = True
                return True
            seen.add(key)
        return False


def code_digest(code):
    return hashlib.sha1(code.encode("utf-8")).hexdigest()


def check_disjoint(heldout, pairs):
    """Fails loudly if a scored file is byte-identical to a training file."""
    train = set()
    for line in io.open(pairs, encoding="utf-8"):
        if line.strip():
            train.add(code_digest(json.loads(line)["code"]))
    clash = sum(1 for r in heldout if code_digest(r["code"]) in train)
    print(f"disjointness vs {os.path.basename(pairs)}: "
          f"{len(heldout) - clash}/{len(heldout)} scored files unseen"
          + ("" if not clash else f"  ** {clash} OVERLAP **"))
    return clash == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ckpt")
    ap.add_argument("heldout")
    ap.add_argument("out")
    ap.add_argument("--n", type=int, default=25)
    ap.add_argument("--files", default="",
                    help="comma separated indices, or a file of one index per line; "
                         "fixes the exact input so two runs are comparable")
    ap.add_argument("--pairs", default="",
                    help="training pairs jsonl; used only to prove the split is disjoint")
    ap.add_argument("--device", default="cuda")
    ap.add_argument("--max-new", type=int, default=0,
                    help="0 picks a budget from the number of names in the file")
    ap.add_argument("--per-name", type=int, default=14,
                    help="token budget per expected map entry, when --max-new is 0")
    ap.add_argument("--temp", type=float, default=0.0)
    ap.add_argument("--top-p", type=float, default=1.0)
    ap.add_argument("--seed", type=int, default=13)
    ap.add_argument("--base", default=BASE)
    args = ap.parse_args()

    device = args.device
    dtype = torch.bfloat16 if device == "cuda" else torch.float32
    torch.manual_seed(args.seed)
    tok = AutoTokenizer.from_pretrained(args.base)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    rows = [json.loads(l) for l in io.open(args.heldout, encoding="utf-8") if l.strip()]
    if args.files:
        idx = ([int(x) for x in args.files.replace(",", " ").split()]
               if not os.path.exists(args.files)
               else [int(x) for x in io.open(args.files).read().split()])
        rows = [rows[i] for i in idx]
    else:
        rows = rows[: args.n]
    digest = hashlib.sha1("".join(code_digest(r["code"]) for r in rows).encode()).hexdigest()[:12]
    print(f"scoring {len(rows)} files, input digest {digest}")
    print(f"input file  : {os.path.abspath(args.heldout)}")
    print(f"adapter     : {os.path.abspath(args.ckpt)}")
    print(f"decoding    : {'greedy' if args.temp <= 0 else f'sample t={args.temp} p={args.top_p}'}"
          f"  seed {args.seed}")
    if args.pairs:
        if not check_disjoint(rows, args.pairs):
            raise SystemExit("refusing to report a score on training data")

    model = AutoModelForCausalLM.from_pretrained(args.base, dtype=dtype).to(device)
    model = PeftModel.from_pretrained(model, args.ckpt)
    model.eval()
    model.config.use_cache = True

    truth_total = hit = pred_total = 0
    covered_total = emitted = valid = 0
    distinct_total = 0
    well_formed = 0
    bad_lines = 0
    ran_past = 0
    past_end = 0
    per_file = []
    for i, r in enumerate(rows):
        truth = dict(
            line.split("=", 1) for line in r["target"].split("\n") if "=" in line)
        allowed = set(REGISTER.findall(r["code"]))
        budget = args.max_new or max(64, args.per_name * len(truth))
        ids = tok(r["code"] + HEADER, return_tensors="pt").to(device)
        stop = MapEnded(tok, ids["input_ids"].shape[1], allowed)
        with torch.no_grad():
            out = model.generate(
                **ids, max_new_tokens=budget, do_sample=args.temp > 0,
                temperature=args.temp if args.temp > 0 else None,
                top_p=args.top_p if args.temp > 0 else None,
                pad_token_id=tok.pad_token_id, eos_token_id=tok.eos_token_id,
                stopping_criteria=StoppingCriteriaList([stop]))
        text = tok.decode(out[0][ids["input_ids"].shape[1]:], skip_special_tokens=True)
        if stop.done:
            ran_past += 1
        got = parse_map(text)
        entries = raw_entries(text)

        t_hits = sum(1 for k, v in truth.items() if got.get(k) == v)
        covered = sum(1 for k in truth if k in got)
        names = [v for _, v in entries]
        ok = sum(1 for v in names if IDENT.match(v))
        over = sum(1 for k, _ in entries if k not in allowed)
        truth_total += len(truth)
        hit += t_hits
        pred_total += len(got)
        covered_total += covered
        emitted += len(names)
        valid += ok
        distinct_total += len(set(names))
        past_end += over
        if got and covered == len(truth):
            well_formed += 1
        bad_lines += 1 if not got else 0
        per_file.append({
            "file": i, "digest": code_digest(r["code"])[:12],
            "truth": len(truth), "correct": t_hits, "covered": covered,
            "parsed": len(got), "emitted": len(names), "valid": ok,
            "distinct": len(set(names)), "past_end": over, "budget": budget,
        })
        print(f"  {i:2d} names={len(truth):3d} exact={t_hits:3d} covered={covered:3d} "
              f"emitted={len(names):3d} valid={ok:3d} distinct={len(set(names)):3d} "
              f"past_end={over:3d}", flush=True)

    n = len(rows)
    d = max(1, truth_total)
    print()
    print(f"files                       : {n}")
    print(f"names in ground truth       : {truth_total}")
    print(f"exact name match            : {hit} ({100.0 * hit / d:.1f}%)")
    print(f"registers covered           : {covered_total} ({100.0 * covered_total / d:.1f}%)")
    print(f"well formed complete maps   : {well_formed}/{n}")
    print(f"parseable map               : {n - bad_lines}/{n}")
    print(f"names emitted               : {emitted}")
    print(f"  valid Lua identifiers     : {valid} ({100.0 * valid / max(1, emitted):.1f}%)")
    print(f"  distinct                  : {distinct_total} "
          f"({100.0 * distinct_total / max(1, emitted):.1f}%)")
    print(f"  registers not in the file : {past_end}  (ran past the end of the map)")
    print(f"generation ended on a stop : {ran_past}/{n}   (otherwise EOS)")
    with io.open(args.out, "w", encoding="utf-8") as fh:
        json.dump({"ckpt": os.path.abspath(args.ckpt),
                   "heldout": os.path.abspath(args.heldout),
                   "input_digest": digest,
                   "files": n, "truth": truth_total, "exact": hit,
                   "covered": covered_total, "well_formed": well_formed,
                   "emitted": emitted, "valid": valid, "distinct": distinct_total,
                   "past_end": past_end,
                   "decoding": {"temp": args.temp, "top_p": args.top_p,
                                "seed": args.seed, "per_name": args.per_name,
                                "max_new": args.max_new},
                   "per_file": per_file}, fh, indent=2)
    print("wrote", os.path.abspath(args.out))


if __name__ == "__main__":
    main()
