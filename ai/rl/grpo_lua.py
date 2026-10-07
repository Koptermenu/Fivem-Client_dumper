"""GRPO with verifiable rewards on the register-naming model.

DeepSeek-V4-style post-training, scaled to a 0.5B dense model on one 8 GB GPU:
group-relative policy optimization where the reward is fully verifiable and needs
no learned reward model. The task triplet (problem, environment, verifier) is the
one the shipped dumper pipeline already defines:

    problem   a Lua chunk whose identifiers are decompiler registers
    verifier  the apply.py classifier (identifier shape, Lua keywords, local and
              parameter shadows, global collisions, duplicate names)
              plus exact match against the ground-truth names, which the pairs
              files carry by construction

The policy starts from the SFT specialist (run_best adapter) and is nudged toward
completions that parse, cover every register, survive every applier check, and
match the original names. Nothing else is rewarded: there is no learned judge and
no reward that can be hacked by changing the verifier, because the verifier is
deterministic code borrowed verbatim from the production applier.
"""

import argparse
import io
import json
import os
import re
import sys
import warnings

os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
os.environ.setdefault("TRANSFORMERS_NO_ADVISORY_WARNINGS", "1")
warnings.filterwarnings("ignore")
import logging
logging.getLogger("torch.utils.flop_counter").setLevel(logging.CRITICAL)

import torch
from datasets import Dataset
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer
from transformers.trainer_callback import PrinterCallback, ProgressCallback, TrainerCallback
from transformers.utils.logging import disable_progress_bar
from trl import GRPOConfig, GRPOTrainer

disable_progress_bar()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extract
from apply import classify, declared_locals, declared_params

HEADER = "\n\n=== rename map ===\n"
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
REGISTER = re.compile(r"SHX\d+_\d+(?:Fn\d+)?|L\d+_\d+|num\d+|text\d+|table\d+")


def raw_entries(text):
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


def parse_map(entries):
    got = {}
    for k, v in entries:
        if k in got:
            break
        if IDENT.match(v):
            got[k] = v
    return got


def build_rows(pairs_path, tok, max_prompt_tokens):
    rows = [json.loads(l) for l in io.open(pairs_path, encoding="utf-8") if l.strip()]
    out, skipped = [], 0
    for r in rows:
        code = r["code"]
        gt = {v: k for k, v in r["mapping"].items()}
        regs = sorted(extract.register_set(code))
        if not regs:
            continue
        ids = tok(code, add_special_tokens=False)["input_ids"]
        if len(ids) > max_prompt_tokens:
            skipped += 1
            continue
        bare = extract.strip_noise(code)
        out.append({
            "prompt": code.strip() + HEADER,
            "regs": regs,
            "gt": gt,
            "vids": sorted(extract.identifiers(code) | extract.register_set(code)),
            "locs": sorted(declared_locals(bare)),
            "pars": sorted(declared_params(bare) - extract.register_set(code)),
        })
    return out, skipped


def naming_reward(completions, regs=None, gt=None, vids=None, locs=None, pars=None,
                  **_):
    scores = []
    for i, comp in enumerate(completions):
        entries = raw_entries(comp)
        if not entries:
            scores.append(0.0)
            continue
        parsed = parse_map(entries)
        reg_set = set(regs[i])
        total = max(1, len(reg_set))
        gt_map = gt[i]
        malformed = len(entries) - len(parsed)

        coverage = sum(1 for k in parsed if k in reg_set) / total

        taken = set()
        ok = 0
        for k, v in parsed.items():
            good, _ = classify(k, v, set(vids[i]), set(locs[i]), set(pars[i]), taken)
            if good:
                taken.add(v)
                ok += 1
        valid = ok / max(1, len(parsed))

        exact = sum(1 for k, v in parsed.items() if gt_map.get(k) == v)
        exact_frac = exact / max(1, len(gt_map)) if gt_map else 0.0

        malformed_frac = min(1.0, malformed / len(entries))
        score = 0.25 * coverage + 0.25 * valid + 0.5 * exact_frac - 0.1 * malformed_frac
        scores.append(max(0.0, min(1.0, score)))
    return scores


class PrettyLog(TrainerCallback):
    def on_log(self, args, state, control, logs=None, **kwargs):
        if not logs or "reward" not in logs:
            return
        step, total = state.global_step, state.max_steps
        eta = int(logs.get("step_time", 0.0) * (total - step))
        print(f"[{step}/{total} {100.0*step/total:5.1f}%] "
              f"reward={logs.get('reward', 0.0):.3f} "
              f"entropy={logs.get('entropy', 0.0):.3f} "
              f"len={logs.get('completions/mean_length', 0):.0f} "
              f"step={logs.get('step_time', 0.0):.1f}s "
              f"ETA={eta//60}m{eta%60:02d}s", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=r"C:\Users\Admin\AppData\Local\Temp\opencode\base\Qwen2.5-Coder-0.5B")
    ap.add_argument("--adapter", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "runs", "run_best", "adapter"))
    ap.add_argument("--pairs", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "np_train4.jsonl"))
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "out"))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--max-prompt-tokens", type=int, default=2560)
    ap.add_argument("--max-completion-tokens", type=int, default=448)
    ap.add_argument("--num-generations", type=int, default=8)
    ap.add_argument("--accum", type=int, default=4)
    ap.add_argument("--batch", type=int, default=4)
    ap.add_argument("--lr", type=float, default=1e-5)
    ap.add_argument("--max-steps", type=int, default=200)
    ap.add_argument("--save-steps", type=int, default=4)
    ap.add_argument("--save-total-limit", type=int, default=3)
    ap.add_argument("--continuous-batching", action="store_true")
    ap.add_argument("--gradient-checkpointing", action="store_true")
    args = ap.parse_args()

    tok = AutoTokenizer.from_pretrained(args.base)
    rows, skipped = build_rows(args.pairs, tok, args.max_prompt_tokens)
    if args.limit:
        rows = rows[:args.limit]
    print(f"dataset: {len(rows)} prompts ({skipped} skipped over {args.max_prompt_tokens} tokens)")
    ds = Dataset.from_list(rows)

    model = AutoModelForCausalLM.from_pretrained(
        args.base, torch_dtype=torch.bfloat16, attn_implementation="sdpa")
    model = PeftModel.from_pretrained(model, args.adapter, is_trainable=True)
    model.config.use_cache = False

    cfg = GRPOConfig(
        output_dir=args.out,
        per_device_train_batch_size=args.batch,
        gradient_accumulation_steps=args.accum,
        num_generations=args.num_generations,
        max_completion_length=args.max_completion_tokens,
        temperature=1.0,
        top_p=1.0,
        beta=0.0,
        learning_rate=args.lr,
        lr_scheduler_type="constant_with_warmup",
        warmup_steps=3,
        max_steps=args.max_steps,
        bf16=True,
        gradient_checkpointing=args.gradient_checkpointing,
        use_transformers_continuous_batching=args.continuous_batching,
        transformers_continuous_batching_config={"max_memory_percent": 0.15},
        mask_truncated_completions=True,
        logging_steps=1,
        save_strategy="steps",
        save_steps=args.save_steps,
        save_total_limit=args.save_total_limit or None,
        report_to=[],
        seed=13,
        disable_tqdm=True,
    )
    trainer = GRPOTrainer(
        model=model,
        reward_funcs=naming_reward,
        args=cfg,
        train_dataset=ds,
        processing_class=tok,
    )
    trainer.remove_callback(PrinterCallback)
    trainer.remove_callback(ProgressCallback)
    trainer.add_callback(PrettyLog())
    trainer.train()
    trainer.save_model(os.path.join(args.out, "final"))
    tok.save_pretrained(os.path.join(args.out, "final"))


if __name__ == "__main__":
    main()
