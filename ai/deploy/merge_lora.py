"""Folds the run10 LoRA adapter into the base weights and saves a standalone HF model.

GGUF conversion needs one plain model, and the conversion script has no notion of an
adapter, so the delta is merged here first. Weights are kept in f16, which is what the
f16 GGUF wants anyway and halves the disk traffic over the f32 the trainer used.
"""

import argparse
import json
import os

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--adapter", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    print("base   :", args.base)
    print("adapter:", args.adapter)

    cfg = json.load(open(os.path.join(args.adapter, "adapter_config.json"), encoding="utf-8"))
    print("  r =", cfg.get("r"), "| alpha =", cfg.get("lora_alpha"),
          "| targets =", len(cfg.get("target_modules", [])))

    tok = AutoTokenizer.from_pretrained(args.base)
    model = AutoModelForCausalLM.from_pretrained(args.base, dtype=torch.float32)
    before = sum(p.numel() for p in model.parameters())
    model = PeftModel.from_pretrained(model, args.adapter, dtype=torch.float32)
    model = model.merge_and_unload()
    after = sum(p.numel() for p in model.parameters())
    print(f"params before {before:,} after {after:,} (equal: {before == after})")

    model = model.to(torch.float16)
    os.makedirs(args.out, exist_ok=True)
    model.save_pretrained(args.out, safe_serialization=True)
    tok.save_pretrained(args.out)
    total = sum(os.path.getsize(os.path.join(args.out, f)) for f in os.listdir(args.out))
    print("saved to", args.out, f"({total / 2**30:.2f} GB)")


if __name__ == "__main__":
    main()