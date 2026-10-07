# DeepSeek-V4-style post-training, 0.5B scale

Applies the transferable parts of the DeepSeek-V4 / V4.1-Flash post-training
recipe (arXiv:2606.19348, arXiv:2609.19969) to the register-naming model the
dumper pipeline ships.

## What was carried over from the papers

| DeepSeek-V4 ingredient | Local equivalent |
|---|---|
| Task synthesis as (problem, environment, verifier) triplets | np_train4.jsonl: decompiled Lua chunks + ground-truth names; verifier = apply.py classifier, deterministic code shared with the production applier |
| Domain-specialist stage: SFT then GRPO with verifiable rewards | run_best SFT adapter (42.1 % exact on held-out), then `grpo_lua.py` GRPO on top of it |
| GRPO, advantages mean-centered within the group, no value network | TRL GRPOTrainer, beta 0, 8 generations per prompt |
| Effort/length-conditioned reward shaping | malformed-entry penalty keeps the map tight instead of echoing past the end |
| Specialist consolidation (on-policy distillation) | not yet run; rejection-sampling SFT from the RL policy is the 0.5B analogue |

Not carried over, deliberately: CSA/CSA2/HCA sparse attention, CED, MoE, FP4 KV,
Muon — all of these target million-token trillion-param MoE serving and are
meaningless for a 0.5B dense model naming registers in a few-K context.

## Files

- `grpo_lua.py` — the RL run. Loads the Qwen2.5-Coder-0.5B base, attaches the
  run_best adapter as the trainable policy, samples 8 rename maps per file and
  rewards each with 0.25 coverage + 0.25 applier-validity + 0.5 exact match
  - 0.1 malformed fraction.
- `extract.py`, `apply.py` — copied verbatim from the training workspace so the
  verifier cannot drift from the applier that ships in the dumper.
- `np_train4.jsonl` — 516 training prompts; `eval_shared.jsonl` — the 25-file
  / 806-name held-out set, checked disjoint from training by input hash.
- `evalnames.py` — held-out scorer, patched to take `--base`.

## Running

```
run_rl.bat                               # visible console window, logs to rl_train.log
python grpo_lua.py                       # batch 4 x accum 4 = 16 completions/step,
                                         # 8 generations/prompt, 200 steps (~1 epoch)
python grpo_lua.py --limit 8 --max-steps 2 --batch 4 --accum 2   # smoke
```

Output is one human-readable line per step: reward, entropy, mean completion
length, seconds per step, ETA. Warnings and loading bars are silenced; the
console shows exactly that line and nothing else. Adapters land in
`out/checkpoint-*` and `out/final`.

Micro-batch 8 was measured to fit (7.9 GB) but not run faster than 4 —
generation, not the logprob forward, dominates — so 4 keeps the 700 MB headroom.

```
python evalnames.py out\final eval_shared.jsonl result_rl.json --pairs np_train4.jsonl
python evalnames.py ..\runs\run_best\adapter eval_shared.jsonl result_sft.json --pairs np_train4.jsonl
```

Both scores use greedy decoding, seed 13, the same 25 files, so the delta
against the SFT baseline (339/806 exact, 97.1 % coverage) is directly
comparable.

## Results

Held-out set, 25 files / 806 names, greedy, seed 13, identical inputs:

| run | exact | coverage | well-formed maps |
|---|---|---|---|
| SFT (run_best adapter) | **339 (42.1 %)** | 97.1 % | 21/25 |
| GRPO 200 steps, lr 1e-5 (out/final) | 322 (40.0 %) | 97.5 % | 23/25 |
| GRPO 60 steps, lr 3e-6, step 10 (out_v2/checkpoint-10) | 338 (41.9 %) | 97.3 % | 22/25 |
| GRPO 60 steps, lr 3e-6, steps 20-60 | 331-337 (41.1-41.8 %) | 97.1-97.5 % | 21-23/25 |

Conclusion: RLVR polish does not raise exact match past the SFT ceiling on
this task — the checkpoint sweep at the gentlest LR never beats 339 (best 338,
a one-name tie at step 10). What it does improve is format robustness:
coverage, well-formed complete maps, and the run-past-the-end failure all
move the right way. If exact match is the metric, keep run_best; if the
consumer is the applier, the RL adapters are the more disciplined ones.

Measured speed facts on the RTX 4060 Laptop 8 GB: the TRL 1.14 continuous
batching engine runs 10x slower than plain generate here (226 s vs 25 s per
step), and disabling gradient checkpointing at batch 4 fills VRAM to the
point where the Windows driver spills to system RAM — also ~10x slower. The
only configuration that fits and is fast: plain generate + gradient
checkpointing + batch 4 x accum 4, ~25 s/step.

## Reward design notes

The reward is fully verifiable: every component is computed by deterministic
code. `apply.py`'s `classify` is the same function the dumper-side applier uses,
so a name that earns reward here is a name the shipped pipeline will accept.
Exact match against ground truth is the densest signal; coverage and validity
shape the map format; the malformed penalty stands in for DeepSeek's
length/effort penalty and stops the model from running past the end of the map.
