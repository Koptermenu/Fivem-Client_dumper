@echo off
title GRPO RL v2 - qwen_lua (lr 3e-6, 60 steps)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "python -u grpo_lua.py --lr 3e-6 --max-steps 60 --save-steps 10 --save-total-limit 0 --batch 4 --accum 4 --gradient-checkpointing --out out_v2 2>&1 | Tee-Object rl_train_v2.log"
pause
