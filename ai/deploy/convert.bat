@echo off
REM Builds the deployable naming model from the run10 adapter:
REM   merge LoRA into the base -> f16 GGUF -> Q4_K_M GGUF.
REM The quantiser here is the CPU build of the pinned b11146 release. The CUDA build's
REM llama-quantize.exe fails on a missing DLL, and pulling in ~600 MB of CUDA runtime just
REM to requantise a 0.5B model is not worth it.
setlocal
cd /d "%~dp0"

set BASE=C:\Users\Admin\AppData\Local\Temp\opencode\base\Qwen2.5-Coder-0.5B
set ADAPTER=C:\Users\Admin\AppData\Local\Temp\opencode\run10\adapter
set MERGED=C:\Users\Admin\AppData\Local\Temp\opencode\deploy\merged10
set F16=C:\Users\Admin\AppData\Local\Temp\opencode\deploy\qwen_lua_ck40_f16.gguf
set Q4=C:\Users\Admin\AppData\Local\Temp\opencode\deploy\qwen_lua_ck40_q4km.gguf

echo === step 1: merge LoRA into base weights ===
python merge_lora.py --base "%BASE%" --adapter "%ADAPTER%" --out "%MERGED%"
if errorlevel 1 goto :fail

echo.
echo === step 2: convert merged HF to GGUF f16 ===
python convert_hf_to_gguf.py "%MERGED%" --outfile "%F16%" --outtype f16
if errorlevel 1 goto :fail

echo.
echo === step 3: quantise to Q4_K_M (CPU build) ===
llama-quantize.exe "%F16%" "%Q4%" Q4_K_M
if errorlevel 1 goto :fail

echo.
echo === result ===
dir "%F16%" "%Q4%"
exit /b 0

:fail
echo FAILED at step with exit code %errorlevel%
exit /b 1