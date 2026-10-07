@echo off
REM Builds the deployable naming model from the RL adapter.
REM
REM   ai\runs\... or ai\rl\out_v2\final  ->  merged HF  ->  f16 GGUF  ->  Q4_K_M GGUF
REM
REM The LoRA is merged into the base weights first, so the result is a single file with no
REM runtime dependency on peft, and the quantiser only ever sees an f16 GGUF. The quantiser is
REM the CPU build of the pinned b11146 release: the CUDA build's llama-quantize.exe fails on a
REM missing DLL, and pulling in ~600 MB of CUDA runtime to requantise a 0.5B model is not
REM worth it. Inference still uses the GPU, via the engine's own CUDA build.
REM
REM Override the adapter with:  build_model.bat <adapterDir>
setlocal
cd /d "%~dp0"

set ADAPTER=%~1
if "%ADAPTER%"=="" set ADAPTER=%~dp0..\rl\out_v2\final
if not exist "%ADAPTER%\adapter_model.safetensors" (
  set ADAPTER=%~dp0..\rl\out\final
)
if not exist "%ADAPTER%\adapter_model.safetensors" (
  echo no adapter_model.safetensors under "%ADAPTER%" or its sibling final
  exit /b 2
)

set BASE=C:\Users\Admin\AppData\Local\Temp\opencode\base\Qwen2.5-Coder-0.5B
set OUT=%~dp0model
set MERGED=%OUT%\merged
set F16=%OUT%\qwen_lua_namer_f16.gguf
set Q4=%OUT%\qwen_lua_namer_q4km.gguf

if not exist "%BASE%\model.safetensors" (
  echo base model missing: %BASE%
  exit /b 2
)
if not exist "%OUT%" mkdir "%OUT%"
if exist "%MERGED%" rmdir /s /q "%MERGED%"

echo === adapter: %ADAPTER%
echo === base   : %BASE%
echo.
echo === step 1: merge LoRA into base weights ===
python merge_lora.py --base "%BASE%" --adapter "%ADAPTER%" --out "%MERGED%"
if errorlevel 1 goto :fail

echo.
echo === step 2: convert merged HF to GGUF f16 ===
if exist "%F16%" del "%F16%"
python convert_hf_to_gguf.py "%MERGED%" --outfile "%F16%" --outtype f16
if errorlevel 1 goto :fail

echo.
echo === step 3: quantise to Q4_K_M ===
if exist "%Q4%" del "%Q4%"
llama-quantize.exe "%F16%" "%Q4%" Q4_K_M
if errorlevel 1 goto :fail

echo.
echo === result ===
dir "%F16%" "%Q4%"
exit /b 0

:fail
echo FAILED with exit code %errorlevel%
exit /b 1