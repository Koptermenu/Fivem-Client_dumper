@echo off
REM End-to-end: ask the model for names, validate them, write the renamed tree, then measure.
setlocal
cd /d "%~dp0"

set ROOT=C:\Users\Admin\AppData\Local\Temp\opencode\yes\Servers\yes\Output_clean
set OUT=%~dp0renamed
set PORT=8731

echo === before ===
python luac_check.py --root "%ROOT%" --label BEFORE

echo.
echo === start server ===
set ENGINE=%LOCALAPPDATA%\FiveMDumper\engine\cuda
start "" /b "%ENGINE%\llama-server.exe" -m "%~dp0qwen_lua_ck40_q4km.gguf" -c 32768 -np 4 --cont-batching -ngl 99 --port %PORT% -t 8 --no-warmup
timeout /t 25 /nobreak >nul

echo.
echo === name the registers ===
python nameit.py --root "%ROOT%" --out proposals.jsonl --workers 4 --chunk-bytes 6000 --port %PORT%

echo.
echo === validate and apply ===
python apply.py --root "%ROOT%" --proposals proposals.jsonl --out "%OUT%" --accepted accepted.jsonl --rejected rejected.jsonl

echo.
echo === after ===
python luac_check.py --root "%OUT%" --label AFTER

echo.
echo === samples ===
python samples.py --root "%ROOT%" --out samples.txt --accepted accepted.jsonl
exit /b 0