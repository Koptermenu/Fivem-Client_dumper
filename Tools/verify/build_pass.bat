@echo off
rem Builds verify\bin\pass.exe from the project's current cleanup sources.
rem Object files land in verify\bin\obj so the project tree is never written to.
rem Rebuilds automatically whenever any source is newer than the binary, which
rem matters because the cleanup pass is edited in place while the gate runs.
setlocal
set VSB="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
call %VSB% >nul || exit /b 9
set HERE=%~dp0
set BIN=%HERE%bin
if not exist "%BIN%\obj" mkdir "%BIN%\obj"
set SRC=%HERE%..\..\src
set BUILD=%HERE%..\..\build
set NEED=0
for %%F in ("%BIN%\pass.exe") do set STAMP=%%~tF
for %%F in ("%HERE%passdrv.cpp" "%SRC%\ai\Cleanup.cpp" "%SRC%\ai\Cleanup.h" "%SRC%\ai\LuaLexer.cpp" "%SRC%\ai\LuaLexer.h" "%SRC%\core\Logger.cpp" "%SRC%\core\Logger.h" "%SRC%\core\Bundler.cpp" "%SRC%\core\Bundler.h" "%SRC%\crypto\Sha256.cpp" "%SRC%\crypto\ChaCha20.cpp" "%SRC%\crypto\AesCbc.cpp" "%SRC%\utils\Str.cpp" "%SRC%\utils\Str.h") do (
  if %%~tF gtr "%STAMP%" set NEED=1
)
if "%NEED%"=="0" (
  echo pass.exe up to date
  exit /b 0
)
cd /d "%BIN%"
cl /nologo /std:c++20 /EHsc /O2 /MT /utf-8 /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DNOGDI /I"%SRC%" /I"%BUILD%" "%HERE%passdrv.cpp" "%SRC%\ai\Cleanup.cpp" "%SRC%\ai\LuaLexer.cpp" "%SRC%\core\Logger.cpp" "%SRC%\core\Bundler.cpp" "%SRC%\crypto\Sha256.cpp" "%SRC%\crypto\ChaCha20.cpp" "%SRC%\crypto\AesCbc.cpp" "%SRC%\utils\Str.cpp" /Fe:"%BIN%\pass.exe" /Fo:"%BIN%\obj\\" /link winhttp.lib bcrypt.lib advapi32.lib
if errorlevel 1 exit /b 1
echo built %BIN%\pass.exe
exit /b 0