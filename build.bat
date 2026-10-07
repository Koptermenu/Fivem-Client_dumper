@echo off
REM No delayed expansion: nothing here reads a variable inside a parenthesised block any
REM more, and leaving it on silently swallows the "!" out of the [!] status markers.
setlocal

cd /d "%~dp0"

set BUILD_DIR=build
set CONFIG=Release
set GENERATOR=

REM Pick the newest Visual Studio that has the C++ x64/x86 tools installed, instead of
REM hardcoding one, so the same checkout builds on VS 2019, 2022 and 2026.
REM
REM Two details this has to get right, both found by running it rather than reading it:
REM  - vswhere's -version takes a RANGE. A bare "18" is not an upper bound and matched the
REM    installed 17.14, which made the build ask CMake for a generator that does not exist.
REM  - the generator is named "Visual Studio <major> <year>", and the year is not the major
REM    plus anything constant: 14->2015, 15->2017, 16->2019, 17->2022, 18->2026. VS 2015 and
REM    2017 are not probed because v141 has no /std:c++20; build those with
REM    -DCMAKE_CXX_STANDARD=17.
set VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe
if exist "%VSWHERE%" (
    if not defined GENERATOR call :probe_vs 18 19 2026
    if not defined GENERATOR call :probe_vs 17 18 2022
    if not defined GENERATOR call :probe_vs 16 17 2019
)
REM Overridable for a pinned build, and for a VS installed somewhere vswhere cannot see.
if defined DUMPER_GENERATOR set "GENERATOR=%DUMPER_GENERATOR%"
if not defined GENERATOR set "GENERATOR=Visual Studio 17 2022"
goto :vs_chosen

:probe_vs
REM %1 = major, %2 = exclusive upper bound, %3 = the year in the generator name
REM Test the OUTPUT, not %ERRORLEVEL%: vswhere exits 0 even when the range matches
REM nothing and prints an empty result, so errorlevel would accept every candidate.
set "_probe="
for /f "usebackq delims=" %%V in (`"%VSWHERE%" -version "[%1.0,%2.0)" -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationVersion 2^>nul`) do set "_probe=%%V"
if defined _probe set "GENERATOR=Visual Studio %1 %3"
exit /b 0

:vs_chosen
REM CMake refuses to reuse a build tree whose cached generator differs from the one
REM being asked for, which is what happens the moment the repository is built on a
REM machine with a different Visual Studio. Drop the stale cache instead of failing.
REM Written with goto rather than a nested if-block on purpose: cmd parses a whole
REM parenthesised block before running any of it, so an empty !CACHED_GEN! inside one
REM leaves a bare () that fails the parse with "was unexpected at this time".
set "CACHED_GEN="
if exist "%BUILD_DIR%\CMakeCache.txt" for /f "tokens=2 delims==" %%G in ('findstr /b /c:"CMAKE_GENERATOR:INTERNAL=" "%BUILD_DIR%\CMakeCache.txt"') do set "CACHED_GEN=%%G"
if defined CACHED_GEN if not "%CACHED_GEN%"=="%GENERATOR%" goto :stale_cache
goto :banner

:stale_cache
echo [*] A build gyorsitotar masik Visual Studiot hasznalt: %CACHED_GEN%
echo     Most ez kell: %GENERATOR%. A nem illo cache torolve.
rmdir /s /q "%BUILD_DIR%" 2>nul
REM rmdir cannot delete a tree that holds the running dumper. It still removes the
REM cache and stops at the locked file, so testing for CMakeCache.txt would pass while
REM a half-deleted tree remains, and CMake then fails with a generator mismatch that
REM blames the cache file rather than the locked exe. Test the directory itself.
if exist "%BUILD_DIR%\" (
    echo [ERROR] A %BUILD_DIR% mappat nem sikerult teljesen torolni, valami zarja a fajlokat.
    echo         Zarhato, hogy egy futo fivem_dumper.exe van a %BUILD_DIR%\%CONFIG% mappaban.
    echo         Zard be, majd futtasd a build.bat-ot ujra.
    exit /b 1
)

:banner
echo ==============================================
echo    FiveM Dumper - Build
echo ==============================================
echo    Generatort: %GENERATOR%
echo.

where cmake >nul 2>&1
if errorlevel 1 (
    echo [ERROR] cmake nem talalhato a PATH-ban.
    echo         Telepitsd: https://cmake.org/download/
    exit /b 1
)

REM A running copy of the target locks the output file and the link step dies with
REM "LNK1104: cannot open file ...fivem_dumper.exe", which reads like a toolchain
REM problem and is not one. Warn rather than refuse: the build may still succeed if
REM the running copy lives in another directory.
tasklist /nh /fi "IMAGENAME eq fivem_dumper.exe" 2>nul | find /i "fivem_dumper.exe" >nul
if not errorlevel 1 echo [!] Fut egy fivem_dumper.exe. Ha a build a linken elbukik
if not errorlevel 1 echo     LNK1104 hibaval, azt ez okozza: a futo peldanyag zarja a fajlt.

REM A configure always runs: the embedded payload (Bin/, VC++ runtime DLLs,
REM unluac54.jar) and its SHA-256 manifest are generated at configure time,
REM so a skipped configure would embed stale content. CMake's incremental
REM configure is cheap and CMAKE_CONFIGURE_DEPENDS detects payload changes.
REM
REM No -A <arch> is passed on purpose: the VS generator already defaults to the
REM host platform (x64), and passing -A x64 is rejected by any build tree that
REM was originally configured without it, breaking incremental configures.
echo [*] CMake configure ^(%GENERATOR%^)...
cmake -B "%BUILD_DIR%" -G "%GENERATOR%"
if errorlevel 1 (
    echo [ERROR] CMake configure sikertelen.
    exit /b 1
)

echo.
echo [*] Build ^(%CONFIG%^)...
cmake --build "%BUILD_DIR%" --config %CONFIG% --parallel
if errorlevel 1 (
    echo [ERROR] Build sikertelen.
    exit /b 1
)

echo.
echo ==============================================
echo    Build kesz!
echo ==============================================
echo.

set EXE=%BUILD_DIR%\%CONFIG%\fivem_dumper.exe
if exist "%EXE%" (
    echo [+] Exe: %EXE%
) else (
    echo [!] Az exe nem talalhato a varhato helyen: %EXE%
    echo     Ellenorizd a build kimenetet.
)

echo.
echo Futtatas: %EXE%
echo.

endlocal
exit /b 0
