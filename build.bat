@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"

set BUILD_DIR=build
set CONFIG=Release
set GENERATOR=Visual Studio 17 2022

echo ==============================================
echo    FiveM Dumper - Build
echo ==============================================
echo.

where cmake >nul 2>&1
if errorlevel 1 (
    echo [ERROR] cmake nem talalhato a PATH-ban.
    echo         Telepitsd: https://cmake.org/download/
    exit /b 1
)

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
