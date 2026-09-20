@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"

set BUILD_DIR=build
set CONFIG=Release
set GENERATOR=Visual Studio 17 2022
set ARCH=x64

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

if not exist "%BUILD_DIR%\CMakeCache.txt" (
    echo [*] CMake configure ^(%GENERATOR% %ARCH%^)...
    cmake -B "%BUILD_DIR%" -G "%GENERATOR%" -A %ARCH%
    if errorlevel 1 (
        echo [ERROR] CMake configure sikertelen.
        exit /b 1
    )
) else (
    echo [*] CMake mar konfiguralva, configure lepes kihagyva.
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