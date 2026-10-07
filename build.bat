@echo off


setlocal

cd /d "%~dp0"

set BUILD_DIR=build
set CONFIG=Release
set GENERATOR=











set VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe
if exist "%VSWHERE%" (
    if not defined GENERATOR call :probe_vs 18 19 2026
    if not defined GENERATOR call :probe_vs 17 18 2022
    if not defined GENERATOR call :probe_vs 16 17 2019
)

if defined DUMPER_GENERATOR set "GENERATOR=%DUMPER_GENERATOR%"
if not defined GENERATOR set "GENERATOR=Visual Studio 17 2022"
goto :vs_chosen

:probe_vs



set "_probe="
for /f "usebackq delims=" %%V in (`"%VSWHERE%" -version "[%1.0,%2.0)" -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationVersion 2^>nul`) do set "_probe=%%V"
if defined _probe set "GENERATOR=Visual Studio %1 %3"
exit /b 0

:vs_chosen






set "CACHED_GEN="
if exist "%BUILD_DIR%\CMakeCache.txt" for /f "tokens=2 delims==" %%G in ('findstr /b /c:"CMAKE_GENERATOR:INTERNAL=" "%BUILD_DIR%\CMakeCache.txt"') do set "CACHED_GEN=%%G"
if defined CACHED_GEN if not "%CACHED_GEN%"=="%GENERATOR%" goto :stale_cache
goto :banner

:stale_cache
echo [*] A build gyorsitotar masik Visual Studiot hasznalt: %CACHED_GEN%
echo     Most ez kell: %GENERATOR%. A nem illo cache torolve.
rmdir /s /q "%BUILD_DIR%" 2>nul




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





tasklist /nh /fi "IMAGENAME eq fivem_dumper.exe" 2>nul | find /i "fivem_dumper.exe" >nul
if not errorlevel 1 echo [!] Fut egy fivem_dumper.exe. Ha a build a linken elbukik
if not errorlevel 1 echo     LNK1104 hibaval, azt ez okozza: a futo peldanyag zarja a fajlt.









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
