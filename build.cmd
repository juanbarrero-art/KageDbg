@echo off
setlocal
set "ROOT=%~dp0"

rem --- Localizar vcvars64.bat (portable via vswhere, con fallback) ---
set "VCVARS="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
  for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
)
if defined VSPATH if exist "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%VSPATH%\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

rem --- Localizar Windows SDK (ultima version de Include) ---
set "KITS=C:\Program Files (x86)\Windows Kits\10"
set "KITSVER="
for /f "delims=" %%d in ('dir /b /ad /o-n "%KITS%\Include" 2^>nul') do if not defined KITSVER set "KITSVER=%%d"
if not defined KITSVER set "KITSVER=10.0.26100.0"

call "%VCVARS%" >nul 2>&1
if errorlevel 1 (echo [ERROR] vcvars64.bat fallo & exit /b 1)

if not exist "%ROOT%bin" mkdir "%ROOT%bin"

echo Compilando KageDbg (ext. cdb) con SDK %KITSVER%...
cl /nologo /Zi /EHsc /LD /I "%KITS%\Include\%KITSVER%\um" ^
   "%ROOT%src\kagedbg.cpp" ^
   "%KITS%\Lib\%KITSVER%\um\x64\DbgEng.Lib" ^
   /Fe:"%ROOT%bin\kagedbg.dll" /Fo:"%ROOT%bin\kagedbg.obj"
if errorlevel 1 (echo [ERROR] build fallo & exit /b 1)

echo [OK] bin\kagedbg.dll
echo Carga en cdb:  .load bin\kagedbg.dll   ^|  !kage help
exit /b 0
