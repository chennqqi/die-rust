@echo off
setlocal

set "BUILD_DIR=target"
set "C_CRT=/MD"
set "NATIVE_CRT=/defaultlib:msvcrt"
set "CARGO_TARGET_DIR="
set "RUSTFLAGS="

if /i "%~1"=="--static-crt" (
    set "BUILD_DIR=target\static-crt"
    set "C_CRT=/MT"
    set "NATIVE_CRT=/defaultlib:libcmt"
    set "CARGO_TARGET_DIR=%CD%\target\static-crt"
    set "RUSTFLAGS=-C target-feature=+crt-static"
) else if not "%~1"=="" (
    echo usage: run-windows-msvc.cmd [--static-crt] 1>&2
    exit /b 2
)

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo vswhere.exe was not found 1>&2
    exit /b 2
)

for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS_INSTALL=%%I"
if not defined VS_INSTALL (
    echo Visual Studio C++ x64 tools were not found 1>&2
    exit /b 2
)

call "%VS_INSTALL%\Common7\Tools\VsDevCmd.bat" -no_logo -arch=x64 -host_arch=x64
if errorlevel 1 exit /b %errorlevel%

cargo +1.88.0 build --release --locked
if errorlevel 1 exit /b %errorlevel%

if not exist "%BUILD_DIR%\c-smoke" mkdir "%BUILD_DIR%\c-smoke"
if errorlevel 1 exit /b %errorlevel%

cl /nologo /W4 /WX /std:c11 %C_CRT% "c\smoke.c" /Fo"%BUILD_DIR%\c-smoke\smoke.obj" /Fe"%BUILD_DIR%\c-smoke\smoke.exe" "%BUILD_DIR%\release\die_c_static_link_spike.lib" /link kernel32.lib ntdll.lib userenv.lib ws2_32.lib dbghelp.lib %NATIVE_CRT%
if errorlevel 1 exit /b %errorlevel%

"%BUILD_DIR%\c-smoke\smoke.exe"
exit /b %errorlevel%
