@echo off
setlocal
set "SCRIPT_DIR=%~dp0"

:: Ensure the installation directory is in PYTHONPATH so fetih_cli can be resolved
if defined PYTHONPATH (
    set "PYTHONPATH=%SCRIPT_DIR%;%PYTHONPATH%"
) else (
    set "PYTHONPATH=%SCRIPT_DIR%"
)

if "%~1"=="" goto run_desktop
if /i "%~1"=="gui" goto run_desktop
if /i "%~1"=="desktop" goto run_desktop

:: Check for python in PATH
where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    python -m fetih_cli %*
    exit /b %ERRORLEVEL%
)

where py >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    py -m fetih_cli %*
    exit /b %ERRORLEVEL%
)

echo [FETIH] Python was not found in PATH. Launching desktop shell...
:run_desktop
start "" "%SCRIPT_DIR%Fetih.Desktop.exe" %*
exit /b 0
