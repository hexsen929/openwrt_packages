@echo off
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "PS1=%SCRIPT_DIR%masscan-cf.ps1"

if not exist "%PS1%" (
    echo [x] 未找到 %PS1%
    exit /b 1
)

where pwsh >nul 2>&1
if %errorlevel%==0 (
    pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
    exit /b %errorlevel%
)

where powershell >nul 2>&1
if %errorlevel%==0 (
    powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
    exit /b %errorlevel%
)

echo [x] 未检测到 PowerShell 运行时，请安装 Windows PowerShell 5.1 或 PowerShell 7 以上版本。
exit /b 1
