@echo off
setlocal
cd /d "%~dp0"
where pwsh >nul 2>&1
if errorlevel 1 (
  echo PowerShell 7+ is required for encrypted evidence mode.
  echo No installation or download is performed by this launcher.
  exit /b 2
)
pwsh.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0src\Invoke-OutilsEspion.ps1"
exit /b %errorlevel%
