@echo off
chcp 65001 >nul
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Collect-WhitelistDiagnostics.ps1" %*
set "collect_exit=%ERRORLEVEL%"
echo.
if not "%collect_exit%"=="0" echo Collection failed. See the error above.
pause
exit /b %collect_exit%
