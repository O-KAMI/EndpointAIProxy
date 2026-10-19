@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Upgrade-Client.ps1" %*
exit /b %ERRORLEVEL%
