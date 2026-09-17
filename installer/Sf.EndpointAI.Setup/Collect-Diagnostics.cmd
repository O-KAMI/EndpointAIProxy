@echo off
chcp 65001 >nul
"%~dp0Sf.EndpointAI.Client.Service.exe" --maintenance=collect-diagnostics %* --auto-attach=false --diagnostics-output="%~dp0diagnostics"
exit /b %ERRORLEVEL%
