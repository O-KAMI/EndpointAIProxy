@echo off
setlocal
net session >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Please run this command as Administrator.
  exit /b 5
)
certutil.exe -addstore -f Root "%~dp0EndpointAI-ControlServer-192.0.2.163.cer"
exit /b %errorlevel%
