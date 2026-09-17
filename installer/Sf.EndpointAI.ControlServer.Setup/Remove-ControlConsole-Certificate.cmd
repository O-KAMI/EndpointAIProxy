@echo off
setlocal
net session >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Please run this command as Administrator.
  exit /b 5
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$path='%~dp0EndpointAI-ControlServer-192.0.2.163.cer'; $certificate=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new($path); Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq $certificate.Thumbprint | Remove-Item -Force"
exit /b %errorlevel%
