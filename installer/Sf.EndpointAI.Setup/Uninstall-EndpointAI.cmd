@echo off
setlocal EnableExtensions

fltmc.exe >nul 2>&1
if errorlevel 1 (
  echo Administrator CMD is required.
  exit /b 5
)

set "productCode="
for /f "tokens=2,*" %%A in ('reg.exe query "HKLM\Software\SF\EndpointAIProxy" /v ProductCode 2^>nul ^| find.exe /i "ProductCode"') do set "productCode=%%B"
if not defined productCode (
  echo UNINSTALL_PRODUCT_NOT_FOUND: MSI ProductCode is missing.
  exit /b 1
)

set "uninstallLog=%TEMP%\SfEndpointAIProxy-Uninstall.log"
echo Uninstalling EndpointAIDLP %productCode% ...
msiexec.exe /x %productCode% /qn /norestart /L*v "%uninstallLog%"
set "exitCode=%ERRORLEVEL%"
echo MSI exit code: %exitCode%
echo MSI log: %uninstallLog%
exit /b %exitCode%
