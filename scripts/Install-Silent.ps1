#requires -Version 5.1
[CmdletBinding()]
param([string]$OutputDirectory)
$ErrorActionPreference='Stop'
$packageRoot=Split-Path $PSScriptRoot -Parent
try {
  $manifest=Get-Content -LiteralPath (Join-Path $packageRoot 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
  $name=$manifest.msi.name
  if ([IO.Path]::GetFileName($name) -ne $name -or $name -notmatch '^EndpointAIDLP-Client-\d+\.\d+\.\d+-go-win-x64\.msi$') { throw 'Invalid package name.' }
  $msi=Join-Path $packageRoot $name
  if ((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant() -ne $manifest.msi.sha256) { throw 'Package digest mismatch.' }
  if (-not $OutputDirectory) { $OutputDirectory=Join-Path $env:ProgramData ('SF\EndpointAIProxy\InstallerLogs\ioa-'+[Guid]::NewGuid().ToString('N')) }
} catch { [Console]::Error.WriteLine('Silent install package validation failed.'); exit 1 }
# Run in a child so the upgrade helper's exit statement cannot skip readiness
# detection or hide 3010 from IOA. Never reinstall/uninstall on general failure.
$arguments=@('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+(Join-Path $PSScriptRoot 'Upgrade-Client.ps1')+'"'),'-MsiFile',('"'+$msi+'"'),'-OutputDirectory',('"'+$OutputDirectory+'"'))
$process=Start-Process -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $arguments -WindowStyle Hidden -Wait -PassThru
if ($process.ExitCode -ne 0) { exit $process.ExitCode }
& "$PSScriptRoot/Test-DeploymentStatus.ps1" -ManifestFile (Join-Path $packageRoot 'manifest.json') -OutputDirectory $OutputDirectory
exit $LASTEXITCODE
