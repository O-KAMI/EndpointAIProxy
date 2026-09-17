[CmdletBinding()]
param([Parameter(Mandatory)][string]$CredentialsFile, [switch]$VerifyRepeatBuild)
$ErrorActionPreference = 'Stop'
# Build-only script. It is never run during endpoint installation.
if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Build the MSI on Windows.' }
$root = Split-Path $PSScriptRoot -Parent
. "$PSScriptRoot/Installer-BuildSupport.ps1"
try {
  $data = Get-Content -LiteralPath $CredentialsFile -Raw | ConvertFrom-Json
} catch { throw 'Client credential input could not be read or parsed; content withheld.' }
if ((@($data.PSObject.Properties.Name | Sort-Object) -join ',') -ne 'clientToken,keyId,origin,policyHmacKey,transportKey') { throw 'Unexpected credential fields.' }
if ($data.origin -ne 'http://control.example.invalid:8080' -or $data.keyId -notmatch '^[A-Za-z0-9_-]{1,64}$' -or $data.clientToken -notmatch '^[A-Za-z0-9_-]{16,}$') { throw 'Invalid client credentials.' }
try {
  if ([Convert]::FromBase64String($data.transportKey).Length -ne 32 -or [Convert]::FromBase64String($data.policyHmacKey).Length -lt 32) { throw 'length' }
} catch { throw 'Invalid client key encoding or length; values withheld.' }
$privateRoot = Join-Path $root 'artifacts/private-msi'
Set-PrivateBuildDirectory $privateRoot
# Checking twice exercises the already-protected-directory path without touching owner or SACL.
Set-PrivateBuildDirectory $privateRoot
$passes = if ($VerifyRepeatBuild) { 2 } else { 1 }
for ($pass = 1; $pass -le $passes; $pass++) {
  $stageDir = Join-Path $privateRoot ([Guid]::NewGuid().ToString('N'))
  Set-PrivateBuildDirectory $stageDir
  $inputDir = Join-Path $stageDir 'input'
  $publish = Join-Path $stageDir 'service'
  $actions = Join-Path $stageDir 'actions'
  $output = Join-Path $stageDir 'msi'
  foreach ($dir in @($inputDir,$publish,$actions,$output)) { Set-PrivateBuildDirectory $dir }
  try {
    Copy-Item -LiteralPath $CredentialsFile (Join-Path $inputDir 'client-credentials.json')
    Copy-Item "$PSScriptRoot/Set-ProductionClientControl.ps1" $inputDir
    dotnet publish "$root/src/Sf.EndpointAI.Client.Service/Sf.EndpointAI.Client.Service.csproj" -c Release -r win-x64 --self-contained true -o $publish -p:Version=0.1.22
    if ($LASTEXITCODE -ne 0) { throw 'Client publish failed.' }
    dotnet publish "$root/installer/Sf.EndpointAI.InstallerActions/Sf.EndpointAI.InstallerActions.csproj" -c Release -r win-x64 --self-contained true -o $actions -p:Version=0.1.22
    if ($LASTEXITCODE -ne 0) { throw 'Installer helper publish failed.' }
    Assert-WindowsGuiExecutable (Join-Path $actions 'Sf.EndpointAI.InstallerActions.exe')
    Copy-Item "$root/installer/Sf.EndpointAI.Setup/Collect-Diagnostics.cmd" $publish
    Copy-Item "$root/installer/Sf.EndpointAI.Setup/Uninstall-EndpointAI.cmd" $publish
    dotnet build "$root/installer/Sf.EndpointAI.Setup/Sf.EndpointAI.Setup.wixproj" -c Release -p:ProductVersion=0.1.22 "-p:ProductionInputDir=$inputDir" "-p:ServicePublishDir=$publish" "-p:InstallerActionsDir=$actions" "-p:OutputPath=$output/" "-p:IntermediateOutputPath=$stageDir/obj/"
    if ($LASTEXITCODE -ne 0) { throw 'MSI build failed.' }
    $msi = Join-Path $output 'EndpointAIDLP-Client-0.1.22-win-x64.msi'
    Assert-ProductionMsi $msi
    $target = Join-Path $privateRoot 'EndpointAIDLP-Client-0.1.22-win-x64.msi'
    Copy-Item -LiteralPath $msi $target -Force
    $digest = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText("$target.sha256", "$digest  EndpointAIDLP-Client-0.1.22-win-x64.msi" + [Environment]::NewLine)
    Write-Host "Build pass $pass succeeded; metadata and sequence checks passed."
  } finally {
    # No keys or embedded-credential CAB files are left in intermediate directories.
    Remove-Item -LiteralPath $stageDir -Recurse -Force
  }
}
Copy-Item "$PSScriptRoot/Collect-InstallerLogs.ps1" $privateRoot -Force
Copy-Item (Join-Path (Split-Path $root -Parent) 'README-WINDOWS-0.1.22.md') $privateRoot -Force
Write-Host "Private MSI: $target"
Write-Host 'Windows installation and IOA acceptance are still required before broad deployment.'
