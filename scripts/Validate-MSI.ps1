#requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$MsiFile,
  [ValidatePattern('^(|\d+\.\d+\.\d+)$')][string]$ProductVersion = '',
  [string]$ReportPath
)
$ErrorActionPreference='Stop'
. "$PSScriptRoot/Installer-BuildSupport.ps1"
. "$PSScriptRoot/Windows-GoSupport.ps1"
if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Validate the MSI on Windows.' }
$MsiFile=[IO.Path]::GetFullPath($MsiFile)
if(-not $ProductVersion){$ProductVersion=Get-MsiProductVersion $MsiFile}
Assert-ProductionMsi $MsiFile $ProductVersion
$installer=New-Object -ComObject WindowsInstaller.Installer
$database=$installer.OpenDatabase($MsiFile,0)
function Read-MsiRows([string]$Sql, [int]$Columns) {
  $view=$database.OpenView($Sql)
  try {
    $view.Execute()
    while ($null -ne ($record=$view.Fetch())) {
      $cells=@()
      for ($index=1; $index -le $Columns; $index++) { $cells += $record.StringData($index) }
      ,$cells
    }
  } finally { $view.Close() }
}
try {
  $files=@(Read-MsiRows 'SELECT `File`, `FileName` FROM `File`' 2)
  $expected=@{
    ProxyServiceExecutable='Sf.EndpointAI.Client.Service.exe'; DiagnosticCommandFile='Collect-Diagnostics.cmd';
    UninstallCommandFile='Uninstall-EndpointAI.cmd'; ProductionCredentials='client-credentials.json';
    ProductionProvisionScript='Set-ProductionClientControl.ps1'
  }
  if ($files.Count -ne $expected.Count) { throw 'Unexpected MSI files: Go package must contain exactly the five approved files, with no .NET runtime.' }
  foreach ($row in $files) {
    $longName=($row[1] -split '\|')[-1]
    if (-not $expected.ContainsKey($row[0]) -or $expected[$row[0]] -ne $longName) { throw 'Unexpected MSI file inventory.' }
  }
  $marker=@(Read-MsiRows 'SELECT `Value` FROM `Property` WHERE `Property`=''EndpointAIDLPLogMarker''' 1)
  if ($marker.Count -ne 1 -or $marker[0][0] -ne "EndpointAIDLP-Windows-Go-$ProductVersion") { throw 'Go MSI log marker mismatch.' }
  $service=@(Read-MsiRows 'SELECT `Name` FROM `ServiceInstall`' 1)
  if ($service.Count -ne 1 -or $service[0][0] -ne 'SfEndpointAIProxy') { throw 'MSI service identity mismatch.' }
  $binary=@(Read-MsiRows 'SELECT `Name` FROM `Binary` WHERE `Name`=''InstallerActionsBinary''' 1)
  if ($binary.Count -ne 1) { throw 'Installer helper binary missing.' }
  $detach=@(Read-MsiRows 'SELECT `Target` FROM `CustomAction` WHERE `Action`=''DetachManagedConfigurations''' 1)
  if ($detach.Count -ne 1 -or $detach[0][0] -ne '--maintenance=detach-all --auto-attach=false') { throw 'Configuration detach action mismatch.' }
  $same=@(Read-MsiRows 'SELECT `ActionProperty` FROM `Upgrade` WHERE `ActionProperty`=''SF_SAME_VERSION_PRODUCTS''' 1)
  $launch=@(Read-MsiRows 'SELECT `Condition` FROM `LaunchCondition`' 1)
  if($same.Count -ne 1 -or -not ($launch | Where-Object {$_[0] -eq 'Installed OR NOT SF_SAME_VERSION_PRODUCTS'})){throw 'Same-version different-product guard missing.'}
  if ($ReportPath) { Write-BuildJson $ReportPath @{ status='passed'; productVersion=$ProductVersion; architecture='x64'; upgradeCode='643CFDA1-3A12-4C57-BD65-5F6106CBAB90'; service='SfEndpointAIProxy'; fileInventory=@($expected.Values | Sort-Object); noDotnetRuntimeFiles=$true; transactionSequence='passed'; nativeInstallationPerformed=$false } }
  Write-Host 'MSI metadata, transaction sequence and Go-only file inventory passed; no install was performed.'
} finally {
  [Runtime.InteropServices.Marshal]::FinalReleaseComObject($database) | Out-Null
  [Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) | Out-Null
}
