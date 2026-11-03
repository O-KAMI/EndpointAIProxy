#requires -Version 5.1
[CmdletBinding()]
param(
  [string]$ManifestFile=(Join-Path (Split-Path $PSScriptRoot -Parent) 'manifest.json'),
  [ValidateRange(0,600)][int]$WaitSeconds=120,
  [switch]$RequireEnabled,
  [string]$OutputDirectory
)
$ErrorActionPreference='Stop'
. "$PSScriptRoot/Installer-BuildSupport.ps1"
. "$PSScriptRoot/Windows-GoSupport.ps1"
$report=@{status='failed'; checks=@{}; atUtc=[DateTime]::UtcNow.ToString('o'); releaseAcceptance='pending'}
try {
  $manifest=Get-Content -LiteralPath $ManifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
  $expected=@($manifest.payload | Where-Object {$_.name -eq 'Sf.EndpointAI.Client.Service.exe'})
  if ($expected.Count -ne 1 -or $expected[0].sha256 -notmatch '^[a-f0-9]{64}$' -or $manifest.productVersion -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid deployment manifest.' }
  $report.version=$manifest.productVersion
  $report.msiSha256=$manifest.msi.sha256
  $deadline=[DateTime]::UtcNow.AddSeconds($WaitSeconds)
  do {
    $checks=@{serviceRunning=$false; serviceAutomatic=$false; listenerOwned=$false; versionMatches=$false; implementationMatches=$false; payloadMatches=$false; installationCommitted=$false; effectiveGatewayMatches=$false; controlOnline=$false; operationReady=$false}
    try {
      $service=Get-CimInstance Win32_Service -Filter "Name='SfEndpointAIProxy'"
      if ($service) {
        $checks.serviceRunning=($service.State -eq 'Running')
        $checks.serviceAutomatic=($service.StartMode -eq 'Auto')
        $match=[regex]::Match($service.PathName,'^(?:"([^"]+\.exe)"|(.+?\.exe))(?:\s|$)')
        if ($match.Success) {
          $image=if ($match.Groups[1].Success) {$match.Groups[1].Value} else {$match.Groups[2].Value}
          $checks.payloadMatches=([IO.Path]::GetFileName($image) -eq $expected[0].name -and (Get-Sha256 $image) -eq $expected[0].sha256)
        }
        $listeners=@(Get-NetTCPConnection -LocalPort 18080 -State Listen -ErrorAction Stop)
        $checks.listenerOwned=($listeners.Count -eq 1 -and $listeners[0].OwningProcess -eq $service.ProcessId -and $listeners[0].LocalAddress -eq '127.0.0.1')
        $health=Invoke-RestMethod 'http://127.0.0.1:18080/healthz' -UseBasicParsing -TimeoutSec 5
        $checks.versionMatches=($health.clientVersion -eq $manifest.productVersion)
        $checks.implementationMatches=($health.status -eq 'ok' -and $health.implementation -eq 'go')
        $checks.installationCommitted=($health.installationPending -eq $false)
        $checks.effectiveGatewayMatches=($health.gatewayOrigin -and ([Uri]$health.gatewayOrigin).AbsoluteUri.TrimEnd('/') -eq ([Uri]$manifest.gatewayOrigin).AbsoluteUri.TrimEnd('/'))
        $checks.controlOnline=($health.lastControlSyncAtUtc -and [DateTime]::Parse($health.lastControlSyncAtUtc).ToUniversalTime() -ge [DateTime]::UtcNow.AddMinutes(-5) -and -not $health.lastControlErrorCode)
        $checks.operationReady=($health.operationState -eq 'Enabled' -or (-not $RequireEnabled -and $health.operationState -eq 'Disabled'))
      }
    } catch { } # Emit fixed checks only; native errors may contain private paths.
    $report.checks=$checks
    if (@($checks.Values | Where-Object {$_ -ne $true}).Count -eq 0) { $report.status='passed'; break }
    if ([DateTime]::UtcNow -ge $deadline) { break }
    Start-Sleep -Seconds 3
  } while ($true)
} catch { $report.errorCode='DEPLOYMENT_INPUT_INVALID' }
if ($OutputDirectory) {
  $OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
  Protect-BuildPath $OutputDirectory
  Write-BuildJson (Join-Path $OutputDirectory 'deployment-status.json') $report
}
$report | ConvertTo-Json -Depth 5
if ($report.status -ne 'passed') { exit 1 }
exit 0
