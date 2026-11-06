#requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$MsiFile,
  [Parameter(Mandatory=$true)][string]$ExpectedMsiSha256,
  [Parameter(Mandatory=$true)][string]$ExpectedServiceSha256,
  [Parameter(Mandatory=$true)][string]$TestRoot
)
$ErrorActionPreference='Stop'
. "$PSScriptRoot/Windows-GoSupport.ps1"
. "$PSScriptRoot/Installer-BuildSupport.ps1"
. "$PSScriptRoot/Acceptance-Support.ps1"
. "$PSScriptRoot/SoakObservation-Support.ps1"
$healthy=[pscustomobject]@{status='ok';implementation='go';clientVersion='0.2.11';installationPending=$false;
  auditState='Healthy';lastControlErrorCode=$null;lastControlSyncAtUtc='2026-10-31T00:00:00Z'}
$now=[DateTimeOffset]::Parse('2026-10-31T00:01:00Z')
$probe=Get-SoakHealthState $healthy '0.2.11' $now
if (-not $probe.auditHealthy -or -not $probe.controlHealthy -or -not $probe.lastControlSyncAtUtc) { throw 'Healthy sample misclassified.' }
$healthy.lastControlSyncAtUtc=$null
if ((Get-SoakHealthState $healthy '0.2.11' $now).controlHealthy) { throw 'Missing control sync misclassified.' }
$healthy.lastControlSyncAtUtc='2026-10-31T00:00:00Z'; $healthy.lastControlErrorCode='CONTROL_SYNC_FAILED'
if ((Get-SoakHealthState $healthy '0.2.11' $now).controlHealthy) { throw 'Control failure misclassified.' }
$healthy.lastControlErrorCode=$null
if ((Get-SoakHealthState $healthy '0.2.11' ($now.AddMinutes(11))).controlHealthy) { throw 'Stale control sync misclassified.' }
$healthy.lastControlSyncAtUtc=$now.AddSeconds(61).ToString('o')
if ((Get-SoakHealthState $healthy '0.2.11' $now).controlHealthy) { throw 'Future control sync misclassified.' }
$healthy.lastControlSyncAtUtc='2026-10-31T00:00:00Z'
$healthy | Add-Member -NotePropertyName controlEventQueue -NotePropertyValue ([pscustomobject]@{
  memoryDepth=3;persistedDepth=2;capacity=1000;memoryBaselineLoaded=$true;persistedReadStatus='available';payload='synthetic-private-event'
})
$queue=(Get-SoakHealthState $healthy '0.2.11' $now).controlEventQueue
if ($null -eq $queue -or $queue.memoryDepth -ne 3 -or $queue.persistedDepth -ne 2 -or $queue.ContainsKey('payload')) { throw 'Queue snapshot lost counts or copied payload.' }
$healthy.controlEventQueue.memoryDepth=2000
if ((Get-SoakHealthState $healthy '0.2.11' $now).controlEventQueue.memoryDepth -ne 2000) { throw 'Merged recovery backlog was hidden.' }
$healthy.controlEventQueue.persistedReadStatus='unavailable';$healthy.controlEventQueue.persistedDepth=$null
$queue=(Get-SoakHealthState $healthy '0.2.11' $now).controlEventQueue
if ($null -eq $queue -or $null -ne $queue.persistedDepth) { throw 'Unavailable queue misclassified as empty.' }
$healthy.controlEventQueue.memoryDepth=$true
if ($null -ne (Get-SoakHealthState $healthy '0.2.11' $now).controlEventQueue) { throw 'Malformed queue accepted.' }
$healthy.controlEventQueue=$null
$gap=Get-SoakSampleGap 0 $now 30 ($now.AddSeconds(30)) 30
if (-not $gap.valid) { throw 'Regular sampling rejected.' }
$gap=Get-SoakSampleGap 0 $now 91 ($now.AddSeconds(91)) 30
if ($gap.valid) { throw 'Sampling gap accepted.' }
$gap=Get-SoakSampleGap 0 $now 30 ($now.AddSeconds(130)) 30
if ($gap.valid) { throw 'Clock discontinuity accepted.' }
$healthy.installationPending=$null
$rejected=$false
try { $null=Get-SoakHealthState $healthy '0.2.11' } catch { $rejected=$true }
if (-not $rejected) { throw 'Missing installation state accepted.' }
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$target=Get-AcceptanceTarget $sid
$output=Join-Path ([IO.Path]::GetFullPath($TestRoot)) ('observer-test-'+[Guid]::NewGuid().ToString('N'))
Protect-AcceptanceDirectory $output $sid
$dataRoot=Join-Path $output 'synthetic-data'
$null=New-Item -ItemType Directory -Path (Join-Path $dataRoot 'captures/nested') -Force
[IO.File]::WriteAllBytes((Join-Path $dataRoot 'captures/body.gz'),[byte[]](1,2,3,4))
[IO.File]::WriteAllBytes((Join-Path $dataRoot 'captures/nested/body.partial'),[byte[]](5,6,7))
# A file where a directory is expected must remain unknown, not appear empty.
[IO.File]::WriteAllText((Join-Path $dataRoot 'state'),'synthetic')
$scanner=New-SoakDirectoryScanner $dataRoot
try {
  $usage=Get-SoakDirectoryUsage $scanner
  if($usage.groups.captures.totalBytes -ne 7 -or $usage.groups.captures.fileCount -ne 2 -or
     $usage.groups.captures.compressedBytes -ne 4 -or $usage.groups.captures.partialBytes -ne 3) {throw 'Directory byte accounting mismatch.'}
  if($usage.groups.state.status -ne 'unavailable' -or $null -ne $usage.groups.state.totalBytes -or $usage.scanComplete) {throw 'Unavailable directory reported as empty.'}
  if(-not $usage.groups.diagnostics.complete -or $usage.groups.diagnostics.totalBytes -ne 0) {throw 'Absent directory accounting mismatch.'}
} finally {Close-SoakDirectoryScanner $scanner}
$version=Get-MsiProductVersion $MsiFile
$baseline=@{schemaVersion=2;msiSha256=$ExpectedMsiSha256.ToLowerInvariant();productVersion=$version;
  targetUserSid=$sid;targetProfile=$target.profile;codexConfigPath=(Join-Path $target.profile '.codex/config.toml')}
[IO.File]::WriteAllText((Join-Path $output 'prepared.json'),($baseline | ConvertTo-Json),[Text.UTF8Encoding]::new($false))
# Simulate an absent service. The observer must record a failed sample without
# touching a real service or opening the local health endpoint.
function Get-CimInstance { return $null }
& "$PSScriptRoot/Observe-WindowsSoak.ps1" -MsiFile $MsiFile -ExpectedMsiSha256 $ExpectedMsiSha256 `
  -ExpectedServiceSha256 $ExpectedServiceSha256 -OutputDirectory $output -TargetUserSid $sid -SmokeSeconds 1
$runs=@(Get-ChildItem -LiteralPath $output -Directory -Filter 'SoakObservation-*')
if ($runs.Count -ne 1) { throw 'Expected one observation run.' }
$summary=Get-Content -LiteralPath (Join-Path $runs[0].FullName 'summary.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$samples=@(Get-Content -LiteralPath (Join-Path $runs[0].FullName 'samples.jsonl') -Encoding UTF8)
if ($summary.status -ne 'smoke-completed' -or $summary.duration8hCompleted -or $summary.samples -lt 1 -or
    $summary.unhealthySamples -ne $summary.samples -or $samples.Count -ne $summary.samples -or
    ($samples[0] | ConvertFrom-Json).healthy -ne $false) { throw 'Observer failure accounting mismatch.' }
Write-Host 'Observer smoke verified: health classification and missing service; no real service was contacted.'
