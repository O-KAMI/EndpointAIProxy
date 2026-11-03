#requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$MsiFile,
  [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedMsiSha256,
  [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedServiceSha256,
  [Parameter(Mandatory=$true)][string]$OutputDirectory,
  [Parameter(Mandatory=$true)][string]$TargetUserSid,
  [ValidateRange(5,300)][int]$SampleSeconds=30,
  [ValidateRange(0,300)][int]$SmokeSeconds=0
)
$ErrorActionPreference='Stop'
$utf8=[Text.UTF8Encoding]::new($false)
[Console]::InputEncoding=$utf8; [Console]::OutputEncoding=$utf8; $OutputEncoding=$utf8
chcp 65001 > $null
. "$PSScriptRoot/Windows-GoSupport.ps1"
. "$PSScriptRoot/Installer-BuildSupport.ps1"
. "$PSScriptRoot/Acceptance-Support.ps1"
. "$PSScriptRoot/SoakObservation-Support.ps1"
$MsiFile=[IO.Path]::GetFullPath($MsiFile)
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
Assert-AcceptancePath $MsiFile
Assert-AcceptancePath $OutputDirectory
$msiHash=Get-Sha256 $MsiFile
if ($msiHash -ne $ExpectedMsiSha256.ToLowerInvariant()) { throw 'MSI digest mismatch.' }
$version=Get-MsiProductVersion $MsiFile
$target=Get-AcceptanceTarget $TargetUserSid
$baselinePath=Join-Path $OutputDirectory 'prepared.json'
Assert-AcceptancePath $baselinePath
$baseline=Get-Content -LiteralPath $baselinePath -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-AcceptanceBaseline $baseline $target $msiHash $version
Protect-AcceptanceDirectory $OutputDirectory $target.sid
$runDirectory=Join-Path $OutputDirectory ('SoakObservation-'+[Guid]::NewGuid().ToString('N'))
Protect-AcceptanceDirectory $runDirectory $target.sid
$samplesPath=Join-Path $runDirectory 'samples.jsonl'
$summaryPath=Join-Path $runDirectory 'summary.json'
$writer=[IO.StreamWriter]::new([IO.FileStream]::new($samplesPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read),$utf8)
$timer=[Diagnostics.Stopwatch]::StartNew()
$duration=if ($SmokeSeconds -gt 0) { $SmokeSeconds } else { 8*60*60 }
$samples=0; $unhealthy=0; $restarts=0; $previousPid=0; $verifiedAt=-600; $complete=$false
$previousElapsed=0.0; $previousUtc=[DateTimeOffset]::UtcNow; $continuityValid=$true; $maxGap=0.0
$allowedGap=[Math]::Max(3*$SampleSeconds,$SampleSeconds+60)
try {
  while ($timer.Elapsed.TotalSeconds -lt $duration) {
    $sampleElapsed=$timer.Elapsed.TotalSeconds; $sampleUtc=[DateTimeOffset]::UtcNow
    $gap=Get-SoakSampleGap $previousElapsed $previousUtc $sampleElapsed $sampleUtc $SampleSeconds
    $continuityValid=$continuityValid -and $gap.valid; $maxGap=[Math]::Max($maxGap,$gap.gapSeconds)
    $previousElapsed=$sampleElapsed; $previousUtc=$sampleUtc
    $sample=@{ elapsedSeconds=[Math]::Round($sampleElapsed,3); atUtc=$sampleUtc.ToString('o'); healthy=$false }
    try {
      $service=Get-CimInstance Win32_Service -Filter "Name='SfEndpointAIProxy'" -ErrorAction Stop
      if ($null -eq $service -or $service.State -ne 'Running' -or $service.ProcessId -le 0) { throw 'SERVICE_UNAVAILABLE' }
      $pidValue=[int]$service.ProcessId
      $process=Get-Process -Id $pidValue -ErrorAction Stop
      if ($previousPid -ne $pidValue -or $timer.Elapsed.TotalSeconds-$verifiedAt -ge 600) {
        if ((Get-Sha256 $process.Path) -ne $ExpectedServiceSha256.ToLowerInvariant()) { throw 'SERVICE_DIGEST_MISMATCH' }
        $verifiedAt=$timer.Elapsed.TotalSeconds
      }
      $listeners=@(Get-NetTCPConnection -LocalPort 18080 -State Listen -ErrorAction Stop)
      if ($listeners.Count -ne 1 -or $listeners[0].LocalAddress -ne '127.0.0.1' -or $listeners[0].OwningProcess -ne $pidValue) { throw 'LISTENER_MISMATCH' }
      $request=[Net.HttpWebRequest]::Create('http://127.0.0.1:18080/healthz')
      $request.Proxy=$null; $request.Timeout=3000; $request.ReadWriteTimeout=3000
      $response=$request.GetResponse()
      try {
        $reader=[IO.StreamReader]::new($response.GetResponseStream(),[Text.Encoding]::UTF8)
        try { $health=$reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
      } finally { $response.Dispose() }
      $healthState=Get-SoakHealthState $health $version
      $again=Get-CimInstance Win32_Service -Filter "Name='SfEndpointAIProxy'" -ErrorAction Stop
      if ($null -eq $again -or $again.State -ne 'Running' -or $again.ProcessId -ne $pidValue) { throw 'SERVICE_CHANGED_DURING_SAMPLE' }
      if ($previousPid -ne 0 -and $previousPid -ne $pidValue) { $restarts++ }
      $previousPid=$pidValue
      $sample.pid=$pidValue
      $sample.workingSetBytes=$process.WorkingSet64; $sample.privateBytes=$process.PrivateMemorySize64
      $sample.cpuSeconds=[Math]::Round($process.TotalProcessorTime.TotalSeconds,3)
      $sample.auditHealthy=$healthState.auditHealthy
      $sample.controlHealthy=$healthState.controlHealthy
      $sample.lastControlSyncAtUtc=$healthState.lastControlSyncAtUtc
      $sample.controlEventQueue=$healthState.controlEventQueue
      $sample.healthy=($sample.auditHealthy -and $sample.controlHealthy)
      if (-not $sample.healthy) { $unhealthy++ }
    } catch {
      # Error details and service paths can contain environment-specific data.
      $sample.errorCode='SAMPLE_UNAVAILABLE_OR_MISMATCH'
      $unhealthy++
    }
    $samples++
    $writer.WriteLine(($sample | ConvertTo-Json -Compress)); $writer.Flush()
    $remaining=$duration-$timer.Elapsed.TotalSeconds
    if ($remaining -gt 0) { Start-Sleep -Milliseconds ([int][Math]::Min($SampleSeconds*1000,[Math]::Ceiling($remaining*1000))) }
  }
  $gap=Get-SoakSampleGap $previousElapsed $previousUtc $timer.Elapsed.TotalSeconds ([DateTimeOffset]::UtcNow) $SampleSeconds
  $continuityValid=$continuityValid -and $gap.valid; $maxGap=[Math]::Max($maxGap,$gap.gapSeconds)
  $complete=$timer.Elapsed.TotalSeconds -ge $duration
} finally {
  $timer.Stop(); $writer.Dispose()
  $summary=@{ schemaVersion=1; status=if (-not $complete) {'interrupted'} elseif (-not $continuityValid) {'observation-incomplete'} elseif ($SmokeSeconds -gt 0) {'smoke-completed'} else {'observation-completed'};
    msiSha256=$msiHash; expectedServiceSha256=$ExpectedServiceSha256.ToLowerInvariant(); productVersion=$version;
    elapsedSeconds=[Math]::Round($timer.Elapsed.TotalSeconds,3); samples=$samples; unhealthySamples=$unhealthy; observedPidChanges=$restarts;
    samplingContinuityValid=$continuityValid; maxSamplingGapSeconds=[Math]::Round($maxGap,3); allowedSamplingGapSeconds=$allowedGap;
    duration8hCompleted=($complete -and $continuityValid -and $SmokeSeconds -eq 0 -and $timer.Elapsed.TotalSeconds -ge 28800);
    releaseAcceptance='pending: business, actual restarts, fault recovery, IOA and resource review' }
  $json=$summary | ConvertTo-Json -Depth 5
  [IO.File]::WriteAllText($summaryPath,$json+[Environment]::NewLine,$utf8)
}
Write-Host "Observation complete. Review summary.json and samples.jsonl in $runDirectory; this is not an acceptance pass."
