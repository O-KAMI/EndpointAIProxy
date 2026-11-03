#requires -Version 5.1
function Get-SoakHealthState($Health,[string]$Version,[DateTimeOffset]$Now=[DateTimeOffset]::UtcNow) {
  if ($Health.status -ne 'ok' -or $Health.implementation -ne 'go' -or
      $Health.clientVersion -ne $Version -or $Health.installationPending -ne $false) {
    throw 'HEALTH_MISMATCH'
  }
  $sync=[DateTimeOffset]::MinValue
  $hasSync=([DateTimeOffset]::TryParse([string]$Health.lastControlSyncAtUtc,[ref]$sync))
  $syncAge=if ($hasSync) {($Now-$sync).TotalSeconds} else {$null}
  $queue=$null
  $value=$Health.controlEventQueue
  if ($null -ne $value -and ($value.capacity -is [int] -or $value.capacity -is [long]) -and $value.capacity -eq 1000 -and
      ($value.memoryDepth -is [int] -or $value.memoryDepth -is [long]) -and $value.memoryDepth -ge 0 -and $value.memoryDepth -le 2000 -and
      $value.memoryBaselineLoaded -is [bool] -and $value.persistedReadStatus -in @('available','unavailable')) {
    $depthValid=if ($value.persistedReadStatus -eq 'available') {
      ($value.persistedDepth -is [int] -or $value.persistedDepth -is [long]) -and $value.persistedDepth -ge 0 -and $value.persistedDepth -le 1000
    } else { $null -eq $value.persistedDepth }
    if ($depthValid) {
      $queue=@{memoryDepth=$value.memoryDepth;persistedDepth=$value.persistedDepth;capacity=1000;
        memoryBaselineLoaded=$value.memoryBaselineLoaded;persistedReadStatus=$value.persistedReadStatus}
    }
  }
  return @{
    auditHealthy=($Health.auditState -eq 'Healthy')
    controlHealthy=($hasSync -and $syncAge -ge -60 -and $syncAge -le 600 -and [string]::IsNullOrWhiteSpace($Health.lastControlErrorCode))
    lastControlSyncAtUtc=if ($hasSync) {$sync.ToUniversalTime().ToString('o')} else {$null}
    controlEventQueue=$queue
  }
}
function Get-SoakSampleGap([double]$PreviousElapsed,[DateTimeOffset]$PreviousUtc,[double]$Elapsed,[DateTimeOffset]$Now,[int]$SampleSeconds) {
  $monotonicGap=$Elapsed-$PreviousElapsed
  $wallGap=($Now-$PreviousUtc).TotalSeconds
  $limit=[Math]::Max(3*$SampleSeconds,$SampleSeconds+60)
  return @{
    valid=($monotonicGap -ge 0 -and $wallGap -ge 0 -and [Math]::Abs($monotonicGap-$wallGap) -le 5 -and [Math]::Max($monotonicGap,$wallGap) -le $limit)
    gapSeconds=[Math]::Max($monotonicGap,$wallGap)
    allowedGapSeconds=$limit
  }
}
