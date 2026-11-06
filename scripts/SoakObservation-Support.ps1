#requires -Version 5.1
function New-SoakDirectoryScanner([string]$DataRoot) {
  $groups=[ordered]@{captures='captures';serviceLogs='logs';state='state';configBackups='config-backups';diagnostics='diagnostics'}
  $items=@()
  foreach($name in $groups.Keys) {
    $items+=@{name=$name;root=(Join-Path $DataRoot $groups[$name]);pending=[Collections.Generic.Queue[string]]::new();iterator=$null;files=0L;bytes=0L;partialFiles=0L;partialBytes=0L;compressedFiles=0L;compressedBytes=0L;status='pending';lastComplete=$null}
  }
  return @{items=$items;next=0;started=$false;cycleStarted=[DateTimeOffset]::MinValue;completed=$null;lastSlice=[DateTimeOffset]::MinValue}
}

function Get-SoakDirectoryUsage($Scanner,[ValidateRange(1,2000)][int]$BudgetMilliseconds=2000) {
  $now=[DateTimeOffset]::UtcNow
  if(-not $Scanner.started -or ($null -ne $Scanner.completed -and ($now-$Scanner.completed).TotalSeconds -ge 60)) {
    $Scanner.started=$true;$Scanner.cycleStarted=$now;$Scanner.completed=$null
    foreach($item in $Scanner.items) {
      if($null -ne $item.iterator){$item.iterator.Dispose();$item.iterator=$null}
      $item.pending.Clear();$item.pending.Enqueue($item.root)
      $item.files=0L;$item.bytes=0L;$item.partialFiles=0L;$item.partialBytes=0L;$item.compressedFiles=0L;$item.compressedBytes=0L;$item.status='scanning'
    }
  }
  $budget=[Diagnostics.Stopwatch]::StartNew()
  $runSlice=($now-$Scanner.lastSlice).TotalSeconds -ge 60
  if($runSlice){$Scanner.lastSlice=$now}
  while($runSlice -and $budget.ElapsedMilliseconds -lt $BudgetMilliseconds -and @($Scanner.items|Where-Object {$_.status -eq 'scanning'}).Count -gt 0) {
    $item=$Scanner.items[$Scanner.next];$Scanner.next=($Scanner.next+1)%$Scanner.items.Count
    if($item.status -ne 'scanning'){continue}
    try {
      if($null -eq $item.iterator) {
        if($item.pending.Count -eq 0){$item.status='complete';$item.lastComplete=[DateTimeOffset]::UtcNow;continue}
        $directory=[IO.DirectoryInfo]::new($item.pending.Dequeue())
        try {$attributes=[IO.File]::GetAttributes($directory.FullName)} catch [IO.DirectoryNotFoundException] {continue} catch [IO.FileNotFoundException] {continue}
        if(($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){$item.status='unavailable';continue}
        $item.iterator=$directory.EnumerateFileSystemInfos().GetEnumerator()
      }
      if(-not $item.iterator.MoveNext()){$item.iterator.Dispose();$item.iterator=$null;continue}
      $entry=$item.iterator.Current
      if(($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){$item.status='unavailable';$item.iterator.Dispose();$item.iterator=$null;continue}
      if(($entry.Attributes -band [IO.FileAttributes]::Directory) -ne 0){if($item.pending.Count -ge 4096){$item.status='unavailable';$item.iterator.Dispose();$item.iterator=$null}else{$item.pending.Enqueue($entry.FullName)};continue}
      $length=[long]$entry.Length;$item.files++;$item.bytes+=$length
      if($entry.Name.EndsWith('.partial')){$item.partialFiles++;$item.partialBytes+=$length}
      if($entry.Name.EndsWith('.gz')){$item.compressedFiles++;$item.compressedBytes+=$length}
    } catch {
      if($null -ne $item.iterator){$item.iterator.Dispose();$item.iterator=$null}
      $item.status='unavailable'
    }
  }
  if($null -eq $Scanner.completed -and @($Scanner.items|Where-Object {$_.status -eq 'scanning'}).Count -eq 0){$Scanner.completed=[DateTimeOffset]::UtcNow}
  $groups=@{}
  foreach($item in $Scanner.items) {
    $complete=$item.status -eq 'complete'
    $groups[$item.name]=@{status=$item.status;complete=$complete;fileCount=if($complete){$item.files}else{$null};totalBytes=if($complete){$item.bytes}else{$null};partialFileCount=if($complete){$item.partialFiles}else{$null};partialBytes=if($complete){$item.partialBytes}else{$null};compressedFileCount=if($complete){$item.compressedFiles}else{$null};compressedBytes=if($complete){$item.compressedBytes}else{$null};partialScanFileCount=$item.files;lastCompletedAtUtc=if($null -ne $item.lastComplete){$item.lastComplete.ToString('o')}else{$null}}
  }
  return @{cycleStartedAtUtc=$Scanner.cycleStarted.ToString('o');scanComplete=(@($Scanner.items|Where-Object {$_.status -ne 'complete'}).Count -eq 0);scanElapsedMilliseconds=$budget.ElapsedMilliseconds;groups=$groups}
}

function Close-SoakDirectoryScanner($Scanner) {
  foreach($item in $Scanner.items){if($null -ne $item.iterator){$item.iterator.Dispose();$item.iterator=$null}}
}

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
