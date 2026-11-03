#requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidateSet('Prepare','Install','Codex','Paused','Resumed','AfterReboot','Uninstall')][string]$Phase,
  [Parameter(Mandatory=$true)][string]$MsiFile,
  [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedMsiSha256,
  [Parameter(Mandatory=$true)][string]$OutputDirectory,
  [switch]$RequireCleanInstall,
  [string]$TargetUserSid,
  [string]$CodexHome
)
$ErrorActionPreference='Stop'
$utf8=[Text.UTF8Encoding]::new($false)
[Console]::InputEncoding=$utf8; [Console]::OutputEncoding=$utf8; $OutputEncoding=$utf8
chcp 65001 > $null
$env:PYTHONUTF8='1'; $env:PYTHONIOENCODING='utf-8'
. "$PSScriptRoot/Windows-GoSupport.ps1"
. "$PSScriptRoot/Installer-BuildSupport.ps1"
. "$PSScriptRoot/Acceptance-Support.ps1"
function Read-InstallRemnants {
  $installer=New-Object -ComObject WindowsInstaller.Installer
  try { $products=@($installer.RelatedProducts('{643CFDA1-3A12-4C57-BD65-5F6106CBAB90}')) }
  finally { [Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) | Out-Null }
  $dataRoot=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SF/EndpointAIProxy'
  return @{ registeredProducts=$products.Count; dataPresent=(Test-Path -LiteralPath $dataRoot) }
}
$report=@{ schemaVersion=1; phase=$Phase; status='failed'; msiSha256=$ExpectedMsiSha256.ToLowerInvariant(); atUtc=[DateTime]::UtcNow.ToString('o'); evidence=@{}; releaseAcceptance='pending'; pending=@('gateway request correlation','SSE transport evidence','control command receipts','configuration restoration review') }
$reportFile=$null
$originalCodexHome=$env:CODEX_HOME
try {
  $MsiFile=[IO.Path]::GetFullPath($MsiFile)
  if ((Get-Sha256 $MsiFile) -ne $report.msiSha256) { throw 'MSI digest mismatch.' }
  $productVersion=Get-MsiProductVersion $MsiFile
  $OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
  Assert-AcceptancePath $OutputDirectory
  $baselinePath=Join-Path $OutputDirectory 'prepared.json'
  Assert-AcceptancePath $baselinePath
  $callerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  if ($callerSid -eq 'S-1-5-18' -and -not $TargetUserSid) { throw 'SYSTEM must specify -TargetUserSid.' }
  if ($Phase -eq 'Prepare') {
    if (Test-Path -LiteralPath $baselinePath) { throw 'Prepare already recorded; preserve the original baseline.' }
    $target=Get-AcceptanceTarget $TargetUserSid
    if ($target.callerSid -ne $target.sid) { throw 'Prepare must run as the target interactive user.' }
    if (-not $CodexHome) { $CodexHome=if ($env:CODEX_HOME) {$env:CODEX_HOME} else {Join-Path $target.profile '.codex'} }
    Assert-AcceptancePath $CodexHome
    $config=Join-Path ([IO.Path]::GetFullPath($CodexHome)) 'config.toml'
  } else {
    $baseline=Get-Content -LiteralPath $baselinePath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $TargetUserSid) { $TargetUserSid=$baseline.targetUserSid }
    $target=Get-AcceptanceTarget $TargetUserSid
    Assert-AcceptanceBaseline $baseline $target $report.msiSha256 $productVersion
    $config=$baseline.codexConfigPath
    if ($CodexHome -and [IO.Path]::GetFullPath($CodexHome) -ne [IO.Path]::GetDirectoryName($config)) { throw 'CodexHome differs from Prepare.' }
  }
  if ($Phase -in @('Codex','Paused','Resumed') -and $callerSid -ne $target.sid) { throw 'Run application checks as the target interactive user.' }
  Protect-AcceptanceDirectory $OutputDirectory $target.sid
  $phaseDirectory=Join-Path $OutputDirectory ($Phase+'-'+[Guid]::NewGuid().ToString('N'))
  Protect-AcceptanceDirectory $phaseDirectory $target.sid
  $reportFile=Join-Path $phaseDirectory 'sanitized-report.json'
  $service=Get-CimInstance Win32_Service -Filter "Name='SfEndpointAIProxy'"
  $report.evidence.productVersion=$productVersion
  $report.evidence.executionIdentity=if ($callerSid -eq 'S-1-5-18') {'SYSTEM'} else {'interactive'}
  $report.evidence.targetUserBound=$true
  if (Test-Path -LiteralPath $config -PathType Leaf) { $report.evidence.codexConfigSha256=Get-Sha256 $config }
  $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
  $report.evidence.bootUtc=$boot
  if ($Phase -eq 'Prepare') {
    if (Test-Path -LiteralPath (Join-Path $OutputDirectory 'prepared.json')) { throw 'Prepare already recorded; preserve the original baseline.' }
    if (Test-Path -LiteralPath $config -PathType Leaf) { Copy-Item -LiteralPath $config -Destination (Join-Path $phaseDirectory 'codex-config.private.toml') }
    $remnants=Read-InstallRemnants
    $clean=($null -eq $service -and $remnants.registeredProducts -eq 0 -and -not $remnants.dataPresent)
    Write-BuildJson $baselinePath @{ schemaVersion=2; msiSha256=$report.msiSha256; productVersion=$productVersion; targetUserSid=$target.sid; targetProfile=$target.profile; codexConfigPath=$config; bootUtc=$boot; servicePresent=($null -ne $service); cleanBaseline=$clean; codexConfigSha256=$report.evidence.codexConfigSha256 }
    $report.evidence.cleanBeforeInstall=$clean
  } else {
    if ($Phase -in @('Install','Uninstall')) {
      $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
      if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Use an elevated shell for the explicitly selected MSI action.' }
      if ($Phase -eq 'Install' -and $RequireCleanInstall) {
        $remnants=Read-InstallRemnants
        if (-not $baseline.cleanBaseline -or $null -ne $service -or $remnants.registeredProducts -ne 0 -or $remnants.dataPresent) { throw 'Clean install requires no service, related MSI registration or previous data.' }
      }
      $verb=if ($Phase -eq 'Install') {'/i'} else {'/x'}
      $installLog=Join-Path $phaseDirectory 'msi.private.log'
      $native=Start-Process -FilePath "$env:WINDIR/System32/msiexec.exe" -ArgumentList @($verb,('"'+$MsiFile+'"'),'/qn','/norestart','/L*v',('"'+$installLog+'"')) -WindowStyle Hidden -Wait -PassThru
      $report.evidence.installerExitCode=$native.ExitCode
      $report.evidence.rebootRequired=($native.ExitCode -eq 3010)
      if ($native.ExitCode -notin @(0,3010)) { throw 'MSI action failed.' }
      if ($native.ExitCode -eq 3010) {
        $report.status='reboot-required'
        Write-Host 'MSI returned 3010. Record pending reboot; do not count this phase as passed.'
        exit 3010
      }
      $service=Get-CimInstance Win32_Service -Filter "Name='SfEndpointAIProxy'"
    }
    if ($Phase -eq 'Uninstall') {
      if ($null -ne $service) { throw 'Service remains after uninstall.' }
      $remaining=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {$_.LocalPort -eq 18080})
      if ($remaining.Count -ne 0) { throw 'Proxy port remains after uninstall.' }
      $report.evidence.serviceRemoved=$true
      $report.evidence.proxyPortReleased=$true
      $restoredDigest=$null
      if (Test-Path -LiteralPath $config -PathType Leaf) { $restoredDigest=Get-Sha256 $config }
      $report.evidence.codexOriginalDigestRestored=($restoredDigest -eq $baseline.codexConfigSha256)
      if (-not $report.evidence.codexOriginalDigestRestored) { throw 'Review configuration restoration; do not overwrite later user changes.' }
    } else {
      if ($null -eq $service -or $service.State -ne 'Running' -or $service.StartMode -ne 'Auto') { throw 'Expected automatic running service.' }
      $listeners=@(Get-NetTCPConnection -LocalPort 18080 -State Listen -ErrorAction Stop)
      if ($listeners.Count -ne 1 -or $listeners[0].OwningProcess -ne $service.ProcessId -or $listeners[0].LocalAddress -ne '127.0.0.1') { throw 'Service and loopback listener identity mismatch.' }
      $report.evidence.serviceOwnsProxyPort=$true
      $health=Invoke-RestMethod -Uri 'http://127.0.0.1:18080/healthz' -UseBasicParsing -TimeoutSec 10
      if ($health.status -ne 'ok' -or $health.implementation -ne 'go' -or $health.clientVersion -ne $productVersion -or $health.installationPending -eq $true) { throw 'Candidate health mismatch.' }
      $report.evidence.serviceVersion=$health.clientVersion
      $report.evidence.operationState=$health.operationState
      if ($Phase -eq 'Paused' -and $health.operationState -ne 'Disabled') { throw 'Pause has not been applied.' }
      if ($Phase -eq 'Resumed' -and $health.operationState -ne 'Enabled') { throw 'Resume has not been applied.' }
      if ($Phase -eq 'AfterReboot') {
        if ($baseline.bootUtc -eq $boot) { throw 'No real reboot since Prepare.' }
        $report.evidence.realRebootObserved=$true
      }
      if ($Phase -in @('Codex','Paused','Resumed')) {
        $codex=Get-Command codex.cmd -ErrorAction Stop
        $help=(& $codex.Source exec --help | Out-String)
        foreach ($flag in @('--ephemeral','--sandbox','--json','--skip-git-repo-check')) { if (-not $help.Contains($flag)) { throw 'Codex CLI does not support the required flags.' } }
        $nonce='EndpointAI-'+[Guid]::NewGuid().ToString('N')
        $work=Join-Path $phaseDirectory 'empty-workspace'
        Protect-AcceptanceDirectory $work $target.sid
        $env:CODEX_HOME=[IO.Path]::GetDirectoryName($config)
        $eventPath=Join-Path $phaseDirectory 'codex-events.private.jsonl'
        $events=[IO.StreamWriter]::new($eventPath,$false,$utf8)
        $completed=$false; $matched=$false; $toolUsed=$false
        $nativeErrorPreference=$ErrorActionPreference
        try {
          $ErrorActionPreference='Continue'
          & $codex.Source exec --ephemeral --sandbox read-only --skip-git-repo-check --json --cd $work "Reply with exactly $nonce. Do not use tools, read files, or run commands." 2>&1 | ForEach-Object {
            $line=[string]$_; $events.WriteLine($line); $events.Flush()
            try {
              $event=$line | ConvertFrom-Json
              if ($event.type -eq 'turn.completed') { $completed=$true }
              if ($event.type -eq 'item.completed' -and $event.item.type -eq 'agent_message' -and $event.item.text.Trim() -eq $nonce) { $matched=$true }
              if ($event.type -eq 'item.started' -and $event.item.type -in @('command_execution','mcp_tool_call','file_change')) { $toolUsed=$true }
            } catch { } # Keep non-JSON diagnostics in the protected raw file only.
          }
          $report.evidence.codexExitCode=$LASTEXITCODE
        } finally { $ErrorActionPreference=$nativeErrorPreference; $events.Dispose() }
        $report.evidence.nonce=$nonce; $report.evidence.turnCompleted=$completed; $report.evidence.expectedReply=$matched; $report.evidence.toolUsed=$toolUsed
        if ($report.evidence.codexExitCode -ne 0 -or -not $completed -or -not $matched -or $toolUsed) { throw 'Codex request check failed.' }
      }
    }
  }
  $report.status='phase-passed'
} catch {
  $report.errorType=$_.Exception.GetType().Name
  [Console]::Error.WriteLine('Acceptance phase failed; details and raw output remain in the protected directory.')
} finally {
  $env:CODEX_HOME=$originalCodexHome
  if ($reportFile) { Write-BuildJson $reportFile $report }
}
if ($report.status -ne 'phase-passed') { exit 1 }
Write-Host 'Phase passed. Return sanitized-report.json only; complete the remaining correlation and lifecycle evidence separately.'
