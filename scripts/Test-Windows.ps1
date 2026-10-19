#requires -Version 5.1
[CmdletBinding()]
param(
  [string]$MsiFile,
  [ValidateSet('None','Install','Uninstall')][string]$MachineAction='None',
  [ValidateRange(0,4)][double]$DurationHours=0,
  [string]$OutputDirectory,
  [ValidatePattern('^(|\d+\.\d+\.\d+)$')][string]$ProductVersion=''
)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. "$PSScriptRoot/Installer-BuildSupport.ps1"
. "$PSScriptRoot/Windows-GoSupport.ps1"
$savedLocation=Get-Location
$temporary=$null
$environment=@{}
$stage='preflight'
$checks=@()
$rebootRequired=$false
try {
  Set-Location -LiteralPath $root
  foreach ($name in @('GOTOOLCHAIN','CGO_ENABLED','GOOS','GOARCH','GOFLAGS')) { $environment[$name]=[Environment]::GetEnvironmentVariable($name,'Process') }
  $env:GOTOOLCHAIN='local'; $env:CGO_ENABLED='0'; $env:GOOS='windows'; $env:GOARCH='amd64'; $env:GOFLAGS=''
  $tools=Assert-WindowsBuildHost
 if(-not $ProductVersion){if($MsiFile){$ProductVersion=Get-MsiProductVersion $MsiFile}else{$ProductVersion='0.2.2'}}
  if (-not $OutputDirectory) { $OutputDirectory=Join-Path $root ('artifacts/windows-test-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmss')) }
  $OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
  Protect-BuildPath $OutputDirectory
  $temporary=Join-Path $OutputDirectory ('fixtures-' + [Guid]::NewGuid().ToString('N'))
  Protect-BuildPath $temporary
  Set-Location -LiteralPath "$root/go-client"
  $moduleMode=if (Test-Path -LiteralPath 'vendor/modules.txt') { '-mod=vendor' } else { '-mod=readonly' }
  $stage='go-tests'
  Invoke-CheckedNative $tools.Go @('test',$moduleMode,'./...')
  Invoke-CheckedNative $tools.Go @('vet',$moduleMode,'./...')
  $checks += 'go test and vet'
  $stage='native-dpapi-interop'
  Add-Type -AssemblyName System.Security
  $entropy=[Text.Encoding]::UTF8.GetBytes('SF.EndpointAI.Route.v1')
  $dotnetBlob=[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes('synthetic-dotnet-dpapi'),$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine)
  [IO.File]::WriteAllBytes((Join-Path $temporary 'dotnet.blob'),$dotnetBlob)
  $bridge=Join-Path $temporary 'windows-dpapi-check.exe'
  Invoke-CheckedNative $tools.Go @('build',$moduleMode,'-trimpath','-o',$bridge,'./cmd/windows-dpapi-check')
  Invoke-CheckedNative $bridge @('-directory',$temporary,'-mode','verify')
  Invoke-CheckedNative $bridge @('-directory',$temporary,'-mode','write')
  $plain=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes((Join-Path $temporary 'go.blob')),$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine)
  if ([Text.Encoding]::UTF8.GetString($plain) -cne 'synthetic-go-dpapi') { throw 'Synthetic Go to .NET DPAPI mismatch.' }
  [Array]::Clear($plain,0,$plain.Length)
  $checks += 'LocalMachine DPAPI .NET-to-Go and Go-to-.NET synthetic fixtures'
  Set-Location -LiteralPath $root
  if ($MsiFile) {
    $MsiFile=[IO.Path]::GetFullPath($MsiFile)
    $stage='msi-validation'
    & "$PSScriptRoot/Validate-MSI.ps1" -MsiFile $MsiFile -ProductVersion $ProductVersion -ReportPath (Join-Path $OutputDirectory 'msi-validation.json')
    $checks += 'MSI metadata and approved payload inventory'
  }
  if ($MachineAction -ne 'None') {
    if (-not $MsiFile) { throw 'Explicit installation/uninstallation requires -MsiFile.' }
    if ($MachineAction -eq 'Uninstall' -and $DurationHours -gt 0) { throw 'Long-run health collection is incompatible with Uninstall.' }
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Explicit machine actions require an elevated Windows PowerShell or IOA identity.' }
    $stage='explicit-' + $MachineAction.ToLowerInvariant()
    $verb=if ($MachineAction -eq 'Install') { '/i' } else { '/x' }
    $log=Join-Path $OutputDirectory 'native-msi-private.log'
    $arguments=@($verb,('"' + $MsiFile + '"'),'/qn','/norestart','/L*v',('"' + $log + '"'))
    $process=Start-Process -FilePath "$env:WINDIR/System32/msiexec.exe" -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -notin @(0,3010)) { throw 'Explicit MSI operation failed; protected raw log remains local.' }
    $rebootRequired=$process.ExitCode -eq 3010
    $checks += ('explicit MSI ' + $MachineAction.ToLowerInvariant())
  }
  if ($MachineAction -eq 'Install' -or $DurationHours -gt 0) {
    $stage='native-health'
    $started=[DateTime]::UtcNow
    $deadline=$started.AddHours($DurationHours)
    $samplePath=Join-Path $OutputDirectory 'health-samples.jsonl'
    $samples=0
    do {
      $service=Get-CimInstance -ClassName Win32_Service -Filter "Name='SfEndpointAIProxy'"
      if ($null -eq $service -or $service.State -ne 'Running' -or $service.ProcessId -eq 0) { throw 'Native service is not running.' }
      $health=Invoke-RestMethod -Uri 'http://127.0.0.1:18080/healthz' -TimeoutSec 10 -UseBasicParsing
      if ($health.status -ne 'ok' -or $health.implementation -ne 'go' -or $health.clientVersion -ne $ProductVersion -or $health.installationPending -eq $true) { throw 'Native health implementation/version mismatch.' }
      $worker=Get-Process -Id $service.ProcessId -ErrorAction Stop
      $record=@{ atUtc=[DateTime]::UtcNow.ToString('o'); status=$health.status; clientVersion=$health.clientVersion; implementation=$health.implementation; workingSetBytes=$worker.WorkingSet64; cpuSeconds=$worker.CPU }
      [IO.File]::AppendAllText($samplePath,((ConvertTo-Json -InputObject $record -Compress) + [Environment]::NewLine),[Text.UTF8Encoding]::new($false))
      $samples++
      if ([DateTime]::UtcNow -lt $deadline) { Start-Sleep -Seconds 30 }
    } while ([DateTime]::UtcNow -lt $deadline)
    $elapsed=([DateTime]::UtcNow - $started).TotalHours
    $checks += 'native service and Go health'
  }
  Write-BuildJson (Join-Path $OutputDirectory 'windows-test-report.json') @{ status='passed'; checks=$checks; machineAction=$MachineAction; machineChangesPerformed=($MachineAction -ne 'None'); dpapiFixture='synthetic-only'; requestedDurationHours=$DurationHours; elapsedHours=$elapsed; duration4hCompleted=($DurationHours -ge 4 -and $elapsed -ge 4); rebootRequired=$rebootRequired; fullLifecycleAndIOAAcceptance='pending-unless-separately-recorded' }
  Write-Host 'Windows checks passed. See the protected report for what was actually tested.'
} catch {
  if ($OutputDirectory -and (Test-Path -LiteralPath $OutputDirectory)) { Write-BuildJson (Join-Path $OutputDirectory 'windows-test-report.json') @{ status='failed'; stage=$stage; checksPassed=$checks; errorType=$_.Exception.GetType().Name; machineAction=$MachineAction; rebootRequired=$rebootRequired } }
  [Console]::Error.WriteLine(('Windows checks failed at ' + $stage + '; values and raw exceptions withheld.'))
  exit 1
} finally {
  Set-Location -LiteralPath $savedLocation.Path
  foreach ($name in $environment.Keys) { [Environment]::SetEnvironmentVariable($name,$environment[$name],'Process') }
  if ($temporary -and (Test-Path -LiteralPath $temporary)) { Remove-Item -LiteralPath $temporary -Recurse -Force }
}
