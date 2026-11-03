#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
. "$PSScriptRoot/Installer-BuildSupport.ps1"
. "$PSScriptRoot/Windows-GoSupport.ps1"
Protect-BuildPath $OutputDirectory
$image=Join-Path $OutputDirectory 'Sf.EndpointAI.Client.Service.exe'
[IO.File]::WriteAllText($image,'synthetic-not-executable',[Text.UTF8Encoding]::new($false))
$manifest=Join-Path $OutputDirectory 'fixture-manifest.json'
Write-BuildJson $manifest @{productVersion='0.2.4';gatewayOrigin='http://gateway.example:80';payload=@(@{name='Sf.EndpointAI.Client.Service.exe';sha256=(Get-Sha256 $image)});msi=@{sha256=('a'*64)}}
function Get-CimInstance { return [pscustomobject]@{State='Running';StartMode='Auto';ProcessId=123;PathName=('"'+$image+'" --synthetic')} }
function Get-NetTCPConnection { return [pscustomobject]@{OwningProcess=$listenerOwner;LocalAddress='127.0.0.1'} }
function Invoke-RestMethod { return $fixtureHealth }
$checks=[Collections.Generic.List[string]]::new()
function Check([string]$Name,[bool]$Passed,[switch]$RequireEnabled) {
  $result=& "$PSScriptRoot/Test-DeploymentStatus.ps1" -ManifestFile $manifest -WaitSeconds 0 -RequireEnabled:$RequireEnabled | ConvertFrom-Json
  $code=$LASTEXITCODE
  if (($result.status -eq 'passed') -ne $Passed -or ($code -eq 0) -ne $Passed) { throw ($Name+' gave wrong detection result.') }
  $checks.Add($Name)
}
$listenerOwner=123
$fixtureHealth=[pscustomobject]@{clientVersion='0.2.4';status='ok';implementation='go';installationPending=$false;gatewayOrigin='http://gateway.example';lastControlSyncAtUtc=[DateTime]::UtcNow.ToString('o');lastControlErrorCode='';operationState='Enabled'}
Check 'ready installation and normalized default port accepted' $true
$fixtureHealth.gatewayOrigin='http://old-gateway.example'
Check 'old cached policy gateway rejected' $false
$fixtureHealth.gatewayOrigin='http://gateway.example'
$fixtureHealth.clientVersion='0.2.3'
Check 'old client version rejected' $false
$fixtureHealth.clientVersion='0.2.4'
$fixtureHealth.installationPending=$true
Check 'uncommitted installation rejected' $false
$fixtureHealth.installationPending=$false
$listenerOwner=456
Check 'foreign listener rejected' $false
$listenerOwner=123
$fixtureHealth.lastControlSyncAtUtc=[DateTime]::UtcNow.AddMinutes(-6).ToString('o')
Check 'stale control synchronization rejected' $false
$fixtureHealth.lastControlSyncAtUtc=[DateTime]::UtcNow.ToString('o')
$fixtureHealth.lastControlErrorCode='CONTROL_FAILED'
Check 'control error rejected' $false
$fixtureHealth.lastControlErrorCode=''
$fixtureHealth.operationState='Disabled'
Check 'preserved paused state accepted for installation' $true
Check 'paused state rejected for enabled rollout' $false -RequireEnabled
$fixtureHealth.operationState='Enabled'
[IO.File]::AppendAllText($image,'-tampered')
Check 'wrong installed payload rejected' $false
Write-BuildJson (Join-Path $OutputDirectory 'deployment-detection-tests.json') @{status='passed';checks=@($checks);nativeInstallationPerformed=$false;fixtures='synthetic service, listener and HTTP only'}
Write-Host ($checks.Count.ToString()+' deployment detection checks passed.')
