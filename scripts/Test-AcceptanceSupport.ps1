#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
. "$PSScriptRoot/Installer-BuildSupport.ps1"
. "$PSScriptRoot/Windows-GoSupport.ps1"
. "$PSScriptRoot/Acceptance-Support.ps1"
Protect-BuildPath $OutputDirectory
$checks=[Collections.Generic.List[string]]::new()
function Must-Reject([string]$Name,[scriptblock]$Action) {
  $rejected=$false
  try { & $Action } catch { $rejected=$true }
  if (-not $rejected) { throw ($Name+' was accepted.') }
  $checks.Add($Name)
}
$target=Get-AcceptanceTarget ''
if ($target.sid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) { throw 'Wrong interactive target.' }
$checks.Add('target resolved from registered SID')
Must-Reject 'SYSTEM SID rejected as target' { Get-AcceptanceTarget 'S-1-5-18' }
Must-Reject 'SID path injection rejected' { Get-AcceptanceTarget 'S-1-5-21-1-2-3-4\other' }
Must-Reject 'relative configuration path rejected' { Assert-AcceptancePath '.codex' }
$path=Join-Path $OutputDirectory 'fixed-user-evidence'
Protect-AcceptanceDirectory $path $target.sid
Protect-AcceptanceDirectory $path $target.sid
$acl=Get-Acl -LiteralPath $path
$sids=@($acl.Access | ForEach-Object {$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value} | Sort-Object)
$expected=@('S-1-5-18','S-1-5-32-544',$target.sid) | Sort-Object
if (-not $acl.AreAccessRulesProtected -or ($sids -join ',') -ne ($expected -join ',')) { throw 'Target user evidence ACL is incorrect.' }
$checks.Add('fixed target ACL preserved on repeated phases')
$config=Join-Path $target.profile '.codex\config.toml'
$baseline=@{schemaVersion=2; targetUserSid=$target.sid; targetProfile=$target.profile; codexConfigPath=$config; msiSha256=('a'*64); productVersion='0.2.4'}
Assert-AcceptanceBaseline $baseline $target ('a'*64) '0.2.4'
$checks.Add('matching user and MSI baseline accepted')
Must-Reject 'different MSI rejected' { Assert-AcceptanceBaseline $baseline $target ('b'*64) '0.2.4' }
Must-Reject 'different product version rejected' { Assert-AcceptanceBaseline $baseline $target ('a'*64) '0.2.3' }
$other=$target.Clone();$other.sid='S-1-5-21-1-2-3-1001'
Must-Reject 'different user rejected' { Assert-AcceptanceBaseline $baseline $other ('a'*64) '0.2.4' }
$other=$target.Clone();$other.profile=Join-Path $OutputDirectory 'other-profile'
Must-Reject 'changed registered profile rejected' { Assert-AcceptanceBaseline $baseline $other ('a'*64) '0.2.4' }
$old=$baseline.Clone();$old.schemaVersion=1
Must-Reject 'unbound legacy baseline rejected' { Assert-AcceptanceBaseline $old $target ('a'*64) '0.2.4' }
$old=$baseline.Clone();$old.codexConfigPath=Join-Path $target.profile 'auth.json'
Must-Reject 'nonconfiguration target rejected' { Assert-AcceptanceBaseline $old $target ('a'*64) '0.2.4' }
Write-BuildJson (Join-Path $OutputDirectory 'acceptance-support-tests.json') @{status='passed'; checks=@($checks); powershellVersion=$PSVersionTable.PSVersion.ToString(); installationPerformed=$false}
Write-Host ($checks.Count.ToString()+' acceptance identity, ACL and baseline checks passed.')
