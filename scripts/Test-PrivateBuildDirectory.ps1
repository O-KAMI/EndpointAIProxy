#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
. "$PSScriptRoot/Installer-BuildSupport.ps1"
. "$PSScriptRoot/Windows-GoSupport.ps1"
Protect-BuildPath $OutputDirectory
$actual=Get-Acl -LiteralPath $OutputDirectory
$desired=[Security.AccessControl.DirectorySecurity]::new()
$desired.SetAccessRuleProtection($true,$false)
foreach ($sid in @('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)) {
  $desired.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
}
if (-not (Test-PrivateBuildDacl $actual $desired)) { throw 'Native protected ACL rejected.' }
# Negative ACLs stay in memory; no broader permission is ever written to disk.
$broader=[Security.AccessControl.DirectorySecurity]::new()
$broader.SetSecurityDescriptorBinaryForm($actual.GetSecurityDescriptorBinaryForm())
$broader.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
if (Test-PrivateBuildDacl $broader $desired) { throw 'Broader ACL accepted.' }
$inheriting=[Security.AccessControl.DirectorySecurity]::new()
$inheriting.SetSecurityDescriptorBinaryForm($actual.GetSecurityDescriptorBinaryForm())
$inheriting.SetAccessRuleProtection($false,$true)
if (Test-PrivateBuildDacl $inheriting $desired) { throw 'Unprotected ACL accepted.' }
Write-BuildJson (Join-Path $OutputDirectory 'acl-test-report.json') @{ status='passed'; nativeProtectedDirectory=$true; broaderAclRejected=$true; inheritedAclRejected=$true; negativeFixtures='memory-only'; powershellVersion=$PSVersionTable.PSVersion.ToString() }
Write-Host 'Three private build ACL checks passed.'
