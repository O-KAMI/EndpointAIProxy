#requires -Version 5.1
function Assert-AcceptancePath([string]$Path) {
  if (-not [IO.Path]::IsPathRooted($Path)) { throw 'Acceptance paths must be absolute.' }
  $current=[IO.Path]::GetFullPath($Path)
  while ($current) {
    if ((Test-Path -LiteralPath $current) -and ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Acceptance paths cannot contain reparse points.' }
    $parent=[IO.Path]::GetDirectoryName($current)
    if ($parent -eq $current) { break }
    $current=$parent
  }
}

function Get-AcceptanceTarget([string]$TargetUserSid) {
  $caller=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  if (-not $TargetUserSid) {
    if ($caller -eq 'S-1-5-18') { throw 'SYSTEM must specify -TargetUserSid for the interactive test user.' }
    $TargetUserSid=$caller
  }
  if ($TargetUserSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw 'An interactive Windows user SID is required.' }
  $key='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\'+$TargetUserSid
  $profile=[Environment]::ExpandEnvironmentVariables((Get-ItemProperty -LiteralPath $key -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath)
  Assert-AcceptancePath $profile
  if (-not (Test-Path -LiteralPath $profile -PathType Container)) { throw 'Target user profile is missing.' }
  return @{ sid=$TargetUserSid; profile=[IO.Path]::GetFullPath($profile); callerSid=$caller }
}

# Unlike build output, acceptance evidence is shared by a fixed interactive user
# and SYSTEM. Never derive its DACL from the identity of the current phase.
function Protect-AcceptanceDirectory([string]$Path,[string]$TargetUserSid) {
  if ($TargetUserSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw 'Invalid acceptance owner SID.' }
  Assert-AcceptancePath $Path
  $directory=[IO.Directory]::CreateDirectory($Path)
  $desired=[Security.AccessControl.DirectorySecurity]::new()
  $desired.SetAccessRuleProtection($true,$false)
  foreach ($sid in @('S-1-5-18','S-1-5-32-544',$TargetUserSid)) {
    $desired.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
  }
  if (-not (Test-PrivateBuildDacl (Get-Acl -LiteralPath $Path) $desired)) {
    if ($PSVersionTable.PSEdition -eq 'Core') { [IO.FileSystemAclExtensions]::SetAccessControl($directory,$desired) }
    else { $directory.SetAccessControl($desired) }
  }
  if (-not (Test-PrivateBuildDacl (Get-Acl -LiteralPath $Path) $desired)) { throw 'Acceptance directory DACL validation failed.' }
}

function Assert-AcceptanceBaseline($Baseline,$Target,[string]$MsiSha256,[string]$ProductVersion) {
  if ($Baseline.schemaVersion -ne 2) { throw 'Use a new output directory and record a user-bound Prepare baseline.' }
  if ($Baseline.msiSha256 -ne $MsiSha256 -or $Baseline.productVersion -ne $ProductVersion) { throw 'Baseline belongs to another MSI.' }
  if ($Baseline.targetUserSid -ne $Target.sid -or $Baseline.targetProfile -ne $Target.profile) { throw 'Baseline target identity changed.' }
  Assert-AcceptancePath $Baseline.codexConfigPath
  if ([IO.Path]::GetFileName($Baseline.codexConfigPath) -ne 'config.toml') { throw 'Invalid target Codex configuration path.' }
}
