function Set-PrivateBuildDirectory([string]$Path) {
  $directory = [IO.Directory]::CreateDirectory($Path)
  if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point not allowed in private build output.' }
  $desired = [Security.AccessControl.DirectorySecurity]::new()
  $desired.SetAccessRuleProtection($true,$false)
  $sids = @('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value) | Select-Object -Unique
  foreach ($sid in $sids) {
    $desired.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
  }
  $section = [Security.AccessControl.AccessControlSections]::Access
  $current = Get-Acl -LiteralPath $Path
  if ($current.GetSecurityDescriptorSddlForm($section) -ne $desired.GetSecurityDescriptorSddlForm($section)) {
    # Constructed descriptor only has modified DACL. Set-Acl is deliberately not used:
    # it can try to persist extra sections from the original descriptor.
    $directory.SetAccessControl($desired)
  }
  $actual = Get-Acl -LiteralPath $Path
  if ($actual.GetSecurityDescriptorSddlForm($section) -ne $desired.GetSecurityDescriptorSddlForm($section)) { throw 'Private directory DACL validation failed.' }
}

function Assert-WindowsGuiExecutable([string]$Path) {
  $bytes = [IO.File]::ReadAllBytes($Path)
  $pe = [BitConverter]::ToInt32($bytes,0x3c)
  if ([BitConverter]::ToUInt32($bytes,$pe) -ne 0x4550 -or [BitConverter]::ToUInt16($bytes,$pe+4) -ne 0x8664 -or [BitConverter]::ToUInt16($bytes,$pe+24+68) -ne 2) {
    throw 'Installer helper must be a Windows x64 GUI-subsystem executable.'
  }
}

function Assert-ProductionMsi([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'Expected MSI output missing.' }
  $installer = New-Object -ComObject WindowsInstaller.Installer
  $database = $installer.OpenDatabase($Path,0)
  function Read-Cell([string]$Sql) {
    $view = $database.OpenView($Sql)
    try {
      $view.Execute()
      $record = $view.Fetch()
      if ($null -eq $record) { throw 'MSI metadata row missing.' }
      return $record.StringData(1)
    } finally { $view.Close() }
  }
  try {
    if ((Read-Cell "SELECT ``Value`` FROM ``Property`` WHERE ``Property``='ProductVersion'") -ne '0.1.22') { throw 'MSI version mismatch.' }
    if ((Read-Cell "SELECT ``Value`` FROM ``Property`` WHERE ``Property``='MsiLogging'") -ne 'voicewarmup!') { throw 'MSI automatic logging missing.' }
    if ((Read-Cell "SELECT ``Value`` FROM ``Property`` WHERE ``Property``='UpgradeCode'").ToUpperInvariant() -ne '{643CFDA1-3A12-4C57-BD65-5F6106CBAB90}') { throw 'MSI upgrade code mismatch.' }
    if ($database.SummaryInformation(0).Property(7) -notlike 'x64;*') { throw 'MSI architecture mismatch.' }
    $sequence = @{}
    foreach ($name in @('PreflightLegacy','InstallValidate','SnapshotConfiguration','InstallInitialize','RollbackConfiguration','QuiesceLegacy','RemoveExistingProducts','InstallServices','ProvisionProductionControl','StartServices','VerifyInstalledService','CommitConfiguration')) {
      $sequence[$name] = [int](Read-Cell "SELECT ``Sequence`` FROM ``InstallExecuteSequence`` WHERE ``Action``='$name'")
    }
    $ordered = @('PreflightLegacy','InstallValidate','SnapshotConfiguration','InstallInitialize','RollbackConfiguration','QuiesceLegacy','RemoveExistingProducts','InstallServices','ProvisionProductionControl','StartServices','VerifyInstalledService','CommitConfiguration')
    for ($i=1; $i -lt $ordered.Count; $i++) {
      if ($sequence[$ordered[$i-1]] -ge $sequence[$ordered[$i]]) { throw "Invalid MSI action order: $($ordered[$i])." }
    }
    foreach ($pair in @(@('RollbackConfiguration',1280),@('ProvisionProductionControl',1024),@('CommitConfiguration',1536))) {
      $type = [int](Read-Cell "SELECT ``Type`` FROM ``CustomAction`` WHERE ``Action``='$($pair[0])'")
      if (($type -band 1792) -ne $pair[1] -or ($type -band 2048) -eq 0) { throw 'MSI transaction action flags mismatch.' }
    }
    if ((Read-Cell "SELECT ``Component_`` FROM ``File`` WHERE ``File``='ProductionCredentials'") -eq (Read-Cell "SELECT ``Component_`` FROM ``File`` WHERE ``File``='ProductionProvisionScript'")) { throw 'Credential and script must be separate components.' }
  } finally {
    [Runtime.InteropServices.Marshal]::FinalReleaseComObject($database) | Out-Null
    [Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) | Out-Null
  }
}
