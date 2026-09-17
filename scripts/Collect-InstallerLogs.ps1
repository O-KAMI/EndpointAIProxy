[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
# Run elevated through IOA. Never read production credentials or installer rollback snapshots.
try {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevation required.' }
  $root = Join-Path $env:ProgramData 'SF\EndpointAIProxy\InstallerLogs'
  $dir = [IO.Directory]::CreateDirectory($root)
  $walk = $dir
  while ($null -ne $walk) {
    if ($walk.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point rejected.' }
    $walk = $walk.Parent
  }
  $acl = [Security.AccessControl.DirectorySecurity]::new()
  $acl.SetAccessRuleProtection($true,$false)
  foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
  }
  $dir.SetAccessControl($acl)
  $id = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmss') + '-' + [Guid]::NewGuid().ToString('N')
  $stage = Join-Path $root ("collect-" + $id)
  [IO.Directory]::CreateDirectory($stage) | Out-Null
  try {
    # Windows Installer chooses MSI*.log in the installer's temporary directory.
    # Run collection under the same elevated IOA identity used for installation.
    $tempRoots = @([IO.Path]::GetTempPath(), (Join-Path $env:WINDIR 'Temp')) | Select-Object -Unique
    $candidates = @(foreach ($tempRoot in $tempRoots) {
      if (-not (Test-Path -LiteralPath $tempRoot -PathType Container)) { continue }
      $walk = Get-Item -LiteralPath $tempRoot
      while ($null -ne $walk) {
        if ($walk.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Log directory reparse point rejected.' }
        $walk = $walk.Parent
      }
      Get-ChildItem -LiteralPath $tempRoot -Filter 'MSI*.log' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTimeUtc -ge [DateTime]::UtcNow.AddDays(-14) }
      $legacy = Join-Path $tempRoot 'EndpointAIDLP-0.1.22-install.log'
      if (Test-Path -LiteralPath $legacy -PathType Leaf) { Get-Item -LiteralPath $legacy }
    })
    $count = 0
    foreach ($candidate in ($candidates | Sort-Object FullName -Unique | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 200)) {
      if ($candidate.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
      $msi = $candidate.FullName
      # Do not export logs of other products; match our marker or original package name.
      if (-not (Select-String -LiteralPath $msi -Pattern 'EndpointAIDLPLogMarker\s*=\s*EndpointAIDLP-Windows-0\.1\.22\s*$', 'EndpointAIDLP-Client-0\.1\.22-win-x64\.msi' -Quiet -ErrorAction SilentlyContinue)) { continue }
      $count++
      # Keep action/rollback/error evidence. Exclude property dumps, command lines and
      # arbitrary custom-action output; a raw verbose log is deliberately not exported.
      $safe = Get-Content -LiteralPath $msi | Where-Object {
        $_ -match 'Action (start|ended)|Doing action:|Return value [0-9]|MainEngineThread is returning|Error (1[0-9]{3})|Rollback:' -and
        $_ -notmatch '(?i)token|password|secret|hmac|transportkey|credential|CustomActionData|PROPERTY CHANGE|CommandLine'
      } | ForEach-Object {
        $_ -replace '[A-Za-z0-9_+/=-]{32,}','[REDACTED]'
      }
      $safe | Set-Content -LiteralPath (Join-Path $stage ("msi-actions-redacted-" + $count + '.log')) -Encoding UTF8
      if ($count -ge 20) { break }
    }
    @{ matchedMsiLogs=$count; searchedCurrentIdentityTemp=$true; searchedWindowsTemp=$true; lookbackDays=14 } |
      ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stage 'msi-discovery.json') -Encoding UTF8
    $fields = @('timeUtc','version','mode','stage','outcome','identity','is64Bit','errorType','hresult','member','line')
    Get-ChildItem -LiteralPath $root -Filter 'install-*.jsonl' -File |
      Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 20 | ForEach-Object {
        if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Log reparse point rejected.' }
        $out = Join-Path $stage $_.Name
        foreach ($line in (Get-Content -LiteralPath $_.FullName)) {
          try {
            $entry = $line | ConvertFrom-Json
            $filtered = [ordered]@{}
            foreach ($field in $fields) {
              if ($null -ne $entry.PSObject.Properties[$field]) { $filtered[$field] = $entry.$field }
            }
            $filtered | ConvertTo-Json -Compress | Add-Content -LiteralPath $out -Encoding UTF8
          } catch { '{"outcome":"unreadable_log_entry"}' | Add-Content -LiteralPath $out -Encoding UTF8 }
        }
      }
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64')
    $key = $base.OpenSubKey('Software\SF\EndpointAIProxy')
    $version = if ($null -ne $key) { [string]$key.GetValue('DisplayVersion') } else { 'not-installed' }
    if ($version -notmatch '^[0-9.]+$') { $version = 'not-installed-or-unknown' }
    $service = Get-Service -Name 'SfEndpointAIProxy' -ErrorAction SilentlyContinue
    @{ version=$version; serviceStatus=if ($null -eq $service) {'not-installed'} else {$service.Status.ToString()}; collectedUtc=[DateTime]::UtcNow.ToString('o') } |
      ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stage 'status.json') -Encoding UTF8
    if ($null -ne $key) { $key.Dispose() }
    $base.Dispose()
    $zip = Join-Path $root ("EndpointAIDLP-install-diagnostics-" + $id + '.zip')
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
    Write-Output $zip
  } finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
  }
} catch {
  Write-Error ("Log collection failed: " + $_.Exception.GetType().Name) -ErrorAction Continue
  exit 1
}
