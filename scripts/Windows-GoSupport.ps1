#requires -Version 5.1
function Assert-WindowsBuildHost {
  if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or -not [Environment]::Is64BitOperatingSystem) { throw 'Windows x64 is required.' }
  $go = (Get-Command go.exe -ErrorAction Stop).Source
  $dotnet = (Get-Command dotnet.exe -ErrorAction Stop).Source
  $goVersion = (& $go version | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $goVersion -notmatch 'go1\.27\.\d+ windows/amd64') { throw 'Install the Windows x64 Go 1.27.x toolchain; automatic SDK download is disabled.' }
  $sdk = (& $dotnet --version | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $sdk -notmatch '^10\.0\.\d+$') { throw 'Install a .NET 10 SDK accepted by global.json. It is only used on the build host.' }
  return @{ Go=$go; Dotnet=$dotnet; GoVersion=$goVersion; DotnetVersion=$sdk }
}
function Invoke-CheckedNative([string]$Executable, [string[]]$Arguments) {
  & $Executable @Arguments | Out-Host
  if ($LASTEXITCODE -ne 0) { throw ('Build tool failed: ' + [IO.Path]::GetFileName($Executable)) }
}
function Write-BuildJson([string]$Path, $Value) {
  $text = ConvertTo-Json -InputObject $Value -Depth 12
  [IO.File]::WriteAllText($Path, $text + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}
function Get-Sha256([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Assert-GoPayload([string]$ServiceDirectory, [string]$ActionsDirectory) {
  $expected = @('Collect-Diagnostics.cmd','Sf.EndpointAI.Client.Service.exe','Uninstall-EndpointAI.cmd')
  $actual = @(Get-ChildItem -LiteralPath $ServiceDirectory -File | ForEach-Object { $_.Name } | Sort-Object)
  if (($actual -join ',') -ne (($expected | Sort-Object) -join ',')) { throw 'Unexpected service payload; only the Go executable and two maintenance commands are allowed.' }
  $actions = @(Get-ChildItem -LiteralPath $ActionsDirectory -File)
  if ($actions.Count -ne 1 -or $actions[0].Name -ne 'Sf.EndpointAI.InstallerActions.exe') { throw 'Unexpected installer helper payload.' }
  Assert-WindowsGuiExecutable (Join-Path $ActionsDirectory 'Sf.EndpointAI.InstallerActions.exe')
}
function Assert-ClientCredentials([string]$Path) {
  try { $data = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json } catch { throw 'Credential JSON is unreadable; content withheld.' }
  if ((@($data.PSObject.Properties.Name | Sort-Object) -join ',') -ne 'clientToken,keyId,origin,policyHmacKey,transportKey') { throw 'Credential input must contain the existing five fields.' }
  $uri = $null
  if (-not [Uri]::TryCreate([string]$data.origin,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -ne 'http' -or $uri.UserInfo -ne '' -or $uri.Query -ne '' -or $uri.Fragment -ne '' -or ($uri.AbsolutePath -ne '/' -and $uri.AbsolutePath -ne '') -or $data.origin -match '[\r\n\t #?]') { throw 'Credential origin must be the existing encrypted-transport HTTP origin without path, userinfo, query or fragment.' }
  if ($data.keyId -notmatch '^[A-Za-z0-9_-]{1,64}$' -or $data.clientToken -notmatch '^[A-Za-z0-9_-]{16,}$') { throw 'Invalid client credential identifiers; values withheld.' }
  try {
    if ([Convert]::FromBase64String($data.transportKey).Length -ne 32 -or [Convert]::FromBase64String($data.policyHmacKey).Length -lt 32) { throw 'length' }
  } catch { throw 'Invalid client key encoding or length; values withheld.' }
}
function Protect-BuildPath([string]$Path) {
  $current = [IO.Path]::GetFullPath($Path)
  while ($true) {
    if (Test-Path -LiteralPath $current) {
      if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Build path contains a reparse point.' }
    }
    $parent = [IO.Path]::GetDirectoryName($current)
    if ([string]::IsNullOrEmpty($parent) -or $parent -eq $current) { break }
    $current = $parent
  }
  Set-PrivateBuildDirectory $Path
}

function Get-MsiProductVersion([string]$Path) {
 $installer=New-Object -ComObject WindowsInstaller.Installer
 $database=$installer.OpenDatabase([IO.Path]::GetFullPath($Path),0)
 try {
  $view=$database.OpenView('SELECT `Value` FROM `Property` WHERE `Property`=''ProductVersion''')
  try {$view.Execute();$record=$view.Fetch();if($null -eq $record){throw 'MSI version missing.'};return $record.StringData(1)}finally{$view.Close()}
 } finally {[Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)|Out-Null;[Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)|Out-Null}
}
