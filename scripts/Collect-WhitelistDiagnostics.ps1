# Compatible with Windows PowerShell 5.1; source baseline: c64b4c0e442a12eb72031801ea4d7aa4bfbb6c44.
[CmdletBinding()]
param(
  [ValidateRange(1,168)][int]$SinceHours = 72,
  [string]$DataRoot = (Join-Path $env:ProgramData 'SF\EndpointAIProxy'),
  [string]$ClientExe,
  [string]$TargetBaseUrl = 'http://claudecode.sf-express.com/ccr',
  [long]$ExpectedPolicyVersion = 3
)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Please run Windows PowerShell as Administrator.'
}
function Assert-NoReparse([string]$Path) {
  $item = Get-Item -LiteralPath $Path -ErrorAction Stop
  while ($null -ne $item) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point rejected.' }
    if ($item -is [IO.FileInfo]) { $item = $item.Directory } else { $item = $item.Parent }
  }
}
function Normalize-BaseUrl([string]$Value) {
  $uri = $null
  if (-not [Uri]::TryCreate($Value.Trim(), [UriKind]::Absolute, [ref]$uri) -or
      $uri.Scheme -notin @('http','https') -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or
      $Value.Contains('?') -or $Value.Contains('#')) { throw 'Invalid or sensitive Base URL.' }
  $builder = [UriBuilder]::new($uri)
  $builder.Host = $uri.IdnHost.ToLowerInvariant()
  $builder.Scheme = $uri.Scheme.ToLowerInvariant()
  if ($uri.IsDefaultPort) { $builder.Port = -1 }
  return $builder.Uri.AbsoluteUri.TrimEnd('/')
}
function Safe-Url([string]$Value) {
  try { Normalize-BaseUrl $Value } catch { '[REDACTED-OR-INVALID-URL]' }
}
function Write-Json($Value, [string]$Name) {
  $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $stage $Name) -Encoding UTF8
}
$target = Normalize-BaseUrl $TargetBaseUrl
$expectedRules = @('https://claudecode.sf-express.com/ccr','http://claudecode.sf-express.com/ccr','https://api.openai.com/v1','https://api.anthropic.com')
$service = Get-CimInstance Win32_Service -Filter "Name='SfEndpointAIProxy'" -ErrorAction Stop
if (-not $ClientExe) {
  if ($service -and $service.PathName -match '^\s*"([^"\r\n]+\.exe)"') { $ClientExe = $Matches[1] }
  elseif ($service -and $service.PathName -match '^\s*(\S+\.exe)(?:\s|$)') { $ClientExe = $Matches[1] }
  else { $ClientExe = Join-Path $env:ProgramFiles 'SF\Endpoint AI Proxy\Sf.EndpointAI.Client.Service.exe' }
}
$ClientExe = [IO.Path]::GetFullPath($ClientExe)
$DataRoot = [IO.Path]::GetFullPath($DataRoot)
Assert-NoReparse $ClientExe
Assert-NoReparse $DataRoot
if ([IO.Path]::GetFileName($ClientExe) -ne 'Sf.EndpointAI.Client.Service.exe') { throw 'Unexpected client executable.' }
$root = Join-Path $DataRoot 'WhitelistDiagnostics'
if (Test-Path -LiteralPath $root) { Assert-NoReparse $root }
[IO.Directory]::CreateDirectory($root) | Out-Null
Assert-NoReparse $root
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
}
(Get-Item -LiteralPath $root).SetAccessControl($acl)
$id = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N')
$stage = Join-Path $root $id
[IO.Directory]::CreateDirectory($stage) | Out-Null
$errors = [Collections.Generic.List[string]]::new()
$health = $null
$policy = $null
$rules = @()
$policyRead = $false
$healthRead = $false
$builtinExit = $null
try {
  Write-Host 'Collecting sanitized client evidence. No service restart or configuration change.'
  Write-Json ([ordered]@{
    collectedUtc=[DateTime]::UtcNow.ToString('o'); sourceCommit='c64b4c0e442a12eb72031801ea4d7aa4bfbb6c44'
    executableVersion=(Get-Item -LiteralPath $ClientExe).VersionInfo.FileVersion
    executableSha256=(Get-FileHash -LiteralPath $ClientExe -Algorithm SHA256).Hash
    serviceState=if ($service) { $service.State } else { 'NotInstalled' }
    servicePid=if ($service) { $service.ProcessId } else { $null }
    serviceAccount=if ($service) { $service.StartName } else { $null }
    targetBaseUrl=$target; expectedPolicyVersion=$ExpectedPolicyVersion; expectedRulesFromScreenshot=$expectedRules
  }) 'collection.json'
  try {
    $h = Invoke-RestMethod 'http://127.0.0.1:18080/healthz' -TimeoutSec 5 -UseBasicParsing
    if ($null -eq $h.policyVersion -or $null -eq $h.clientVersion) { throw 'Incomplete health fields.' }
    $health = [ordered]@{}
    foreach ($field in @('status','clientVersion','listenEndpoint','routeCount','routeMode','policyVersion','auditState','operationState','operationStateUpdatedAtUtc','lastErrorCode','deviceId','lastControlSyncAtUtc','lastControlErrorCode')) {
      $health[$field] = $h.$field
    }
    $healthRead = $true
    Write-Json $health 'health.json'
  } catch { $errors.Add('Health read failed: ' + $_.Exception.GetType().Name) }
  # Native Windows SQLite; open READONLY, query only the cached EndpointPolicy.
  # Never export the signature, database, registry credentials, or the raw policy JSON.
  try {
    if (-not ('WhitelistDiagnosticSqlite' -as [type])) {
      Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class WhitelistDiagnosticSqlite {
  [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)] static extern int sqlite3_open_v2(byte[] name, out IntPtr db, int flags, IntPtr vfs);
  [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)] static extern int sqlite3_close(IntPtr db);
  [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)] static extern int sqlite3_busy_timeout(IntPtr db, int ms);
  [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)] static extern int sqlite3_prepare_v2(IntPtr db, byte[] sql, int n, out IntPtr stmt, IntPtr tail);
  [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)] static extern int sqlite3_step(IntPtr stmt);
  [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)] static extern IntPtr sqlite3_column_text(IntPtr stmt, int col);
  [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)] static extern int sqlite3_column_bytes(IntPtr stmt, int col);
  [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)] static extern int sqlite3_finalize(IntPtr stmt);
  public static string[] Read(string path) {
    IntPtr db=IntPtr.Zero, stmt=IntPtr.Zero;
    try {
      int rc=sqlite3_open_v2(Encoding.UTF8.GetBytes(path+"\0"),out db,1,IntPtr.Zero);
      if(rc!=0) throw new Exception("SQLite open code "+rc);
      sqlite3_busy_timeout(db,3000);
      byte[] sql=Encoding.UTF8.GetBytes("SELECT policy_json,policy_version,received_at_utc FROM cached_policy WHERE singleton_id=1;\0");
      rc=sqlite3_prepare_v2(db,sql,-1,out stmt,IntPtr.Zero);
      if(rc!=0) throw new Exception("SQLite prepare code "+rc);
      rc=sqlite3_step(stmt);
      if(rc==101) return null;
      if(rc!=100) throw new Exception("SQLite step code "+rc);
      string[] result=new string[3];
      for(int i=0;i<3;i++) {
        IntPtr ptr=sqlite3_column_text(stmt,i); int size=sqlite3_column_bytes(stmt,i);
        if(size>1048576) throw new Exception("Policy exceeds diagnostic size bound");
        byte[] bytes=new byte[size]; if(size>0) Marshal.Copy(ptr,bytes,0,size);
        result[i]=Encoding.UTF8.GetString(bytes);
      }
      return result;
    } finally { if(stmt!=IntPtr.Zero) sqlite3_finalize(stmt); if(db!=IntPtr.Zero) sqlite3_close(db); }
  }
}
'@
    }
    $db = Join-Path $DataRoot 'state\client.db'
    Assert-NoReparse $db
    foreach ($suffix in @('-wal','-shm')) { if (Test-Path -LiteralPath ($db+$suffix)) { Assert-NoReparse ($db+$suffix) } }
    $row = [WhitelistDiagnosticSqlite]::Read($db)
    if ($null -eq $row) { throw 'No cached policy.' }
    $p = $row[0] | ConvertFrom-Json
    if ($null -eq $p.allowlistedBaseUrls) {
      $rules = @('https://claudecode.sf-express.com/ccr')
      $ruleSource = 'Legacy default: field missing or null'
    } else {
      $rules = @(foreach ($rule in $p.allowlistedBaseUrls) { Normalize-BaseUrl ([string]$rule) })
      $ruleSource = 'Cached policy explicit list (empty means no bypass)'
    }
    $policy = [ordered]@{
      cachedPolicyVersion=[long]$row[1]; receivedAtUtc=$row[2]
      schemaVersion=$p.schemaVersion; enabled=$p.enabled; routeMode=$p.routeMode
      gatewayOrigin=if ($p.gatewayOrigin) { Safe-Url ([string]$p.gatewayOrigin) } else { $null }
      allowInsecureGateway=$p.allowInsecureGateway; allowlistedBaseUrls=$rules; ruleSource=$ruleSource
      targetMatchesCachedPolicy=($rules -ccontains $target)
      missingScreenshotRules=@($expectedRules | Where-Object { $rules -cnotcontains $_ })
    }
    $policyRead = $true
    Write-Json $policy 'cached-policy-sanitized.json'
    $p=$null; $row=$null
  } catch { $errors.Add('Cached policy read failed: ' + $_.Exception.GetType().Name) }
  $builtin = Join-Path $stage 'client-bundle'
  [IO.Directory]::CreateDirectory($builtin) | Out-Null
  $fileVersion = (Get-Item -LiteralPath $ClientExe).VersionInfo.FileVersion
  if ($fileVersion -notmatch '^0\.1\.22(?:\.|$)') {
    $errors.Add('Built-in maintenance skipped: executable version is not the verified 0.1.22 baseline.')
  } else {
  $start = [Diagnostics.ProcessStartInfo]::new()
  $start.FileName = $ClientExe
  $start.UseShellExecute = $false
  $start.CreateNoWindow = $true
  $start.WorkingDirectory = Split-Path -Parent $ClientExe
  $start.EnvironmentVariables['SF_PROXY_DATA_ROOT'] = $DataRoot
  $start.Arguments = '--maintenance=collect-diagnostics --auto-attach=false --diagnostics-since-hours=' + $SinceHours + ' --diagnostics-output="' + $builtin + '"'
  $proc = [Diagnostics.Process]::Start($start)
  try {
    if (-not $proc.WaitForExit(150000)) {
      # Only terminate the maintenance process created here, never the running service.
      $proc.Kill(); $proc.WaitForExit(); $errors.Add('Client diagnostic maintenance timed out.')
    } else {
      $builtinExit = $proc.ExitCode
      if ($builtinExit -notin @(0,2)) { $errors.Add('Client diagnostics exit code: ' + $builtinExit) }
    }
  } finally { $proc.Dispose() }
  }
  if (-not @(Get-ChildItem -LiteralPath $builtin -Filter '*.zip' -File).Count) {
    $errors.Add('Built-in diagnostic ZIP was not produced.')
  }
  $match = if ($policyRead) { $rules -ccontains $target } else { $null }
  $versionMatches = if ($policyRead -and $healthRead) { [long]$health.policyVersion -eq [long]$policy.cachedPolicyVersion } else { $null }
  Write-Json ([ordered]@{
    cachedPolicyReadable=$policyRead; liveHealthReadable=$healthRead
    targetMatchesCachedPolicy=$match; cachedAndLiveVersionsMatch=$versionMatches
    expectedVersionApplied=if ($healthRead) { [long]$health.policyVersion -eq $ExpectedPolicyVersion } else { $null }
    builtinExitCode=$builtinExit; errors=@($errors.ToArray())
    caveats=@('Cached policy is not proof of successful config restoration. Compare live health, route status and CC Switch current provider.',
      'Built-in CCR_ALLOWLIST_DECISION_MISMATCH uses the legacy HTTPS default, not the custom allowlist. Retained historical routes alone do not prove active proxying.',
      '403 does not establish the failure origin. Correlate request ID, request timestamp and gateway evidence.',
      'Collection reads multiple live snapshots; a concurrent policy change can produce different versions. No authenticated model request is sent.')
  }) 'whitelist-assessment.json'
  @'
Read cached-policy-sanitized.json and health.json first. Expected console policy: v3.
Then inspect the nested client-bundle ZIP:
  configuration/profiles.json: Claude/CC Switch current and original addresses.
  routes/registry-sanitized.json: route status and original/injected Base URLs.
  state/client-runtime.json: identity, cached policy metadata, command receipts.
  service/operational-log.jsonl: policy sync, route reconciliation and restore errors.
  requests/recent-summary.jsonl: request IDs, 403 timing and routing results.
  summary.md / manifest.json: missing, partial or truncated evidence.
No raw configs/databases, credentials or request/response bodies are exported.
The package contains internal host/network/configuration metadata: share internally only.
The built-in collector performs bounded connectivity probes, not real model requests.
Do not infer current routing from an old failed request or a retained retired route alone.
'@ | Set-Content -LiteralPath (Join-Path $stage 'READ-FIRST.txt') -Encoding UTF8
  $zip = Join-Path $root ('EndpointAIDLP-whitelist-diagnostics-' + $id + '.zip')
  Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
  $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
  ($hash + '  ' + [IO.Path]::GetFileName($zip)) | Set-Content -LiteralPath ($zip+'.sha256') -Encoding ASCII
  Write-Host ('Diagnostic ZIP: ' + $zip)
  Write-Host ('SHA256: ' + $hash)
  if ($errors.Count) { Write-Warning 'Partial collection. See whitelist-assessment.json; missing evidence is not a healthy result.' }
} finally {
  # Keep only the final archive when it was successfully created; preserve partial evidence on failure.
  if ($zip -and (Test-Path -LiteralPath $zip)) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
