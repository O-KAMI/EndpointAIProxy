#requires -Version 5.1
[CmdletBinding()]
param(
  [string]$CredentialsFile,
  [ValidatePattern('^\d+\.\d+\.\d+$')][string]$ProductVersion = '0.2.2',
  [string]$OutputDirectory,
  [ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$SigningCertificateThumbprint,
  [string]$SignToolPath,
  [string]$TimestampUrl
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. "$PSScriptRoot/Installer-BuildSupport.ps1"
. "$PSScriptRoot/Windows-GoSupport.ps1"
$stage = 'preflight'
$temporary = $null
$oldEnvironment = @{}
$savedLocation = Get-Location
try {
  Set-Location -LiteralPath $root
  if ([string]::IsNullOrWhiteSpace($CredentialsFile)) { $CredentialsFile = Read-Host 'Path to the external client-credentials.json (never enter credential values here)' }
  $CredentialsFile = [IO.Path]::GetFullPath($CredentialsFile.Trim().Trim('"'))
  if (-not (Test-Path -LiteralPath $CredentialsFile -PathType Leaf)) { throw 'External credential file not found.' }
  Assert-ClientCredentials $CredentialsFile
  if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path $root 'artifacts/private-windows-go' }
  $OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
  Protect-BuildPath $OutputDirectory
  $reportPath = Join-Path $OutputDirectory 'build-report.json'
  foreach ($name in @('GOTOOLCHAIN','CGO_ENABLED','GOOS','GOARCH','GOFLAGS')) { $oldEnvironment[$name] = [Environment]::GetEnvironmentVariable($name,'Process') }
  $env:GOTOOLCHAIN='local'; $env:CGO_ENABLED='0'; $env:GOOS='windows'; $env:GOARCH='amd64'; $env:GOFLAGS=''
  $hostTools = Assert-WindowsBuildHost
  if ($SigningCertificateThumbprint) {
    $certificate = Get-Item -LiteralPath ("Cert:\CurrentUser\My\" + $SigningCertificateThumbprint) -ErrorAction SilentlyContinue
    if ($null -eq $certificate -or -not $certificate.HasPrivateKey) { throw 'Signing certificate with private key is required in CurrentUser\My.' }
    if (-not (Test-Path -LiteralPath $SignToolPath -PathType Leaf)) { throw 'Supply -SignToolPath when signing.' }
    $SignToolPath = [IO.Path]::GetFullPath($SignToolPath)
    $timestamp = $null
    if (-not [Uri]::TryCreate($TimestampUrl,[UriKind]::Absolute,[ref]$timestamp) -or $timestamp.Scheme -ne 'https') { throw 'Supply an HTTPS -TimestampUrl when signing.' }
  } elseif ($SignToolPath -or $TimestampUrl) { throw 'Signing requires all three signing parameters.' }
  $temporary = Join-Path $OutputDirectory ('stage-' + [Guid]::NewGuid().ToString('N'))
  Protect-BuildPath $temporary
  $inputDir=Join-Path $temporary 'input'; $publish=Join-Path $temporary 'service'; $actions=Join-Path $temporary 'actions'; $msiOutput=Join-Path $temporary 'msi'
  foreach ($path in @($inputDir,$publish,$actions,$msiOutput)) { Protect-BuildPath $path }
  Copy-Item -LiteralPath $CredentialsFile -Destination (Join-Path $inputDir 'client-credentials.json')
  $guard = @'
[CmdletBinding()]
param([string]$CredentialsFile, [switch]$SkipServiceRestart)
[Console]::Error.WriteLine('Use the Go MSI through IOA. Configuration and rollback are managed by the windowless installer helper.')
exit 1603
'@
  [IO.File]::WriteAllText((Join-Path $inputDir 'Set-ProductionClientControl.ps1'),$guard,[Text.UTF8Encoding]::new($false))
  Set-Location -LiteralPath (Join-Path $root 'go-client')
  $moduleMode = if (Test-Path -LiteralPath 'vendor/modules.txt') { '-mod=vendor' } else { '-mod=readonly' }
  $stage = 'go-tests'
  Invoke-CheckedNative $hostTools.Go @('test',$moduleMode,'./...')
  Invoke-CheckedNative $hostTools.Go @('vet',$moduleMode,'./...')
  $stage = 'go-payload'
  Invoke-CheckedNative $hostTools.Go @('build',$moduleMode,'-trimpath','-ldflags',("-s -w -X main.version=" + $ProductVersion),'-o',(Join-Path $publish 'Sf.EndpointAI.Client.Service.exe'),'./cmd/endpointai')
  Invoke-CheckedNative $hostTools.Go @('build',$moduleMode,'-trimpath','-ldflags',("-s -w -H=windowsgui -X main.version=" + $ProductVersion),'-o',(Join-Path $actions 'Sf.EndpointAI.InstallerActions.exe'),'./cmd/installer-actions')
  foreach ($name in @('Collect-Diagnostics.cmd','Uninstall-EndpointAI.cmd')) { Copy-Item -LiteralPath (Join-Path "$root/installer/Sf.EndpointAI.Setup" $name) -Destination $publish }
  Assert-GoPayload $publish $actions
  foreach ($path in @((Join-Path $publish 'Sf.EndpointAI.Client.Service.exe'),(Join-Path $actions 'Sf.EndpointAI.InstallerActions.exe'))) {
    $buildInfo = (& $hostTools.Go version -m $path | Out-String)
    if ($LASTEXITCODE -ne 0 -or $buildInfo -notmatch 'endpointai/client/cmd/(endpointai|installer-actions)') { throw 'The service and helper must contain Go build metadata for this module.' }
  }
  $signatureStatus = 'unsigned-test-candidate'
  if ($SigningCertificateThumbprint) {
    $stage = 'sign-payload'
    foreach ($exe in @((Join-Path $publish 'Sf.EndpointAI.Client.Service.exe'),(Join-Path $actions 'Sf.EndpointAI.InstallerActions.exe'))) {
      Invoke-CheckedNative $SignToolPath @('sign','/sha1',$SigningCertificateThumbprint,'/fd','SHA256','/tr',$TimestampUrl,'/td','SHA256',$exe)
      Invoke-CheckedNative $SignToolPath @('verify','/pa',$exe)
    }
    $signatureStatus='authenticode-signed'
  }
  $payload = @()
  foreach ($path in @((Join-Path $publish 'Sf.EndpointAI.Client.Service.exe'),(Join-Path $actions 'Sf.EndpointAI.InstallerActions.exe'))) { $payload += @{ name=[IO.Path]::GetFileName($path); sha256=(Get-Sha256 $path); bytes=(Get-Item -LiteralPath $path).Length } }
  Set-Location -LiteralPath $root
  $stage = 'wix-msi'
  $project = Join-Path $root 'installer/Sf.EndpointAI.Go.Setup/Sf.EndpointAI.Go.Setup.wixproj'
  Invoke-CheckedNative $hostTools.Dotnet @('build',$project,'-c','Release',"-p:ProductVersion=$ProductVersion","-p:ProductionInputDir=$inputDir","-p:ServicePublishDir=$publish","-p:InstallerActionsDir=$actions","-p:OutputPath=$msiOutput/","-p:IntermediateOutputPath=$temporary/obj/")
  $name = "EndpointAIDLP-Client-$ProductVersion-go-win-x64.msi"
  $msi = Join-Path $msiOutput $name
  $stage = 'validate-msi'
  & "$PSScriptRoot/Validate-MSI.ps1" -MsiFile $msi -ProductVersion $ProductVersion -ReportPath (Join-Path $temporary 'msi-validation.json')
  if ($SigningCertificateThumbprint) {
    $stage = 'sign-msi'
    Invoke-CheckedNative $SignToolPath @('sign','/sha1',$SigningCertificateThumbprint,'/fd','SHA256','/tr',$TimestampUrl,'/td','SHA256',$msi)
    Invoke-CheckedNative $SignToolPath @('verify','/pa',$msi)
  }
  $target = Join-Path $OutputDirectory $name
  if (Test-Path -LiteralPath $target) { throw 'Output MSI already exists; choose a new output directory to preserve earlier candidates.' }
  Copy-Item -LiteralPath $msi -Destination $target
  $upgradeScripts=Join-Path $OutputDirectory 'scripts'
  Protect-BuildPath $upgradeScripts
  Copy-Item -LiteralPath "$root/Upgrade-Client.cmd" -Destination $OutputDirectory
  foreach($script in @('Upgrade-Client.ps1','Windows-GoSupport.ps1','Installer-BuildSupport.ps1')){Copy-Item -LiteralPath (Join-Path $PSScriptRoot $script) -Destination $upgradeScripts}
  $migrationBinary=Join-Path $OutputDirectory 'MigrationHelper.exe'
  Copy-Item -LiteralPath (Join-Path $actions 'Sf.EndpointAI.InstallerActions.exe') -Destination $migrationBinary
  [IO.File]::WriteAllText(($migrationBinary+'.sha256'),((Get-Sha256 $migrationBinary)+'  MigrationHelper.exe'+[Environment]::NewLine),[Text.UTF8Encoding]::new($false))
  $digest = Get-Sha256 $target
  [IO.File]::WriteAllText("$target.sha256", "$digest  $name" + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
  Copy-Item -LiteralPath (Join-Path $temporary 'msi-validation.json') -Destination (Join-Path $OutputDirectory 'msi-validation.json') -Force
  Copy-Item -LiteralPath "$PSScriptRoot/Collect-InstallerLogs.ps1" -Destination $OutputDirectory -Force
  Copy-Item -LiteralPath "$root/docs/WINDOWS-GO-DELIVERY.md" -Destination $OutputDirectory -Force
  Write-BuildJson (Join-Path $OutputDirectory 'manifest.json') @{ productVersion=$ProductVersion; implementation='go'; architecture='windows-amd64'; signature=$signatureStatus; builtUtc=[DateTime]::UtcNow.ToString('o'); toolchain=$hostTools; moduleMode=$moduleMode; goModSha256=(Get-Sha256 "$root/go-client/go.mod"); goSumSha256=(Get-Sha256 "$root/go-client/go.sum"); payload=$payload; msi=@{ name=$name; sha256=$digest; bytes=(Get-Item -LiteralPath $target).Length }; installCommand="msiexec.exe /i `"$name`" /qn /norestart"; installed=$false; nativeLifecycleAcceptance='pending'; soakHoursRequired=4 }
  Write-BuildJson $reportPath @{ status='passed'; checks=@('go test','go vet','x64 GUI helper','MSI metadata and transaction sequence','Go-only MSI payload'); signature=$signatureStatus; installationPerformed=$false; nativeLifecycleAcceptance='pending'; ioaAcceptance='pending' }
  Write-Host "Candidate MSI: $target"
  Write-Host "Signature: $signatureStatus. No installation was performed."
} catch {
  if ($reportPath) { Write-BuildJson $reportPath @{ status='failed'; stage=$stage; errorType=$_.Exception.GetType().Name; installationPerformed=$false } }
  [Console]::Error.WriteLine(('Windows Go build failed at ' + $stage + '. Credential values and raw exceptions are withheld.'))
  $hints=@{ preflight='Check the external credential path/format, Windows x64, Go 1.27.x, .NET 10 SDK and complete signing arguments.'; 'go-tests'='Inspect the test/vet output above; no installation was attempted.'; 'go-payload'='Inspect the Go compilation output above.'; 'wix-msi'='Check .NET SDK and first-build NuGet access for WiX 6.0.2.'; 'validate-msi'='Inspect MSI metadata and ensure a fresh output directory is selected.'; 'sign-payload'='Check the CurrentUser signing certificate/private key, SignTool and timestamp access.'; 'sign-msi'='Check SignTool verification and timestamp access; unsigned fallback is disabled.' }
  if ($hints.ContainsKey($stage)) { [Console]::Error.WriteLine($hints[$stage]) }
  exit 1
} finally {
  Set-Location -LiteralPath $savedLocation.Path
  foreach ($name in $oldEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name,$oldEnvironment[$name],'Process') }
  if ($temporary -and (Test-Path -LiteralPath $temporary)) { Remove-Item -LiteralPath $temporary -Recurse -Force }
}
