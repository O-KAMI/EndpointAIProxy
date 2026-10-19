#requires -Version 5.1
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$MsiFile,
 [ValidateSet('Upgrade','Reinstall')][string]$Mode='Upgrade',
 [string]$RollbackMsi,
 [string]$MigrationHelper,
 [string]$OutputDirectory
)
$ErrorActionPreference='Stop'
. "$PSScriptRoot/Installer-BuildSupport.ps1"
. "$PSScriptRoot/Windows-GoSupport.ps1"
$stage='preflight';$exitCode=1;$old=$null;$transaction=$null;$uninstalled=$false;$installedNew=$false
function Read-Package([string]$Path) {
 $Path=[IO.Path]::GetFullPath($Path)
 if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'MSI missing.' }
 $installer=New-Object -ComObject WindowsInstaller.Installer
 $db=$installer.OpenDatabase($Path,0)
 try {
  $result=@{Path=$Path}
  foreach($name in @('ProductCode','ProductVersion','UpgradeCode')) {
   $view=$db.OpenView(('SELECT `Value` FROM `Property` WHERE `Property`='''+$name+''''));$view.Execute();$row=$view.Fetch()
   if($null -eq $row){throw 'MSI identity missing.'};$result[$name]=$row.StringData(1);$view.Close()
  }
  if($result.UpgradeCode.ToUpperInvariant() -ne '{643CFDA1-3A12-4C57-BD65-5F6106CBAB90}') { throw 'Unrelated MSI product.' }
  if($db.SummaryInformation(0).Property(7) -notlike 'x64;*'){throw 'Unsupported MSI architecture.'}
  $result.Sha256=Get-Sha256 $Path
  return $result
 } finally { [Runtime.InteropServices.Marshal]::FinalReleaseComObject($db)|Out-Null;[Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)|Out-Null }
}
function Invoke-Msi([string]$Verb,[string]$Package,[string]$LogName) {
 $log=Join-Path $OutputDirectory $LogName
 $process=Start-Process "$env:WINDIR\System32\msiexec.exe" -ArgumentList @($Verb,('"'+$Package+'"'),'/qn','/norestart','/L*v',('"'+$log+'"')) -Wait -PassThru
 return $process.ExitCode
}
function Invoke-Migration([string]$Action) {
 $args=@('--mode',$Action,'--install-dir',('"'+$installRoot+'"'),'--data-dir',('"'+$dataRoot+'"'),'--transaction',$transaction)
 $process=Start-Process -FilePath $MigrationHelper -ArgumentList $args -Wait -PassThru
 if($process.ExitCode -ne 0){throw ('Migration step failed: '+$Action)}
}
try {
 if([Environment]::OSVersion.Platform -ne 'Win32NT' -or -not [Environment]::Is64BitProcess){throw 'Windows x64 PowerShell required.'}
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 if(-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator or SYSTEM required.'}
 $new=Read-Package $MsiFile
 if(-not $OutputDirectory){$OutputDirectory=Join-Path $env:ProgramData ('SF\EndpointAIProxy\InstallerLogs\upgrade-'+[Guid]::NewGuid().ToString('N'))}
 $OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory);Protect-BuildPath $OutputDirectory
 $checksum=$new.Path+'.sha256'
 if(-not (Test-Path -LiteralPath $checksum)){throw 'New MSI checksum file required.'}
 if(([IO.File]::ReadAllText($checksum).Trim().Split()[0]).ToLowerInvariant() -ne $new.Sha256){throw 'New MSI checksum mismatch.'}
 $installer=New-Object -ComObject WindowsInstaller.Installer
 try {
  $related=@($installer.RelatedProducts($new.UpgradeCode))
  if($related.Count -gt 1){throw 'Multiple related products require recovery.'}
  if($related.Count -eq 1){$code=[string]$related[0];$old=@{ProductCode=$code;Version=$installer.ProductInfo($code,'VersionString');Location=$installer.ProductInfo($code,'InstallLocation')}}
 } finally {[Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)|Out-Null}
 if($old -and [version]$old.Version -gt [version]$new.ProductVersion){throw 'Downgrade refused.'}
 if($old -and [version]$old.Version -eq [version]$new.ProductVersion -and $old.ProductCode -ne $new.ProductCode){throw 'Same version different package refused.'}
 $stage='upgrade'
 if($Mode -eq 'Upgrade'){
  # No failure here ever causes an uninstall. MSI owns the upgrade transaction.
  $verb=if($old -and $old.ProductCode -eq $new.ProductCode){'/fa'}else{'/i'}
  $exitCode=Invoke-Msi $verb $new.Path 'upgrade-private.log'
 } else {
  $stage='reinstall-preflight'
  $resumePath=Join-Path $OutputDirectory 'reinstall-resume.json'
  $resume=$null
  if(Test-Path -LiteralPath $resumePath){
   if((Get-Item -LiteralPath $resumePath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Unsafe resume record.'}
   $resume=Get-Content -LiteralPath $resumePath -Raw | ConvertFrom-Json
   if($resume.newSha256 -ne $new.Sha256 -or $resume.phase -notin @('uninstalled-reboot-required','installed-reboot-required')){throw 'Resume state does not match package.'}
   if($resume.phase -eq 'uninstalled-reboot-required' -and $old){throw 'Unexpected installed product during resume.'}
   if($resume.phase -eq 'installed-reboot-required' -and (-not $old -or $old.ProductCode -ne $new.ProductCode)){throw 'New package registration missing during resume.'}
   if($resume.dataRoot -ne (Join-Path $env:ProgramData 'SF\EndpointAIProxy')){throw 'Invalid resume data root.'}
   $old=@{ProductCode=$resume.oldCode;Version=$resume.oldVersion}
  }
  if(-not $old -or -not $RollbackMsi){throw 'Recognized product and original rollback MSI required.'}
  if($old.Version -notin @('0.1.20','0.1.21','0.1.22','0.2.0','0.2.1')){throw 'Unverified source version; automatic uninstall refused.'}
  $restore=Read-Package $RollbackMsi
  if($restore.ProductCode -ne $old.ProductCode -or $restore.ProductVersion -ne $old.Version){throw 'Rollback package does not match installed product.'}
  if(-not $MigrationHelper){$MigrationHelper=Join-Path (Split-Path $new.Path -Parent) 'MigrationHelper.exe'}
  $helperChecksum=$MigrationHelper+'.sha256'
  if(-not (Test-Path -LiteralPath $helperChecksum) -or ([IO.File]::ReadAllText($helperChecksum).Trim().Split()[0]).ToLowerInvariant() -ne (Get-Sha256 $MigrationHelper)){throw 'Migration helper missing or checksum mismatch.'}
  if($resume){
   if($restore.Sha256 -ne $resume.rollbackSha256){throw 'Rollback package changed since uninstall.'}
   $installRoot=$resume.installRoot;$dataRoot=$resume.dataRoot;$transaction=$resume.transaction;$uninstalled=$true
   if($resume.phase -eq 'installed-reboot-required'){
    $installedNew=$true;Invoke-Migration 'verify-state'
    $health=Invoke-RestMethod 'http://127.0.0.1:18080/healthz' -TimeoutSec 10 -UseBasicParsing
    if($health.status -ne 'ok' -or $health.clientVersion -ne $new.ProductVersion -or $health.implementation -ne 'go' -or $health.installationPending -eq $true){throw 'Resumed installation not ready.'}
    Write-BuildJson (Join-Path $OutputDirectory 'upgrade-report.json') @{status='passed';mode=$Mode;version=$new.ProductVersion;msiExitCode=0;resumed=$true;transaction=$transaction}
    Remove-Item -LiteralPath $resumePath -Force
    exit 0
   }
  } else {
  $service=Get-CimInstance Win32_Service -Filter "Name='SfEndpointAIProxy'"
  if($null -eq $service){throw 'Installed service missing; recovery required.'}
  $match=[regex]::Match($service.PathName,'^(?:"([^"]+\.exe)"|(.+?\.exe))(?:\s|$)')
  if(-not $match.Success){throw 'Invalid service image path.'}
  $image=if($match.Groups[1].Success){$match.Groups[1].Value}else{$match.Groups[2].Value}
  if([IO.Path]::GetFileName($image) -ne 'Sf.EndpointAI.Client.Service.exe'){throw 'Unrecognized service image.'}
  $installRoot=Split-Path $image -Parent;$dataRoot=Join-Path $env:ProgramData 'SF\EndpointAIProxy'
  $transaction=[Guid]::NewGuid().ToString('B')
  foreach($action in @('preflight','snapshot','quiesce')){Invoke-Migration $action}
  $stage='uninstall-old';$exitCode=Invoke-Msi '/x' $old.ProductCode 'uninstall-private.log'
  if($exitCode -eq 3010){
    Write-BuildJson (Join-Path $OutputDirectory 'reinstall-resume.json') @{transaction=$transaction;installRoot=$installRoot;dataRoot=$dataRoot;newSha256=$new.Sha256;oldCode=$old.ProductCode;oldVersion=$old.Version;rollbackSha256=$restore.Sha256;phase='uninstalled-reboot-required'}
    Write-BuildJson (Join-Path $OutputDirectory 'upgrade-report.json') @{status='reboot-required';stage=$stage;msiExitCode=3010;transaction=$transaction;resume='Run the same Reinstall command with the same OutputDirectory after reboot.'}
    exit 3010
   }
  if($exitCode -ne 0){throw 'Old uninstall failed; new installation was not attempted.'}
  $uninstalled=$true
  }
  $stage='restore-state-before-install';Invoke-Migration 'restore-state'
  $stage='install-new';$exitCode=Invoke-Msi '/i' $new.Path 'install-private.log'
  if($exitCode -notin @(0,3010)){throw 'New installation failed.'}
  $installedNew=$true
  if($exitCode -eq 3010){Write-BuildJson $resumePath @{transaction=$transaction;installRoot=$installRoot;dataRoot=$dataRoot;newSha256=$new.Sha256;oldCode=$old.ProductCode;oldVersion=$old.Version;rollbackSha256=$restore.Sha256;phase='installed-reboot-required'}}
  if($exitCode -eq 0){Invoke-Migration 'verify-state';if(Test-Path -LiteralPath $resumePath){Remove-Item -LiteralPath $resumePath -Force}}
 }
 if($exitCode -notin @(0,3010)){throw 'MSI failed; protected raw log retained.'}
 if($exitCode -eq 0){
  $stage='verify-new-service';$health=Invoke-RestMethod 'http://127.0.0.1:18080/healthz' -TimeoutSec 10 -UseBasicParsing
  if($health.status -ne 'ok' -or $health.implementation -ne 'go' -or $health.installationPending -eq $true -or $health.clientVersion -ne $new.ProductVersion){throw 'Installed version not ready.'}
 }
 Write-BuildJson (Join-Path $OutputDirectory 'upgrade-report.json') @{status=if($exitCode -eq 3010){'reboot-required'}else{'passed'};mode=$Mode;version=$new.ProductVersion;msiSha256=$new.Sha256;msiExitCode=$exitCode;transaction=$transaction;productionAcceptance='pending';stateRecoveryEvidenceRetained=($null -ne $transaction)}
} catch {
 $recovery='not-required-or-not-started'
 if($installedNew){
  # After MSI commit, normal control/configuration activity may have resumed.
  # Never replace that state with an old snapshot on an outer health failure.
  $recovery='candidate-committed-recovery-required'
 } elseif($uninstalled -and $RollbackMsi){
  $recovery='required'
  try {
   Invoke-Migration 'restore-state'
   $rollbackExit=Invoke-Msi '/i' $restore.Path 'rollback-private.log'
   if($rollbackExit -eq 0){Invoke-Migration 'verify-state';$recovery='old-package-restored-needs-native-verification'}elseif($rollbackExit -eq 3010){$recovery='reboot-required'}
  } catch {$recovery='required'}
 }
 if(-not $uninstalled -and $transaction){
  try {Invoke-Migration 'rollback';$recovery='old-service-restored'}catch{$recovery='required'}
 }
 if($OutputDirectory -and (Test-Path -LiteralPath $OutputDirectory)){Write-BuildJson (Join-Path $OutputDirectory 'upgrade-report.json') @{status='failed';stage=$stage;mode=$Mode;msiExitCode=$exitCode;recovery=$recovery;transaction=$transaction;errorType=$_.Exception.GetType().Name}}
 [Console]::Error.WriteLine(('Upgrade failed at '+$stage+'; recovery evidence and raw logs remain protected.'))
 if($exitCode -eq 0){$exitCode=1}
}
exit $exitCode
