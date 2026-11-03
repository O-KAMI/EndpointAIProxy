#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$ScratchDirectory)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/Windows-GoSupport.ps1"
$key = [Convert]::ToBase64String((New-Object byte[] 32))
$short = [Convert]::ToBase64String((New-Object byte[] 31))
$cases = @(
  @{ Origin='http://example.test:8080'; Pin=$null; Valid=$true },
  @{ Origin='https://example.test'; Pin=$key; Valid=$true },
  @{ Origin='https://example.test'; Pin=$null; Valid=$false },
  @{ Origin='https://example.test'; Pin=$short; Valid=$false },
  @{ Origin='http://example.test'; Pin=$key; Valid=$false },
  @{ Origin='HTTPS://example.test'; Pin=$null; Valid=$false }
)
$i = 0
foreach ($case in $cases) {
  $data = @{ origin=$case.Origin; clientToken=('x' * 16); keyId='v1'; transportKey=$key; policyPublicKey=$key }
  if ($null -ne $case.Pin) { $data.certificateSpkiSha256 = $case.Pin }
  $path = Join-Path $ScratchDirectory ("synthetic-credential-{0}.json" -f $i)
  $data | ConvertTo-Json | Set-Content -LiteralPath $path -Encoding UTF8
  $accepted = $true
  try { Assert-ClientCredentials $path } catch { $accepted = $false }
  if ($accepted -ne $case.Valid) { throw "Credential validation failed for synthetic case $i" }
  $i++
}
Write-Output "$i synthetic credential cases passed"
