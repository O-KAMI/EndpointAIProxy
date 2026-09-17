[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [Uri] $ControlOrigin,
    [Parameter(Mandatory)] [string] $ClientToken,
    [Parameter(Mandatory)] [string] $PolicyHmacKey,
    [Parameter(Mandatory)] [string] $ServerCertificateSpkiSha256,
    [string] $GatewayHmacKey,
    [switch] $SkipServiceRestart
)

$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $utf8
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8
chcp 65001 > $null

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this prototype provisioning script from an elevated PowerShell session.'
}
if (-not $ControlOrigin.IsAbsoluteUri -or -not [string]::IsNullOrEmpty($ControlOrigin.PathAndQuery.Trim('/'))) {
    throw 'ControlOrigin must be an absolute origin without a path or query.'
}
if ($ControlOrigin.Scheme -ne 'https') {
    throw 'ControlOrigin must use HTTPS.'
}
if ([Text.Encoding]::UTF8.GetByteCount($ClientToken) -lt 16) {
    throw 'ClientToken must contain at least 16 UTF-8 bytes.'
}

try {
    $policyKeyBytes = [Convert]::FromBase64String($PolicyHmacKey)
}
catch {
    throw 'PolicyHmacKey must be valid Base64.'
}
if ($policyKeyBytes.Length -lt 32) {
    throw 'PolicyHmacKey must decode to at least 32 bytes.'
}
try {
    $certificatePinBytes = [Convert]::FromBase64String($ServerCertificateSpkiSha256)
}
catch {
    throw 'ServerCertificateSpkiSha256 must be valid Base64.'
}
if ($certificatePinBytes.Length -ne 32) {
    throw 'ServerCertificateSpkiSha256 must decode to exactly 32 bytes.'
}
if (-not [string]::IsNullOrWhiteSpace($GatewayHmacKey)) {
    try { $gatewayKeyBytes = [Convert]::FromBase64String($GatewayHmacKey) }
    catch { throw 'GatewayHmacKey must be valid Base64.' }
    if ($gatewayKeyBytes.Length -lt 32) { throw 'GatewayHmacKey must decode to at least 32 bytes.' }
}

$serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SfEndpointAIProxy'
if (-not (Test-Path -LiteralPath $serviceKey)) {
    throw 'SfEndpointAIProxy is not installed.'
}

$entries = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
$existing = (Get-ItemProperty -LiteralPath $serviceKey -Name Environment -ErrorAction SilentlyContinue).Environment
foreach ($entry in @($existing)) {
    $separator = $entry.IndexOf('=')
    if ($separator -gt 0) { $entries[$entry.Substring(0, $separator)] = $entry.Substring($separator + 1) }
}
$entries['SF_PROXY_CONTROL_ORIGIN'] = $ControlOrigin.GetLeftPart([UriPartial]::Authority)
$entries['SF_PROXY_CONTROL_TOKEN'] = $ClientToken
$entries['SF_PROXY_CONTROL_HMAC_KEY'] = $PolicyHmacKey
$entries['SF_PROXY_CONTROL_SERVER_CERTIFICATE_SPKI_SHA256'] = $ServerCertificateSpkiSha256
$entries.Remove('SF_PROXY_ALLOW_INSECURE_CONTROL_SERVER') | Out-Null
if ([string]::IsNullOrWhiteSpace($GatewayHmacKey)) {
    $entries.Remove('SF_PROXY_GATEWAY_HMAC_KEY') | Out-Null
}
else {
    $entries['SF_PROXY_GATEWAY_HMAC_KEY'] = $GatewayHmacKey
}
$newValue = @($entries.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key)=$($_.Value)" })

if ($PSCmdlet.ShouldProcess('SfEndpointAIProxy service environment', 'Provision prototype control-plane settings')) {
    Set-ItemProperty -LiteralPath $serviceKey -Name Environment -Type MultiString -Value $newValue
    if (-not $SkipServiceRestart) {
        Restart-Service -Name SfEndpointAIProxy -Force
    }
}

[PSCustomObject]@{
    Service = 'SfEndpointAIProxy'
    ControlOrigin = $entries['SF_PROXY_CONTROL_ORIGIN']
    ServerCertificateSpkiSha256 = $entries['SF_PROXY_CONTROL_SERVER_CERTIFICATE_SPKI_SHA256']
    ServiceRestarted = -not $SkipServiceRestart
    SecretStorage = 'Prototype REG_MULTI_SZ; replace with machine certificate/DPAPI provisioning before production.'
}
