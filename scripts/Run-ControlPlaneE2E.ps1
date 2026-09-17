param(
    [Parameter()]
    [string] $DotnetRoot = $env:DOTNET_ROOT
)

function Wait-Endpoint {
    param(
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] [Diagnostics.Process] $Process,
        [Parameter(Mandatory)] [string] $Name
    )

    $lastError = $null
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        try {
            & curl.exe -k -sS --fail --max-time 2 $Uri 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                return
            }
            $lastError = "curl exit code $LASTEXITCODE"
        }
        catch {
            $lastError = $_.Exception.Message
            if ($Process.HasExited) {
                throw "$Name exited before becoming ready."
            }
            Start-Sleep -Milliseconds 500
        }
    }

    throw "$Name did not become ready. Last error: $lastError"
}

function Invoke-ControlRest {
    param(
        [Parameter(Mandatory)] [string] $Uri,
        [string] $Method = 'GET',
        [hashtable] $Headers = @{},
        [string] $ContentType,
        [string] $Body
    )

    $arguments = [Collections.Generic.List[string]]::new()
    foreach ($value in @('-k', '-s', '--fail-with-body', '--max-time', '10', '-X', $Method)) {
        $arguments.Add($value)
    }
    foreach ($header in $Headers.GetEnumerator()) {
        $arguments.Add('-H')
        $arguments.Add("$($header.Key): $($header.Value)")
    }
    if (-not [string]::IsNullOrWhiteSpace($ContentType)) {
        $arguments.Add('-H')
        $arguments.Add("Content-Type: $ContentType")
    }
    $bodyFile = $null
    if ($PSBoundParameters.ContainsKey('Body')) {
        $bodyFile = Join-Path $e2eRoot ("control-request-{0:N}.json" -f [Guid]::NewGuid())
        [IO.File]::WriteAllText($bodyFile, $Body, [Text.UTF8Encoding]::new($false))
        $arguments.Add('--data-binary')
        $arguments.Add("@$bodyFile")
    }
    $arguments.Add($Uri)

    try {
        $raw = (& curl.exe @arguments) -join [Environment]::NewLine
        if ($LASTEXITCODE -ne 0) {
            throw "Control request failed with curl exit code ${LASTEXITCODE}: $raw"
        }
    }
    finally {
        if ($bodyFile -and (Test-Path -LiteralPath $bodyFile)) {
            Remove-Item -LiteralPath $bodyFile -Force
        }
    }
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $null
    }
    return $raw | ConvertFrom-Json
}

function Wait-PolicyVersion {
    param(
        [Parameter(Mandatory)] [long] $Version,
        [Parameter(Mandatory)] [Diagnostics.Process] $Process
    )

    for ($attempt = 0; $attempt -lt 45; $attempt++) {
        if ($Process.HasExited) {
            throw 'Proxy exited while waiting for the policy update.'
        }

        try {
            $health = Invoke-RestMethod -Uri 'http://127.0.0.1:18080/healthz' -TimeoutSec 2
            if ($health.policyVersion -eq $Version) {
                return
            }
        }
        catch {
        }

        Start-Sleep -Seconds 1
    }

    throw "Proxy did not apply policy version $Version."
}

function Wait-ReportingDevice {
    param(
        [Parameter(Mandatory)] [string] $AdminToken,
        [int] $MinimumEndpointCount = 0
    )

    for ($attempt = 0; $attempt -lt 45; $attempt++) {
        $devices = @(Invoke-ControlRest `
            -Uri 'https://127.0.0.1:18180/admin/v1/devices' `
            -Headers @{ Authorization = "Bearer $AdminToken" })
        if ($devices.Count -eq 1 -and $devices[0].endpointCount -ge $MinimumEndpointCount) {
            return $devices[0]
        }
        Start-Sleep -Seconds 1
    }

    throw "Expected one reporting device with at least $MinimumEndpointCount endpoint asset(s)."
}

function Wait-CommandTerminal {
    param(
        [Parameter(Mandatory)] [Guid] $DeviceId,
        [Parameter(Mandatory)] [string] $CommandId,
        [Parameter(Mandatory)] [string] $AdminToken
    )

    $lastStatuses = ''
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $commands = Invoke-ControlRest `
            -Uri "https://127.0.0.1:18180/admin/v1/devices/$DeviceId/commands" `
            -Headers @{ Authorization = "Bearer $AdminToken" }
        $commandIds = @($commands.commandId)
        $commandStatuses = @($commands.status)
        $lastStatuses = 0..($commandIds.Count - 1) |
            ForEach-Object { "$($commandIds[$_]):$($commandStatuses[$_])" }
        $lastStatuses = $lastStatuses -join ','
        $commandIndex = [Array]::IndexOf($commandIds, $CommandId)
        $command = if ($commandIndex -ge 0) { @($commands)[$commandIndex] } else { $null }
        $terminalStatuses = @('succeeded', 'failed', 'expired', 'cancelled')
        if ($null -ne $command -and $terminalStatuses.Contains(([string]$command.status).ToLowerInvariant())) {
            return $command
        }
        Start-Sleep -Seconds 1
    }

    throw "Command $CommandId did not reach a terminal status. Last commands: $lastStatuses"
}

function Wait-OperationState {
    param(
        [Parameter(Mandatory)] [string] $Expected,
        [Parameter(Mandatory)] [Diagnostics.Process] $Process
    )

    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        if ($Process.HasExited) {
            throw 'Proxy exited while waiting for the operation state.'
        }
        try {
            $health = Invoke-RestMethod -Uri 'http://127.0.0.1:18080/healthz' -TimeoutSec 2
            if ($health.operationState -eq $Expected) {
                return $health
            }
        }
        catch {
        }
        Start-Sleep -Seconds 1
    }

    throw "Proxy did not reach operation state $Expected."
}

$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $utf8
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8
chcp 65001 > $null

if ([string]::IsNullOrWhiteSpace($DotnetRoot)) {
    throw 'Pass -DotnetRoot or set DOTNET_ROOT to a .NET 10 installation.'
}

$env:DOTNET_ROOT = $DotnetRoot
$env:DOTNET_ROOT_X64 = $DotnetRoot
$env:ASPNETCORE_ENVIRONMENT = 'Development'
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$artifactsRoot = Join-Path $workspace 'artifacts'
$e2eRoot = Join-Path $artifactsRoot 'control-e2e'
$resolvedArtifacts = [IO.Path]::GetFullPath($artifactsRoot).TrimEnd('\')
$resolvedE2e = [IO.Path]::GetFullPath($e2eRoot)
if (-not $resolvedE2e.StartsWith($resolvedArtifacts + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Unsafe control E2E cleanup target.'
}

if (Test-Path -LiteralPath $e2eRoot) {
    Remove-Item -LiteralPath $e2eRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $e2eRoot | Out-Null

$requiredPorts = 18080, 18180, 19090, 19091
$occupied = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object LocalPort -in $requiredPorts
if ($occupied) {
    throw "Required control E2E ports are occupied: $($occupied.LocalPort -join ',')."
}

$mockExe = Join-Path $workspace 'tools\Sf.EndpointAI.MockLab\bin\Release\net10.0\Sf.EndpointAI.MockLab.exe'
$controlExe = Join-Path $workspace 'src\Sf.EndpointAI.ControlServer\bin\Release\net10.0\win-x64\Sf.EndpointAI.ControlServer.exe'
$proxyExe = Join-Path $workspace 'src\Sf.EndpointAI.Client.Service\bin\Release\net10.0\win-x64\Sf.EndpointAI.Client.Service.exe'
foreach ($requiredExe in @($mockExe, $controlExe, $proxyExe)) {
    if (-not [IO.File]::Exists($requiredExe)) {
        throw "Required Release executable was not found: $requiredExe"
    }
}
$hmacKey = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('01234567890123456789012345678901'))
$clientToken = 'prototype-control-client-token'
$adminToken = 'prototype-control-admin-token'
$certificatePassword = 'control-e2e-certificate-password'
$processes = [Collections.Generic.List[Diagnostics.Process]]::new()

try {
    $env:SF_MOCK_PORT = '19090'
    $originalMock = Start-Process -FilePath $mockExe -WorkingDirectory $e2eRoot -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $e2eRoot 'original.stdout.log') `
        -RedirectStandardError (Join-Path $e2eRoot 'original.stderr.log')
    $processes.Add($originalMock)
    Wait-Endpoint -Uri 'http://127.0.0.1:19090/healthz' -Process $originalMock -Name 'Original mock'

    $env:SF_MOCK_PORT = '19091'
    $gatewayMock = Start-Process -FilePath $mockExe -WorkingDirectory $e2eRoot -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $e2eRoot 'gateway.stdout.log') `
        -RedirectStandardError (Join-Path $e2eRoot 'gateway.stderr.log')
    $processes.Add($gatewayMock)
    Wait-Endpoint -Uri 'http://127.0.0.1:19091/healthz' -Process $gatewayMock -Name 'Gateway mock'

    $certificateTool = Join-Path $workspace 'tools\Sf.EndpointAI.CertificateTool\bin\Release\net10.0\Sf.EndpointAI.CertificateTool.dll'
    $certificateJson = & (Join-Path $DotnetRoot 'dotnet.exe') $certificateTool ensure `
        --ip 127.0.0.1 `
        --pfx (Join-Path $e2eRoot 'control-server.pfx') `
        --cer (Join-Path $e2eRoot 'control-server.cer') `
        --password $certificatePassword `
        --days 7
    if ($LASTEXITCODE -ne 0) {
        throw 'Control E2E certificate generation failed.'
    }
    $certificate = $certificateJson | ConvertFrom-Json
    $env:SF_CONTROL_DATA_ROOT = Join-Path $e2eRoot 'control'
    $env:SF_CONTROL_CLIENT_TOKEN = $clientToken
    $env:SF_CONTROL_ADMIN_TOKEN = $adminToken
    $env:SF_CONTROL_POLICY_HMAC_KEY = $hmacKey
    $env:SF_CONTROL_CERTIFICATE_PATH = Join-Path $e2eRoot 'control-server.pfx'
    $env:SF_CONTROL_CERTIFICATE_PASSWORD = $certificatePassword
    $env:SF_CONTROL_HTTPS_PORT = '18180'
    $env:SF_CONTROL_ROUTE_MODE = 'PassthroughOriginal'
    $env:SF_CONTROL_POLL_INTERVAL_SECONDS = '15'
    $env:SF_CONTROL_HEARTBEAT_INTERVAL_SECONDS = '15'
    $control = Start-Process -FilePath $controlExe -WorkingDirectory $e2eRoot -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $e2eRoot 'control.stdout.log') `
        -RedirectStandardError (Join-Path $e2eRoot 'control.stderr.log')
    $processes.Add($control)
    Wait-Endpoint -Uri 'https://127.0.0.1:18180/health/ready' -Process $control -Name 'Control server'
    $consoleContent = (& curl.exe -k -sS --fail --max-time 5 'https://127.0.0.1:18180/console' 2>&1) -join [Environment]::NewLine
    if ($LASTEXITCODE -ne 0 -or $consoleContent -notlike '*EndpointAIDLP*') {
        throw 'Expected the asset control console to be available.'
    }

    $env:SF_PROXY_DATA_ROOT = Join-Path $e2eRoot 'client'
    $e2eProfileRoot = Join-Path $e2eRoot 'profile'
    $e2eCodexRoot = Join-Path $e2eProfileRoot '.codex'
    New-Item -ItemType Directory -Path $e2eCodexRoot -Force | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $e2eProfileRoot '.endpointai-e2e-profile'),
        'isolated',
        [Text.UTF8Encoding]::new($false))
    $e2eCodexConfig = Join-Path $e2eCodexRoot 'config.toml'
    [IO.File]::WriteAllText(
        $e2eCodexConfig,
        "model = `"mock-model`"`nopenai_base_url = `"https://api.example.com/v1`"`n",
        [Text.UTF8Encoding]::new($false))
    $env:SF_PROXY_E2E_PROFILE_ROOT = $e2eProfileRoot
    $env:SF_PROXY_AUTO_ATTACH = 'true'
    $env:SF_PROXY_BOOTSTRAP_UPSTREAM = 'http://127.0.0.1:19090/v1'
    $env:SF_PROXY_BOOTSTRAP_ROUTE_ID = 'abcdefghijklmnopqrstuv'
    $env:SF_PROXY_BOOTSTRAP_USER_SID = 'S-1-5-21-control-e2e'
    $env:SF_PROXY_CONTROL_ORIGIN = 'https://127.0.0.1:18180'
    $env:SF_PROXY_CONTROL_TOKEN = $clientToken
    $env:SF_PROXY_CONTROL_HMAC_KEY = $hmacKey
    $env:SF_PROXY_GATEWAY_HMAC_KEY = $hmacKey
    $badPinBytes = [Text.Encoding]::UTF8.GetBytes('not-the-control-server-public-key')
    try {
        $env:SF_PROXY_CONTROL_SERVER_CERTIFICATE_SPKI_SHA256 = [Convert]::ToBase64String(
            [Security.Cryptography.SHA256]::Create().ComputeHash($badPinBytes))
    }
    finally {
        [Array]::Clear($badPinBytes, 0, $badPinBytes.Length)
    }
    $pinRejectedProxy = Start-Process -FilePath $proxyExe -WorkingDirectory $e2eRoot -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $e2eRoot 'proxy-bad-pin.stdout.log') `
        -RedirectStandardError (Join-Path $e2eRoot 'proxy-bad-pin.stderr.log')
    $processes.Add($pinRejectedProxy)
    Wait-Endpoint -Uri 'http://127.0.0.1:18080/healthz' -Process $pinRejectedProxy -Name 'Bad-pin proxy'
    Start-Sleep -Seconds 3
    Stop-Process -Id $pinRejectedProxy.Id -Force
    $pinRejectedProxy.WaitForExit()
    $devicesBeforeValidPin = Invoke-ControlRest `
        -Uri 'https://127.0.0.1:18180/admin/v1/devices' `
        -Headers @{ Authorization = "Bearer $adminToken" }
    if (@($devicesBeforeValidPin).Count -ne 0) {
        throw 'A client with an incorrect SPKI pin reached the control server.'
    }

    $env:SF_PROXY_CONTROL_SERVER_CERTIFICATE_SPKI_SHA256 = $certificate.SpkiSha256
    $proxy = Start-Process -FilePath $proxyExe -WorkingDirectory $e2eRoot -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $e2eRoot 'proxy.stdout.log') `
        -RedirectStandardError (Join-Path $e2eRoot 'proxy.stderr.log')
    $processes.Add($proxy)
    Wait-Endpoint -Uri 'http://127.0.0.1:18080/healthz' -Process $proxy -Name 'Proxy'

    $initialDevice = Wait-ReportingDevice -AdminToken $adminToken

    Stop-Process -Id $control.Id -Force
    $control.WaitForExit()
    foreach ($databaseFileName in @('control.db', 'control.db-wal', 'control.db-shm')) {
        $databaseFile = [IO.Path]::GetFullPath((Join-Path $env:SF_CONTROL_DATA_ROOT $databaseFileName))
        if (-not $databaseFile.StartsWith($resolvedE2e + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw "Unsafe control database reset target: $databaseFile"
        }
        if (Test-Path -LiteralPath $databaseFile) {
            Remove-Item -LiteralPath $databaseFile -Force
        }
    }
    $control = Start-Process -FilePath $controlExe -WorkingDirectory $e2eRoot -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $e2eRoot 'control-reset.stdout.log') `
        -RedirectStandardError (Join-Path $e2eRoot 'control-reset.stderr.log')
    $processes.Add($control)
    Wait-Endpoint -Uri 'https://127.0.0.1:18180/health/ready' -Process $control -Name 'Reset control server'
    $reenrolledDevice = Wait-ReportingDevice -AdminToken $adminToken

    $requestBody = '{"model":"mock-model","input":"control-plane"}'
    $direct = Invoke-RestMethod -Method Post `
        -Uri 'http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv/responses?scenario=normal-json' `
        -ContentType 'application/json' `
        -Body $requestBody
    if ($direct.localPort -ne 19090) {
        throw "Expected passthrough request on port 19090, received $($direct.localPort)."
    }

    $policyBody = @{
        expectedVersion = 1
        enabled = $true
        routeMode = 'fixedGateway'
        gatewayOrigin = 'http://127.0.0.1:19091'
        allowInsecureGateway = $true
        pollIntervalSeconds = 15
        heartbeatIntervalSeconds = 15
    } | ConvertTo-Json
    $updatedPolicy = Invoke-ControlRest -Method Put `
        -Uri 'https://127.0.0.1:18180/admin/v1/policy' `
        -Headers @{ Authorization = "Bearer $adminToken" } `
        -ContentType 'application/json' `
        -Body $policyBody
    if ($updatedPolicy.policyVersion -ne 2) {
        throw "Expected control policy version 2, received $($updatedPolicy.policyVersion)."
    }
    if (@($updatedPolicy.allowlistedBaseUrls).Count -ne 1 -or
        $updatedPolicy.allowlistedBaseUrls[0] -ne 'https://internal.example.invalid/ccr') {
        throw 'An update from an old caller did not preserve the migrated CCR allowlist.'
    }

    Wait-PolicyVersion -Version 2 -Process $proxy
    $gateway = Invoke-RestMethod -Method Post `
        -Uri 'http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv/responses?scenario=normal-json' `
        -ContentType 'application/json' `
        -Body $requestBody
    if ($gateway.localPort -ne 19091) {
        throw "Expected gateway request on port 19091, received $($gateway.localPort)."
    }

    $device = Wait-ReportingDevice -AdminToken $adminToken -MinimumEndpointCount 1
    if ($device.schemaVersion -ne 2) {
        throw "Expected heartbeat schema 2, received $($device.schemaVersion)."
    }
    if ($device.endpointCount -lt 1) {
        throw "Expected at least one endpoint asset, received $($device.endpointCount)."
    }
    if ($device.onlineState -ne 'online') {
        throw "Expected online asset state, received $($device.onlineState)."
    }

    $allowlistPolicyBody = @{
        expectedVersion = 2
        enabled = $true
        routeMode = 'fixedGateway'
        gatewayOrigin = 'http://127.0.0.1:19091'
        allowInsecureGateway = $true
        pollIntervalSeconds = 15
        heartbeatIntervalSeconds = 15
        allowlistedBaseUrls = @('http://127.0.0.1:19090/v1/')
    } | ConvertTo-Json
    $allowlistPolicy = Invoke-ControlRest -Method Put `
        -Uri 'https://127.0.0.1:18180/admin/v1/policy' `
        -Headers @{ Authorization = "Bearer $adminToken" } `
        -ContentType 'application/json' `
        -Body $allowlistPolicyBody
    Wait-PolicyVersion -Version 3 -Process $proxy
    try {
        Invoke-RestMethod -Method Post `
            -Uri 'http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv/responses?scenario=normal-json' `
            -ContentType 'application/json' `
            -Body $requestBody | Out-Null
        throw 'An allowlisted residual route was forwarded instead of being blocked.'
    }
    catch {
        if ($_.Exception.Response.StatusCode.value__ -ne 409) {
            throw
        }
    }

    $clearAllowlistBody = @{
        expectedVersion = $allowlistPolicy.policyVersion
        enabled = $true
        routeMode = 'fixedGateway'
        gatewayOrigin = 'http://127.0.0.1:19091'
        allowInsecureGateway = $true
        pollIntervalSeconds = 15
        heartbeatIntervalSeconds = 15
        allowlistedBaseUrls = @()
    } | ConvertTo-Json
    $clearedPolicy = Invoke-ControlRest -Method Put `
        -Uri 'https://127.0.0.1:18180/admin/v1/policy' `
        -Headers @{ Authorization = "Bearer $adminToken" } `
        -ContentType 'application/json' `
        -Body $clearAllowlistBody
    Wait-PolicyVersion -Version 4 -Process $proxy
    $reattached = Invoke-RestMethod -Method Post `
        -Uri 'http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv/responses?scenario=normal-json' `
        -ContentType 'application/json' `
        -Body $requestBody
    if ($reattached.localPort -ne 19091) {
        throw "Expected the route to resume through gateway port 19091, received $($reattached.localPort)."
    }

    if (([IO.File]::ReadAllText($e2eCodexConfig)) -notlike '*127.0.0.1:18080*') {
        throw 'The isolated Codex profile was not attached before remote-command testing.'
    }
    $disableBody = @{
        type = 'disableProxy'
        reason = 'control-e2e-disable'
        expiresInMinutes = 30
    } | ConvertTo-Json
    $disableCommand = Invoke-ControlRest -Method Post `
        -Uri "https://127.0.0.1:18180/admin/v1/devices/$($device.deviceId)/commands" `
        -Headers @{ Authorization = "Bearer $adminToken"; 'X-SF-Admin-Actor' = 'control-e2e' } `
        -ContentType 'application/json' `
        -Body $disableBody
    $disableConfirmResponse = Invoke-ControlRest `
        -Uri "https://127.0.0.1:18180/admin/v1/devices/$($device.deviceId)/commands" `
        -Headers @{ Authorization = "Bearer $adminToken" }
    $disableConfirmed = @($disableConfirmResponse.commandId) -contains [string]$disableCommand.commandId
    if (([string]$disableCommand.status).ToLowerInvariant() -ne 'pending' -or -not $disableConfirmed) {
        throw "The disable command POST did not return Pending or was not immediately queryable by Command ID. POST=$($disableCommand | ConvertTo-Json -Compress); query=$($disableConfirmResponse | ConvertTo-Json -Compress)"
    }
    $disabledCommand = Wait-CommandTerminal `
        -DeviceId $device.deviceId `
        -CommandId $disableCommand.commandId `
        -AdminToken $adminToken
    if (([string]$disabledCommand.status).ToLowerInvariant() -ne 'succeeded' -or
        -not $disabledCommand.deliveredAtUtc -or
        -not $disabledCommand.startedAtUtc -or
        -not $disabledCommand.completedAtUtc -or
        $disabledCommand.deliveryCount -lt 1) {
        throw "Disable command did not complete with a full lifecycle: $($disabledCommand | ConvertTo-Json -Compress)."
    }
    $disabledHealth = Wait-OperationState -Expected 'disabled' -Process $proxy
    if ($disabledHealth.status -ne 'ok') {
        throw 'The local service became unhealthy after the proxy was disabled.'
    }
    if (([IO.File]::ReadAllText($e2eCodexConfig)) -notlike '*https://api.example.com/v1*') {
        throw 'The managed Codex configuration was not restored by DisableProxy.'
    }
    try {
        Invoke-RestMethod -Method Post `
            -Uri 'http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv/responses?scenario=normal-json' `
            -ContentType 'application/json' `
            -Body $requestBody | Out-Null
        throw 'Forwarding succeeded while the proxy operation state was Disabled.'
    }
    catch {
        if ($_.Exception.Message -eq 'Forwarding succeeded while the proxy operation state was Disabled.') {
            throw
        }
    }

    $enableBody = @{
        type = 'enableProxy'
        reason = 'control-e2e-enable'
        expiresInMinutes = 30
    } | ConvertTo-Json
    $enableCommand = Invoke-ControlRest -Method Post `
        -Uri "https://127.0.0.1:18180/admin/v1/devices/$($device.deviceId)/commands" `
        -Headers @{ Authorization = "Bearer $adminToken"; 'X-SF-Admin-Actor' = 'control-e2e' } `
        -ContentType 'application/json' `
        -Body $enableBody
    $enabledCommand = Wait-CommandTerminal `
        -DeviceId $device.deviceId `
        -CommandId $enableCommand.commandId `
        -AdminToken $adminToken
    if (([string]$enabledCommand.status).ToLowerInvariant() -ne 'succeeded') {
        throw "Enable command failed: $($enabledCommand.resultCode) $($enabledCommand.resultSummary)"
    }
    $enabledHealth = Wait-OperationState -Expected 'enabled' -Process $proxy
    if ($enabledHealth.status -ne 'ok' -or ([IO.File]::ReadAllText($e2eCodexConfig)) -notlike '*127.0.0.1:18080*') {
        throw 'EnableProxy did not restore the attached, healthy operation state.'
    }
    $enabledForward = Invoke-RestMethod -Method Post `
        -Uri 'http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv/responses?scenario=normal-json' `
        -ContentType 'application/json' `
        -Body $requestBody
    if ($enabledForward.localPort -ne 19091) {
        throw "Expected forwarding to resume through gateway port 19091, received $($enabledForward.localPort)."
    }

    Stop-Process -Id $proxy.Id -Force
    $proxy.WaitForExit()
    $env:SF_PROXY_CONTROL_TOKEN = $null
    $restartedProxy = Start-Process -FilePath $proxyExe -WorkingDirectory $e2eRoot -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $e2eRoot 'proxy-restarted.stdout.log') `
        -RedirectStandardError (Join-Path $e2eRoot 'proxy-restarted.stderr.log')
    $processes.Add($restartedProxy)
    Wait-Endpoint -Uri 'http://127.0.0.1:18080/healthz' -Process $restartedProxy -Name 'Restarted proxy'

    $restartPolicyBody = @{
        expectedVersion = 4
        enabled = $true
        routeMode = 'fixedGateway'
        gatewayOrigin = 'http://127.0.0.1:19091'
        allowInsecureGateway = $true
        pollIntervalSeconds = 15
        heartbeatIntervalSeconds = 15
    } | ConvertTo-Json
    $restartPolicy = Invoke-ControlRest -Method Put `
        -Uri 'https://127.0.0.1:18180/admin/v1/policy' `
        -Headers @{ Authorization = "Bearer $adminToken" } `
        -ContentType 'application/json' `
        -Body $restartPolicyBody
    if ($restartPolicy.policyVersion -ne 5) {
        throw "Expected post-restart policy version 5, received $($restartPolicy.policyVersion)."
    }
    Wait-PolicyVersion -Version 5 -Process $restartedProxy

    Stop-Process -Id $restartedProxy.Id -Force
    $restartedProxy.WaitForExit()
    $commandBody = @{
        type = 'disableProxy'
        reason = 'control-e2e-cancel-before-delivery'
        expiresInMinutes = 30
    } | ConvertTo-Json
    $createdCommand = Invoke-ControlRest -Method Post `
        -Uri "https://127.0.0.1:18180/admin/v1/devices/$($device.deviceId)/commands" `
        -Headers @{ Authorization = "Bearer $adminToken"; 'X-SF-Admin-Actor' = 'control-e2e' } `
        -ContentType 'application/json' `
        -Body $commandBody
    Invoke-ControlRest -Method Post `
        -Uri "https://127.0.0.1:18180/admin/v1/commands/$($createdCommand.commandId)/cancel" `
        -Headers @{ Authorization = "Bearer $adminToken"; 'X-SF-Admin-Actor' = 'control-e2e' } | Out-Null
    $commands = Invoke-ControlRest `
        -Uri "https://127.0.0.1:18180/admin/v1/devices/$($device.deviceId)/commands" `
        -Headers @{ Authorization = "Bearer $adminToken" }
    $cancelledIndex = [Array]::IndexOf(@($commands.commandId), [string]$createdCommand.commandId)
    $cancelledCommand = if ($cancelledIndex -ge 0) { @($commands)[$cancelledIndex] } else { $null }
    if (([string]$cancelledCommand.status).ToLowerInvariant() -ne 'cancelled') {
        throw "Expected the undelivered command to be cancelled, received $($cancelledCommand.status)."
    }

    [PSCustomObject]@{
        InitialPolicyVersion = 1
        AppliedPolicyVersion = 5
        PassthroughPort = $direct.localPort
        GatewayPort = $gateway.localPort
        ReportingDevices = 1
        HeartbeatSchema = $device.schemaVersion
        EndpointAssets = $device.endpointCount
        OnlineState = $device.onlineState
        RestartWithoutBootstrapToken = $true
        PinMismatchBlockedEnrollment = $true
        ReenrolledAfterServerReset = $true
        OldCallerPreservedAllowlist = $true
        AllowlistedRouteBlocked = $true
        ExplicitEmptyAllowlistReattached = $true
        DisableCommand = $disabledCommand.status
        DisabledHealth = $disabledHealth.status
        DisabledForwardingBlocked = $true
        EnableCommand = $enabledCommand.status
        EnabledForwardingPort = $enabledForward.localPort
        ConsoleStatus = 200
        CancelledCommand = $cancelledCommand.status
    }
}
finally {
    foreach ($process in $processes) {
        if ($process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force
        }
    }
}
