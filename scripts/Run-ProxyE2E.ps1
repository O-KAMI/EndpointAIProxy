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

    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $Uri -TimeoutSec 2 | Out-Null
            return
        }
        catch {
            if ($Process.HasExited) {
                throw "$Name exited before becoming ready."
            }
            Start-Sleep -Milliseconds 500
        }
    }

    throw "$Name did not become ready."
}

function Read-LogText {
    param([Parameter(Mandatory)] [IO.FileInfo] $File)

    $path = $File.FullName
    if (-not $path.EndsWith('.gz', [StringComparison]::OrdinalIgnoreCase) -and
        [IO.File]::Exists($path + '.gz')) {
        $path += '.gz'
    }
    $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    try {
        $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
    }
    catch [IO.FileNotFoundException] {
        $path = $File.FullName + '.gz'
        $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
    }
    try {
        $content = if ($path.EndsWith('.gz', [StringComparison]::OrdinalIgnoreCase)) {
            [IO.Compression.GZipStream]::new($stream, [IO.Compression.CompressionMode]::Decompress)
        }
        else { $stream }
        $reader = [IO.StreamReader]::new($content, [Text.Encoding]::UTF8)
        try { return $reader.ReadToEnd() }
        finally { $reader.Dispose() }
    }
    finally { $stream.Dispose() }
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
$e2eRoot = Join-Path $artifactsRoot 'e2e'
$resolvedArtifacts = [IO.Path]::GetFullPath($artifactsRoot).TrimEnd('\')
$resolvedE2e = [IO.Path]::GetFullPath($e2eRoot)
if (-not $resolvedE2e.StartsWith($resolvedArtifacts + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Unsafe E2E cleanup target.'
}

if (Test-Path -LiteralPath $e2eRoot) {
    Remove-Item -LiteralPath $e2eRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $e2eRoot | Out-Null

$occupied = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object LocalPort -in 15721, 18080, 19090
if ($occupied) {
    throw "Required E2E ports are occupied: $($occupied.LocalPort -join ',')."
}

$windowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$e2eUserSid = $windowsIdentity.User.Value
$e2eAccountName = $windowsIdentity.Name
$expectedUserId = if ($e2eAccountName.StartsWith('SF\', [StringComparison]::OrdinalIgnoreCase) -and
    $e2eAccountName.Length -gt 3) {
    $e2eAccountName.Substring(3)
}
else {
    $e2eAccountName
}

$mockExe = Join-Path $workspace 'tools\Sf.EndpointAI.MockLab\bin\Release\net10.0\Sf.EndpointAI.MockLab.exe'
$proxyExe = Join-Path $workspace 'src\Sf.EndpointAI.Client.Service\bin\Release\net10.0\win-x64\Sf.EndpointAI.Client.Service.exe'
foreach ($requiredExe in @($mockExe, $proxyExe)) {
    if (-not [IO.File]::Exists($requiredExe)) {
        throw "Required Release executable was not found: $requiredExe"
    }
}
$env:SF_MOCK_PORT = '19090'
Remove-Item Env:SF_MOCK_FORWARD_ORIGIN -ErrorAction SilentlyContinue
$mock = Start-Process -FilePath $mockExe `
    -WorkingDirectory $e2eRoot `
    -PassThru `
    -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $e2eRoot 'mock.stdout.log') `
    -RedirectStandardError (Join-Path $e2eRoot 'mock.stderr.log')

try {
    Wait-Endpoint -Uri 'http://127.0.0.1:19090/healthz' -Process $mock -Name 'Mock'

    $env:SF_PROXY_DATA_ROOT = Join-Path $e2eRoot 'client'
    $env:SF_PROXY_BOOTSTRAP_UPSTREAM = 'http://127.0.0.1:19090/v1'
    $env:SF_PROXY_BOOTSTRAP_ROUTE_ID = 'abcdefghijklmnopqrstuv'
    $env:SF_PROXY_BOOTSTRAP_USER_SID = $e2eUserSid
    $env:SF_PROXY_ROUTE_MODE = 'FixedGateway'
    $env:SF_PROXY_GATEWAY_ORIGIN = 'http://127.0.0.1:19090'
    $env:SF_PROXY_ALLOW_INSECURE_GATEWAY = 'true'
    Remove-Item Env:SF_PROXY_GATEWAY_HMAC_KEY -ErrorAction SilentlyContinue
    $env:SF_PROXY_ENABLE_MANAGEMENT_API = 'true'
    $env:SF_PROXY_MANAGEMENT_TOKEN = 'prototype-management-token-32-bytes-minimum'
    $proxy = Start-Process -FilePath $proxyExe `
        -WorkingDirectory $e2eRoot `
        -PassThru `
        -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $e2eRoot 'proxy.stdout.log') `
        -RedirectStandardError (Join-Path $e2eRoot 'proxy.stderr.log')

    try {
        Wait-Endpoint -Uri 'http://127.0.0.1:18080/healthz' -Process $proxy -Name 'Proxy'
        $unauthorizedStatus = curl.exe `
            -sS `
            -o NUL `
            -w '%{http_code}' `
            'http://127.0.0.1:18080/management/discovery'
        if ($unauthorizedStatus -ne '401') {
            throw "Expected unauthenticated discovery to return 401, received $unauthorizedStatus."
        }
        $discoveryResponse = Invoke-WebRequest `
            -UseBasicParsing `
            -Uri 'http://127.0.0.1:18080/management/discovery' `
            -Headers @{ Authorization = "Bearer $env:SF_PROXY_MANAGEMENT_TOKEN" }
        if ($discoveryResponse.StatusCode -ne 200) {
            throw "Expected authenticated discovery to return 200, received $($discoveryResponse.StatusCode)."
        }
        $env:SF_MOCK_PORT = '15721'
        $env:SF_MOCK_FORWARD_ORIGIN = 'http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv'
        $ccSwitchProxy = Start-Process -FilePath $mockExe `
            -WorkingDirectory $e2eRoot `
            -PassThru `
            -WindowStyle Hidden `
            -RedirectStandardOutput (Join-Path $e2eRoot 'ccswitch-proxy.stdout.log') `
            -RedirectStandardError (Join-Path $e2eRoot 'ccswitch-proxy.stderr.log')
        Wait-Endpoint -Uri 'http://127.0.0.1:15721/healthz' -Process $ccSwitchProxy -Name 'CC Switch proxy simulator'

        $headers = @{ Authorization = 'Bearer prototype-secret' }
        $jsonBody = '{"model":"mock-model","input":"hello"}'
        $jsonResponse = Invoke-WebRequest `
            -UseBasicParsing `
            -Method Post `
            -Uri 'http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv/responses?scenario=normal-json&responseDelayMs=150' `
            -Headers $headers `
            -ContentType 'application/json' `
            -Body $jsonBody
        $sseBody = '{"model":"mock-model","stream":true}'
        $sseResponse = Invoke-WebRequest `
            -UseBasicParsing `
            -Method Post `
            -Uri 'http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv/messages?scenario=anthropic-sse' `
            -Headers $headers `
            -ContentType 'application/json' `
            -Body $sseBody
        $chatBody = '{"model":"mock-chat","messages":[{"role":"user","content":"hello"}]}'
        $chatResponse = Invoke-WebRequest `
            -UseBasicParsing `
            -Method Post `
            -Uri 'http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv/chat/completions?scenario=normal-json' `
            -Headers $headers `
            -ContentType 'application/json' `
            -Body $chatBody
        $ccSwitchSseResponse = Invoke-WebRequest `
            -UseBasicParsing `
            -Method Post `
            -Uri 'http://127.0.0.1:15721/messages?scenario=anthropic-sse' `
            -Headers $headers `
            -ContentType 'application/json' `
            -Body $sseBody

        $captureRoot = Join-Path $e2eRoot "client\captures\$e2eUserSid"
        $captures = @()
        for ($attempt = 0; $attempt -lt 50; $attempt++) {
            $captureCandidates = @(Get-ChildItem -LiteralPath $captureRoot -Recurse -File | Where-Object {
                $_.Name.EndsWith('.md', [StringComparison]::OrdinalIgnoreCase) -or
                $_.Name.EndsWith('.md.gz', [StringComparison]::OrdinalIgnoreCase)
            })
            $captures = @($captureCandidates |
                Group-Object { $_.FullName -replace '\.gz$', '' } |
                ForEach-Object {
                    @($_.Group | Sort-Object { -not $_.Name.EndsWith('.gz', [StringComparison]::OrdinalIgnoreCase) })[0]
                })
            if ($captures.Count -eq 4 -and
                @($captures | Where-Object { -not $_.Name.EndsWith('.gz', [StringComparison]::OrdinalIgnoreCase) }).Count -eq 0) {
                break
            }
            Start-Sleep -Milliseconds 100
        }
        if ($captures.Count -ne 4) {
            throw "Expected four captures, found $($captures.Count)."
        }
        if (@($captures | Where-Object { -not $_.Name.EndsWith('.gz', [StringComparison]::OrdinalIgnoreCase) }).Count -ne 0) {
            throw 'Completed captures were not compressed within five seconds.'
        }

        $captureText = ($captures | ForEach-Object {
            Read-LogText -File $_
        }) -join "`n"
        if ($captureText.IndexOf('Bearer prototype-secret', [StringComparison]::Ordinal) -ge 0 -or
            $captureText.IndexOf('Authorization: [REDACTED]', [StringComparison]::Ordinal) -lt 0) {
            throw 'Capture did not redact the Authorization header.'
        }
        if ($captureText.IndexOf('message_start', [StringComparison]::Ordinal) -lt 0) {
            throw 'Capture is missing SSE content.'
        }
        if ($captureText.IndexOf("- User ID: ``$expectedUserId``", [StringComparison]::Ordinal) -lt 0 -or
            $captureText.IndexOf("- User SID: ``$e2eUserSid``", [StringComparison]::Ordinal) -lt 0) {
            throw 'Capture does not contain the normalized UserID and original SID.'
        }
        if ($captureText.IndexOf('## Latency', [StringComparison]::Ordinal) -lt 0 -or
            $captureText.IndexOf('Gateway response headers received UTC:', [StringComparison]::Ordinal) -lt 0 -or
            $captureText.IndexOf('Gateway round trip milliseconds:', [StringComparison]::Ordinal) -lt 0) {
            throw 'Capture does not contain latency telemetry.'
        }
        $jsonPayload = $jsonResponse.Content | ConvertFrom-Json
        if ($jsonPayload.receivedBody -cne $jsonBody) {
            throw 'The JSON request body was not preserved by the proxy.'
        }
        if ($sseResponse.Content.IndexOf('message_start', [StringComparison]::Ordinal) -lt 0) {
            throw 'The SSE response was not preserved by the proxy.'
        }
        if ($ccSwitchSseResponse.Content.IndexOf('message_start', [StringComparison]::Ordinal) -lt 0) {
            throw 'The CC Switch local proxy chain did not preserve SSE content.'
        }
        $chatPayload = $chatResponse.Content | ConvertFrom-Json
        if ($chatPayload.path -cne '/v1/chat/completions?scenario=normal-json' -or
            $chatPayload.receivedBody -cne $chatBody) {
            throw 'The Chat Completions path or body was not preserved by the proxy.'
        }
        $gatewayRequest = Invoke-RestMethod `
            -Uri "http://127.0.0.1:19090/debug/requests/$($jsonPayload.requestId)"
        if ($gatewayRequest.headers.'X-SF-AI-User-Id'[0] -cne $expectedUserId -or
            $gatewayRequest.headers.'X-SF-AI-User-Sid'[0] -cne $e2eUserSid -or
            $gatewayRequest.headers.'X-SF-AI-Agent'[0] -cne 'ClaudeCode' -or
            $gatewayRequest.headers.'X-SF-AI-Original-Base-Url'[0] -cne 'http://127.0.0.1:19090/v1') {
            throw 'Gateway identity metadata is incomplete.'
        }
        if ($gatewayRequest.headers.PSObject.Properties.Name -contains 'X-SF-AI-Signature') {
            throw 'The no-HMAC gateway request unexpectedly contains a signature.'
        }
        $summaryFiles = @(Get-ChildItem -LiteralPath (Join-Path $e2eRoot 'client\captures\summary') -Filter '*.jsonl')
        $summaryLines = @($summaryFiles | ForEach-Object { Get-Content -LiteralPath $_.FullName -Encoding UTF8 })
        if ($summaryLines.Count -ne 4) {
            throw "Expected four JSONL summaries, found $($summaryLines.Count)."
        }
        $summaries = @($summaryLines | ForEach-Object { $_ | ConvertFrom-Json })
        if ($summaries.Where({ $_.UserId -cne $expectedUserId -or $_.UserSid -cne $e2eUserSid }).Count -ne 0) {
            throw 'JSONL summary does not contain the normalized UserID and original SID.'
        }
        foreach ($summary in $summaries) {
            if ($null -eq $summary.AgentRequestReceivedAtUtc -or
                $null -eq $summary.GatewayRequestStartedAtUtc -or
                $null -eq $summary.GatewayResponseHeadersReceivedAtUtc -or
                $null -eq $summary.AgentResponseStartedAtUtc -or
                $null -eq $summary.GatewayRoundTripMilliseconds) {
                throw 'A successful JSONL summary is missing latency telemetry.'
            }
            if ([DateTimeOffset]$summary.AgentRequestReceivedAtUtc -gt [DateTimeOffset]$summary.GatewayRequestStartedAtUtc -or
                [DateTimeOffset]$summary.GatewayRequestStartedAtUtc -gt [DateTimeOffset]$summary.GatewayResponseHeadersReceivedAtUtc -or
                [DateTimeOffset]$summary.GatewayResponseHeadersReceivedAtUtc -gt [DateTimeOffset]$summary.AgentResponseStartedAtUtc) {
                throw 'JSONL latency timestamps are out of order.'
            }
        }
        $delayedSummary = @($summaries | Where-Object { $_.InboundPathAndQuery -like '*responseDelayMs=150*' })
        if ($delayedSummary.Count -ne 1 -or [long]$delayedSummary[0].GatewayRoundTripMilliseconds -lt 100) {
            throw 'Gateway round-trip telemetry did not include the controlled response delay.'
        }

        Start-Sleep -Milliseconds 250
        $operationalFiles = @(Get-ChildItem -LiteralPath (Join-Path $e2eRoot 'client\logs\service') -Filter '*.jsonl')
        if ($operationalFiles.Count -eq 0) {
            throw 'The asynchronous operational log was not created.'
        }
        $operationalText = ($operationalFiles | ForEach-Object {
            Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8
        }) -join "`n"
        if ($operationalText.IndexOf('Bearer prototype-secret', [StringComparison]::Ordinal) -ge 0 -or
            $operationalText.IndexOf($e2eUserSid, [StringComparison]::Ordinal) -ge 0) {
            throw 'The operational log contains an unredacted credential or SID.'
        }
        if ($operationalText.IndexOf('RequestCompleted', [StringComparison]::Ordinal) -lt 0) {
            throw 'The operational log is missing proxy request completion events.'
        }

        [PSCustomObject]@{
            JsonStatus = $jsonResponse.StatusCode
            SseStatus = $sseResponse.StatusCode
            ChatStatus = $chatResponse.StatusCode
            CcSwitchProxySseStatus = $ccSwitchSseResponse.StatusCode
            DiscoveryStatus = $discoveryResponse.StatusCode
            UnauthorizedDiscoveryStatus = $unauthorizedStatus
            CaptureCount = $captures.Count
            SummaryCount = $summaryLines.Count
            OperationalLogCount = $operationalFiles.Count
            UserId = $expectedUserId
            UserSid = $e2eUserSid
            DelayedGatewayRoundTripMs = $delayedSummary[0].GatewayRoundTripMilliseconds
            CaptureFiles = $captures.FullName
        }
    }
    finally {
        if ($ccSwitchProxy -and -not $ccSwitchProxy.HasExited) {
            Stop-Process -Id $ccSwitchProxy.Id -Force
        }
        if ($proxy -and -not $proxy.HasExited) {
            Stop-Process -Id $proxy.Id -Force
        }
    }
}
finally {
    Remove-Item Env:SF_MOCK_FORWARD_ORIGIN -ErrorAction SilentlyContinue
    Remove-Item Env:SF_MOCK_PORT -ErrorAction SilentlyContinue
    if ($mock -and -not $mock.HasExited) {
        Stop-Process -Id $mock.Id -Force
    }
}
