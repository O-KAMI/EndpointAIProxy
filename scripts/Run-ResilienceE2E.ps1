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
            if ($Process.HasExited) { throw "$Name exited before becoming ready." }
            Start-Sleep -Milliseconds 500
        }
    }

    throw "$Name did not become ready."
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
$testRoot = Join-Path $artifactsRoot 'resilience-e2e'
$resolvedArtifacts = [IO.Path]::GetFullPath($artifactsRoot).TrimEnd('\')
$resolvedTest = [IO.Path]::GetFullPath($testRoot)
if (-not $resolvedTest.StartsWith($resolvedArtifacts + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Unsafe resilience E2E cleanup target.'
}

if (Test-Path -LiteralPath $testRoot) {
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $testRoot | Out-Null
$occupied = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object LocalPort -in 18080, 19092
if ($occupied) {
    throw "Required resilience E2E ports are occupied: $($occupied.LocalPort -join ',')."
}

$mockExe = Join-Path $workspace 'tools\Sf.EndpointAI.MockLab\bin\Release\net10.0\Sf.EndpointAI.MockLab.exe'
$proxyExe = Join-Path $workspace 'src\Sf.EndpointAI.Client.Service\bin\Release\net10.0\win-x64\Sf.EndpointAI.Client.Service.exe'
foreach ($requiredExe in @($mockExe, $proxyExe)) {
    if (-not [IO.File]::Exists($requiredExe)) {
        throw "Required Release executable was not found: $requiredExe"
    }
}
$env:SF_MOCK_PORT = '19092'
$mock = Start-Process -FilePath $mockExe -WorkingDirectory $testRoot -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $testRoot 'mock.stdout.log') `
    -RedirectStandardError (Join-Path $testRoot 'mock.stderr.log')

try {
    Wait-Endpoint -Uri 'http://127.0.0.1:19092/healthz' -Process $mock -Name 'Mock'
    $env:SF_PROXY_DATA_ROOT = Join-Path $testRoot 'client'
    $env:SF_PROXY_BOOTSTRAP_UPSTREAM = 'http://127.0.0.1:19092/v1'
    $env:SF_PROXY_BOOTSTRAP_ROUTE_ID = 'zyxwvutsrqponmlkjihgfe'
    $env:SF_PROXY_BOOTSTRAP_USER_SID = 'S-1-5-21-resilience'
    $env:SF_PROXY_AUTO_ATTACH = 'false'
    $env:SF_PROXY_ROUTE_MODE = 'PassthroughOriginal'
    Remove-Item Env:SF_PROXY_GATEWAY_ORIGIN -ErrorAction SilentlyContinue
    Remove-Item Env:SF_PROXY_CONTROL_ORIGIN -ErrorAction SilentlyContinue
    $proxy = Start-Process -FilePath $proxyExe -WorkingDirectory $testRoot -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $testRoot 'proxy.stdout.log') `
        -RedirectStandardError (Join-Path $testRoot 'proxy.stderr.log')

    try {
        Wait-Endpoint -Uri 'http://127.0.0.1:18080/healthz' -Process $proxy -Name 'Proxy'
        $baseUri = 'http://127.0.0.1:18080/r/zyxwvutsrqponmlkjihgfe/test'
        $expectedStatuses = @{
            '401' = '401'
            '429' = '429'
            '500' = '500'
            'redirect' = '502'
        }
        foreach ($scenario in $expectedStatuses.Keys) {
            $actual = curl.exe -sS -o NUL -w '%{http_code}' -X POST "$baseUri`?scenario=$scenario" `
                -H 'Content-Type: application/json' -d '{"test":true}'
            if ($actual -ne $expectedStatuses[$scenario]) {
                throw "Scenario $scenario returned $actual; expected $($expectedStatuses[$scenario])."
            }
        }

        Add-Type -AssemblyName System.Net.Http
        $handler = [Net.Http.HttpClientHandler]::new()
        $handler.UseProxy = $false
        $handler.AllowAutoRedirect = $false
        $client = [Net.Http.HttpClient]::new($handler)
        $client.Timeout = [TimeSpan]::FromSeconds(15)
        try {
            $stopwatch = [Diagnostics.Stopwatch]::StartNew()
            $tasks = [Collections.Generic.List[Threading.Tasks.Task[Net.Http.HttpResponseMessage]]]::new()
            for ($index = 0; $index -lt 20; $index++) {
                $content = [Net.Http.StringContent]::new("{`"index`":$index}", [Text.Encoding]::UTF8, 'application/json')
                $tasks.Add($client.PostAsync("$baseUri`?scenario=normal-json", $content))
            }

            [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$tasks.ToArray())
            $stopwatch.Stop()
            $statuses = $tasks | ForEach-Object { [int]$_.Result.StatusCode }
            if (@($statuses | Where-Object { $_ -ne 200 }).Count -ne 0) {
                throw "Concurrent proxy requests returned a non-200 status: $($statuses -join ',')."
            }
            if ($stopwatch.Elapsed -gt [TimeSpan]::FromSeconds(10)) {
                throw "Twenty concurrent requests took $($stopwatch.Elapsed.TotalSeconds) seconds."
            }
        }
        finally {
            $client.Dispose()
            $handler.Dispose()
        }

        curl.exe -sS --max-time 1 -o NUL -X POST "$baseUri`?scenario=timeout" `
            -H 'Content-Type: application/json' -d '{"test":true}'
        if ($LASTEXITCODE -ne 28) {
            throw "Expected the client-cancel scenario to exit with curl code 28, received $LASTEXITCODE."
        }

        $mockCount = (Invoke-RestMethod -Uri 'http://127.0.0.1:19092/debug/count' -TimeoutSec 5).count
        if ($mockCount -ne 25) {
            throw "Mock received $mockCount requests; expected 25 (no proxy retries)."
        }

        if (-not $mock.HasExited) {
            Stop-Process -Id $mock.Id -Force
            $mock.WaitForExit(5000) | Out-Null
        }
        $connectionFailureStatus = curl.exe -sS -o NUL -w '%{http_code}' -X POST "$baseUri`?scenario=normal-json" `
            -H 'Content-Type: application/json' -d '{"test":true}'
        if ($connectionFailureStatus -ne '502') {
            throw "Expected a stopped gateway to return 502, received $connectionFailureStatus."
        }

        $captureRoot = Join-Path $testRoot 'client\captures'
        $captures = @()
        for ($attempt = 0; $attempt -lt 100; $attempt++) {
            $captureCandidates = @(Get-ChildItem -LiteralPath $captureRoot -Recurse -File | Where-Object {
                $_.Name.EndsWith('.md', [StringComparison]::OrdinalIgnoreCase) -or
                $_.Name.EndsWith('.md.gz', [StringComparison]::OrdinalIgnoreCase)
            })
            $captures = @($captureCandidates |
                Group-Object { $_.FullName -replace '\.gz$', '' } |
                ForEach-Object {
                    @($_.Group | Sort-Object { -not $_.Name.EndsWith('.gz', [StringComparison]::OrdinalIgnoreCase) })[0]
                })
            if ($captures.Count -eq 26 -and
                @($captures | Where-Object { -not $_.Name.EndsWith('.gz', [StringComparison]::OrdinalIgnoreCase) }).Count -eq 0) {
                break
            }
            Start-Sleep -Milliseconds 100
        }
        if ($captures.Count -ne 26) {
            throw "Expected 26 completed captures, found $($captures.Count)."
        }
        if (@($captures | Where-Object { -not $_.Name.EndsWith('.gz', [StringComparison]::OrdinalIgnoreCase) }).Count -ne 0) {
            throw 'Completed captures were not compressed within ten seconds.'
        }
        $summaryFiles = @(Get-ChildItem -LiteralPath (Join-Path $testRoot 'client\captures\summary') -Filter '*.jsonl')
        $summaries = @($summaryFiles | ForEach-Object { Get-Content -LiteralPath $_.FullName -Encoding UTF8 } | ForEach-Object { $_ | ConvertFrom-Json })
        if ($summaries.Count -ne 26) {
            throw "Expected 26 JSONL summaries, found $($summaries.Count)."
        }
        $gatewayResponses = @($summaries | Where-Object { $_.Outcome -in 'SUCCESS', 'GATEWAY_HTTP_ERROR', 'UPSTREAM_REDIRECT_BLOCKED' })
        if (@($gatewayResponses | Where-Object {
            $null -eq $_.GatewayResponseHeadersReceivedAtUtc -or
            $null -eq $_.GatewayRoundTripMilliseconds -or
            $null -eq $_.AgentResponseStartedAtUtc
        }).Count -ne 0) {
            throw 'A completed gateway response is missing latency telemetry.'
        }
        $cancelled = @($summaries | Where-Object { $_.Outcome -eq 'CLIENT_CANCELLED' })
        if ($cancelled.Count -ne 1 -or
            $null -eq $cancelled[0].GatewayRequestStartedAtUtc -or
            $null -ne $cancelled[0].GatewayResponseHeadersReceivedAtUtc -or
            $null -ne $cancelled[0].GatewayRoundTripMilliseconds -or
            $null -ne $cancelled[0].AgentResponseStartedAtUtc) {
            throw 'Client-cancel latency telemetry does not match the reached phases.'
        }
        $connectionFailure = @($summaries | Where-Object { $_.Outcome -eq 'GATEWAY_CONNECTION_FAILED' })
        if ($connectionFailure.Count -ne 1 -or
            $null -eq $connectionFailure[0].GatewayRequestStartedAtUtc -or
            $null -ne $connectionFailure[0].GatewayResponseHeadersReceivedAtUtc -or
            $null -ne $connectionFailure[0].GatewayRoundTripMilliseconds -or
            $null -eq $connectionFailure[0].AgentResponseStartedAtUtc) {
            throw 'Connection-failure latency telemetry does not match the reached phases.'
        }

        [PSCustomObject]@{
            FailureStatuses = ($expectedStatuses.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
            ConcurrentRequests = 20
            ConcurrentElapsedMs = [Math]::Round($stopwatch.Elapsed.TotalMilliseconds)
            MockRequestCount = $mockCount
            CaptureCount = $captures.Count
            SummaryCount = $summaries.Count
            ClientCancelled = $cancelled.Count
            GatewayConnectionFailed = $connectionFailure.Count
        }
    }
    finally {
        if ($proxy -and -not $proxy.HasExited) { Stop-Process -Id $proxy.Id -Force }
    }
}
finally {
    if ($mock -and -not $mock.HasExited) { Stop-Process -Id $mock.Id -Force }
}
