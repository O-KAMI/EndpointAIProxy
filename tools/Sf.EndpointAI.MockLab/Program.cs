using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Sf.EndpointAI.MockLab;

var builder = WebApplication.CreateBuilder(args);
var listenPort = int.TryParse(Environment.GetEnvironmentVariable("SF_MOCK_PORT"), out var configuredPort)
    ? configuredPort
    : 19090;
var forwardOrigin = Uri.TryCreate(
    Environment.GetEnvironmentVariable("SF_MOCK_FORWARD_ORIGIN"),
    UriKind.Absolute,
    out var configuredForwardOrigin)
        ? configuredForwardOrigin
        : null;
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenLocalhost(listenPort, listen => listen.Protocols = HttpProtocols.Http1AndHttp2);
    options.AddServerHeader = false;
});

var received = new ConcurrentDictionary<Guid, ReceivedRequest>();
using var forwardingClient = new HttpClient(new SocketsHttpHandler
{
    AllowAutoRedirect = false,
    UseProxy = false,
})
{
    Timeout = Timeout.InfiniteTimeSpan,
};
var app = builder.Build();

app.MapGet("/healthz", () => Results.Ok(new { status = "ok", service = "SF Endpoint AI Mock Lab" }));
app.MapGet("/debug/count", () => Results.Ok(new { count = received.Count }));
app.MapGet("/debug/requests/{requestId:guid}", (Guid requestId) =>
    received.TryGetValue(requestId, out var item) ? Results.Ok(item) : Results.NotFound());
app.MapMethods("/{**path}",
    [HttpMethods.Get, HttpMethods.Post, HttpMethods.Put, HttpMethods.Patch, HttpMethods.Delete, HttpMethods.Options, HttpMethods.Head],
    async context =>
    {
        if (forwardOrigin is null)
        {
            await HandleMockRequestAsync(context, received);
            return;
        }

        await ForwardAsync(context, forwardingClient, forwardOrigin);
    });

app.Run();

static async Task ForwardAsync(HttpContext context, HttpClient client, Uri forwardOrigin)
{
    var target = new Uri(
        $"{forwardOrigin.AbsoluteUri.TrimEnd('/')}{context.Request.Path}{context.Request.QueryString}",
        UriKind.Absolute);
    using var outbound = new HttpRequestMessage(new HttpMethod(context.Request.Method), target);
    if (context.Request.ContentLength is not null || context.Request.Headers.ContainsKey("Transfer-Encoding"))
    {
        outbound.Content = new StreamContent(context.Request.Body);
    }

    foreach (var header in context.Request.Headers)
    {
        if (!outbound.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray()))
        {
            outbound.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
        }
    }

    using var response = await client.SendAsync(
        outbound,
        HttpCompletionOption.ResponseHeadersRead,
        context.RequestAborted);
    context.Response.StatusCode = (int)response.StatusCode;
    foreach (var header in response.Headers)
    {
        context.Response.Headers[header.Key] = header.Value.ToArray();
    }

    foreach (var header in response.Content.Headers)
    {
        context.Response.Headers[header.Key] = header.Value.ToArray();
    }

    context.Response.Headers.Remove("transfer-encoding");
    await response.Content.CopyToAsync(context.Response.Body, context.RequestAborted);
}

static async Task HandleMockRequestAsync(
    HttpContext context,
    ConcurrentDictionary<Guid, ReceivedRequest> received)
{
    var requestId = Guid.TryParse(context.Request.Headers["X-SF-AI-Request-Id"], out var parsed)
        ? parsed
        : Guid.NewGuid();
    var body = await ReadBodyAsync(context.Request, context.RequestAborted);
    received[requestId] = new ReceivedRequest(
        requestId,
        context.Request.Method,
        $"{context.Request.Path}{context.Request.QueryString}",
        context.Request.Headers.ToDictionary(
            pair => pair.Key,
            pair => pair.Value.Select(value => value ?? string.Empty).ToArray(),
            StringComparer.OrdinalIgnoreCase),
        body,
        DateTimeOffset.UtcNow);

    var scenario = context.Request.Query["scenario"].FirstOrDefault()
        ?? context.Request.Headers["X-Mock-Scenario"].FirstOrDefault()
        ?? "normal-json";
    if (int.TryParse(context.Request.Query["responseDelayMs"].FirstOrDefault(), out var responseDelayMs)
        && responseDelayMs is > 0 and <= 30_000)
    {
        await Task.Delay(TimeSpan.FromMilliseconds(responseDelayMs), context.RequestAborted);
    }

    switch (scenario)
    {
        case "anthropic-sse":
            await WriteSseAsync(context, MockEvents.Anthropic, context.RequestAborted);
            return;
        case "responses-sse":
            await WriteSseAsync(context, MockEvents.Responses, context.RequestAborted);
            return;
        case "chat-sse":
            await WriteSseAsync(context, MockEvents.Chat, context.RequestAborted);
            return;
        case "401":
            await WriteJsonErrorAsync(context, StatusCodes.Status401Unauthorized, "mock_unauthorized");
            return;
        case "429":
            context.Response.Headers["Retry-After"] = "1";
            await WriteJsonErrorAsync(context, StatusCodes.Status429TooManyRequests, "mock_rate_limit");
            return;
        case "500":
            await WriteJsonErrorAsync(context, StatusCodes.Status500InternalServerError, "mock_failure");
            return;
        case "timeout":
            await Task.Delay(TimeSpan.FromMinutes(5), context.RequestAborted);
            return;
        case "mid-stream-disconnect":
            context.Response.ContentType = "text/event-stream";
            await context.Response.WriteAsync("data: {\"partial\":true}\n\n", context.RequestAborted);
            await context.Response.Body.FlushAsync(context.RequestAborted);
            context.Abort();
            return;
        case "redirect":
            context.Response.Redirect("https://api.openai.com/v1/responses", permanent: false);
            return;
        default:
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsJsonAsync(new
            {
                requestId,
                localPort = context.Connection.LocalPort,
                method = context.Request.Method,
                path = $"{context.Request.Path}{context.Request.QueryString}",
                receivedBody = body,
            }, context.RequestAborted);
            return;
    }
}

static async Task<string> ReadBodyAsync(HttpRequest request, CancellationToken cancellationToken)
{
    using var reader = new StreamReader(
        request.Body,
        Encoding.UTF8,
        detectEncodingFromByteOrderMarks: true,
        bufferSize: 16 * 1024,
        leaveOpen: true);
    return await reader.ReadToEndAsync(cancellationToken);
}

static async Task WriteSseAsync(
    HttpContext context,
    IReadOnlyList<string> events,
    CancellationToken cancellationToken)
{
    context.Response.ContentType = "text/event-stream";
    context.Response.Headers["Cache-Control"] = "no-cache";
    foreach (var item in events)
    {
        await context.Response.WriteAsync(item, cancellationToken);
        await context.Response.Body.FlushAsync(cancellationToken);
        await Task.Delay(20, cancellationToken);
    }
}

static Task WriteJsonErrorAsync(HttpContext context, int statusCode, string code)
{
    context.Response.StatusCode = statusCode;
    return context.Response.WriteAsJsonAsync(new { error = new { code } }, context.RequestAborted);
}
