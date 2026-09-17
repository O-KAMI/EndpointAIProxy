using System.Threading.Channels;

namespace Sf.EndpointAI.Client.Service;

public sealed class RouteReconciliationSignals
{
    private readonly Channel<RouteReconciliationSignal> _channel = Channel.CreateUnbounded<RouteReconciliationSignal>(
        new UnboundedChannelOptions { SingleReader = true, SingleWriter = false });

    internal ChannelReader<RouteReconciliationSignal> Reader => _channel.Reader;

    public bool Request(string? userSid, string source) =>
        _channel.Writer.TryWrite(new RouteReconciliationSignal(userSid, source));

    internal void Complete() => _channel.Writer.TryComplete();
}

internal sealed record RouteReconciliationSignal(string? UserSid, string Source);
