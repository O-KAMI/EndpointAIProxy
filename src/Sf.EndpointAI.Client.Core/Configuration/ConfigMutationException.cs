namespace Sf.EndpointAI.Client.Core.Configuration;

public sealed class ConfigMutationException(string code, string message, Exception? innerException = null)
    : Exception(message, innerException)
{
    public string Code { get; } = code;
}

public sealed record ConfigTransformResult(
    byte[] Content,
    string? PreviousValue,
    string InjectedValue,
    bool Changed);
