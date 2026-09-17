using System.Text.Json;

namespace Sf.EndpointAI.Contracts;

public sealed record EndpointEvent(
    Guid EventId,
    DateTimeOffset OccurredAtUtc,
    EventSeverity Severity,
    string Type,
    string Code,
    string Summary,
    string? UserSid,
    Guid? AgentInstanceId,
    IReadOnlyDictionary<string, JsonElement>? Details);

public sealed record EventBatchRequest(
    int SchemaVersion,
    Guid BatchId,
    Guid DeviceId,
    IReadOnlyList<EndpointEvent> Events);

public sealed record EventBatchResponse(
    int Accepted,
    int Duplicates,
    int Rejected,
    IReadOnlyList<ApiError> Errors);

public sealed record ApiError(string Code, string Message, string? TraceId = null);

public sealed record ApiErrorEnvelope(ApiError Error);
