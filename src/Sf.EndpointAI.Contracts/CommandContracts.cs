namespace Sf.EndpointAI.Contracts;

public sealed record DeviceEnrollmentRequest(
    int SchemaVersion,
    Guid DeviceId,
    string Hostname,
    string ServiceVersion);

public sealed record DeviceEnrollmentResponse(
    Guid DeviceId,
    string DeviceToken,
    DateTimeOffset EnrolledAtUtc);

public sealed record RemoteCommandPayload(
    int SchemaVersion,
    Guid CommandId,
    Guid DeviceId,
    RemoteCommandType Type,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc);

public sealed record SignedRemoteCommand(
    RemoteCommandPayload Payload,
    string Signature);

public sealed record RemoteCommandStatusUpdate(
    int SchemaVersion,
    Guid DeviceId,
    Guid CommandId,
    RemoteCommandStatus Status,
    DateTimeOffset ObservedAtUtc,
    string? ResultCode,
    string? ResultSummary);
