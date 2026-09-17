namespace Sf.EndpointAI.MockLab;

public sealed record ReceivedRequest(
    Guid RequestId,
    string Method,
    string PathAndQuery,
    IReadOnlyDictionary<string, string[]> Headers,
    string Body,
    DateTimeOffset ReceivedAtUtc);

internal static class MockEvents
{
    public static readonly string[] Anthropic =
    [
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_mock\"}}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n",
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
    ];

    public static readonly string[] Responses =
    [
        "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_mock\"}}\n\n",
        "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n",
        "event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n",
    ];

    public static readonly string[] Chat =
    [
        "data: {\"id\":\"chat_mock\",\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n",
        "data: [DONE]\n\n",
    ];
}
