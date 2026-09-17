using Sf.EndpointAI.Client.Core.Diagnostics;

namespace Sf.EndpointAI.UnitTests;

public sealed class DiagnosticCollectionLockTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"sf-diagnostics-lock-{Guid.NewGuid():N}");

    public DiagnosticCollectionLockTests() => Directory.CreateDirectory(_root);

    [Fact]
    public void Exclusive_file_lock_rejects_concurrent_collection_and_recovers_after_release()
    {
        using var first = DiagnosticCollectionLock.TryAcquire(_root);

        Assert.NotNull(first);
        Assert.Null(DiagnosticCollectionLock.TryAcquire(_root));

        first.Dispose();
        using var recovered = DiagnosticCollectionLock.TryAcquire(_root);
        Assert.NotNull(recovered);
    }

    [Fact]
    public void Install_directory_uses_process_path_instead_of_single_file_extraction_directory()
    {
        var resolved = DiagnosticPathResolver.ResolveInstallDirectory(
            @"C:\Program Files\SF\Endpoint AI Proxy\Sf.EndpointAI.Client.Service.exe",
            @"C:\Windows\SystemTemp\.net\Sf.EndpointAI.Client.Service\random\");

        Assert.Equal(@"C:\Program Files\SF\Endpoint AI Proxy", resolved);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }
}
