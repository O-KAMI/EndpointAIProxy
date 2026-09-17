namespace Sf.EndpointAI.Client.Service;

public sealed class OperationalLogFileTracker
{
    private string? _activePath;

    public string? ActivePath => Volatile.Read(ref _activePath);

    public void SetActive(string path) =>
        Volatile.Write(ref _activePath, Path.GetFullPath(path));

    public void Clear(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (string.Equals(ActivePath, fullPath, StringComparison.OrdinalIgnoreCase))
        {
            Volatile.Write(ref _activePath, null);
        }
    }

    public bool IsActive(string path) =>
        string.Equals(ActivePath, Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase);
}
