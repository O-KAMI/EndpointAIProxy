using System.Security.Cryptography;
using System.Text;

namespace Sf.EndpointAI.Client.Core.Security;

/// <summary>
/// Protects local state with an AES key stored in a machine-owned file. The
/// installer must keep the containing directory restricted to root.
/// </summary>
public sealed class FileKeyTextProtector : ITextProtector
{
    private const byte FormatVersion = 1;
    private const int KeyLength = 32;
    private const int NonceLength = 12;
    private const int TagLength = 16;
    private readonly byte[] _key;

    public FileKeyTextProtector(string keyPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyPath);
        _key = LoadOrCreateKey(Path.GetFullPath(keyPath));
    }

    public byte[] Protect(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        var clear = Encoding.UTF8.GetBytes(value);
        var nonce = RandomNumberGenerator.GetBytes(NonceLength);
        var cipher = new byte[clear.Length];
        var tag = new byte[TagLength];
        using var aes = new AesGcm(_key, TagLength);
        aes.Encrypt(nonce, clear, cipher, tag);

        var protectedValue = new byte[1 + NonceLength + TagLength + cipher.Length];
        protectedValue[0] = FormatVersion;
        nonce.CopyTo(protectedValue, 1);
        tag.CopyTo(protectedValue, 1 + NonceLength);
        cipher.CopyTo(protectedValue, 1 + NonceLength + TagLength);
        CryptographicOperations.ZeroMemory(clear);
        return protectedValue;
    }

    public string Unprotect(byte[] protectedValue)
    {
        ArgumentNullException.ThrowIfNull(protectedValue);
        if (protectedValue.Length < 1 + NonceLength + TagLength
            || protectedValue[0] != FormatVersion)
        {
            throw new CryptographicException("The protected value format is invalid.");
        }

        var clear = new byte[protectedValue.Length - 1 - NonceLength - TagLength];
        using var aes = new AesGcm(_key, TagLength);
        aes.Decrypt(
            protectedValue.AsSpan(1, NonceLength),
            protectedValue.AsSpan(1 + NonceLength + TagLength),
            protectedValue.AsSpan(1 + NonceLength, TagLength),
            clear);
        try
        {
            return Encoding.UTF8.GetString(clear);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clear);
        }
    }

    private static byte[] LoadOrCreateKey(string keyPath)
    {
        var parent = Path.GetDirectoryName(keyPath)
            ?? throw new InvalidOperationException("The key path has no parent directory.");
        Directory.CreateDirectory(parent);
        if (File.Exists(keyPath))
        {
            return ValidateKey(File.ReadAllBytes(keyPath));
        }

        var key = RandomNumberGenerator.GetBytes(KeyLength);
        var temporaryPath = Path.Combine(parent, $".{Path.GetFileName(keyPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: KeyLength,
                FileOptions.WriteThrough))
            {
                stream.Write(key);
                stream.Flush(flushToDisk: true);
            }

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(temporaryPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            try
            {
                File.Move(temporaryPath, keyPath);
            }
            catch (IOException) when (File.Exists(keyPath))
            {
                CryptographicOperations.ZeroMemory(key);
                return ValidateKey(File.ReadAllBytes(keyPath));
            }

            return key;
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static byte[] ValidateKey(byte[] key)
    {
        if (key.Length != KeyLength)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new CryptographicException("The machine protection key has an invalid length.");
        }

        return key;
    }
}
