using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

if (args.Length == 0 || !string.Equals(args[0], "ensure", StringComparison.OrdinalIgnoreCase))
{
    Console.Error.WriteLine("Usage: ensure --ip <address> --pfx <path> --cer <path> --password <value> [--days <1-825>]");
    return 1;
}

var options = ParseOptions(args[1..]);
var ipAddress = IPAddress.Parse(GetRequired(options, "ip"));
var pfxPath = Path.GetFullPath(GetRequired(options, "pfx"));
var cerPath = Path.GetFullPath(GetRequired(options, "cer"));
var password = GetRequired(options, "password");
var days = options.TryGetValue("days", out var daysText) && int.TryParse(daysText, out var parsedDays)
    ? parsedDays
    : 365;
if (days is < 1 or > 825)
{
    throw new ArgumentException("Certificate validity must be between 1 and 825 days.");
}

Directory.CreateDirectory(Path.GetDirectoryName(pfxPath)
    ?? throw new InvalidOperationException("The PFX path has no parent directory."));
Directory.CreateDirectory(Path.GetDirectoryName(cerPath)
    ?? throw new InvalidOperationException("The CER path has no parent directory."));

if (!File.Exists(pfxPath))
{
    using var rsa = RSA.Create(3072);
    var request = new CertificateRequest(
        $"CN={ipAddress}",
        rsa,
        HashAlgorithmName.SHA256,
        RSASignaturePadding.Pkcs1);
    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
    request.CertificateExtensions.Add(new X509KeyUsageExtension(
        X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
        true));
    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
        new OidCollection { new("1.3.6.1.5.5.7.3.1", "Server Authentication") },
        true));
    var subjectAlternativeName = new SubjectAlternativeNameBuilder();
    subjectAlternativeName.AddIpAddress(ipAddress);
    request.CertificateExtensions.Add(subjectAlternativeName.Build(true));
    request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

    var now = DateTimeOffset.UtcNow;
    using var certificate = request.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(days));
    File.WriteAllBytes(pfxPath, certificate.Export(X509ContentType.Pfx, password));
}

using var installedCertificate = X509CertificateLoader.LoadPkcs12FromFile(
    pfxPath,
    password,
    X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
Validate(installedCertificate, ipAddress, DateTimeOffset.UtcNow);
File.WriteAllBytes(cerPath, installedCertificate.Export(X509ContentType.Cert));

using var publicKey = installedCertificate.GetRSAPublicKey()
    ?? throw new InvalidOperationException("The certificate does not contain an RSA public key.");
var spkiSha256 = Convert.ToBase64String(SHA256.HashData(publicKey.ExportSubjectPublicKeyInfo()));
Console.WriteLine(JsonSerializer.Serialize(new
{
    CertificatePath = pfxPath,
    PublicCertificatePath = cerPath,
    Subject = installedCertificate.Subject,
    installedCertificate.SerialNumber,
    installedCertificate.NotBefore,
    installedCertificate.NotAfter,
    RsaKeySize = publicKey.KeySize,
    SpkiSha256 = spkiSha256,
}));
return 0;

static Dictionary<string, string> ParseOptions(string[] values)
{
    var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    for (var index = 0; index < values.Length; index += 2)
    {
        if (index + 1 >= values.Length || !values[index].StartsWith("--", StringComparison.Ordinal))
        {
            throw new ArgumentException("Certificate tool options must use --name value pairs.");
        }

        result[values[index][2..]] = values[index + 1];
    }

    return result;
}

static string GetRequired(IReadOnlyDictionary<string, string> values, string name)
    => values.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
        ? value
        : throw new ArgumentException($"The --{name} option is required.");

static void Validate(X509Certificate2 certificate, IPAddress expectedIpAddress, DateTimeOffset nowUtc)
{
    if (!certificate.HasPrivateKey)
    {
        throw new InvalidOperationException("The control server certificate has no private key.");
    }

    if (nowUtc < certificate.NotBefore.ToUniversalTime() || nowUtc > certificate.NotAfter.ToUniversalTime())
    {
        throw new InvalidOperationException("The control server certificate is not currently valid.");
    }

    using var rsa = certificate.GetRSAPrivateKey()
        ?? throw new InvalidOperationException("The control server certificate must use RSA.");
    if (rsa.KeySize != 3072)
    {
        throw new InvalidOperationException("The control server certificate must use RSA 3072.");
    }

    var basicConstraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault()
        ?? throw new InvalidOperationException("The control server certificate has no Basic Constraints extension.");
    if (basicConstraints.CertificateAuthority)
    {
        throw new InvalidOperationException("The control server certificate must be a leaf certificate.");
    }

    var eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault()
        ?? throw new InvalidOperationException("The control server certificate has no EKU extension.");
    if (eku.EnhancedKeyUsages.Count != 1
        || !string.Equals(eku.EnhancedKeyUsages[0]?.Value, "1.3.6.1.5.5.7.3.1", StringComparison.Ordinal))
    {
        throw new InvalidOperationException("The control server certificate EKU must contain only Server Authentication.");
    }

    var san = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().SingleOrDefault()
        ?? throw new InvalidOperationException("The control server certificate has no SAN extension.");
    var ipAddresses = san.EnumerateIPAddresses().ToArray();
    if (ipAddresses.Length != 1 || !ipAddresses[0].Equals(expectedIpAddress))
    {
        throw new InvalidOperationException("The control server certificate SAN must contain only the configured IP address.");
    }
}
