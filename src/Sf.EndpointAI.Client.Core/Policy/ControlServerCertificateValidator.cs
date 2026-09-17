using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sf.EndpointAI.Client.Core.Policy;

public sealed class ControlTlsValidationException(string code, string message) : AuthenticationException(message)
{
    public string Code { get; } = code;
}

public static class ControlServerCertificateValidator
{
    public static bool ValidateAndReturnTrue(
        X509Certificate2? certificate,
        SslPolicyErrors sslPolicyErrors,
        ReadOnlySpan<byte> expectedSpkiSha256,
        DateTimeOffset nowUtc)
    {
        Validate(certificate, sslPolicyErrors, expectedSpkiSha256, nowUtc);
        return true;
    }

    public static byte[] ParsePin(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("A control server SPKI SHA-256 pin is required.", nameof(value));
        }

        byte[] pin;
        try
        {
            pin = Convert.FromBase64String(value);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("The control server SPKI SHA-256 pin is not valid Base64.", nameof(value), exception);
        }

        if (pin.Length != SHA256.HashSizeInBytes)
        {
            CryptographicOperations.ZeroMemory(pin);
            throw new ArgumentException("The control server SPKI SHA-256 pin must contain 32 bytes.", nameof(value));
        }

        return pin;
    }

    public static void Validate(
        X509Certificate2? certificate,
        SslPolicyErrors sslPolicyErrors,
        ReadOnlySpan<byte> expectedSpkiSha256,
        DateTimeOffset nowUtc)
    {
        if (certificate is null)
        {
            throw new ControlTlsValidationException(
                "CONTROL_TLS_PIN_MISMATCH",
                "The control server did not present a certificate.");
        }

        var unacceptableErrors = sslPolicyErrors & ~SslPolicyErrors.RemoteCertificateChainErrors;
        if (unacceptableErrors != SslPolicyErrors.None)
        {
            throw new ControlTlsValidationException(
                "CONTROL_TLS_PIN_MISMATCH",
                "The control server certificate does not match the configured origin.");
        }

        if (nowUtc < certificate.NotBefore.ToUniversalTime()
            || nowUtc > certificate.NotAfter.ToUniversalTime())
        {
            throw new ControlTlsValidationException(
                "CONTROL_TLS_CERTIFICATE_EXPIRED",
                "The control server certificate is not currently valid.");
        }

        using var publicKey = certificate.GetRSAPublicKey();
        if (publicKey is null)
        {
            throw new ControlTlsValidationException(
                "CONTROL_TLS_PIN_MISMATCH",
                "The control server certificate does not contain the expected RSA public key.");
        }

        var subjectPublicKeyInfo = publicKey.ExportSubjectPublicKeyInfo();
        var actualPin = SHA256.HashData(subjectPublicKeyInfo);
        try
        {
            if (expectedSpkiSha256.Length != actualPin.Length
                || !CryptographicOperations.FixedTimeEquals(expectedSpkiSha256, actualPin))
            {
                throw new ControlTlsValidationException(
                    "CONTROL_TLS_PIN_MISMATCH",
                    "The control server certificate public key does not match the configured pin.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
            CryptographicOperations.ZeroMemory(actualPin);
        }
    }
}
