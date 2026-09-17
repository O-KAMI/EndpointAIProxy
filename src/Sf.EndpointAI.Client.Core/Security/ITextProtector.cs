namespace Sf.EndpointAI.Client.Core.Security;

public interface ITextProtector
{
    byte[] Protect(string value);

    string Unprotect(byte[] protectedValue);
}
