using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AdvancedSystems.Security.Tests.Helpers;

internal static class Certificates
{
    internal const string PasswordCertificateThumbprint = "2BFC1C18AC1A99E4284D07F1D2F0312C8EAB33FC";

    internal static X509Certificate2 CreateSelfSignedCertificate(string subject)
    {
        using var csdsa = ECDsa.Create();
        var request = new CertificateRequest(subject, csdsa, HashAlgorithmName.SHA256);
        var validFrom = DateTimeOffset.UtcNow;
        X509Certificate2 certificate = request.CreateSelfSigned(validFrom, validFrom.AddHours(1));
        return certificate;
    }
}