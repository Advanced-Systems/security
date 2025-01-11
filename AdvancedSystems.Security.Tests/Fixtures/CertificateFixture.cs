using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Services;

using Microsoft.Extensions.Logging;

using Moq;

namespace AdvancedSystems.Security.Tests.Fixtures;

public class CertificateFixture
{
    public CertificateFixture()
    {
        this.Logger = new Mock<ILogger<CertificateService>>();
        this.Store = new Mock<ICertificateStore>();
        this.CertificateService = new CertificateService(this.Logger.Object, this.Store.Object);
    }

    #region Properties

    public Mock<ILogger<CertificateService>> Logger { get; private set; }

    public ICertificateService CertificateService { get; private set; }

    public Mock<ICertificateStore> Store { get; private set; }

    #endregion

    #region Helper Methods

    public static X509Certificate2 CreateCertificate(string subjectName)
    {
        using var ecdsa = ECDsa.Create();
        var request = new CertificateRequest(subjectName, ecdsa, HashAlgorithmName.SHA256);
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));
        return certificate;
    }

    public static X509Certificate2Collection CreateCertificateCollection(int length)
    {
        var certificates = Enumerable.Range(0, length)
            .Select(_ => CreateCertificate("O=AdvancedSystems"))
            .ToArray();

        return new X509Certificate2Collection(certificates);
    }

    #endregion
}