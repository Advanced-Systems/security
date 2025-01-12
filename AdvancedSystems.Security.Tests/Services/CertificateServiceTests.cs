using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Tests.Fixtures;

using Microsoft.Extensions.DependencyInjection;

using Xunit;

namespace AdvancedSystems.Security.Tests.Services;

/// <summary>
///     Tests the public methods in <seealso cref="ICertificateService"/>.
/// </summary>
public sealed class CertificateServiceTests : IClassFixture<CertificateFixture>
{
    private readonly CertificateFixture _sut;

    public CertificateServiceTests(CertificateFixture certificateFixture)
    {
        this._sut = certificateFixture;
    }

    #region Tests

    /// <summary>
    ///     Tests that <seealso cref="ICertificateService.GetCertificate(string, string, bool)"/>
    ///     returns a certificate from the certificate store.
    /// </summary>
    [Fact]
    public void TestGetCertificate_ByThumbprint()
    {
        // Arrange
        string storeService = this._sut.ConfiguredStoreService;
        string thumbprint = "A24421E3B4149A12B219AA67CD263D419829BD53";

        // Act
        var certificateService = this._sut.Host?.Services.GetService<ICertificateService>();
        X509Certificate2? certificate = certificateService?.GetCertificate(storeService, thumbprint, validOnly: false);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.NotNull(certificate);
            Assert.Equal(thumbprint, certificate.Thumbprint);
        });
    }

    #endregion
}