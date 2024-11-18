using System.Linq;
using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Options;
using AdvancedSystems.Security.Tests.Fixtures;

using Moq;

using Xunit;

namespace AdvancedSystems.Security.Tests.Services;

/// <summary>
///     Tests the public methods in <seealso cref="ICertificateService"/>.
/// </summary>
public sealed class CertificateServiceTests : IClassFixture<CertificateFixture>
{
    private readonly CertificateFixture _sut;

    public CertificateServiceTests(CertificateFixture fixture)
    {
        this._sut = fixture;
    }

    #region Tests

    /// <summary>
    ///     Tests that <seealso cref="ICertificateService.GetStoreCertificate(string, StoreName, StoreLocation)"/>
    ///     returns a mocked certificate from the certificate store.
    /// </summary>
    [Fact]
    public void TestGetStoreCertificate()
    {
        // Arrange
        var certificates = CertificateFixture.CreateCertificateCollection(3);
        string thumbprint = certificates.Select(x => x.Thumbprint).First();
        this._sut.Store.Setup(x => x.Certificates)
            .Returns(certificates);

        // Act
        var certificate = this._sut.CertificateService.GetStoreCertificate(thumbprint, StoreName.My, StoreLocation.CurrentUser);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.NotNull(certificate);
            Assert.Equal(thumbprint, certificate.Thumbprint);
        });

        this._sut.Store.Verify(service => service.Open(It.Is<OpenFlags>(flags => flags == OpenFlags.ReadOnly)));
    }

    /// <summary>
    ///     Tests that <seealso cref="ICertificateService.GetStoreCertificate(string, StoreName, StoreLocation)"/>
    ///     returns <see langword="null"/> if a certificate could not be found in the certificate store.
    /// </summary>
    [Fact]
    public void TestGetStoreCertificate_NotFound()
    {
        // Arrange
        string thumbprint = "123456789";
        var storeName = StoreName.My;
        var storeLocation = StoreLocation.CurrentUser;
        this._sut.Store.Setup(x => x.Certificates)
            .Returns(new X509Certificate2Collection());

        // Act
        var certificate = this._sut.CertificateService.GetStoreCertificate(thumbprint, storeName, storeLocation);

        // Assert
        Assert.Null(certificate);
    }

    /// <summary>
    ///     Tests that <seealso cref="ICertificateService.GetConfiguredCertificate()"/>
    ///     returns a mocked certificate from the certificate store.
    /// </summary>
    [Fact]
    public void GetConfiguredCertificate()
    {
        // Arrange
        var certificates = CertificateFixture.CreateCertificateCollection(3);
        var certificateOptions = new CertificateOptions
        {
            Thumbprint = certificates.Select(x => x.Thumbprint).First(),
            Store = new CertificateStoreOptions
            {
                Location = StoreLocation.CurrentUser,
                Name = StoreName.My,
            }
        };

        this._sut.Options.Setup(x => x.Value)
            .Returns(certificateOptions);

        this._sut.Store.Setup(x => x.Certificates)
            .Returns(certificates);

        // Act
        var certificate = this._sut.CertificateService.GetConfiguredCertificate();

        // Assert
        Assert.Multiple(() =>
        {
            Assert.NotNull(certificate);
            Assert.Equal(certificateOptions.Thumbprint, certificate.Thumbprint);
        });

        this._sut.Store.Verify(service => service.Open(It.Is<OpenFlags>(flags => flags == OpenFlags.ReadOnly)));
    }

    /// <summary>
    ///     Tests that <seealso cref="ICertificateService.GetConfiguredCertificate()"/>
    ///     returns <see langword="null"/> if a certificate could not be found in the certificate store.
    /// </summary>
    [Fact]
    public void GetConfiguredCertificate_NotFound()
    {
        // Arrange
        var certificateOptions = new CertificateOptions
        {
            Thumbprint = "123456789",
            Store = new CertificateStoreOptions
            {
                Location = StoreLocation.CurrentUser,
                Name = StoreName.My,
            }
        };

        this._sut.Options.Setup(x => x.Value)
            .Returns(certificateOptions);

        this._sut.Store.Setup(x => x.Certificates)
            .Returns(new X509Certificate2Collection());

        // Act
        var certificate = this._sut.CertificateService.GetConfiguredCertificate();

        // Assert
        Assert.Null(certificate);
    }

    #endregion
}