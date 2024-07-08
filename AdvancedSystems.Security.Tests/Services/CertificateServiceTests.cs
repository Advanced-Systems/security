using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Options;
using AdvancedSystems.Security.Tests.Fixtures;

using Xunit;

namespace AdvancedSystems.Security.Tests.Services;

public class CertificateServiceTests : IClassFixture<CertificateFixture>
{
    private readonly CertificateFixture _fixture;

    public CertificateServiceTests(CertificateFixture fixture)
    {
        this._fixture = fixture;
    }

    #region Tests

    [Fact]
    public void TestGetStoreCertificate()
    {

    }

    [Fact]
    public void TestGetStoreCertificate_NotFound()
    {
        // Arrange
        string thumbprint = "123456789";
        var storeName = StoreName.My;
        var storeLocation = StoreLocation.CurrentUser;

        // Act
        var certificate = this._fixture.CertificateService.GetStoreCertificate(thumbprint, storeName, storeLocation);

        // Assert
        Assert.Null(certificate);
    }

    [Fact]
    public void GetConfiguredCertificate()
    {

    }

    [Fact]
    public void GetConfiguredCertificate_NotFound()
    {
        // Arrange
        var options = new CertificateOptions
        {
            Thumbprint = "123456789",
            StoreName = StoreName.My,
            StoreLocation = StoreLocation.CurrentUser
        };

        this._fixture.Options.Setup(x => x.Value)
            .Returns(options);

        // Act
        var certificate = this._fixture.CertificateService.GetConfiguredCertificate();

        // Assert
        Assert.Null(certificate);
    }

    #endregion
}
