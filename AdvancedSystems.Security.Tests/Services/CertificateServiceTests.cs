using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.DependencyInjection;
using AdvancedSystems.Security.Options;
using AdvancedSystems.Security.Tests.Fixtures;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

using Moq;

using Xunit;

namespace AdvancedSystems.Security.Tests.Services;

public class CertificateServiceTests : IClassFixture<CertificateFixture>
{
    private readonly CertificateFixture _sut;

    public CertificateServiceTests(CertificateFixture fixture)
    {
        this._sut = fixture;
    }

    #region Tests

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
        Assert.NotNull(certificate);
        Assert.Equal(thumbprint, certificate.Thumbprint);
        this._sut.Store.Verify(service => service.Open(It.Is<OpenFlags>(flags => flags == OpenFlags.ReadOnly)));
    }

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
        Assert.NotNull(certificate);
        Assert.Equal(certificateOptions.Thumbprint, certificate.Thumbprint);
        this._sut.Store.Verify(service => service.Open(It.Is<OpenFlags>(flags => flags == OpenFlags.ReadOnly)));
    }

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

    [Fact]
    public async Task TestAddCertificateService_FromOptions()
    {
        // Arrange
        using var hostBuilder = await new HostBuilder()
            .ConfigureWebHost(builder => builder
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddCertificateService(options =>
                    {
                        options.Thumbprint = "123456789";
                        options.Store = new CertificateStoreOptions
                        {
                            Location = StoreLocation.CurrentUser,
                            Name = StoreName.My,
                        };
                    });
                })
            .Configure(app =>
            {

            }))
            .StartAsync();

        // Act
        var certificateService = hostBuilder.Services.GetService<ICertificateService>();
        var certificate = certificateService?.GetConfiguredCertificate();

        // Assert
        Assert.NotNull(certificateService);
        Assert.Null(certificate);
        await hostBuilder.StopAsync();
    }

    [Fact]
    public async Task TestAddCertificateService_FromAppSettings()
    {
        // Arrange
        using var hostBuilder = await new HostBuilder()
            .ConfigureWebHost(builder => builder
                .UseTestServer()
                .ConfigureAppConfiguration(config =>
                {
                    config.AddJsonFile("appsettings.json", optional: false);
                })
                .ConfigureServices((context, services) =>
                {
                    services.AddCertificateService(context.Configuration);
                })
            .Configure(app =>
            {

            }))
            .StartAsync();

        // Act
        var certificateService = hostBuilder.Services.GetService<ICertificateService>();
        var certificate = certificateService?.GetConfiguredCertificate();

        // Assert
        Assert.NotNull(certificateService);
        Assert.Null(certificate);
        await hostBuilder.StopAsync();
    }

    #endregion
}