using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.DependencyInjection;
using AdvancedSystems.Security.Tests.Fixtures;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

using Xunit;

namespace AdvancedSystems.Security.Tests.Services;

public class CertificateStoreTests : IClassFixture<CertificateStoreFixture>
{
    private readonly CertificateStoreFixture _sut;

    public CertificateStoreTests(CertificateStoreFixture fixture)
    {
        this._sut = fixture;
    }

    #region Tests

    [Fact]
    public async Task TestAddCertificateStore_FromOptions()
    {
        // Arrange
        using var hostBuilder = await new HostBuilder()
            .ConfigureWebHost(builder => builder
            .UseTestServer()
            .ConfigureServices(services =>
            {
                services.AddCertificateStore(options =>
                {
                    options.Name = StoreName.My;
                    options.Location = StoreLocation.CurrentUser;
                });
            })
            .Configure(app =>
            {

            }))
            .StartAsync();

        // Act
        var certificateStore = hostBuilder.Services.GetService<ICertificateStore>();

        // Assert
        Assert.NotNull(certificateStore);
        await hostBuilder.StopAsync();
    }

    [Fact]
    public async Task TestAddCertificateStore_FromAppSettings()
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
                services.AddCertificateStore(context.Configuration.GetSection($"{Sections.CERTIFICATE}:{Sections.STORE}"));
            })
            .Configure(app =>
            {

            }))
            .StartAsync();

        // Act
        var certificateStore = hostBuilder.Services.GetService<ICertificateStore>();

        // Assert
        Assert.NotNull(certificateStore);
        await hostBuilder.StopAsync();
    }

    #endregion
}