using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.DependencyInjection;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

using Xunit;

namespace AdvancedSystems.Security.Tests.DependencyInjection;

/// <summary>
///     Tests the public methods in <seealso cref="Security.DependencyInjection.ServiceCollectionExtensions"/>.
/// </summary>
public sealed class ServiceCollectionExtensionsTests
{
    #region AddCertificateService Tests

    /// <summary>
    ///     Tests that <seealso cref="ICertificateService"/> can be initialized through dependency injection.
    /// </summary>
    [Fact]
    public async Task TestAddCertificateService_FromOptions()
    {
        // Arrange
        string storeService = "my/CurrentUser";
        string thumbprint = "A24421E3B4149A12B219AA67CD263D419829BD53";

        using var hostBuilder = await new HostBuilder()
            .ConfigureWebHost(builder => builder
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddCertificateStore(storeService, options =>
                    {
                        options.Location = StoreLocation.CurrentUser;
                        options.Name = StoreName.My;
                    });

                    services.AddCertificateService();
                })
            .Configure(app =>
            {

            }))
            .StartAsync();

        // Act
        var certificateService = hostBuilder.Services.GetService<ICertificateService>();
        var certificate = certificateService?.GetCertificate(storeService, thumbprint, validOnly: false);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.NotNull(certificateService);
            Assert.NotNull(certificate);
        });

        await hostBuilder.StopAsync();
    }

    #endregion

    #region AddCertificateStore Tests

    /// <summary>
    ///     Tests that <seealso cref="ICertificateStore"/> can be initialized through dependency injection from configuration options.
    /// </summary>
    [Fact]
    public async Task TestAddCertificateStore_FromOptions()
    {
        // Arrange
        string storeService = "my/CurrentUser";

        using var hostBuilder = await new HostBuilder()
            .ConfigureWebHost(builder => builder
            .UseTestServer()
            .ConfigureServices(services =>
            {
                services.AddCertificateStore(storeService, options =>
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
        var certificateStore = hostBuilder.Services.GetKeyedService<ICertificateStore>(storeService);

        // Assert
        Assert.NotNull(certificateStore);
        await hostBuilder.StopAsync();
    }

    /// <summary>
    ///     Tests that <seealso cref="ICertificateStore"/> can be initialized through dependency injection from configuration sections.
    /// </summary>
    [Fact]
    public async Task TestAddCertificateStore_FromAppSettings()
    {
        // Arrange
        string storeService = "my/CurrentUser";

        using var hostBuilder = await new HostBuilder()
            .ConfigureWebHost(builder => builder
            .UseTestServer()
            .ConfigureAppConfiguration(config =>
            {
                config.AddJsonFile("appsettings.json", optional: false);
            })
            .ConfigureServices((context, services) =>
            {
                var storeSettings = context.Configuration.GetSection(Sections.CERTIFICATE_STORE);
                services.AddCertificateStore(storeService, storeSettings);
            })
            .Configure(app =>
            {

            }))
            .StartAsync();

        // Act
        var certificateStore = hostBuilder.Services.GetKeyedService<ICertificateStore>(storeService);

        // Assert
        Assert.NotNull(certificateStore);
        await hostBuilder.StopAsync();
    }

    #endregion

    #region AddCryptoRandomService Tests

    /// <summary>
    ///     Tests that <seealso cref="ICryptoRandomService"/> can be initialized through dependency injection.
    /// </summary>
    [Fact]
    public async Task TestAddCryptoRandomService()
    {
        // Arrange
        using var hostBuilder = await new HostBuilder()
            .ConfigureWebHost(builder =>
            {
                builder.UseTestServer();
                builder.ConfigureServices(services =>
                {
                    services.AddCryptoRandomService();
                });
                builder.Configure(app =>
                {

                });
            })
            .StartAsync();

        // Act
        var cryptoRandomService = hostBuilder.Services.GetService<ICryptoRandomService>();

        // Assert
        Assert.NotNull(cryptoRandomService);
        await hostBuilder.StopAsync();
    }

    #endregion

    #region AddHashService Tests

    /// <summary>
    ///     Tests that <seealso cref="IHashService"/> can be initialized through dependency injection.
    /// </summary>
    [Fact]
    public async Task TestAddHashService()
    {
        // Arrange
        using var hostBuilder = await new HostBuilder()
            .ConfigureWebHost(builder => builder
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddHashService();
                })
                .Configure(app =>
                {

                }))
                .StartAsync();

        string input = "The quick brown fox jumps over the lazy dog";
        byte[] buffer = Encoding.UTF8.GetBytes(input);

        // Act
        var hashService = hostBuilder.Services.GetService<IHashService>();
        string? sha256 = hashService?.GetSHA256Hash(buffer);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.NotNull(hashService);
            Assert.Equal("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", sha256);
        });

        await hostBuilder.StopAsync();
    }

    #endregion
}