using System.Threading.Tasks;

using AdvancedSystems.Security.DependencyInjection;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using Xunit;

namespace AdvancedSystems.Security.Tests.Fixtures;

public class CertificateFixture : IAsyncLifetime
{
    #region Properties

    public string ConfiguredStoreService { get; } = "my/CurrentUser";

    public IHost? Host { get; private set; }

    #endregion

    #region Methods

    public async Task InitializeAsync()
    {
        this.Host = await new HostBuilder()
            .ConfigureWebHost(builder => builder
            .UseTestServer()
            .ConfigureAppConfiguration(config =>
            {
                config.AddJsonFile("appsettings.json", optional: false);
            })
            .ConfigureServices((context, services) =>
            {
                var storeSettings = context.Configuration.GetSection(Sections.CERTIFICATE_STORE);
                services.AddCertificateStore(this.ConfiguredStoreService, storeSettings);
                services.AddCertificateService();
            })
            .Configure(app =>
            {

            }))
            .StartAsync();
    }

    public async Task DisposeAsync()
    {
        if (this.Host is null) return;

        await this.Host.StopAsync();
    }

    #endregion
}