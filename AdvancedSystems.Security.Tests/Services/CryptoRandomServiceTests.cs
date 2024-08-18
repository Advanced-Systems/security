using System;
using System.Linq;
using System.Threading.Tasks;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.DependencyInjection;
using AdvancedSystems.Security.Tests.Fixtures;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

using Xunit;

namespace AdvancedSystems.Security.Tests.Services;

public class CryptoRandomServiceTests : IClassFixture<CryptoRandomFixture>
{
    private readonly CryptoRandomFixture _sut;

    public CryptoRandomServiceTests(CryptoRandomFixture fixture)
    {
        this._sut = fixture;
    }

    #region Tests

    [Fact]
    public void TestGetBytes()
    {
        // Arrange
        int length = 32;

        // Act
        Span<byte> buffer = this._sut.CryptoRandomService.GetBytes(length);

        // Assert
        Assert.Equal(length, buffer.Length);
    }

    [Fact]
    public void TestGetInt32()
    {
        // Arrange

        // Act
        int randomNumber = this._sut.CryptoRandomService.GetInt32();

        // Assert
        Assert.InRange(randomNumber, int.MinValue, int.MaxValue - 1);
    }

    [Fact]
    public void TestGetInt32_MinMax()
    {
        // Arrange
        int min = 10;
        int max = 99;

        // Act
        int randomNumber = this._sut.CryptoRandomService.GetInt32(min, max);

        // Assert
        Assert.InRange(randomNumber, min, max - 1);
    }

    [Fact]
    public void TestShuffle()
    {
        // Arrange
        int[] array1 = Enumerable.Range(1, 100).ToArray();
        int[] array2 = Enumerable.Range(1, 100).ToArray();

        // Act
        this._sut.CryptoRandomService.Shuffle<int>(array1);

        // Assert
        Assert.NotEqual(array1, array2);
    }

    [Fact]
    public void TestChoice()
    {
        // Arrange
        int[] array = Enumerable.Range(1, 100).ToArray();
        int min = array.Min();
        int max = array.Max();

        // Act
        int randomNumber = this._sut.CryptoRandomService.Choice<int>(array);

        // Assert
        Assert.Contains(randomNumber, array);
        Assert.InRange(randomNumber, min, max - 1);
    }

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
}
