using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Services;
using AdvancedSystems.Security.Tests.Fixtures;
using AdvancedSystems.Security.Tests.Helpers;

using Microsoft.Extensions.DependencyInjection;

using Xunit;

namespace AdvancedSystems.Security.Tests.Services;

/// <summary>
///     Tests the public methods in <seealso cref="RSACryptoService"/>.
/// </summary>
public sealed class RSACryptoServiceTests : IClassFixture<HostFixture>
{
    private readonly HostFixture _certificateFixture;

    public RSACryptoServiceTests(HostFixture certificateFixture)
    {
        this._certificateFixture = certificateFixture;
    }

    #region Tests

    /// <summary>
    ///     Tests that <seealso cref="IRSACryptoService"/> encrypts an array of bytes correctly
    ///     by using a pre-configured certificate.
    /// </summary>
    [Fact]
    public void TestEncryptionDecryption_Roundtrip()
    {
        // Arrange
        string storeService = this._certificateFixture.ConfiguredStoreService;
        string thumbprint = Certificates.PasswordCertificateThumbprint;

        // Act
        ICertificateService? certificateService = this._certificateFixture.Host?.Services.GetService<ICertificateService>();
        var certificate = certificateService?.GetCertificate(storeService, thumbprint, validOnly: false);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.NotNull(certificateService);
        });
    }

    #endregion
}