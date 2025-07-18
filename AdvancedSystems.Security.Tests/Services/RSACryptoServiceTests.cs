using System;
using System.Security.Cryptography;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Cryptography;
using AdvancedSystems.Security.Extensions;
using AdvancedSystems.Security.Options;
using AdvancedSystems.Security.Services;
using AdvancedSystems.Security.Tests.Fixtures;
using AdvancedSystems.Security.Tests.Helpers;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using Moq;

using Xunit;

namespace AdvancedSystems.Security.Tests.Services;

/// <summary>
///     Tests the public methods in <seealso cref="RSACryptoService"/>.
/// </summary>
public sealed class RSACryptoServiceTests : IClassFixture<HostFixture>
{
    private readonly HostFixture _certificateFixture;
    private readonly Mock<ILogger<RSACryptoService>> _logger = new();
    private readonly RSACryptoService _sut;

    public RSACryptoServiceTests(HostFixture certificateFixture)
    {
        this._certificateFixture = certificateFixture;

        var rsaOptions = new RSACryptoOptions
        {
            HashFunction = HashFunction.SHA256,
            EncryptionPadding = RSAEncryptionPadding.OaepSHA256,
            SignaturePadding = RSASignaturePadding.Pss,
            Thumbprint = Certificates.PasswordCertificateThumbprint,
            StoreService = this._certificateFixture.ConfiguredStoreService,
            ValidOnly = false,
        };

        ICertificateService certificateService = this._certificateFixture.Host?.Services.GetService<ICertificateService>()
            ?? throw new InvalidOperationException($"Failed to retrieve {nameof(ICertificateService)} from DI container.");

        this._sut = new RSACryptoService(
            this._logger.Object,
            certificateService,
            Microsoft.Extensions.Options.Options.Create(rsaOptions)
        );
    }

    #region Tests

    /// <summary>
    ///     Tests that <seealso cref="RSACryptoContract"/> encrypts an array of bytes correctly
    ///     by using a pre-configured certificate.
    /// </summary>
    [Fact]
    public void TestEncryptionDecryption_Roundtrip()
    {
        // Arrange
        string message = "Hello, World!";
        byte[] buffer = message.GetBytes(Format.String);

        // Act
        byte[] cipher = this._sut.Encrypt(buffer);
        byte[] source = this._sut.Decrypt(cipher);
        string decryptedMessage = source.ToString(Format.String);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.NotEmpty(cipher);
            Assert.NotEmpty(source);
            Assert.Equal(message, decryptedMessage);
        });
    }

    #endregion
}