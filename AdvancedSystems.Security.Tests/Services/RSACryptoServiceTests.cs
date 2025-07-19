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

using Moq;

using Xunit;

namespace AdvancedSystems.Security.Tests.Services;

/// <summary>
///     Tests the default implementation of <seealso cref="RSACryptoContract"/>
///     as a service class (<seealso cref="RSACryptoService"/>).
/// </summary>
public sealed class RSACryptoServiceTests : IClassFixture<HostFixture>
{
    private readonly HostFixture _certificateFixture;
    private readonly Mock<ICertificateService> _certificateService = new();
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
        };

        ICertificateService certificateService = this._certificateFixture.Host?.Services.GetService<ICertificateService>()
            ?? throw new InvalidOperationException($"Failed to retrieve {nameof(ICertificateService)} from DI container.");

        // NOTE: Use invalid certificates for testing purposes only
        this._certificateService.Setup(x => x.GetCertificate(rsaOptions.StoreService, rsaOptions.Thumbprint, true))
            .Returns(certificateService.GetCertificate(rsaOptions.StoreService, rsaOptions.Thumbprint, false));

        this._sut = new RSACryptoService(
            this._certificateService.Object,
            Microsoft.Extensions.Options.Options.Create(rsaOptions)
        );

        this._certificateService.VerifyAll();
    }

    #region Tests

    /// <summary>
    ///     Tests that <seealso cref="RSACryptoService"/> encrypts an array of bytes correctly
    ///     by using a pre-configured certificate.
    /// </summary>
    [Fact]
    public void TestEncryptionDecryption_Roundtrip()
    {
        // Arrange
        string message = "Hello, World!";
        Span<byte> buffer = message.GetBytes(Format.String);

        // Act
        Span<byte> cipher = this._sut.Encrypt(buffer);
        Span<byte> source = this._sut.Decrypt(cipher);
        string decryptedMessage = source.ToString(Format.String);

        // Assert
        Assert.Equal(message, decryptedMessage);
    }

    /// <summary>
    ///     Tests that <seealso cref="RSACryptoService"/> signs and verifies an array of bytes
    ///     correctly by using a pre-configured certificate.
    /// </summary>
    [Fact]
    public void TestSigningVerification_Roundtrip()
    {
        // Arrange
        string message = "Hello, World!";
        Span<byte> buffer = message.GetBytes(Format.String);

        // Act
        Span<byte> signature = this._sut.SignData(buffer);
        bool verified = this._sut.VerifyData(buffer, signature);

        // Assert
        Assert.True(verified);
    }

    #endregion
}