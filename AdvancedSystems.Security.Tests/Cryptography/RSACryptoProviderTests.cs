using System;

using AdvancedSystems.Security.Cryptography;
using AdvancedSystems.Security.Extensions;
using AdvancedSystems.Security.Tests.Fixtures;

using Xunit;

namespace AdvancedSystems.Security.Tests.Cryptography;

/// <summary>
///     Tests the public methods in <seealso cref="RSACryptoProvider"/>.
/// </summary>
public sealed class RSACryptoProviderTests : IClassFixture<RSACryptoProviderFixture>
{
    private readonly RSACryptoProviderFixture _sut;

    public RSACryptoProviderTests(RSACryptoProviderFixture rsaCryptoProviderFixture)
    {
        this._sut = rsaCryptoProviderFixture;
    }

    #region Tests

    /// <summary>
    ///     Tests that <seealso cref="RSACryptoProvider"/> encrypts an array of bytes correctly
    ///     by using a pre-configured certificate.
    /// </summary>
    [Fact]
    public void TestEncryptionDecryption_Roundtrip()
    {
        // Arrange
        string message = "Hello, World!";
        Span<byte> buffer = message.GetBytes(Format.String);

        // Act
        Span<byte> cipher = this._sut.RSACryptoProvider.Encrypt(buffer);
        Span<byte> source = this._sut.RSACryptoProvider.Decrypt(cipher);
        string decryptedMessage = source.ToString(Format.String);

        // Assert
        Assert.Equal(message, decryptedMessage);
    }

    /// <summary>
    ///     Tests that <seealso cref="RSACryptoProvider"/> signs and verifies an array of bytes
    ///     correctly by using a pre-configured certificate.
    /// </summary>
    [Fact]
    public void TestSigningVerification_Roundtrip()
    {
        // Arrange
        string message = "Hello, World!";
        Span<byte> buffer = message.GetBytes(Format.String);

        // Act
        Span<byte> signature = this._sut.RSACryptoProvider.SignData(buffer);
        bool verified = this._sut.RSACryptoProvider.VerifyData(buffer, signature);

        // Assert
        Assert.True(verified);
    }

    #endregion
}