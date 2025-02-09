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
        byte[] buffer = message.GetBytes(Format.String);

        // Act
        byte[] cipher = this._sut.RSACryptoProvider.Encrypt(buffer);
        byte[] source = this._sut.RSACryptoProvider.Decrypt(cipher);
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