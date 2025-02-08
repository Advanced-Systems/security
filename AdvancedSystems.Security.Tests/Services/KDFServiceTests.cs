using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Cryptography;
using AdvancedSystems.Security.Extensions;
using AdvancedSystems.Security.Tests.Fixtures;

using Xunit;

namespace AdvancedSystems.Security.Tests.Services;

/// <summary>
///     Tests the public methods in <seealso cref="IKDFService"/>.
/// </summary>
public sealed class KDFServiceTests : IClassFixture<KDFServiceFixture>
{
    private readonly IKDFService _sut;

    public KDFServiceTests(KDFServiceFixture kdfServiceFixture)
    {
        this._sut = kdfServiceFixture.KDFService;
    }

    #region Tests

    /// <summary>
    ///     Tests that <seealso cref="IKDFService.TryComputePBKDF2(HashFunction, byte[], byte[], int, int, out byte[])"/>
    ///     returns a non-empty hash with success state <see langword="true"/>.
    /// </summary>
    [Fact]
    public void TestTryComputePBKDF2()
    {
        // Arrange
        var sha256 = HashFunction.SHA256;
        int iterations = 30_000;
        int saltSize = 128;
        byte[] password = "REDACTED".GetBytes(Format.String);
        byte[] salt = CryptoRandomProvider.GetBytes(saltSize).ToArray();

        // Act
        bool success = this._sut.TryComputePBKDF2(sha256, password, salt, sha256.GetSize(), iterations, out byte[]? pbkdf2);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.True(success);
            Assert.NotNull(pbkdf2);
        });
    }

    #endregion
}