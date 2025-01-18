using System;
using System.Text;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Cryptography;
using AdvancedSystems.Security.Tests.Fixtures;

using Microsoft.Extensions.Logging;

using Moq;

using Xunit;

namespace AdvancedSystems.Security.Tests.Services;

/// <summary>
///     Tests the public methods in <seealso cref="IHashService"/>.
/// </summary>
/// <remarks>
///     These methods are more exhaustively tested by the underlying provider class.
/// </remarks>
public sealed class HashServiceTests : IClassFixture<HashServiceFixture>
{
    private readonly HashServiceFixture _sut;

    public HashServiceTests(HashServiceFixture fixture)
    {
        this._sut = fixture;
    }

    #region Tests

    /// <summary>
    ///     Tests that <seealso cref="IHashService.GetMD5Hash(byte[])"/> returns the expected hash,
    ///     and that the log warning message is called.
    /// </summary>
    [Fact]
    public void TestMD5Hash()
    {
        // Arrange
        string input = "The quick brown fox jumps over the lazy dog";
        byte[] buffer = Encoding.UTF8.GetBytes(input);
        this._sut.Logger.Invocations.Clear();

        // Act
#pragma warning disable CS0618 // Type or member is obsolete
        string md5 = this._sut.HashService.GetMD5Hash(buffer);
#pragma warning restore CS0618 // Type or member is obsolete

        // Assert
        Assert.Equal("9e107d9d372bb6826bd81d3542a419d6", md5);
        this._sut.Logger.Verify(x => x.Log(
            LogLevel.Warning,
            It.IsAny<EventId>(),
            It.Is<It.IsAnyType>((v, t) => v.ToString()!.StartsWith("Computing hash with a cryptographically insecure hash algorithm")),
            It.IsAny<Exception>(),
            It.Is<Func<It.IsAnyType, Exception?, string>>((v, t) => true))
        );
    }

    /// <summary>
    ///     Tests that <seealso cref="IHashService.GetSHA1Hash(byte[])"/> returns the expected hash,
    ///     and that the log warning message is called.
    /// </summary>
    [Fact]
    public void TestSHA1Hash()
    {
        // Arrange
        string input = "The quick brown fox jumps over the lazy dog";
        byte[] buffer = Encoding.UTF8.GetBytes(input);
        this._sut.Logger.Invocations.Clear();

        // Act
#pragma warning disable CS0618 // Type or member is obsolete
        string sha1 = this._sut.HashService.GetSHA1Hash(buffer);
#pragma warning restore CS0618 // Type or member is obsolete

        // Assert
        Assert.Equal("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", sha1);
        this._sut.Logger.Verify(x => x.Log(
            LogLevel.Warning,
            It.IsAny<EventId>(),
            It.Is<It.IsAnyType>((v, t) => v.ToString()!.StartsWith("Computing hash with a cryptographically insecure hash algorithm")),
            It.IsAny<Exception>(),
            It.Is<Func<It.IsAnyType, Exception?, string>>((v, t) => true))
        );
    }

    /// <summary>
    ///     Tests that <seealso cref="IHashService.GetSHA256Hash(byte[])"/> returns the expected hash.
    /// </summary>
    [Fact]
    public void TestSHA256Hash()
    {
        // Arrange
        string input = "The quick brown fox jumps over the lazy dog";
        byte[] buffer = Encoding.UTF8.GetBytes(input);

        // Act
        string sha256 = this._sut.HashService.GetSHA256Hash(buffer);

        // Assert
        Assert.Equal("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", sha256);
    }

    /// <summary>
    ///     Tests that <seealso cref="IHashService.GetSHA384Hash(byte[])"/> returns the expected hash.
    /// </summary>
    [Fact]
    public void TestSHA384Hash()
    {
        // Arrange
        string input = "The quick brown fox jumps over the lazy dog";
        byte[] buffer = Encoding.UTF8.GetBytes(input);

        // Act
        string sha384 = this._sut.HashService.GetSHA384Hash(buffer);

        // Assert
        Assert.Equal("ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1", sha384);
    }

    /// <summary>
    ///     Tests that <seealso cref="IHashService.GetSHA512Hash(byte[])"/> returns the expected hash.
    /// </summary>
    [Fact]
    public void TestSHA512Hash()
    {
        // Arrange
        string input = "The quick brown fox jumps over the lazy dog";
        byte[] buffer = Encoding.UTF8.GetBytes(input);

        // Act
        string sha512 = this._sut.HashService.GetSHA512Hash(buffer);

        // Assert
        Assert.Equal("07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6", sha512);
    }

    /// <summary>
    ///     Tests that <seealso cref="IHashService.GetSecureSHA1Hash(byte[], byte[], int)"/> returns the hash
    ///     with the expected length.
    /// </summary>
    [Fact]
    public void TestGetSecureSHA1Hash()
    {
        // Arrange
        int sha1Size = 160;
        int expectedLength = sha1Size * 2;
        byte[] password = Encoding.UTF8.GetBytes("secret");
        byte[] salt = CryptoRandomProvider.GetBytes(32).ToArray();

        // Act
        string sha1 = this._sut.HashService.GetSecureSHA1Hash(password, salt);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.NotEmpty(sha1);
            Assert.Equal(expectedLength, sha1.Length);
        });
    }

    /// <summary>
    ///     Tests that <seealso cref="IHashService.GetSecureSHA256Hash(byte[], byte[], int)"/> returns the hash
    ///     with the expected length.
    /// </summary>
    [Fact]
    public void GetSecureSHA256Hash()
    {
        // Arrange
        int sha256Size = 256;
        int expectedLength = sha256Size * 2;
        byte[] password = Encoding.UTF8.GetBytes("secret");
        byte[] salt = CryptoRandomProvider.GetBytes(32).ToArray();

        // Act
        string sha256 = this._sut.HashService.GetSecureSHA256Hash(password, salt);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.NotEmpty(sha256);
            Assert.Equal(expectedLength, sha256.Length);
        });
    }

    /// <summary>
    ///     Tests that <seealso cref="IHashService.GetSecureSHA384Hash(byte[], byte[], int)"/> returns the hash
    ///     with the expected length.
    /// </summary>
    [Fact]
    public void GetSecureSHA384Hash()
    {
        // Arrange
        int sha384Size = 256;
        int expectedLength = sha384Size * 2;
        byte[] password = Encoding.UTF8.GetBytes("secret");
        byte[] salt = CryptoRandomProvider.GetBytes(32).ToArray();

        // Act
        string sha384 = this._sut.HashService.GetSecureSHA256Hash(password, salt);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.NotEmpty(sha384);
            Assert.Equal(expectedLength, sha384.Length);
        });
    }

    /// <summary>
    ///     Tests that <seealso cref="IHashService.GetSecureSHA512Hash(byte[], byte[], int)"/> returns the hash
    ///     with the expected length.
    /// </summary>
    [Fact]
    public void GetSecureSHA512Hash()
    {
        // Arrange
        int sha512Size = 256;
        int expectedLength = sha512Size * 2;
        byte[] password = Encoding.UTF8.GetBytes("secret");
        byte[] salt = CryptoRandomProvider.GetBytes(32).ToArray();

        // Act
        string sha512 = this._sut.HashService.GetSecureSHA256Hash(password, salt);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.NotEmpty(sha512);
            Assert.Equal(expectedLength, sha512.Length);
        });
    }

    #endregion
}