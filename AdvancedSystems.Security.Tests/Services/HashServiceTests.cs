﻿using System;
using System.Text;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Cryptography;
using AdvancedSystems.Security.Extensions;
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
    ///     Tests that <seealso cref="IHashService.Compute(HashFunction, byte[])"/> returns the expected hash,
    ///     and that the log warning message is called on <seealso cref="HashFunction.MD5"/> or <seealso cref="HashFunction.SHA1"/>.
    /// </summary>
    /// <param name="input"></param>
    /// <param name="expectedHash"></param>
    /// <param name="hashFunction"></param>
    [Theory]
    [InlineData("The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6", HashFunction.MD5)]
    [InlineData("The quick brown fox jumps over the lazy dog", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", HashFunction.SHA1)]
    [InlineData("The quick brown fox jumps over the lazy dog", "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", HashFunction.SHA256)]
    [InlineData("The quick brown fox jumps over the lazy dog", "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1", HashFunction.SHA384)]
    [InlineData("The quick brown fox jumps over the lazy dog", "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6", HashFunction.SHA512)]
    public void TestCompute(string input, string expectedHash, HashFunction hashFunction)
    {
        // Arrange
        byte[] buffer = Encoding.UTF8.GetBytes(input);
        this._sut.Logger.Invocations.Clear();

        // Act
        string actualHash = this._sut.HashService.Compute(hashFunction, buffer).ToString(Format.Hex);

        // Assert
        Assert.Equal(expectedHash, actualHash);

        if (hashFunction is HashFunction.MD5 or HashFunction.SHA1)
        {
            this._sut.Logger.Verify(x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.StartsWith("Computing hash with a cryptographically insecure hash algorithm")),
                It.IsAny<Exception>(),
                It.Is<Func<It.IsAnyType, Exception?, string>>((v, t) => true))
            );
        }

    }

    #endregion
}