using System;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Cryptography;
using AdvancedSystems.Security.Extensions;
using AdvancedSystems.Security.Tests.Fixtures;

using Xunit;

namespace AdvancedSystems.Security.Tests.Services;

/// <summary>
///     Tests the public methods in <seealso cref="IHMACService"/>.
/// </summary>
public sealed class HMACServiceTests : IClassFixture<HMACServiceFixture>, IClassFixture<CryptoRandomServiceFixture>
{
    private readonly IHMACService _sut;
    private readonly ICryptoRandomService _cryptoRandomService;

    public HMACServiceTests(HMACServiceFixture fixture, CryptoRandomServiceFixture cryptoRandomFixture)
    {
        this._sut = fixture.HMACService;
        this._cryptoRandomService = cryptoRandomFixture.CryptoRandomService;
    }

    #region Tests

    /// <summary>
    ///     Tests that <seealso cref="IHMACService.Compute(HashFunction, ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>
    ///     returns a non-empty result.
    /// </summary>
    [Fact]
    public void TestCompute()
    {
        // Arrange
        var sha256 = HashFunction.SHA256;
        Span<byte> key = this._cryptoRandomService.GetBytes(32);
        Span<byte> data = "Hello, World".GetBytes(Format.String);

        // Act
        Span<byte> mac = this._sut.Compute(sha256, key, data);

        // Assert
        Assert.NotEmpty(mac.ToArray());
    }

    #endregion
}