using System;
using System.Text;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Cryptography;
using AdvancedSystems.Security.Extensions;

using Xunit;

namespace AdvancedSystems.Security.Tests.Cryptography;

/// <summary>
///     Tests the public methods in <seealso cref="HMACProvider"/>.
/// </summary>
public sealed class HMACTests
{
    #region Test

    /// <summary>
    ///     Tests that <seealso cref="HMACProvider.Compute(HashFunction, ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>
    ///     computes the MAC value of <paramref name="text"/> with <paramref name="hashFunction"/> as cryptographic
    ///     algorithm and a hard-coded key correctly.
    /// </summary>
    /// <param name="hashFunction">
    ///     The hash function to use.
    /// </param>
    /// <param name="text">
    ///     The data to HMAC.
    /// </param>
    /// <param name="expectedMac">
    ///     The expected MAC value for <paramref name="text"/>.
    /// </param>
    [Theory]
    [InlineData(HashFunction.MD5, "Hello, World!", "c8972c594d22ce2b4f73e91538db5737")]
    [InlineData(HashFunction.MD5, "The quick brown fox jumps over the lazy dog", "2e3f3742c21be88e64deb2127fe792d2")]
    [InlineData(HashFunction.SHA1, "Hello, World!", "883a982dc2ae46d20f7f106c786a9241b60dc340")]
    [InlineData(HashFunction.SHA1, "The quick brown fox jumps over the lazy dog", "198ea1ea04c435c1246b586a06d5cf11c3ffcda6")]
    [InlineData(HashFunction.SHA256, "Hello, World!", "fcfaffa7fef86515c7beb6b62d779fa4ccf092f2e61c164376054271252821ff")]
    [InlineData(HashFunction.SHA256, "The quick brown fox jumps over the lazy dog", "54cd5b827c0ec938fa072a29b177469c843317b095591dc846767aa338bac600")]
    [InlineData(HashFunction.SHA384, "Hello, World!", "699f60b90c6dc0a32be14690a22c541bc3eba8d3215a782c28d66db3f0a3eb81cc0703c932bc181b02d190c9f9967e41")]
    [InlineData(HashFunction.SHA384, "The quick brown fox jumps over the lazy dog", "bf8a22d3bd5cf88e0f41fa90eeb00eb908fccd925d55a7305f23e206358bb488fbef01039308e434c255e59f8e3badc3")]
    [InlineData(HashFunction.SHA512, "Hello, World!", "851caed63934ad1c9a03aef23ba2b84f224bdff4f5148efc57d95f9ae80ca9db2e98bc4c709a529eb1b7234a1ac2e381d28e0eb1efa090bb19613f5c124b6d5b")]
    [InlineData(HashFunction.SHA512, "The quick brown fox jumps over the lazy dog", "76af3588620ef6e2c244d5a360e080c0d649b6dd6b82ccd115eeefee8ff403bcee9aeb08618db9a2a94a9e80c7996bb2cb0c00f6e69de38ed8af2758ef39df0a")]
    public void TestHMAC_Value(HashFunction hashFunction, string text, string expectedMac)
    {
        // Arrange
        byte[] key = "secret".GetBytes(Format.String);
        byte[] buffer = text.GetBytes(Format.String);

        // Act
        byte[] actualMac = HMACProvider.Compute(hashFunction, key, buffer);

        // Assert
        Assert.Equal(expectedMac.GetBytes(Format.Hex), actualMac);
    }

    /// <summary>
    ///     Tests that <seealso cref="HMACProvider.Compute(HashFunction, ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>
    ///     the computed MAC equals the size of <paramref name="hashFunction"/>.
    /// </summary>
    /// <param name="hashFunction">
    ///     The hash function to use.
    /// </param>
    /// <param name="text">
    ///     The data to HMAC.
    /// </param>
    [Theory]
    [InlineData(HashFunction.MD5, "Hello, World!")]
    [InlineData(HashFunction.MD5, "The quick brown fox jumps over the lazy dog")]
    [InlineData(HashFunction.SHA1, "Hello, World!")]
    [InlineData(HashFunction.SHA1, "The quick brown fox jumps over the lazy dog")]
    [InlineData(HashFunction.SHA256, "Hello, World!")]
    [InlineData(HashFunction.SHA256, "The quick brown fox jumps over the lazy dog")]
    [InlineData(HashFunction.SHA384, "Hello, World!")]
    [InlineData(HashFunction.SHA384, "The quick brown fox jumps over the lazy dog")]
    [InlineData(HashFunction.SHA512, "Hello, World!")]
    [InlineData(HashFunction.SHA512, "The quick brown fox jumps over the lazy dog")]
    public void TestHMAC_Size(HashFunction hashFunction, string text)
    {
        // Arrange
        int keySize = 32;
        byte[] buffer = text.GetBytes(Format.String);
        int expectedMacSize = hashFunction.GetSize();

        // Act
        ReadOnlySpan<byte> key = CryptoRandomProvider.GetBytes(keySize);
        byte[] mac = HMACProvider.Compute(hashFunction, key, buffer);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.NotEmpty(mac);
            Assert.Equal(expectedMacSize, mac.Length * 8);
        });
    }

    #endregion
}