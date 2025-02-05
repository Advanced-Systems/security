using System.Security.Cryptography;
using System.Text;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Cryptography;
using AdvancedSystems.Security.Extensions;

using Xunit;

namespace AdvancedSystems.Security.Tests.Cryptography;

public sealed class KDFProviderTests
{
    #region Tests

    /// <summary>
    ///     Tests that <seealso cref="KDFProvider.TryComputePBKDF2(HashFunction, byte[], byte[], int, int, out byte[])"/>
    ///     computes the hash code successfully and returns the hash with the expected size using the
    ///     <paramref name="hashFunction"/> algorithm.
    /// </summary>
    /// <param name="hashFunction">
    ///     The specified hash function.
    /// </param>
    /// <param name="saltSize">
    ///     The salt size to use.
    /// </param>
    [Theory]
    [InlineData(HashFunction.SHA1, 128)]
    [InlineData(HashFunction.SHA256, 128)]
    [InlineData(HashFunction.SHA384, 128)]
    [InlineData(HashFunction.SHA512, 128)]
    public void TestTryComputePBKDF2(HashFunction hashFunction, int saltSize)
    {
        // Arrange
        int iterations = 100_000;
        int hashSize = hashFunction.GetSize();

        byte[] password = Encoding.UTF8.GetBytes("secret");
        byte[] salt = CryptoRandomProvider.GetBytes(saltSize).ToArray();

        // Act
        bool isSuccessful = KDFProvider.TryComputePBKDF2(hashFunction, password, salt, hashSize, iterations, out byte[]? pbkdf2);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.True(isSuccessful);
            Assert.Equal(saltSize, salt.Length);
            Assert.Equal(hashSize, pbkdf2?.Length);
            Assert.NotNull(pbkdf2);
        });
    }

    /// <summary>
    ///     Tests that <seealso cref="KDFProvider.TryComputePBKDF2(HashFunction, byte[], byte[], int, int, out byte[])"/>
    ///     fails to compute the hash code on unsupported <paramref name="hashFunction"/> values and that the resulting
    ///     hash is empty.
    /// </summary>
    /// <param name="hashFunction">
    ///     The specified hash function.
    /// </param>
    /// <param name="saltSize">
    ///     The salt size to use.
    /// </param>
    [Theory]
    [InlineData(HashFunction.SHA3_256, 128)]
    [InlineData(HashFunction.SHA3_384, 128)]
    [InlineData(HashFunction.SHA3_512, 128)]
    public void TestTryComputePBKDF2_HashFunctionSupport(HashFunction hashFunction, int saltSize)
    {
        // Arrange
        int iterations = 100_000;
        int hashSize = hashFunction.GetSize();

        byte[] password = Encoding.UTF8.GetBytes("secret");
        byte[] salt = CryptoRandomProvider.GetBytes(saltSize).ToArray();

        // Act
        bool isSuccessful = KDFProvider.TryComputePBKDF2(hashFunction, password, salt, hashSize, iterations, out byte[]? hash);

        // Assert
        Assert.Multiple(() =>
        {
            // All current platforms support HMAC-SHA3-256, 384, and 512 together, so we can simplify the check
            // to just checking HMAC-SHA3-256 for the availability of 384 and 512, too.
            Assert.Equal(HMACSHA3_256.IsSupported, isSuccessful);
        });
    }

    #endregion
}