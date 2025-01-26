using System;
using System.Security.Cryptography;

using AdvancedSystems.Security.Abstractions;

namespace AdvancedSystems.Security.Cryptography;

/// <summary>
///     Represents a class designed for computing HashProvider-Based Message Authentication Codes (HMACProvider).
/// </summary>
public static class HMACProvider
{
    /// <inheritdoc cref="IHMACService.Compute(byte[], byte[], HashFunction)"/>
    public static byte[] Compute(byte[] buffer, byte[] key, HashFunction hashFunction)
    {
        using var hmac = HMACProvider.Create(key, hashFunction);
        return hmac.ComputeHash(buffer);
    }

    #region Helpers

    /// <summary>
    ///     Creates a new instance of <seealso cref="KeyedHashAlgorithm"/> that implements <paramref name="hashFunction"/>.
    /// </summary>
    /// <param name="key">
    ///     The secret key for HMACProvider computation.
    /// </param>
    /// <param name="hashFunction">
    ///     The hash function to use.
    /// </param>
    /// <returns>
    ///     A new instance of <seealso cref="HashAlgorithm"/>.
    /// </returns>
    /// <exception cref="NotImplementedException">
    ///     Raised if the specified <paramref name="hashFunction"/> is not implemented.
    /// </exception>
    private static KeyedHashAlgorithm Create(byte[] key, HashFunction hashFunction)
    {
        return hashFunction switch
        {
            HashFunction.MD5 => new HMACMD5(key),
            HashFunction.SHA1 => new HMACSHA1(key),
            HashFunction.SHA256 => new HMACSHA256(key),
            HashFunction.SHA384 => new HMACSHA384(key),
            HashFunction.SHA512 => new HMACSHA512(key),
            HashFunction.SHA3_256 => new HMACSHA3_256(key),
            HashFunction.SHA3_384 => new HMACSHA3_384(key),
            HashFunction.SHA3_512 => new HMACSHA3_512(key),
            _ => throw new NotImplementedException($"The hash function {hashFunction} is not implemented."),
        };
    }

    #endregion
}