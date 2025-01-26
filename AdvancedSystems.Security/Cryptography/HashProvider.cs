using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Extensions;

namespace AdvancedSystems.Security.Cryptography;

/// <summary>
///     Represents a class designed for computing hash algorithms.
/// </summary>
public static class HashProvider
{
    /// <inheritdoc cref="IHashService.Compute(byte[], HashFunction)"/>
    public static byte[] Compute(byte[] buffer, HashFunction hashFunction)
    {
        using var hashAlgorithm = HashProvider.Create(hashFunction);
        return hashAlgorithm.ComputeHash(buffer);
    }

    /// <inheritdoc cref="IHashService.TryComputePBKDF2(byte[], byte[], int, int, HashFunction, out byte[])"/>
    public static bool TryComputePBKDF2(byte[] password, byte[] salt, int hashSize, int iterations, HashFunction hashFunction, [NotNullWhen(true)] out byte[] pbkdf2)
    {
        try
        {
            pbkdf2 = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, hashFunction.ToHashAlgorithmName(), hashSize);
            return true;
        }
        catch (Exception)
        {
            pbkdf2 = [];
            return false;
        }
    }

    #region Helpers

    /// <summary>
    ///     Creates a new instance of <seealso cref="HashAlgorithm"/> that implements <paramref name="hashFunction"/>.
    /// </summary>
    /// <param name="hashFunction">
    ///     The hash function to use.
    /// </param>
    /// <returns>
    ///     A new instance of <seealso cref="HashAlgorithm"/>.
    /// </returns>
    /// <exception cref="NotImplementedException">
    ///     Raised if the specified <paramref name="hashFunction"/> is not implemented.
    /// </exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static HashAlgorithm Create(HashFunction hashFunction)
    {
        return hashFunction switch
        {
            HashFunction.MD5 => MD5.Create(),
            HashFunction.SHA1 => SHA1.Create(),
            HashFunction.SHA256 => SHA256.Create(),
            HashFunction.SHA384 => SHA384.Create(),
            HashFunction.SHA512 => SHA512.Create(),
            HashFunction.SHA3_256 => SHA3_256.Create(),
            HashFunction.SHA3_384 => SHA3_384.Create(),
            HashFunction.SHA3_512 => SHA3_512.Create(),
            _ => throw new NotImplementedException($"The hash function {hashFunction} is not implemented."),
        };
    }

    #endregion
}