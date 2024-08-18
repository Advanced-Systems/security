using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace AdvancedSystems.Security.Cryptography;

/// <summary>
///     Implements cryptographic hash algorithms.
/// </summary>
public static class Hash
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static HashAlgorithm Create(HashAlgorithmName hashAlgorithmName)
    {
        // Starting with net8, cryptographic factory methods accepting an algorithm
        // name are obsolet and to be replaced by the parameterless Create factory
        // method on the algorithm type, because their derived cryptographic types
        // such as SHA1Managed were obsoleted with net6. That is why this function
        // is intentionally not using the HashAlgorithmName.Create(name) factory.
        return hashAlgorithmName.Name switch
        {
            "MD5" => MD5.Create(),
            "SHA1" => SHA1.Create(),
            "SHA256" => SHA256.Create(),
            "SHA384" => SHA384.Create(),
            "SHA512" => SHA512.Create(),
            "SHA3-256" => SHA3_256.Create(),
            "SHA3-384" => SHA3_384.Create(),
            "SHA3-512" => SHA3_512.Create(),
            _ => throw new NotImplementedException()
        };
    }

    /// <summary>
    ///     Computes the hash value for the specified byte array.
    /// </summary>
    /// <param name="buffer">
    ///     The input to compute the hash code for.
    /// </param>
    /// <param name="hashAlgorithmName">
    ///     The hash algorithm implementation to use.
    /// </param>
    /// <returns>
    ///     The computed hash code.
    /// </returns>
    public static byte[] Compute(byte[] buffer, HashAlgorithmName hashAlgorithmName)
    {
        using var hashAlgorithm = Hash.Create(hashAlgorithmName);
        return hashAlgorithm.ComputeHash(buffer);
    }
}
