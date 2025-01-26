using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

using AdvancedSystems.Security.Abstractions;

namespace AdvancedSystems.Security.Extensions;

public static class HashFunctionExtensions
{
    /// <summary>
    ///     Converts the specified <paramref name="hashFunction"/> to its corresponding instance of
    ///     <seealso cref="HashAlgorithmName"/>.
    /// </summary>
    /// <param name="hashFunction">
    ///     The specified hash algorithm.
    /// </param>
    /// <returns>
    ///     An instance of <seealso cref="HashAlgorithmName"/>.
    /// </returns>
    /// <exception cref="NotImplementedException">
    ///     Raised if the value of <paramref name="hashFunction"/> cannot be backed by a built-in implementation.
    /// </exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static HashAlgorithmName ToHashAlgorithmName(this HashFunction hashFunction)
    {
        return hashFunction switch
        {
            HashFunction.MD5 => HashAlgorithmName.MD5,
            HashFunction.SHA1 => HashAlgorithmName.SHA1,
            HashFunction.SHA256 => HashAlgorithmName.SHA256,
            HashFunction.SHA384 => HashAlgorithmName.SHA384,
            HashFunction.SHA512 => HashAlgorithmName.SHA512,
            HashFunction.SHA3_256 => HashAlgorithmName.SHA3_256,
            HashFunction.SHA3_384 => HashAlgorithmName.SHA3_384,
            HashFunction.SHA3_512 => HashAlgorithmName.SHA3_512,
            _ => throw new NotImplementedException($"The hash function {hashFunction} is not implemented."),
        };
    }

    /// <summary>
    ///     Gets the size, in bits, of the computed hash code.
    /// </summary>
    /// <param name="hashFunction">
    ///     The specified hash algorithm.
    /// </param>
    /// <returns>
    ///     Raised if the value of <paramref name="hashFunction"/> cannot be backed by a built-in implementation.
    /// </returns>
    /// <exception cref="NotImplementedException"></exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetSize(this HashFunction hashFunction)
    {
        return hashFunction switch
        {
            HashFunction.MD5 => 128,
            HashFunction.SHA1 => 160,
            HashFunction.SHA256 or HashFunction.SHA3_256 => 256,
            HashFunction.SHA384 or HashFunction.SHA3_384 => 384,
            HashFunction.SHA512 or HashFunction.SHA3_512 => 512,
            _ => throw new NotImplementedException($"The hash function {hashFunction} is not implemented."),
        };
    }

    /// <summary>
    ///     Gets the name of the hash function.
    /// </summary>
    /// <param name="hashFunction">
    ///     The specified hash algorithm.
    /// </param>
    /// <returns>
    ///     The name of the hash function.
    /// </returns>
    /// <exception cref="NotImplementedException">
    ///     Raised if the value of <paramref name="hashFunction"/> cannot be backed by a built-in implementation.
    /// </exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static string GetName(this HashFunction hashFunction)
    {
        return hashFunction switch
        {
            HashFunction.MD5 => "MD5",
            HashFunction.SHA1 => "SHA1",
            HashFunction.SHA256 => "SHA256",
            HashFunction.SHA384 => "SHA384",
            HashFunction.SHA512 => "SHA512",
            HashFunction.SHA3_256 => "SHA3-256",
            HashFunction.SHA3_384 => "SHA3-384",
            HashFunction.SHA3_512 => "SHA3-512",
            _ => throw new NotImplementedException($"The hash function {hashFunction} is not implemented.")
        };
    }
}