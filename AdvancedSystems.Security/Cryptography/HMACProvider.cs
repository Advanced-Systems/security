using System;
using System.Security.Cryptography;

using AdvancedSystems.Security.Abstractions;

namespace AdvancedSystems.Security.Cryptography;

/// <summary>
///     Represents a class designed for computing Hash-Based Message Authentication Codes (HMAC).
/// </summary>
public static class HMACProvider
{
    /// <inheritdoc cref="IHMACService.Compute(HashFunction, ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>
    public static byte[] Compute(HashFunction hashFunction, ReadOnlySpan<byte> key, ReadOnlySpan<byte> buffer)
    {
        return hashFunction switch
        {
            HashFunction.MD5 => HMACMD5.HashData(key, buffer),
            HashFunction.SHA1 => HMACSHA1.HashData(key, buffer),
            HashFunction.SHA256 => HMACSHA256.HashData(key, buffer),
            HashFunction.SHA384 => HMACSHA384.HashData(key, buffer),
            HashFunction.SHA512 => HMACSHA512.HashData(key, buffer),
            HashFunction.SHA3_256 => HMACSHA3_256.HashData(key, buffer),
            HashFunction.SHA3_384 => HMACSHA3_384.HashData(key, buffer),
            HashFunction.SHA3_512 => HMACSHA3_512.HashData(key, buffer),
            _ => throw new NotImplementedException($"The hash function {hashFunction} is not implemented."),
        };
    }
}