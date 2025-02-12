﻿using System;
using System.Security.Cryptography;

using AdvancedSystems.Security.Abstractions;

namespace AdvancedSystems.Security.Cryptography;

/// <summary>
///     Represents a class designed for computing hash algorithms.
/// </summary>
public static class HashProvider
{
    /// <inheritdoc cref="IHashService.Compute(HashFunction, byte[])"/>
    public static byte[] Compute(HashFunction hashFunction, byte[] buffer)
    {
        return hashFunction switch
        {
            HashFunction.MD5 => MD5.HashData(buffer),
            HashFunction.SHA1 => SHA1.HashData(buffer),
            HashFunction.SHA256 => SHA256.HashData(buffer),
            HashFunction.SHA384 => SHA384.HashData(buffer),
            HashFunction.SHA512 => SHA512.HashData(buffer),
            HashFunction.SHA3_256 => SHA3_256.HashData(buffer),
            HashFunction.SHA3_384 => SHA3_384.HashData(buffer),
            HashFunction.SHA3_512 => SHA3_512.HashData(buffer),
            _ => throw new NotImplementedException($"The hash function {hashFunction} is not implemented."),
        };
    }
}