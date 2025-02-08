using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Extensions;

namespace AdvancedSystems.Security.Cryptography;

/// <summary>
///     Represents a class designed for employing key derivation functions.
/// </summary>
public static class KDFProvider
{
    /// <inheritdoc cref="IKDFService.TryComputePBKDF2(HashFunction, byte[], byte[], int, int, out byte[])"/>
    public static bool TryComputePBKDF2(HashFunction hashFunction, byte[] password, byte[] salt, int hashSize, int iterations, [NotNullWhen(true)] out byte[]? pbkdf2)
    {
        try
        {
            pbkdf2 = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, hashFunction.ToHashAlgorithmName(), hashSize);
            return true;
        }
        catch (Exception)
        {
            pbkdf2 = null;
            return false;
        }
    }
}