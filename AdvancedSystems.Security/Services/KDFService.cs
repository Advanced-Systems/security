using System;
using System.Diagnostics.CodeAnalysis;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Cryptography;

namespace AdvancedSystems.Security.Services;

/// <summary>
///     Represents a service designed for employing key derivation functions.
/// </summary>
public sealed class KDFService : IKDFService
{
    #region Methods

    /// <inheritdoc />
    public bool TryComputePBKDF2(HashFunction hashFunction, Span<byte> password, Span<byte> salt, int hashSize, int iterations, [NotNullWhen(true)] out byte[]? pbkdf2)
    {
        return KDFProvider.TryComputePBKDF2(hashFunction, password.ToArray(), salt.ToArray(), hashSize, iterations, out pbkdf2);
    }

    #endregion
}