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
    public bool TryComputePBKDF2(HashFunction hashFunction, byte[] password, byte[] salt, int hashSize, int iterations, [NotNullWhen(true)] out byte[]? pbkdf2)
    {
        return KDFProvider.TryComputePBKDF2(hashFunction, password, salt, hashSize, iterations, out pbkdf2);
    }

    #endregion
}