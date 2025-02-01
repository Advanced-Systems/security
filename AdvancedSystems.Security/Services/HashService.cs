using System.Diagnostics.CodeAnalysis;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Cryptography;
using AdvancedSystems.Security.Extensions;

using Microsoft.Extensions.Logging;

namespace AdvancedSystems.Security.Services;

/// <summary>
///     Represents a service designed for computing hash algorithms.
/// </summary>
public sealed class HashService : IHashService
{
    private readonly ILogger<HashService> _logger;

    public HashService(ILogger<HashService> logger)
    {
        this._logger = logger;
    }

    #region Methods

    /// <inheritdoc />
    public byte[] Compute(HashFunction hashFunction, byte[] buffer)
    {
        if (hashFunction is HashFunction.MD5 or HashFunction.SHA1)
        {
            this._logger.LogWarning(
                "Computing hash with a cryptographically insecure hash algorithm ({HashFunction}).",
                hashFunction.GetName()
            );
        }

        return HashProvider.Compute(hashFunction, buffer);
    }

    /// <inheritdoc />
    public bool TryComputePBKDF2(HashFunction hashFunction, byte[] password, byte[] salt, int hashSize, int iterations, [NotNullWhen(true)] out byte[] pbkdf2)
    {
        return HashProvider.TryComputePBKDF2(hashFunction, password, salt, hashSize, iterations, out pbkdf2);
    }

    #endregion
}