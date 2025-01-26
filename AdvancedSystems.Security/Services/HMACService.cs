using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Cryptography;

namespace AdvancedSystems.Security.Services;

/// <summary>
///     Represents a service designed for computing hash algorithms.
/// </summary>
public sealed class HMACService : IHMACService
{
    #region Methods

    /// <inheritdoc cref="IHMACService.Compute(byte[], byte[], HashFunction)"/>
    public byte[] Compute(byte[] buffer, byte[] key, HashFunction hashFunction)
    {
        return HMACProvider.Compute(buffer, key, hashFunction);
    }

    #endregion
}