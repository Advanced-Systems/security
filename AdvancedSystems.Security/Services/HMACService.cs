using System;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Cryptography;

namespace AdvancedSystems.Security.Services;

/// <summary>
///     Represents a service designed for computing hash algorithms.
/// </summary>
public sealed class HMACService : IHMACService
{
    #region Methods

    /// <inheritdoc cref="IHMACService.Compute(HashFunction, ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>
    public byte[] Compute(HashFunction hashFunction, ReadOnlySpan<byte> key, ReadOnlySpan<byte> buffer)
    {
        return HMACProvider.Compute(hashFunction, key, buffer);
    }

    #endregion
}