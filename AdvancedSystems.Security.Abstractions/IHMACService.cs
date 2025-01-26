using System;

namespace AdvancedSystems.Security.Abstractions;

/// <summary>
///     Represents a contract designed for computing Hash-Based Message Authentication Codes (HMAC).
/// </summary>
public interface IHMACService
{
    #region Methods

    /// <summary>
    ///     Computes the hash value for the specified byte array using the specified <paramref name="key"/>.
    /// </summary>
    /// <param name="buffer">
    ///     The input to compute the hash code for.
    /// </param>
    /// <param name="key">
    ///     The secret key for HMAC computation.
    /// </param>
    /// <param name="hashFunction">
    ///     The hash algorithm implementation to use.
    /// </param>
    /// <returns>
    ///     The computed hash code.
    /// </returns>
    /// <exception cref="NotImplementedException">
    ///     Raised if the specified <paramref name="hashFunction"/> is not implemented.
    /// </exception>
    public byte[] Compute(byte[] buffer, byte[] key, HashFunction hashFunction);

    #endregion
}