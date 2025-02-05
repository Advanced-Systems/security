using System;

namespace AdvancedSystems.Security.Abstractions;

/// <summary>
///     Represents a contract designed for computing hash algorithms.
/// </summary>
/// <seealso cref="IHMACService"/>
public interface IHashService
{
    #region Methods

    /// <summary>
    ///     Computes the hash value for the specified byte array.
    /// </summary>
    /// <param name="hashFunction">
    ///     The hash algorithm implementation to use.
    /// </param>
    /// <param name="buffer">
    ///     The input to compute the hash code for.
    /// </param>
    /// <returns>
    ///     The computed hash code.
    /// </returns>
    /// <remarks>
    ///     WARNING: Do <i>not</i> use this method to compute hashes for confidential data (e.g., passwords).
    /// </remarks>
    /// <exception cref="NotImplementedException">
    ///     Raised if the specified <paramref name="hashFunction"/> is not implemented.
    /// </exception>
    byte[] Compute(HashFunction hashFunction, byte[] buffer);

    #endregion
}