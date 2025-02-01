using System;

namespace AdvancedSystems.Security.Abstractions;

/// <summary>
///     Represents a contract designed for computing hash algorithms.
/// </summary>
public interface IHashService
{
    #region Methods

    /// <summary>
    ///     Computes the hash value for the specified byte array.
    /// </summary>
    /// <param name="buffer">
    ///     The input to compute the hash code for.
    /// </param>
    /// <param name="hashFunction">
    ///     The hash algorithm implementation to use.
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
    byte[] Compute(byte[] buffer, HashFunction hashFunction);

    /// <summary>
    ///     Attempts to compute a PBKDF2 (password-based key derivation function).
    ///     This method is suitable for securely hashing passwords.
    /// </summary>
    /// <param name="password">
    ///     The password used to derive the hash.
    /// </param>
    /// <param name="salt">
    ///     The salt used to derive the hash.
    /// </param>
    /// <param name="hashSize">
    ///     The size of hash to derive.
    /// </param>
    /// <param name="iterations">
    ///     The number of iterations for the operation.
    /// </param>
    /// <param name="hashFunction">
    ///     The hash algorithm to use to derive the hash.
    /// </param>
    /// <param name="pbkdf2">
    ///     A byte array containing the created PBKDF2 derived hash.
    /// </param>
    /// <returns>
    ///     <see langword="true"/> if the operation succeeds; otherwise, <see langword="false"/>.
    /// </returns>
    /// <remarks>
    ///     Supported algorithms for the <paramref name="hashFunction"/> parameter are:
    ///     <list type="bullet">
    ///         <item>
    ///             <seealso cref="HashFunction.SHA1"/>
    ///         </item>
    ///         <item>
    ///             <seealso cref="HashFunction.SHA256"/>
    ///         </item>
    ///         <item>
    ///             <seealso cref="HashFunction.SHA384"/>
    ///         </item>
    ///         <item>
    ///             <seealso cref="HashFunction.SHA512"/>
    ///         </item>
    ///     </list>
    ///     Additionally, some platforms may support SHA3-equivalent hash functions.
    /// </remarks>
    bool TryComputePBKDF2(byte[] password, byte[] salt, int hashSize, int iterations, HashFunction hashFunction, out byte[] pbkdf2);

    #endregion
}