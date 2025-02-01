using System;

namespace AdvancedSystems.Security.Abstractions;

/// <summary>
///     Represents a contract designed for computing Hash-Based Message Authentication Codes (HMAC).
/// </summary>
public interface IHMACService
{
    #region Methods

    /// <summary>
    ///     Computes the HMAC of <paramref name="buffer"/> using the specified <paramref name="hashFunction"/>.
    /// </summary>
    /// <param name="hashFunction">
    ///     The hash function to use.
    /// </param>
    /// <param name="key">
    ///     The HMAC key. This cryptographic key uniquely identifies one or more entities.
    /// </param>
    /// <param name="buffer">
    ///     The data to HMAC.
    /// </param>
    /// <returns>
    ///     The HMAC of the data. This cryptographic checksum is the result of passing through <paramref name="buffer"/>
    ///     through a message authentication algorithm.
    /// </returns>
    /// <exception cref="NotImplementedException">
    ///     Raised if an unsupported <seealso cref="HashFunction"/> is passed to this method.
    /// </exception>
    /// <remarks>
    ///     <para>
    ///         Message Authentication Codes (MACs) are primarily used for message authentication. MACs based on
    ///         cryptographic hash functions are known as HMACs. Their purpose is to authenticate both the source
    ///         of a message as well as its integrity. A message authentication algorithm is called HMAC, while the
    ///         result of applying HMAC is called the MAC.
    ///     </para>
    ///     <para>
    ///         HMAC keys should be generated from a cryptographically strong random number generator.
    ///         You must securely store the HMAC <paramref name="key"/> and treat this information as a secret.
    ///         The value of the secret key should only be known to the message originator and the intended receiver(s).
    ///         The recommended key size is at least 32-bytes for full-entropy keys.
    ///     </para>
    ///     <para>
    ///         The hash function does not require collision-resistance as long as the hash function meets the very
    ///         weak requirement of being almost universal (c.f. <seealso href="https://eprint.iacr.org/2006/043"/>).
    ///         FIPS complieant hash algorithms are defined by FIPS PUB 180-4:
    ///         <list type="bullet">
    ///             <item>
    ///                 <seealso cref="HashFunction.SHA1"/>
    ///             </item>
    ///             <item>
    ///                 <seealso cref="HashFunction.SHA256"/>
    ///             </item>
    ///             <item>
    ///                 <seealso cref="HashFunction.SHA512"/>
    ///             </item>
    ///         </list>
    ///         See also: <seealso href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf"/>.
    ///     </para>
    /// </remarks>
    public byte[] Compute(HashFunction hashFunction, ReadOnlySpan<byte> key, ReadOnlySpan<byte> buffer);

    #endregion
}