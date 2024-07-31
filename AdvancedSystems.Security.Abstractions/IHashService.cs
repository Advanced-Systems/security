using System;

namespace AdvancedSystems.Security.Abstractions;

/// <summary>
///     Defines a service for computing hash codes.
/// </summary>
public interface IHashService
{
    /// <summary>
    ///     Computes the MD5 hash value for the specified byte array.
    /// </summary>
    /// <param name="buffer">The input to compute the hash code for.</param>
    /// <returns>The hexadecimal <seealso cref="string"/> representation of the computed hash code.</returns>
    /// <seealso href="https://datatracker.ietf.org/doc/rfc1321/"/>
    [Obsolete("MD5 is not a cryptographically secure hash algorithm.")]
    string GetMD5Hash(byte[] buffer);

    /// <summary>
    ///     Computes the SHA1 hash value for the specified byte array.
    /// </summary>
    /// <param name="buffer">The input to compute the hash code for.</param>
    /// <returns>The hexadecimal <seealso cref="string"/> representation of the computed hash code.</returns>
    /// <seealso href="https://datatracker.ietf.org/doc/rfc3174/"/>
    [Obsolete("SHA1 is not a cryptographically secure hash algorithm.")]
    string GetSHA1Hash(byte[] buffer);

    /// <summary>
    ///     Computes the SHA256 hash value for the specified byte array.
    /// </summary>
    /// <param name="buffer">The input to compute the hash code for.</param>
    /// <returns>The hexadecimal <seealso cref="string"/> representation of the computed hash code.</returns>
    /// <seealso href="https://datatracker.ietf.org/doc/rfc4634/"/>
    string GetSHA256Hash(byte[] buffer);

    /// <summary>
    ///     Computes the SHA384 hash value for the specified byte array.
    /// </summary>
    /// <param name="buffer">The input to compute the hash code for.</param>
    /// <returns>The hexadecimal <seealso cref="string"/> representation of the computed hash code.</returns>
    /// <seealso href="https://datatracker.ietf.org/doc/rfc6234/"/>
    string GetSHA384Hash(byte[] buffer);

    /// <summary>
    ///     Computes the SHA512 hash value for the specified byte array.
    /// </summary>
    /// <param name="buffer">The input to compute the hash code for.</param>
    /// <returns>The hexadecimal <seealso cref="string"/> representation of the computed hash code.</returns>
    /// <seealso href="https://datatracker.ietf.org/doc/rfc4634/"/>
    string GetSHA512Hash(byte[] buffer);
}
