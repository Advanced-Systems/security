using System;

namespace AdvancedSystems.Security.Abstractions;

/// <summary>
///     Defines a service for computing hash codes.
/// </summary>
public interface IHashService
{
    #region Methods

    /// <summary>
    ///     Computes the MD5 hash value for the specified <paramref name="buffer"/>.
    /// </summary>
    /// <param name="buffer">
    ///     The input to compute the hash code for.
    /// </param>
    /// <returns>
    ///     The hexadecimal <see langword="string"/> representation of the computed hash code.
    /// </returns>
    /// <remarks>
    ///     <para>
    ///         See also: <seealso href="https://datatracker.ietf.org/doc/rfc1321/"/>
    ///     </para>
    /// </remarks>
    [Obsolete("MD5 is not a cryptographically secure hash algorithm.")]
    string GetMD5Hash(byte[] buffer);

    /// <summary>
    ///     Computes the SHA1 hash value for the specified <paramref name="buffer"/>.
    /// </summary>
    /// <param name="buffer">
    ///     The input to compute the hash code for.
    /// </param>
    /// <returns>
    ///     The hexadecimal <see langword="string"/> representation of the computed hash code.
    /// </returns>
    /// <remarks>
    ///     <para>
    ///         WARNING: Do <i>not</i> use this method to compute hashes for  confidential data
    ///         (e.g., passwords). Instead, use
    ///         <seealso cref="GetSecureSHA1Hash(byte[], byte[], int)"/>
    ///         for secure hashing instead.
    ///     </para>
    ///     <para>
    ///         See also: <seealso href="https://datatracker.ietf.org/doc/rfc1321/"/>
    ///     </para>
    /// </remarks>
    /// <seealso href="https://datatracker.ietf.org/doc/rfc3174/"/>
    [Obsolete("SHA1 is not a cryptographically secure hash algorithm.")]
    string GetSHA1Hash(byte[] buffer);

    /// <summary>
    ///     Computes the SHA256 hash value for the specified <paramref name="buffer"/>.
    /// </summary>
    /// <param name="buffer">
    ///     The input to compute the hash code for.
    /// </param>
    /// <returns>
    ///     The hexadecimal <see langword="string"/> representation of the computed hash code.
    /// </returns>
    /// <remarks>
    ///     <para>
    ///         WARNING: Do <i>not</i> use this method to compute hashes for  confidential data
    ///         (e.g., passwords). Instead, use
    ///         <seealso cref="GetSecureSHA256Hash(byte[], byte[], int)"/>
    ///         for secure hashing instead.
    ///     </para>
    ///     <para>
    ///         See also: <seealso href="https://datatracker.ietf.org/doc/rfc4634/"/>
    ///     </para>
    /// </remarks>
    string GetSHA256Hash(byte[] buffer);

    /// <summary>
    ///     Computes the SHA384 hash value for the specified <paramref name="buffer"/>.
    /// </summary>
    /// <param name="buffer">
    ///     The input to compute the hash code for.
    /// </param>
    /// <returns>
    ///     The hexadecimal <see langword="string"/> representation of the computed hash code.
    /// </returns>
    /// <remarks>
    ///     <para>
    ///         WARNING: Do <i>not</i> use this method to compute hashes for  confidential data
    ///         (e.g., passwords). Instead, use
    ///         <seealso cref="GetSecureSHA384Hash(byte[], byte[], int)"/>
    ///         for secure hashing instead.
    ///     </para>
    ///     <para>
    ///         See also: <seealso href="https://datatracker.ietf.org/doc/rfc6234/"/>
    ///     </para>
    /// </remarks>
    string GetSHA384Hash(byte[] buffer);

    /// <summary>
    ///     Computes the SHA512 hash value for the specified <paramref name="buffer"/>.
    /// </summary>
    /// <param name="buffer">
    ///     The input to compute the hash code for.
    /// </param>
    /// <returns>
    ///     The hexadecimal <see langword="string"/> representation of the computed hash code.
    /// </returns>
    /// <remarks>
    ///     <para>
    ///         WARNING: Do <i>not</i> use this method to compute hashes for  confidential data
    ///         (e.g., passwords). Instead, use
    ///         <seealso cref="GetSecureSHA512Hash(byte[], byte[], int)"/>
    ///         for secure hashing instead.
    ///     </para>
    ///     <para>
    ///         See also: <seealso href="https://datatracker.ietf.org/doc/rfc4634/"/>
    ///     </para>
    /// </remarks>
    string GetSHA512Hash(byte[] buffer);

    /// <summary>
    ///     Creates a cryptographically secure hash value for the specified <paramref name="buffer"/>
    ///     as a PBKDF2 derived key using the SHA1 hash algorithm.
    /// </summary>
    /// <param name="buffer">
    ///     The buffer used to derive the hash.
    /// </param>
    /// <param name="salt">
    ///     The salt used to derive the hash.
    /// </param>
    /// <param name="iterations">
    ///     The number of iterations for the operation.
    /// </param>
    /// <returns>
    ///     The hexadecimal <see langword="string"/> representation of the computed hash code
    ///     if the computation succeeded; else <seealso cref="string.Empty"/>.
    /// </returns>
    /// <remarks>
    ///     Notes on usage:
    ///     <list type="bullet">
    ///         <item>
    ///             Create an array of bytes filled with cryptographically strong random sequence
    ///             of values for the <paramref name="salt"/> parameter.
    ///         </item>
    ///         <item>
    ///             The <paramref name="salt"/> has to be stored alongside the password hash and
    ///             <paramref name="iterations"/> count.
    ///         </item>
    ///         <item>
    ///             A higher <paramref name="iterations"/> count results in more computational
    ///             overhead, thus slowing down this function invocation considerably. This behavior
    ///             is intentional to mitigate brute-force attacks on leaked databases.
    ///         </item>
    ///     </list>
    ///     See also: <seealso href="https://datatracker.ietf.org/doc/html/rfc2898"/>.
    /// </remarks>
    public string GetSecureSHA1Hash(byte[] buffer, byte[] salt, int iterations = 1000);

    /// <summary>
    ///     Creates a cryptographically secure hash value for the specified <paramref name="buffer"/>
    ///     as a PBKDF2 derived key using the SHA256 hash algorithm.
    /// </summary>
    /// <param name="buffer">
    ///     The buffer used to derive the hash.
    /// </param>
    /// <param name="salt">
    ///     The salt used to derive the hash.
    /// </param>
    /// <param name="iterations">
    ///     The number of iterations for the operation.
    /// </param>
    /// <returns>
    ///     The hexadecimal <see langword="string"/> representation of the computed hash code
    ///     if the computation succeeded; else <seealso cref="string.Empty"/>.
    /// </returns>
    /// <remarks>
    ///     <inheritdoc cref="GetSecureSHA1Hash(byte[], byte[], int)" path="/remarks"/>
    /// </remarks>
    public string GetSecureSHA256Hash(byte[] buffer, byte[] salt, int iterations = 1000);

    /// <summary>
    ///     Creates a cryptographically secure hash value for the specified <paramref name="buffer"/>
    ///     as a PBKDF2 derived key using the SHA384 hash algorithm.
    /// </summary>
    /// <param name="buffer">
    ///     The buffer used to derive the hash.
    /// </param>
    /// <param name="salt">
    ///     The salt used to derive the hash.
    /// </param>
    /// <param name="iterations">
    ///     The number of iterations for the operation.
    /// </param>
    /// <returns>
    ///     The hexadecimal <see langword="string"/> representation of the computed hash code
    ///     if the computation succeeded; else <seealso cref="string.Empty"/>.
    /// </returns>
    /// <remarks>
    ///     <inheritdoc cref="GetSecureSHA1Hash(byte[], byte[], int)" path="/remarks"/>
    /// </remarks>
    public string GetSecureSHA384Hash(byte[] buffer, byte[] salt, int iterations = 1000);

    /// <summary>
    ///     Creates a cryptographically secure hash value for the specified <paramref name="buffer"/>
    ///     as a PBKDF2 derived key using the SHA512 hash algorithm.
    /// </summary>
    /// <param name="buffer">
    ///     The buffer used to derive the hash.
    /// </param>
    /// <param name="salt">
    ///     The salt used to derive the hash.
    /// </param>
    /// <param name="iterations">
    ///     The number of iterations for the operation.
    /// </param>
    /// <returns>
    ///     The hexadecimal <see langword="string"/> representation of the computed hash code
    ///     if the computation succeeded; else <seealso cref="string.Empty"/>.
    /// </returns>
    /// <remarks>
    ///     <inheritdoc cref="GetSecureSHA1Hash(byte[], byte[], int)" path="/remarks"/>
    /// </remarks>
    public string GetSecureSHA512Hash(byte[] buffer, byte[] salt, int iterations = 1000);

    #endregion
}