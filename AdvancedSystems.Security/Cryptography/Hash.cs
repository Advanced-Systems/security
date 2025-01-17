using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace AdvancedSystems.Security.Cryptography;

/// <summary>
///     Implements cryptographic hash algorithms.
/// </summary>
public static class Hash
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static HashAlgorithm Create(HashAlgorithmName hashAlgorithmName)
    {
        // Starting with net8, cryptographic factory methods accepting an algorithm
        // name are obsolet and to be replaced by the parameterless Create factory
        // method on the algorithm type, because their derived cryptographic types
        // such as SHA1Managed were obsoleted with net6. That is why this function
        // is intentionally not using the HashAlgorithmName.Create(name) factory.
        return hashAlgorithmName.Name switch
        {
            "MD5" => MD5.Create(),
            "SHA1" => SHA1.Create(),
            "SHA256" => SHA256.Create(),
            "SHA384" => SHA384.Create(),
            "SHA512" => SHA512.Create(),
            "SHA3-256" => SHA3_256.Create(),
            "SHA3-384" => SHA3_384.Create(),
            "SHA3-512" => SHA3_512.Create(),
            _ => throw new NotImplementedException()
        };
    }

    /// <summary>
    ///     Computes the hash value for the specified byte array.
    /// </summary>
    /// <param name="buffer">
    ///     The input to compute the hash code for.
    /// </param>
    /// <param name="hashAlgorithmName">
    ///     The hash algorithm implementation to use.
    /// </param>
    /// <returns>
    ///     The computed hash code.
    /// </returns>
    /// <remarks>
    ///     WARNING: Do <i>not</i> use this method to compute hashes for  confidential data (e.g., passwords).
    ///     Instead, use 
    ///     <seealso cref="TryComputeSecure(byte[], byte[], int, int, HashAlgorithmName, out byte[])"/> 
    ///     for secure hashing.
    /// </remarks>
    public static byte[] Compute(byte[] buffer, HashAlgorithmName hashAlgorithmName)
    {
        using var hashAlgorithm = Hash.Create(hashAlgorithmName);

        return hashAlgorithm.ComputeHash(buffer);
    }

    /// <summary>
    ///     Creates a cryptographically secure hash value for the specified byte array as a PBKDF2 derived key.
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
    /// <param name="hashAlgorithmName">
    ///     The hash algorithm to use to derive the hash. Supported algorithms are:
    ///     <list type="bullet">
    ///         <item>
    ///             <seealso cref="HashAlgorithmName.SHA1"/>
    ///         </item>
    ///         <item>
    ///             <seealso cref="HashAlgorithmName.SHA3_256"/>
    ///         </item>
    ///         <item>
    ///             <seealso cref="HashAlgorithmName.SHA3_384"/>
    ///         </item>
    ///         <item>
    ///             <seealso cref="HashAlgorithmName.SHA3_512"/>
    ///         </item>
    ///     </list>
    /// </param>
    /// <param name="pbkdf2">
    ///     A byte array containing the created PBKDF2 derived hash.
    /// </param>
    /// <returns>
    ///     <see langword="true"/> if the operation succeeds; otherwise, <see langword="false"/>.
    /// </returns>
    /// <remarks>
    ///     Notes on usage:
    ///     <list type="bullet">
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
    public static bool TryComputeSecure(byte[] password, byte[] salt, int hashSize, int iterations, HashAlgorithmName hashAlgorithmName, [NotNullWhen(true)] out byte[] pbkdf2)
    {
        try
        {
            pbkdf2 = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, hashAlgorithmName, hashSize);
            return true;
        }
        catch (Exception)
        {
            pbkdf2 = [];
            return false;
        }
    }
}