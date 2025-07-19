using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AdvancedSystems.Security.Abstractions;

/// <summary>
///     Represents a contract for performing RSA-based asymmetric operations.
/// </summary>
public abstract class RSACryptoContract
{
    #region Properties

    /// <inheritdoc cref="X509Certificate2" path="/summary" />
    public abstract X509Certificate2 Certificate { get; }

    /// <inheritdoc cref="Abstractions.HashFunction" path="/summary" />
    public abstract HashFunction HashFunction { get; set; }

    /// <inheritdoc cref="RSAEncryptionPadding" path="/summary" />
    public abstract RSAEncryptionPadding EncryptionPadding { get; set; }

    /// <inheritdoc cref="RSASignaturePadding" path="/summary" />
    public abstract RSASignaturePadding SignaturePadding { get; set; }

    #endregion

    #region Methods

    /// <summary>
    ///     Encrypts the input <paramref name="data"/>.
    /// </summary>
    /// <param name="data">
    ///     The data to encrypt.
    /// </param>
    /// <returns>
    ///     The encrypted data.
    /// </returns>
    /// <exception cref="ObjectDisposedException">
    ///     Raised if this object has already been disposed.
    /// </exception>
    /// <exception cref="CryptographicException">
    ///     Raised if the public key of the specified certificate is null.
    /// </exception>
    public abstract Span<byte> Encrypt(Span<byte> data);

    /// <summary>
    ///     Decrypts the <paramref name="cipher"/>.
    /// </summary>
    /// <param name="cipher">
    ///     The data to decrypt.
    /// </param>
    /// <returns>
    ///     The decrypted data.
    /// </returns>
    /// <exception cref="ObjectDisposedException">
    ///     Raised if this object has already been disposed.
    /// </exception>
    /// <exception cref="CryptographicException">
    ///     Raised if the private key of the specified certificate is null.
    /// </exception>
    public abstract Span<byte> Decrypt(Span<byte> cipher);

    /// <summary>
    ///     Computes the hash value of the specified data and signs it.
    /// </summary>
    /// <param name="data">
    ///     The input data to hash and sign.
    /// </param>
    /// <returns>
    ///     The RSA signature for the specified data.
    /// </returns>
    /// <exception cref="ObjectDisposedException">
    ///     Raised if this object has already been disposed.
    /// </exception>
    /// <exception cref="CryptographicException">
    ///     Raised if the private key of the specified certificate is null.
    /// </exception>
    public abstract Span<byte> SignData(Span<byte> data);

    /// <summary>
    ///     Verifies that a digital signature is valid by calculating the
    ///     hash value of the specified data using the specified hash algorithm
    ///     and padding, and comparing it to the provided signature.
    /// </summary>
    /// <param name="data">
    ///     The signed data.
    /// </param>
    /// <param name="signature">
    ///     The signature data to be verified.
    /// </param>
    /// <returns>
    ///     <see langword="true"/> if the signature is valid; otherwise, <see langword="false"/>.
    /// </returns>
    /// <exception cref="ObjectDisposedException">
    ///     Raised if this object has already been disposed.
    /// </exception>
    /// <exception cref="CryptographicException">
    ///     Raised if the public key of the specified certificate is null.
    /// </exception>
    public abstract bool VerifyData(Span<byte> data, Span<byte> signature);

    #endregion
}