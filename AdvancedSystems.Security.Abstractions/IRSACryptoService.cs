using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AdvancedSystems.Security.Abstractions;

/// <summary>
///     Represents a contract for performing RSA-based asymmetric operations.
/// </summary>
public interface IRSACryptoService : IDisposable
{
    #region Properties

    X509Certificate2 Certificate { get; }

    HashFunction HashFunction { get; }

    RSAEncryptionPadding EncryptionPadding { get; }

    RSASignaturePadding SignaturePadding { get; }

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
    byte[] Encrypt(byte[] data);

    /// <summary>
    ///     Decrypts the <paramref name="cipher"/>.
    /// </summary>
    /// <param name="cipher">
    ///     The data to decrypt.
    /// </param>
    /// <returns>
    ///     The decrypted data.
    /// </returns>
    byte[] Decrypt(byte[] cipher);

    byte[] SignData(byte[] data);

    bool VerifyData(byte[] data, byte[] signature);

    #endregion
}