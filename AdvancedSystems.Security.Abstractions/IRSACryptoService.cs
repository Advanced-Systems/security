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

    byte[] Encrypt(byte[] message);

    byte[] Decrypt(byte[] cipher);

    byte[] SignData(byte[] data);

    bool VerifyData(byte[] data, byte[] signature);

    #endregion
}