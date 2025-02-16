using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Extensions;

namespace AdvancedSystems.Security.Cryptography;

/// <summary>
///     Represents a class for performing RSA-based asymmetric operations.
/// </summary>
public sealed class RSACryptoProvider : IDisposable
{
    private bool _isDisposed = false;

    public RSACryptoProvider(X509Certificate2 certificate)
    {
        this.Certificate = certificate;
    }

    ~RSACryptoProvider()
    {
        this.Dispose(false);
    }

    #region Properties

    public X509Certificate2 Certificate { get; private set; }

    public HashFunction HashFunction { get; set; } = HashFunction.SHA256;

    public RSAEncryptionPadding EncryptionPadding { get; set; } = RSAEncryptionPadding.OaepSHA256;

    public RSASignaturePadding SignaturePadding { get; set; } = RSASignaturePadding.Pss;

    #endregion

    #region Public Methods

    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (this._isDisposed) return;

        if (disposing)
        {
            this.Certificate.Dispose();
        }

        this._isDisposed = true;
    }

    /// <inheritdoc cref="IRSACryptoService.Encrypt(byte[])" />
    public byte[] Encrypt(byte[] data)
    {
        using RSA? publicKey = this.Certificate.GetRSAPublicKey();
        ArgumentNullException.ThrowIfNull(publicKey, nameof(publicKey));

        byte[] cipher = publicKey.Encrypt(data, this.EncryptionPadding);
        return cipher;
    }

    /// <inheritdoc cref="IRSACryptoService.Decrypt(byte[])" />
    public byte[] Decrypt(byte[] cipher)
    {
        if (!this.Certificate.HasPrivateKey)
        {
            throw new CryptographicException($"Certificate with thumbprint '{this.Certificate.Thumbprint}' has no private key.");
        }

        using RSA? privateKey = this.Certificate.GetRSAPrivateKey();
        ArgumentNullException.ThrowIfNull(privateKey, nameof(privateKey));

        byte[] source = privateKey.Decrypt(cipher, this.EncryptionPadding);
        return source;
    }

    /// <inheritdoc cref="IRSACryptoService.SignData(byte[])" />
    public byte[] SignData(byte[] data)
    {
        using RSA? privateKey = this.Certificate.GetRSAPrivateKey();
        ArgumentNullException.ThrowIfNull(privateKey, nameof(privateKey));

        byte[] signature = privateKey.SignData(data, this.HashFunction.ToHashAlgorithmName(), this.SignaturePadding);
        return signature;
    }

    /// <inheritdoc cref="IRSACryptoService.VerifyData(byte[], byte[])" />
    public bool VerifyData(byte[] data, byte[] signature)
    {
        using RSA? publicKey = this.Certificate.GetRSAPublicKey();
        ArgumentNullException.ThrowIfNull(publicKey, nameof(publicKey));

        bool isVerified = publicKey.VerifyData(data, signature, this.HashFunction.ToHashAlgorithmName(), this.SignaturePadding);
        return isVerified;
    }

    #endregion
}