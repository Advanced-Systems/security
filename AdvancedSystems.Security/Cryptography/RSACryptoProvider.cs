using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Extensions;

namespace AdvancedSystems.Security.Cryptography;

/// <summary>
///     Represents a class for performing RSA-based asymmetric operations.
/// </summary>
public sealed class RSACryptoProvider : RSACryptoContract, IDisposable
{
    private bool _isDisposed = false;

    public RSACryptoProvider(X509Certificate2 certificate)
    {
        this.Certificate = certificate;
    }

    #region Properties

    /// <inheritdoc cref="RSACryptoContract.Certificate" />
    public override X509Certificate2 Certificate { get; }

    /// <inheritdoc cref="RSACryptoContract.HashFunction" />
    public override HashFunction HashFunction { get; set; } = HashFunction.SHA256;

    /// <inheritdoc cref="RSACryptoContract.EncryptionPadding" />
    public override RSAEncryptionPadding EncryptionPadding { get; set; } = RSAEncryptionPadding.OaepSHA256;

    /// <inheritdoc cref="RSACryptoContract.SignaturePadding" />
    public override RSASignaturePadding SignaturePadding { get; set; } = RSASignaturePadding.Pss;

    #endregion

    #region Methods

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

    /// <inheritdoc cref="RSACryptoContract.Encrypt(byte[])" />
    public override byte[] Encrypt(byte[] data)
    {
        ObjectDisposedException.ThrowIf(this._isDisposed, nameof(this.Certificate));

        using RSA publicKey = this.Certificate.GetRSAPublicKey()
            ?? throw new CryptographicException("Public Key is null.");

        byte[] cipher = publicKey.Encrypt(data, this.EncryptionPadding);
        return cipher;
    }

    /// <inheritdoc cref="RSACryptoContract.Decrypt(byte[])" />
    public override byte[] Decrypt(byte[] cipher)
    {
        ObjectDisposedException.ThrowIf(this._isDisposed, nameof(this.Certificate));

        if (!this.Certificate.HasPrivateKey)
        {
            throw new CryptographicException($"Certificate with thumbprint \"{this.Certificate.Thumbprint}\" has no private key.");
        }

        using RSA privateKey = this.Certificate.GetRSAPrivateKey()
            ?? throw new CryptographicException("Private Key is null.");

        byte[] source = privateKey.Decrypt(cipher, this.EncryptionPadding);
        return source;
    }

    /// <inheritdoc cref="RSACryptoContract.SignData(byte[])" />
    public override byte[] SignData(byte[] data)
    {
        ObjectDisposedException.ThrowIf(this._isDisposed, nameof(this.Certificate));

        if (!this.Certificate.HasPrivateKey)
        {
            throw new CryptographicException($"Certificate with thumbprint \"{this.Certificate.Thumbprint}\" has no private key.");
        }

        using RSA privateKey = this.Certificate.GetRSAPrivateKey()
            ?? throw new CryptographicException("Private Key is null.");

        byte[] signature = privateKey.SignData(data, this.HashFunction.ToHashAlgorithmName(), this.SignaturePadding);
        return signature;
    }

    /// <inheritdoc cref="RSACryptoContract.VerifyData(byte[], byte[])" />
    public override bool VerifyData(byte[] data, byte[] signature)
    {
        ObjectDisposedException.ThrowIf(this._isDisposed, nameof(this.Certificate));

        using RSA publicKey = this.Certificate.GetRSAPublicKey()
            ?? throw new CryptographicException("Public Key is null.");

        bool isVerified = publicKey.VerifyData(data, signature, this.HashFunction.ToHashAlgorithmName(), this.SignaturePadding);
        return isVerified;
    }

    #endregion
}