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

    private static readonly HashFunction DEFAULT_HASH_FUNCTION = HashFunction.SHA256;
    private static readonly RSAEncryptionPadding DEFAULT_RSA_ENCRYPTION_PADDING = RSAEncryptionPadding.OaepSHA256;
    private static readonly RSASignaturePadding DEFAULT_RSA_SIGNATURE_PADDING = RSASignaturePadding.Pss;

    public RSACryptoProvider(X509Certificate2 certificate, HashFunction hashFunction, RSAEncryptionPadding encryptionPadding, RSASignaturePadding signaturePadding)
    {
        this.Certificate = certificate;
        this.HashFunction = hashFunction;
        this.EncryptionPadding = encryptionPadding;
        this.SignaturePadding = signaturePadding;
    }

    public RSACryptoProvider(X509Certificate2 certificate)
    {
        this.Certificate = certificate;
        this.HashFunction = DEFAULT_HASH_FUNCTION;
        this.EncryptionPadding = DEFAULT_RSA_ENCRYPTION_PADDING;
        this.SignaturePadding = DEFAULT_RSA_SIGNATURE_PADDING;
    }

    #region Properties

    public X509Certificate2 Certificate { get; private set; }

    public HashFunction HashFunction { get; set; }

    public RSAEncryptionPadding EncryptionPadding { get; set; }

    public RSASignaturePadding SignaturePadding { get; set; }

    #endregion

    #region Public Methods

    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    public void Dispose(bool disposing)
    {
        if (this._isDisposed) return;

        if (disposing && this.Certificate is not null)
        {
            this.Certificate.Dispose();
        }

        this._isDisposed = true;
    }

    public byte[] Encrypt(byte[] buffer)
    {
        using RSA? publicKey = this.Certificate.GetRSAPublicKey();
        ArgumentNullException.ThrowIfNull(publicKey, nameof(publicKey));

        byte[] cipher = publicKey.Encrypt(buffer, this.EncryptionPadding);
        return cipher;
    }

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

    public byte[] SignData(byte[] data)
    {
        using RSA? privateKey = this.Certificate.GetRSAPrivateKey();
        ArgumentNullException.ThrowIfNull(privateKey, nameof(privateKey));

        byte[] signature = privateKey.SignData(data, this.HashFunction.ToHashAlgorithmName(), this.SignaturePadding);
        return signature;
    }

    public bool VerifyData(byte[] data, byte[] signature)
    {
        using RSA? publicKey = this.Certificate.GetRSAPublicKey();
        ArgumentNullException.ThrowIfNull(publicKey, nameof(publicKey));

        bool isVerified = publicKey.VerifyData(data, signature, this.HashFunction.ToHashAlgorithmName(), this.SignaturePadding);
        return isVerified;
    }

    #endregion
}