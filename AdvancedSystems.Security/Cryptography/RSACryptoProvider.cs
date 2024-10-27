using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using AdvancedSystems.Core.Extensions;

namespace AdvancedSystems.Security.Cryptography;

public sealed class RSACryptoProvider
{
    private static readonly HashAlgorithmName DEFAULT_HASH_ALGORITHM_NAME = HashAlgorithmName.SHA256;
    private static readonly RSAEncryptionPadding DEFAULT_RSA_ENCRYPTION_PADDING = RSAEncryptionPadding.OaepSHA256;
    private static readonly RSASignaturePadding DEFAULT_RSA_SIGNATURE_PADDING = RSASignaturePadding.Pss;
    private static readonly Encoding DEFAULT_ENCODING = Encoding.UTF8;

    public RSACryptoProvider(X509Certificate2 certificate, HashAlgorithmName hashAlgorithm, RSAEncryptionPadding encryptionPadding, RSASignaturePadding signaturePadding, Encoding encoding)
    {
        this.Certificate = certificate;
        this.HashAlgorithmName = hashAlgorithm;
        this.EncryptionPadding = encryptionPadding;
        this.SignaturePadding = signaturePadding;
        this.Encoding = encoding;
    }

    public RSACryptoProvider(X509Certificate2 certificate)
    {
        this.Certificate = certificate;
        this.HashAlgorithmName = RSACryptoProvider.DEFAULT_HASH_ALGORITHM_NAME;
        this.EncryptionPadding = RSACryptoProvider.DEFAULT_RSA_ENCRYPTION_PADDING;
        this.SignaturePadding = RSACryptoProvider.DEFAULT_RSA_SIGNATURE_PADDING;
        this.Encoding = RSACryptoProvider.DEFAULT_ENCODING;
    }

    #region Properties

    public X509Certificate2 Certificate { get; private set; }

    public HashAlgorithmName HashAlgorithmName { get; set; }

    public RSAEncryptionPadding EncryptionPadding { get; set; }

    public RSASignaturePadding SignaturePadding { get; set; }

    public Encoding Encoding { get; set; }

    #endregion

    #region Public Methods

    public bool IsValidMessage(string message, RSAEncryptionPadding? padding, Encoding? encoding = null)
    {
        using RSA? publicKey = this.Certificate.GetRSAPublicKey();
        ArgumentNullException.ThrowIfNull(publicKey, nameof(publicKey));

        encoding ??= this.Encoding;
        int messageSize = encoding.GetByteCount(message);
        decimal keySize = Math.Floor(publicKey.KeySize / 8M);

        if (padding is null)
        {
            decimal limit = keySize - 11;
            return messageSize <= limit;
        }

        using var hashAlgorithm = Hash.Create(padding.OaepHashAlgorithm);
        decimal hashSize = Math.Ceiling(hashAlgorithm.HashSize / 8M);
        decimal limitPadded = keySize - (2 * hashSize) - 2;
        return messageSize <= limitPadded;
    }

    public string Encrypt(string message, Encoding? encoding = null)
    {
        encoding ??= this.Encoding;

        using RSA? publicKey = this.Certificate.GetRSAPublicKey();
        ArgumentNullException.ThrowIfNull(publicKey, nameof(publicKey));

        byte[] buffer = encoding.GetBytes(message);
        byte[] cipher = publicKey.Encrypt(buffer, this.EncryptionPadding);
        return Convert.ToBase64String(cipher);
    }

    public string Decrypt(string cipher, Encoding? encoding = null)
    {
        if (!this.Certificate.HasPrivateKey)
        {
            throw new CryptographicException($"Certificate with thumbprint '{this.Certificate.Thumbprint}' has no private key.");
        }

        encoding ??= this.Encoding;

        using RSA? privateKey = this.Certificate.GetRSAPrivateKey();
        ArgumentNullException.ThrowIfNull(privateKey, nameof(privateKey));

        byte[] buffer = Convert.FromBase64String(cipher);
        byte[] source = privateKey.Decrypt(buffer, this.EncryptionPadding);
        return encoding.GetString(source);
    }

    public string SignData(string data, Encoding? encoding = null)
    {
        if (data.IsNullOrEmpty())
        {
            throw new ArgumentNullException(nameof(data));
        }

        using RSA? privateKey = this.Certificate.GetRSAPrivateKey();
        ArgumentNullException.ThrowIfNull(privateKey, nameof(privateKey));

        encoding ??= this.Encoding;
        byte[] buffer = encoding.GetBytes(data);

        byte[] signature = privateKey.SignData(buffer, this.HashAlgorithmName, this.SignaturePadding);
        return Convert.ToBase64String(signature);
    }

    public bool VerifyData(string data, string signature, Encoding? encoding = null)
    {
        using RSA? publicKey = this.Certificate.GetRSAPublicKey();
        ArgumentNullException.ThrowIfNull(publicKey, nameof(publicKey));

        encoding ??= this.Encoding;
        byte[] buffer = encoding.GetBytes(data);
        byte[] signedBuffer = Convert.FromBase64String(signature);

        bool isVerified = publicKey.VerifyData(buffer, signedBuffer, this.HashAlgorithmName, this.SignaturePadding);
        return isVerified;
    }

    #endregion
}