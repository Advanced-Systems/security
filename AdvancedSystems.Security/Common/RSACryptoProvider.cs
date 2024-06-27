using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AdvancedSystems.Security.Common;

public sealed class RSACryptoProvider
{
    private static readonly HashAlgorithmName DEFAULT_HASH_ALGORITHM_NAME = HashAlgorithmName.SHA256;
    private static readonly RSAEncryptionPadding DEFAULT_RSA_ENCRYPTION_PADDING = RSAEncryptionPadding.OaepSHA256;
    private static readonly RSASignaturePadding DEFAULT_RSA_SIGNATURE_PADDING = RSASignaturePadding.Pss;
    private static readonly Encoding DEFAULT_ENCODING = Encoding.UTF8;

    private readonly X509Certificate2 _certificate;
    private readonly HashAlgorithmName _hashAlgorithmName;
    private readonly RSAEncryptionPadding _rsaEncryptionPadding;
    private readonly RSASignaturePadding _rsaSignaturePadding;

    public RSACryptoProvider(X509Certificate2 certificate, HashAlgorithmName hashAlgorithm, RSAEncryptionPadding encryptionPadding, RSASignaturePadding signaturePadding)
    {
        this._certificate = new X509Certificate2(certificate);
        this._hashAlgorithmName = hashAlgorithm;
        this._rsaEncryptionPadding = encryptionPadding;
        this._rsaSignaturePadding = signaturePadding;
    }

    public RSACryptoProvider(X509Certificate2 certificate)
    {
        this._certificate = certificate;
        this._hashAlgorithmName = RSACryptoProvider.DEFAULT_HASH_ALGORITHM_NAME;
        this._rsaEncryptionPadding = RSACryptoProvider.DEFAULT_RSA_ENCRYPTION_PADDING;
        this._rsaSignaturePadding = RSACryptoProvider.DEFAULT_RSA_SIGNATURE_PADDING;
    }

    #region Properties

    public X509Certificate2 Certificate => this._certificate;

    #endregion

    #region Public Methods

    public static bool IsValidMessage(string message, Encoding encoding, RSA publicKey, RSAEncryptionPadding padding = null)
    {
        throw new NotImplementedException();
    }

    public byte[] Encrypt(byte[] message)
    {
        throw new NotImplementedException();
    }

    public byte[] Encrypt(string message, Encoding? encoding = null)
    {
        encoding ??= RSACryptoProvider.DEFAULT_ENCODING;

        throw new NotImplementedException();
    }

    public byte[] Decrypt(byte[] cipher)
    {
        throw new NotImplementedException();
    }

    public string Decrypt(byte[] cipher, Encoding? encoding = null)
    {
        encoding ??= RSACryptoProvider.DEFAULT_ENCODING;

        throw new NotImplementedException();
    }

    public byte[] Sign(byte[] data)
    {
        throw new NotImplementedException();
    }

    public bool Verify(byte[] data, byte[] signature)
    {
        throw new NotImplementedException();
    }

    #endregion
}
