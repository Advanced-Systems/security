using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Cryptography;
using AdvancedSystems.Security.Options;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AdvancedSystems.Security.Services;

/// <summary>
///     Represents a service for performing RSA-based asymmetric operations.
/// </summary>
public sealed class RSACryptoService : IRSACryptoService
{
    private bool _isDisposed = false;
    private readonly ILogger<RSACryptoService> _logger;
    private readonly RSACryptoProvider _provider;

    public RSACryptoService(ILogger<RSACryptoService> logger, ICertificateService certificateService, IOptions<RSACryptoOptions> rsaOptions)
    {
        this._logger = logger;
        RSACryptoOptions rsaOptions1 = rsaOptions.Value;

        this.Certificate = certificateService.GetCertificate("default", rsaOptions1.Thumbprint, validOnly: true)
            ?? throw new ArgumentNullException(nameof(rsaOptions));

        this._provider = new RSACryptoProvider(this.Certificate);
        this._provider.HashFunction = rsaOptions1.HashFunction;
        this._provider.EncryptionPadding = rsaOptions1.EncryptionPadding;
        this._provider.SignaturePadding = rsaOptions1.SignaturePadding;
    }

    ~RSACryptoService()
    {
        this.Dispose(false);
    }

    #region Properties

    /// <inheritdoc />
    public X509Certificate2 Certificate { get; }

    /// <inheritdoc />
    public HashFunction HashFunction
    {
        get
        {
            return this._provider.HashFunction;
        }
    }

    /// <inheritdoc />
    public RSAEncryptionPadding EncryptionPadding
    {
        get
        {
            return this._provider.EncryptionPadding;
        }
    }

    /// <inheritdoc />
    public RSASignaturePadding SignaturePadding
    {
        get
        {
            return this._provider.SignaturePadding;
        }
    }

    #endregion

    #region Methods

    /// <inheritdoc />
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
            this._provider.Dispose();
        }

        this._isDisposed = true;
    }

    /// <inheritdoc />
    public byte[] Encrypt(byte[] buffer)
    {
        return this._provider.Encrypt(buffer);
    }

    /// <inheritdoc />
    public byte[] Decrypt(byte[] cipher)
    {
        return this._provider.Decrypt(cipher);
    }

    /// <inheritdoc />
    public byte[] SignData(byte[] data)
    {
        return this._provider.SignData(data);
    }

    /// <inheritdoc />
    public bool VerifyData(byte[] data, byte[] signature)
    {
        return this._provider.VerifyData(data, signature);
    }

    #endregion
}