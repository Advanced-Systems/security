using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Abstractions.Exceptions;
using AdvancedSystems.Security.Cryptography;
using AdvancedSystems.Security.Options;

using Microsoft.Extensions.Options;

namespace AdvancedSystems.Security.Services;

/// <summary>
///     Represents a service for performing RSA-based asymmetric operations.
/// </summary>
public sealed class RSACryptoService : RSACryptoContract, IDisposable
{
    private bool _isDisposed = false;
    private readonly RSACryptoProvider _provider;

    public RSACryptoService(ICertificateService certificateService, IOptions<RSACryptoOptions> options)
    {
        RSACryptoOptions rsaOptions = options.Value;

        this.Certificate = certificateService.GetCertificate(rsaOptions.StoreService, rsaOptions.Thumbprint, validOnly: true)
            ?? throw new CertificateNotFoundException($"Failed to retrieve certificate with options {nameof(RSACryptoOptions.StoreService)}=\"{rsaOptions.StoreService}\" and {nameof(RSACryptoOptions.Thumbprint)}=\"{rsaOptions.Thumbprint}\".");

        this._provider = new RSACryptoProvider(this.Certificate)
        {
            HashFunction = rsaOptions.HashFunction,
            EncryptionPadding = rsaOptions.EncryptionPadding,
            SignaturePadding = rsaOptions.SignaturePadding
        };
    }

    #region Properties

    /// <inheritdoc />
    public override X509Certificate2 Certificate { get; }

    /// <inheritdoc />
    public override HashFunction HashFunction
    {
        get
        {
            return this._provider.HashFunction;
        }
        set
        {
            this._provider.HashFunction = value;
        }
    }

    /// <inheritdoc />
    public override RSAEncryptionPadding EncryptionPadding
    {
        get
        {
            return this._provider.EncryptionPadding;
        }
        set
        {
            this._provider.EncryptionPadding = value;
        }
    }

    /// <inheritdoc />
    public override RSASignaturePadding SignaturePadding
    {
        get
        {
            return this._provider.SignaturePadding;
        }
        set
        {
            this._provider.SignaturePadding = value;
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
    public override byte[] Encrypt(byte[] buffer)
    {
        ObjectDisposedException.ThrowIf(this._isDisposed, nameof(this.Certificate));

        return this._provider.Encrypt(buffer);
    }

    /// <inheritdoc />
    public override byte[] Decrypt(byte[] cipher)
    {
        ObjectDisposedException.ThrowIf(this._isDisposed, nameof(this.Certificate));

        return this._provider.Decrypt(cipher);
    }

    /// <inheritdoc />
    public override byte[] SignData(byte[] data)
    {
        ObjectDisposedException.ThrowIf(this._isDisposed, nameof(this.Certificate));

        return this._provider.SignData(data);
    }

    /// <inheritdoc />
    public override bool VerifyData(byte[] data, byte[] signature)
    {
        ObjectDisposedException.ThrowIf(this._isDisposed, nameof(this.Certificate));

        return this._provider.VerifyData(data, signature);
    }

    #endregion
}