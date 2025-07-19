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

    /// <inheritdoc cref="RSACryptoContract.Certificate" />
    public override X509Certificate2 Certificate { get; }

    /// <inheritdoc cref="RSACryptoContract.HashFunction" />
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

    /// <inheritdoc cref="RSACryptoContract.EncryptionPadding" />
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

    /// <inheritdoc cref="RSACryptoContract.SignaturePadding" />
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

    /// <inheritdoc cref="IDisposable.Dispose" />
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

    /// <inheritdoc cref="RSACryptoContract.Encrypt(Span{byte})" />
    public override Span<byte> Encrypt(Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(this._isDisposed, nameof(this.Certificate));

        return this._provider.Encrypt(buffer);
    }

    /// <inheritdoc cref="RSACryptoContract.Decrypt(Span{byte})" />
    public override Span<byte> Decrypt(Span<byte> cipher)
    {
        ObjectDisposedException.ThrowIf(this._isDisposed, nameof(this.Certificate));

        return this._provider.Decrypt(cipher);
    }

    /// <inheritdoc cref="RSACryptoContract.SignData(Span{byte})" />
    public override Span<byte> SignData(Span<byte> data)
    {
        ObjectDisposedException.ThrowIf(this._isDisposed, nameof(this.Certificate));

        return this._provider.SignData(data);
    }

    /// <inheritdoc cref="RSACryptoContract.VerifyData(Span{byte}, Span{byte})" />
    public override bool VerifyData(Span<byte> data, Span<byte> signature)
    {
        ObjectDisposedException.ThrowIf(this._isDisposed, nameof(this.Certificate));

        return this._provider.VerifyData(data, signature);
    }

    #endregion
}