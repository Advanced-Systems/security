using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Cryptography;
using AdvancedSystems.Security.Options;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AdvancedSystems.Security.Services;

/// <summary>
///     Represents a service for performing RSA-based asymmetric operations.
/// </summary>
public sealed class RSACryptoService
{
    private readonly ILogger<RSACryptoService> _logger;
    private readonly ICertificateService _certificateService;
    private readonly RSACryptoOptions _rsaOptions;

    private bool _disposed = false;
    private readonly X509Certificate2 _certificate;
    private readonly RSACryptoProvider _provider;

    public RSACryptoService(ILogger<RSACryptoService> logger, ICertificateService certificateService, IOptions<RSACryptoOptions> rsaOptions)
    {
        this._logger = logger;
        this._certificateService = certificateService;
        this._rsaOptions = rsaOptions.Value;

        this._certificate = this._certificateService.GetCertificate("default", this._rsaOptions.Thumbprint, validOnly: true)
            ?? throw new ArgumentNullException();

        this._provider = new RSACryptoProvider(
            this._certificate,
            this._rsaOptions.HashAlgorithmName,
            this._rsaOptions.EncryptionPadding,
            this._rsaOptions.SignaturePadding,
            this._rsaOptions.Encoding
         );
    }

    #region Properties

    /// <inheritdoc />
    public X509Certificate2 Certificate
    {
        get
        {
            return this._certificate;
        }
    }

    /// <inheritdoc />
    public HashAlgorithmName HashAlgorithmName
    {
        get
        {
            return this._provider.HashAlgorithmName;
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

    /// <inheritdoc />
    public Encoding Encoding
    {
        get
        {
            return this._provider.Encoding;
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

    /// <inheritdoc />
    public void Dispose(bool disposing)
    {
        if (this._disposed || !disposing) return;

        this._certificate.Dispose();
        this._disposed = true;
    }

    /// <inheritdoc />
    public string Encrypt(string message, Encoding? encoding = null)
    {
        return this._provider.Encrypt(message, encoding);
    }

    /// <inheritdoc />
    public string Decrypt(string cipher, Encoding? encoding = null)
    {
        return this._provider.Decrypt(cipher, encoding);
    }

    /// <inheritdoc />
    public string SignData(string data, Encoding? encoding = null)
    {
        return this._provider.SignData(data, encoding);
    }

    /// <inheritdoc />
    public bool VerifyData(string data, string signature, Encoding? encoding = null)
    {
        return this._provider.VerifyData(data, signature, encoding);
    }

    #endregion
}