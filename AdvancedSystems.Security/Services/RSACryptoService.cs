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

public sealed class RSACryptoService : IRSACryptoService
{
    private readonly ILogger<RSACryptoService> _logger;
    private readonly ICertificateService _certificateService;
    private readonly IOptions<RSACryptoOptions> _options;

    private bool _disposed = false;
    private readonly X509Certificate2 _certificate;
    private readonly RSACryptoProvider _provider;

    public RSACryptoService(ILogger<RSACryptoService> logger, ICertificateService certificateService, IOptions<RSACryptoOptions> options)
    {
        this._logger = logger;
        this._certificateService = certificateService;
        this._options = options;

        this._certificate = this._certificateService.GetConfiguredCertificate()
            ?? throw new ArgumentNullException(nameof(certificateService));

        var config = this._options.Value;
        this._provider = new RSACryptoProvider(this._certificate, config.HashAlgorithmName, config.EncryptionPadding, config.SignaturePadding, config.Encoding);
    }

    #region Properties

    public X509Certificate2 Certificate
    {
        get
        {
            return this._certificate;
        }
    }

    public HashAlgorithmName HashAlgorithmName
    {
        get
        {
            return this._provider.HashAlgorithmName;
        }
    }

    public RSAEncryptionPadding EncryptionPadding
    {
        get
        {
            return this._provider.EncryptionPadding;
        }
    }

    public RSASignaturePadding SignaturePadding
    {
        get
        {
            return this._provider.SignaturePadding;
        }
    }

    public Encoding Encoding
    {
        get
        {
            return this._provider.Encoding;
        }
    }

    #endregion

    #region Public Methods

    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    public void Dispose(bool disposing)
    {
        if (this._disposed) return;

        if (disposing)
        {
            this._certificate.Dispose();
            this._disposed = true;
        }
    }

    public bool IsValidMessage(string message, RSAEncryptionPadding? padding, Encoding? encoding = null)
    {
        return this._provider.IsValidMessage(message, padding, encoding);
    }

    public string Encrypt(string message, Encoding? encoding = null)
    {
        return this._provider.Encrypt(message, encoding);
    }

    public string Decrypt(string cipher, Encoding? encoding = null)
    {
        return this._provider.Decrypt(cipher, encoding);
    }

    public string SignData(string data, Encoding? encoding = null)
    {
        return this._provider.SignData(data, encoding);
    }

    public bool VerifyData(string data, string signature, Encoding? encoding = null)
    {
        return this._provider.VerifyData(data, signature, encoding);
    }

    #endregion
}
