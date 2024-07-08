using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Cryptography;
using AdvancedSystems.Security.Exceptions;
using AdvancedSystems.Security.Options;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using static AdvancedSystems.Security.Internals.ExceptionFilter;

namespace AdvancedSystems.Security.Services;

public sealed class CertificateService : ICertificateService
{
    private readonly ILogger<CertificateService> _logger;
    private readonly IOptions<CertificateOptions> _options;

    public CertificateService(ILogger<CertificateService> logger, IOptions<CertificateOptions> options)
    {
        this._logger = logger;
        this._options = options;
    }

    #region Public Methods

    public X509Certificate2? GetStoreCertificate(string thumbprint, StoreName storeName, StoreLocation storeLocation)
    {
        try
        {
            using var _ = this._logger.BeginScope("Searching for {thumbprint} in {storeName} at {storeLocation}", thumbprint, storeName, storeLocation);
            return Certificate.GetStoreCertificate(storeName, storeLocation, thumbprint);
        }
        catch (CertificateNotFoundException exception) when (True(() => this._logger.LogError(exception, "{Service} failed to retrieve certificate.", nameof(CertificateService))))
        {
            return null;
        }
    }

    public X509Certificate2? GetConfiguredCertificate()
    {
        var config = this._options.Value;
        return this.GetStoreCertificate(config.Thumbprint, config.StoreName, config.StoreLocation);
    }

    #endregion
}
