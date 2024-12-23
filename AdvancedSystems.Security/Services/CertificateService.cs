﻿using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Abstractions.Exceptions;
using AdvancedSystems.Security.Extensions;
using AdvancedSystems.Security.Options;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using static AdvancedSystems.Core.Common.ExceptionFilter;

namespace AdvancedSystems.Security.Services;

/// <inheritdoc cref="ICertificateService"/>
public sealed class CertificateService : ICertificateService
{
    private readonly ILogger<CertificateService> _logger;
    private readonly IOptions<CertificateOptions> _certificateOptions;
    private readonly ICertificateStore _certificateStore;

    public CertificateService(ILogger<CertificateService> logger, IOptions<CertificateOptions> certificateOptions, ICertificateStore certificateStore)
    {
        this._logger = logger;
        this._certificateOptions = certificateOptions;
        this._certificateStore = certificateStore;
    }

    #region Methods

    /// <inheritdoc />
    public X509Certificate2? GetStoreCertificate(string thumbprint, StoreName storeName, StoreLocation storeLocation)
    {
        try
        {
            using var _ = this._logger.BeginScope("Searching for {thumbprint} in {storeName} at {storeLocation}", thumbprint, storeName, storeLocation);
            return this._certificateStore.GetCertificate(thumbprint);
        }
        catch (CertificateNotFoundException exception) when (True(() => this._logger.LogError(exception, "{Service} failed to retrieve certificate.", nameof(CertificateService))))
        {
            return null;
        }
    }

    /// <inheritdoc />
    public X509Certificate2? GetConfiguredCertificate()
    {
        var options = this._certificateOptions.Value;
        return this.GetStoreCertificate(options.Thumbprint, options.Store.Name, options.Store.Location);
    }

    #endregion
}