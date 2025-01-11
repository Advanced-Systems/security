using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Abstractions;

using Microsoft.Extensions.Logging;

namespace AdvancedSystems.Security.Services;

/// <inheritdoc cref="ICertificateService"/>
public sealed class CertificateService : ICertificateService
{
    private readonly ILogger<CertificateService> _logger;
    private readonly ICertificateStore _certificateStore;

    public CertificateService(ILogger<CertificateService> logger, ICertificateStore certificateStore)
    {
        this._logger = logger;
        this._certificateStore = certificateStore;
    }

    #region Methods

    public void ImportCertificate()
    {
        throw new NotImplementedException();
    }

    public IEnumerable<X509Certificate2> GetCertificate()
    {
        try
        {
            this._certificateStore.Open(OpenFlags.ReadOnly);

            return this._certificateStore.Certificates.OfType<X509Certificate2>();
        }
        catch (ArgumentNullException)
        {
            return Enumerable.Empty<X509Certificate2>();
        }
        finally
        {
            this._certificateStore.Close();
        }
    }

    /// <inheritdoc />
    public X509Certificate2? GetStoreCertificate(string thumbprint, StoreName storeName, StoreLocation storeLocation, bool validOnly = true)
    {
        try
        {
            this._certificateStore.Open(OpenFlags.ReadOnly);

            var certificate = this._certificateStore.Certificates
                .Find(X509FindType.FindByThumbprint, thumbprint, validOnly)
                .OfType<X509Certificate2>()
                .FirstOrDefault();

            return certificate;
        }
        finally
        {
            this._certificateStore.Close();
        }
    }

    /// <inheritdoc />
    public X509Certificate2? GetConfiguredCertificate(bool validOnly = true)
    {
        return null;
    }

    public bool RemoveCertificate(string thumbprint)
    {
        try
        {
            this._certificateStore.Open(OpenFlags.ReadWrite);

            X509Certificate2Collection? certificates = this._certificateStore.Certificates
                .Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);

            if (certificates is null) return false;

            this._certificateStore.RemoveRange(certificates);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
        finally
        {
            this._certificateStore.Close();
        }
    }

    #endregion
}