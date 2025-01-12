using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace AdvancedSystems.Security.Abstractions;

/// <summary>
///      Defines a service for managing and retrieving X.509 certificates. 
/// </summary>
/// <seealso href="https://datatracker.ietf.org/doc/rfc5280/"/>
public interface ICertificateService
{
    #region Methods

    bool AddCertificate(string storeService, X509Certificate2 certificate);

    bool TryImportPemCertificate(string storeService, string publicKeyPath, string privateKeyPath, out X509Certificate2? certificate);

    bool TryImportPemCertificate(string storeService, string publicKeyPath, string privateKeyPath, string password, out X509Certificate2? certificate);

    bool TryImportPfxCertificate(string storeService, string path, string password, out X509Certificate2? certificate);

    bool TryImportPfxCertificate(string storeService, string path, out X509Certificate2? certificate);

    IEnumerable<X509Certificate2> GetCertificate(string storeService);

    X509Certificate2? GetCertificate(string storeService, string thumbprint, bool validOnly = true);

    bool RemoveCertificate(string storeService, string thumbprint);

    #endregion
}