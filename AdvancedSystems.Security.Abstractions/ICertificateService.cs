using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Abstractions.Exceptions;

namespace AdvancedSystems.Security.Abstractions;

/// <summary>
///      Defines a service for managing and retrieving X.509 certificates. 
/// </summary>
public interface ICertificateService
{
    #region Methods

    /// <summary>
    ///     Retrieves an X.509 certificate from the specified store using the provided
    ///     <paramref name="thumbprint"/>.
    /// </summary>
    /// <param name="thumbprint">
    ///     The thumbprint of the certificate to locate.
    /// </param>
    /// <param name="storeName">
    ///     The certificate store from which to retrieve the certificate.
    /// </param>
    /// <param name="storeLocation">
    ///     The location of the certificate store, such as <see cref="StoreLocation.CurrentUser"/>
    ///     or <see cref="StoreLocation.LocalMachine"/>.
    /// </param>
    /// <param name="validOnly">
    ///     <see langword="true"/> to allow only valid certificates to be returned from the search; otherwise, <see langword="false"/>.
    /// </param>
    /// <returns>
    ///     The <see cref="X509Certificate2"/> object if the certificate is found, else <c>null</c>.
    /// </returns>
    /// <exception cref="CertificateNotFoundException">
    ///     Thrown when no certificate with the specified thumbprint is found in the store.
    /// </exception>
    X509Certificate2? GetStoreCertificate(string thumbprint, StoreName storeName, StoreLocation storeLocation, bool validOnly = true);

    /// <summary>
    ///      Retrieves an application-configured X.509 certificate.
    /// </summary>
    /// <param name="validOnly">
    ///     <see langword="true"/> to allow only valid certificates to be returned from the search; otherwise, <see langword="false"/>.
    /// </param>
    /// <returns>
    ///     The <see cref="X509Certificate2"/> object if the certificate is found, else <c>null</c>.
    /// </returns>
    X509Certificate2? GetConfiguredCertificate(bool validOnly = true);

    #endregion
}