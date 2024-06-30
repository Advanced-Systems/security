using System.Linq;
using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Exceptions;

namespace AdvancedSystems.Security.Cryptography;

/// <summary>
///     Defines functions for interacting with X.509 certificates.
/// </summary>
/// <seealso href="https://datatracker.ietf.org/doc/rfc5280/"/>
public static class Certificate
{
    /// <summary>
    ///     Retrieves an X509 certificate from the specified store using the provided thumbprint.
    /// </summary>
    /// <param name="storeName">The name of the certificate store to search in, such as <see cref="StoreName.My"/>.</param>
    /// <param name="storeLocation">The location of the certificate store, such as <see cref="StoreLocation.CurrentUser"/> or <see cref="StoreLocation.LocalMachine"/>.</param>
    /// <param name="thumbprint">The thumbprint of the certificate to locate.</param>
    /// <returns>The <see cref="X509Certificate2"/> object if the certificate is found.</returns>
    /// <exception cref="CertificateNotFoundException">Thrown when no valid certificate with the specified thumbprint is found in the store.</exception>
    public static X509Certificate2 GetStoreCertificate(StoreName storeName, StoreLocation storeLocation, string thumbprint)
    {
        using var store = new X509Store(storeName, storeLocation);
        store.Open(OpenFlags.ReadOnly);

        var certificate = store.Certificates
            .Find(X509FindType.FindByThumbprint, thumbprint, validOnly: true)
            .OfType<X509Certificate2>()
            .FirstOrDefault();

        return certificate
            ?? throw new CertificateNotFoundException("No valid certificate matching the search criteria could be found in the store.");
    }
}
