using System.Linq;
using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Abstractions.Exceptions;

namespace AdvancedSystems.Security.Extensions;

/// <summary>
///     Defines functions for interacting with X.509 certificates.
/// </summary>
/// <seealso href="https://datatracker.ietf.org/doc/rfc5280/"/>
public static class CertificateStore
{
    /// <summary>
    ///     Retrieves an X.509 certificate from the specified store using the provided thumbprint.
    /// </summary>
    /// <typeparam name="T">The type of the certificate store, which must implement the <see cref="ICertificateStore"/> interface.</typeparam>
    /// <param name="store">The certificate store from which to retrieve the certificate.</param>
    /// <param name="thumbprint">The thumbprint of the certificate to locate.</param>
    /// <returns>The <see cref="X509Certificate2"/> object if the certificate is found.</returns>
    /// <exception cref="CertificateNotFoundException">Thrown when no certificate with the specified thumbprint is found in the store.</exception>
    public static X509Certificate2 GetCertificate<T>(this T store, string thumbprint) where T : ICertificateStore
    {
        store.Open(OpenFlags.ReadOnly);

        var certificate = store.Certificates
            .Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
            .OfType<X509Certificate2>()
            .FirstOrDefault();

        return certificate
            ?? throw new CertificateNotFoundException("No valid certificate matching the search criteria could be found in the store.");
    }
}
