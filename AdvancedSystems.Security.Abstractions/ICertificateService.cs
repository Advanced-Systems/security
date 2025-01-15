using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace AdvancedSystems.Security.Abstractions;

/// <summary>
///      Defines a service for managing and retrieving X.509 certificates. 
/// </summary>
/// <seealso href="https://datatracker.ietf.org/doc/rfc5280/"/>
/// <seealso cref="ICertificateStore"/>
public interface ICertificateService
{
    #region Methods

    /// <summary>
    ///     Adds a certificate to a certificate store.
    /// </summary>
    /// <param name="storeService">
    ///     The name of the keyed <seealso cref="ICertificateStore"/> service to use.
    /// </param>
    /// <param name="certificate">
    ///     The certificate to add.
    /// </param>
    /// <returns>
    ///     Returns <see langword="true"/> if the <paramref name="certificate"/> was added
    ///     successfully to the certificate store, else <see langword="false"/>.
    /// </returns>
    bool AddCertificate(string storeService, X509Certificate2 certificate);

    /// <summary>
    ///     <inheritdoc cref="TryImportPemCertificate(string, string, string, string, out X509Certificate2?)" path="/summary"/>
    /// </summary>
    /// <param name="storeService">
    ///     <inheritdoc cref="TryImportPemCertificate(string, string, string, string, out X509Certificate2?)" path="/param[@name='storeService']"/>
    /// </param>
    /// <param name="publicKeyPath">
    ///     <inheritdoc cref="TryImportPemCertificate(string, string, string, string, out X509Certificate2?)" path="/param[@name='publicKeyPath']"/>
    /// </param>
    /// <param name="privateKeyPath">
    ///     <inheritdoc cref="TryImportPemCertificate(string, string, string, string, out X509Certificate2?)" path="/param[@name='privateKeyPath']"/>
    /// </param>
    /// <param name="certificate">
    ///     <inheritdoc cref="TryImportPemCertificate(string, string, string, string, out X509Certificate2?)" path="/param[@name='certificate']"/>
    /// </param>
    /// <returns>
    ///     <inheritdoc cref="TryImportPemCertificate(string, string, string, string, out X509Certificate2?)" path="/returns"/>
    /// </returns>
    /// <remarks>
    ///     <inheritdoc cref="TryImportPemCertificate(string, string, string, string, out X509Certificate2?)" path="/remarks"/>
    /// </remarks>
    bool TryImportPemCertificate(string storeService, string publicKeyPath, string privateKeyPath, out X509Certificate2? certificate);

    /// <summary>
    ///     Tries to import a PEM certificate file into a certificate store.
    /// </summary>
    /// <param name="storeService">
    ///     The name of the keyed <seealso cref="ICertificateStore"/> service to use.
    /// </param>
    /// <param name="publicKeyPath">
    ///     The file path to the PEM file containing the public key or certificate.
    /// </param>
    /// <param name="privateKeyPath">
    ///      The file path to the PEM file containing the private key associated with the public key.
    /// </param>
    /// <param name="password">
    ///     The password required to decrypt the private key in the PEM file.
    /// </param>
    /// <param name="certificate">
    ///     An output parameter that will contain the imported <see cref="X509Certificate2"/> instance if the operation succeeds;
    ///     otherwise, it will be <see langword="null"/>.
    /// </param>
    /// <returns>
    ///     <see langword="true"/> if the certificate was imported to the certificate store successfully, else <see langword="false"/>.
    /// </returns>
    /// <remarks>
    ///     See also: <seealso href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail"/>.
    /// </remarks>
    bool TryImportPemCertificate(string storeService, string publicKeyPath, string privateKeyPath, string password, out X509Certificate2? certificate);

    /// <summary>
    ///     <inheritdoc cref="TryImportPfxCertificate(string, string, string, out X509Certificate2?)" path="/summary"/>
    /// </summary>
    /// <param name="storeService">
    ///     <inheritdoc cref="TryImportPfxCertificate(string, string, string, out X509Certificate2?)" path="/param[@name='storeService']"/>
    /// </param>
    /// <param name="path">
    ///     <inheritdoc cref="TryImportPfxCertificate(string, string, string, out X509Certificate2?)" path="/param[@name='path']"/>
    /// </param>
    /// <param name="certificate">
    ///     <inheritdoc cref="TryImportPfxCertificate(string, string, string, out X509Certificate2?)" path="/param[@name='certificate']"/>
    /// </param>
    /// <returns>
    ///     <inheritdoc cref="TryImportPfxCertificate(string, string, string, out X509Certificate2?)" path="/returns"/>
    /// </returns>
    /// <remarks>
    ///     <inheritdoc cref="TryImportPfxCertificate(string, string, string, out X509Certificate2?)" path="/remarks"/>
    /// </remarks>
    bool TryImportPfxCertificate(string storeService, string path, out X509Certificate2? certificate);

    /// <summary>
    ///     Tries to import a PFX certificate file into a certificate store.
    /// </summary>
    /// <param name="storeService">
    ///     The name of the keyed <seealso cref="ICertificateStore"/> service to use.
    /// </param>
    /// <param name="path">
    ///      The file path to the PFX certificate file that needs to be imported.
    /// </param>
    /// <param name="password">
    ///     The password required to access the PFX file's private key.
    /// </param>
    /// <param name="certificate">
    ///     An output parameter that will contain the imported <see cref="X509Certificate2"/> instance if the operation succeeds;
    ///     otherwise, it will be <see langword="null"/>.
    /// </param>
    /// <returns>
    ///     <see langword="true"/> if the certificate was imported to the certificate store successfully, else <see langword="false"/>.
    /// </returns>
    /// <remarks>
    ///     See also: <seealso href="https://en.wikipedia.org/wiki/PKCS_12"/>.
    /// </remarks>
    bool TryImportPfxCertificate(string storeService, string path, string password, out X509Certificate2? certificate);

    /// <summary>
    ///     Retrieves all certificates from the certificate store.
    /// </summary>
    /// <param name="storeService">
    ///     The name of the keyed <seealso cref="ICertificateStore"/> service to use.
    /// </param>
    /// <returns>
    ///     Returns a collection of <seealso cref="X509Certificate2"/> certificates. 
    /// </returns>
    IEnumerable<X509Certificate2> GetCertificate(string storeService);

    /// <summary>
    ///     Retrieves a certificate from the certificate store by using the <paramref name="thumbprint"/>.
    /// </summary>
    /// <param name="storeService">
    ///     The name of the keyed <seealso cref="ICertificateStore"/> service to use.
    /// </param>
    /// <param name="thumbprint">
    ///     The string representing the thumbprint of the certificate to retrieve.
    /// </param>
    /// <param name="validOnly">
    ///     <see langword="true"/> to allow only valid certificates to be returned from the search;
    ///     otherwise, <see langword="false"/>.
    /// </param>
    /// <returns>
    ///     A <seealso cref="X509Certificate2"/> object if a certificate in the certificate store
    ///     matches the search criteria, else <see langword="null"/>.
    /// </returns>
    X509Certificate2? GetCertificate(string storeService, string thumbprint, bool validOnly = true);

    /// <summary>
    ///     Removes a certificate from the certificate store by using the <paramref name="thumbprint"/>.
    /// </summary>
    /// <param name="storeService">
    ///     The name of the keyed <seealso cref="ICertificateStore"/> service to use.
    /// </param>
    /// <param name="thumbprint">
    ///     The string representing the thumbprint of the certificate to remove.
    /// </param>
    /// <returns>
    ///     Returns <see langword="true"/> if a certificate with the specified <paramref name="thumbprint"/>
    ///     was removed from the certificate store, else <see langword="false"/>.
    /// </returns>
    bool RemoveCertificate(string storeService, string thumbprint);

    #endregion
}