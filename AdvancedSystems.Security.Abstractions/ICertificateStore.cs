using System;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AdvancedSystems.Security.Abstractions;

/// <summary>
///     Represents an X.509 store, which is a physical store where certificates are persisted and managed.
/// </summary>
public interface ICertificateStore : IDisposable
{
    #region Properties

    /// <summary>
    ///     Gets an <seealso cref="IntPtr"/> handle to an <c>HCERTSTORE</c> store.
    /// </summary>
    IntPtr StoreHandle { get; }

    /// <summary>
    ///     Gets the location of the X.509 certificate store.
    /// </summary>
    StoreLocation Location { get; }

    /// <summary>
    ///     Gets the name of the X.509 certificate store.
    /// </summary>
    string? Name { get; }

    /// <summary>
    ///     Returns a collection of certificates located in an X.509 certificate store.
    /// </summary>
    X509Certificate2Collection Certificates { get; }

    /// <summary>
    ///     Gets a value that indicates whether the instance is connected to an open certificate store.
    /// </summary>
    bool IsOpen { get; }

    #endregion

    #region Methods

    /// <summary>
    ///     Opens an X.509 certificate store or creates a new store, depending on <seealso cref="OpenFlags"/> flag settings.
    /// </summary>
    /// <param name="flags">A bitwise combination of enumeration values that specifies the way to open the X.509 certificate store.</param>
    /// <exception cref="CryptographicException">The store cannot be opened as requested.</exception>
    /// <exception cref="SecurityException">The caller does not have the required permission.</exception>
    /// <exception cref="ArgumentException">The store contains invalid values.</exception>
    /// <remarks>
    ///     Use this method to open an existing X.509 store. Note that you must have additional permissions, specified by
    ///     <c>StorePermissionFlags</c>, to enumerate the certificates in the store. You can create a new store
    ///     by passing a store name that does not exist to the class constructor, and then using any of the <seealso cref="OpenFlags"/>
    ///     flags except <seealso cref="OpenFlags.OpenExistingOnly"/>.
    /// </remarks>
    void Open(OpenFlags flags);

    /// <summary>
    ///     Closes an X.509 certificate store.
    /// </summary>
    /// <remarks>
    ///     This method releases all resources associated with the store. You should always
    ///     close an X.509 certificate store after use.
    /// </remarks>
    void Close();

    /// <summary>
    ///     Adds a certificate to an X.509 certificate store.
    /// </summary>
    /// <param name="certificate">The certificate to add.</param>
    /// <exception cref="ArgumentNullException"><paramref name="certificate"/> is <c>null</c>.</exception>
    /// <exception cref="CryptographicException">The certificate could not be added to the store.</exception>
    void Add(X509Certificate2 certificate);

    /// <summary>
    ///     Adds a collection of certificates to an X.509 certificate store.
    /// </summary>
    /// <param name="certificates">The collection of certificates to add.</param>
    /// <exception cref="ArgumentNullException"><paramref name="certificates"/> is <c>null</c>.</exception>
    /// <exception cref="SecurityException">The caller does not have the required permission.</exception>
    /// <remarks>
    ///     This method adds more than one certificate to an X.509 certificate store; if one certificate
    ///     addition fails, the operation is reverted and no certificates are added.
    /// </remarks>
    void AddRange(X509Certificate2Collection certificates);

    /// <summary>
    ///     Removes a certificate from an X.509 certificate store.
    /// </summary>
    /// <param name="certificate">The certificate to remove.</param>
    /// <exception cref="ArgumentNullException"><paramref name="certificate"/> is <c>null</c>.</exception>
    /// <exception cref="SecurityException">The caller does not have the required permission.</exception>
    void Remove(X509Certificate2 certificate);

    /// <summary>
    ///     Removes a range of certificates from an X.509 certificate store.
    /// </summary>
    /// <param name="certificates">A range of certificates to remove.</param>
    /// <exception cref="ArgumentNullException"><paramref name="certificates"/> is <c>null</c>.</exception>
    /// <exception cref="SecurityException">The caller does not have the required permission.</exception>
    /// <remarks>
    ///     This method removes more than one certificate from an X.509 certificate store; if one certificate
    ///     removal fails, the operation is reverted and no certificates are removed.
    /// </remarks>
    void RemoveRange(X509Certificate2Collection certificates);

    #endregion
}
