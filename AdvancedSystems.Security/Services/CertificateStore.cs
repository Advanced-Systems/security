using System;
using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Abstractions;

namespace AdvancedSystems.Security.Services;

/// <inheritdoc cref="ICertificateStore" />
public sealed class CertificateStore : ICertificateStore
{
    private readonly X509Store _store;

    public CertificateStore(StoreName storeName, StoreLocation storeLocation)
    {
        this._store = new X509Store(storeName, storeLocation);
    }

    #region Properties

    /// <inheritdoc />
    public IntPtr StoreHandle
    {
        get
        {
            return this._store.StoreHandle;
        }
    }

    /// <inheritdoc />
    public StoreLocation Location
    {
        get
        {
            return this._store.Location;
        }
    }

    /// <inheritdoc />
    public string? Name
    {
        get
        {
            return this._store.Name;
        }
    }

    /// <inheritdoc />
    public X509Certificate2Collection Certificates
    {
        get
        {
            return this._store.Certificates;
        }
    }

    /// <inheritdoc />
    public bool IsOpen
    {
        get
        {
            return this._store.IsOpen;
        }
    }

    #endregion

    #region Methods

    /// <inheritdoc />
    public void Open(OpenFlags flags)
    {
        this._store.Open(flags);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        this._store?.Dispose();
    }

    /// <inheritdoc />
    public void Close()
    {
        this._store?.Close();
    }

    /// <inheritdoc />
    public void Add(X509Certificate2 certificate)
    {
        this._store.Add(certificate);
    }

    /// <inheritdoc />
    public void AddRange(X509Certificate2Collection certificates)
    {
        this._store.AddRange(certificates);
    }

    /// <inheritdoc />
    public void Remove(X509Certificate2 certificate)
    {
        this._store.Remove(certificate);
    }

    /// <inheritdoc />
    public void RemoveRange(X509Certificate2Collection certificates)
    {
        this._store.RemoveRange(certificates);
    }

    #endregion
}