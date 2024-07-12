using System;
using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Abstractions;

namespace AdvancedSystems.Security.Services;

/// <summary>
///     Implements X.509 store, which is a physical store where certificates are persisted and managed.
///     This class cannot be inherited.
/// </summary>
public sealed class CertificateStore : ICertificateStore
{
    private readonly X509Store _store;

    public CertificateStore(StoreName storeName, StoreLocation storeLocation)
    {
        this._store = new X509Store(storeName, storeLocation);
    }

    #region Properties

    public IntPtr StoreHandle
    {
        get
        {
            return this._store.StoreHandle;
        }
    }

    public StoreLocation Location
    {
        get
        {
            return this._store.Location;
        }
    }

    public string? Name
    {
        get
        {
            return this._store.Name;
        }
    }

    public X509Certificate2Collection Certificates
    {
        get
        {
            return this._store.Certificates;
        }
    }

    public bool IsOpen
    {
        get
        {
            return this._store.IsOpen;
        }
    }

    #endregion

    #region Methods

    public void Open(OpenFlags flags)
    {
        this._store.Open(flags);
    }

    public void Dispose()
    {
        this._store?.Dispose();
    }

    public void Close()
    {
        this._store?.Close();
    }

    public void Add(X509Certificate2 certificate)
    {
        this._store.Add(certificate);
    }

    public void AddRange(X509Certificate2Collection certificates)
    {
        this._store.AddRange(certificates);
    }

    public void Remove(X509Certificate2 certificate)
    {
        this._store.Remove(certificate);
    }

    public void RemoveRange(X509Certificate2Collection certificates)
    {
        this._store.RemoveRange(certificates);
    }

    #endregion
}
