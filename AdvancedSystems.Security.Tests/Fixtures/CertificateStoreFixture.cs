using System;
using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Services;

namespace AdvancedSystems.Security.Tests.Fixtures;

public sealed class CertificateStoreFixture : IDisposable
{
    private bool _isDisposed = false;

    public CertificateStoreFixture()
    {
        this.CertificateStore = new CertificateStore(StoreName.My, StoreLocation.CurrentUser);
    }

    #region Properties

    public CertificateStore CertificateStore { get; set; }

    #endregion

    #region Methods

    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    public void Dispose(bool disposing)
    {
        if (this._isDisposed) return;

        if (disposing)
        {
            this.CertificateStore.Dispose();
        }

        this._isDisposed = true;
    }

    #endregion
}