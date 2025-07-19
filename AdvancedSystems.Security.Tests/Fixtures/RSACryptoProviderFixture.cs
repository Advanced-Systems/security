using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Cryptography;
using AdvancedSystems.Security.Services;
using AdvancedSystems.Security.Tests.Helpers;

namespace AdvancedSystems.Security.Tests.Fixtures;

public sealed class RSACryptoProviderFixture : IDisposable
{
    public RSACryptoProviderFixture()
    {
        using var store = new CertificateStore(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);

        this.PasswordCertificate = store.Certificates
            .Find(X509FindType.FindByThumbprint, Certificates.PasswordCertificateThumbprint, validOnly: false)
            .OfType<X509Certificate2>()
            .First();

        this.RSACryptoProvider = new RSACryptoProvider(this.PasswordCertificate);
    }

    #region Properties

    public X509Certificate2 PasswordCertificate { get; private set; }

    public RSACryptoProvider RSACryptoProvider { get; private set; }

    #endregion

    #region Methods

    public void Dispose()
    {
        this.PasswordCertificate.Dispose();
        this.RSACryptoProvider.Dispose();
    }

    #endregion
}