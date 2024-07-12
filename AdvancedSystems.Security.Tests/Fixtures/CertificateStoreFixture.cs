using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Services;

namespace AdvancedSystems.Security.Tests.Fixtures;

public class CertificateStoreFixture
{
    public CertificateStoreFixture()
    {
        this.CertificateStore = new CertificateStore(StoreName.My, StoreLocation.CurrentUser);
    }

    #region Properties

    public CertificateStore CertificateStore { get; set; }

    #endregion
}
