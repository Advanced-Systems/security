using System.Security.Cryptography.X509Certificates;

namespace AdvancedSystems.Security.Abstractions
{
    public interface ICertificateService
    {
        #region Methods

        X509Certificate2? GetStoreCertificate(string thumbprint, StoreName storeName, StoreLocation storeLocation);

        X509Certificate2? GetConfiguredCertificate();

        #endregion
    }
}
