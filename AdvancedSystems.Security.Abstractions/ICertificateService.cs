using System.Security.Cryptography.X509Certificates;

namespace AdvancedSystems.Security.Abstractions
{
    public interface ICertificateService
    {
        #region Methods

        X509Certificate2? GetStoreCertificate(StoreName storeName, StoreLocation storeLocation, string thumbprint);

        X509Certificate2? GetConfiguredCertificate();

        #endregion
    }
}
