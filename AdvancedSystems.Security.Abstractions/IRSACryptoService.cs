using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;

namespace AdvancedSystems.Security.Abstractions
{
    public interface IRSACryptoProvider
    {
        #region Properties

        X509Certificate2 Certificate { get; }

        HashAlgorithmName HashAlgorithmName { get; set; }

        RSAEncryptionPadding EncryptionPadding { get; set; }

        RSASignaturePadding SignaturePadding { get; set; }

        Encoding Encoding { get; set; }

        #endregion

        #region Methods

        bool IsValidMessage(string message, RSAEncryptionPadding? padding = null, Encoding? encoding = null);

        string Encrypt(string message, Encoding? encoding = null);

        string Decrypt(string cipher, Encoding? encoding = null);

        string Sign(string data, Encoding? encoding = null);

        bool Verify(string data, string signature, Encoding? encoding = null);

        #endregion
    }
}
