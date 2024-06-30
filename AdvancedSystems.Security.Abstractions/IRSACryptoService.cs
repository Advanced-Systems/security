using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AdvancedSystems.Security.Abstractions
{
    public interface IRSACryptoService : IDisposable
    {
        #region Properties

        X509Certificate2 Certificate { get; }

        HashAlgorithmName HashAlgorithmName { get; }

        RSAEncryptionPadding EncryptionPadding { get; }

        RSASignaturePadding SignaturePadding { get; }

        Encoding Encoding { get; }

        #endregion

        #region Methods

        bool IsValidMessage(string message, RSAEncryptionPadding? padding, Encoding? encoding = null);

        string Encrypt(string message, Encoding? encoding = null);

        string Decrypt(string cipher, Encoding? encoding = null);

        string SignData(string data, Encoding? encoding = null);

        bool VerifyData(string data, string signature, Encoding? encoding = null);

        #endregion
    }
}
