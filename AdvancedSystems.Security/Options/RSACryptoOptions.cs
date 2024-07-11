using System.Security.Cryptography;
using System.Text;

namespace AdvancedSystems.Security.Options;

public sealed class RSACryptoOptions
{
    public required HashAlgorithmName HashAlgorithmName { get; set; }

    public required RSAEncryptionPadding EncryptionPadding { get; set; }

    public required RSASignaturePadding SignaturePadding { get; set; }

    public required Encoding Encoding { get; set; }
}
