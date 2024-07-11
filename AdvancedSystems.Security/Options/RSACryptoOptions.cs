using System.Security.Cryptography;
using System.Text;

namespace AdvancedSystems.Security.Options;

public sealed class RSACryptoOptions
{
    public required HashAlgorithmName HashAlgorithmName { get; init; }

    public required RSAEncryptionPadding EncryptionPadding { get; init; }

    public required RSASignaturePadding SignaturePadding { get; init; }

    public required Encoding Encoding { get; init; }
}
