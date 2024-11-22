using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;

namespace AdvancedSystems.Security.Options;

public sealed record RSACryptoOptions
{
    [Required]
    public required HashAlgorithmName HashAlgorithmName { get; set; }

    [Required]
    public required RSAEncryptionPadding EncryptionPadding { get; set; }

    [Required]
    public required RSASignaturePadding SignaturePadding { get; set; }

    [Required]
    public required Encoding Encoding { get; set; }
}