using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;

using AdvancedSystems.Security.Abstractions;

namespace AdvancedSystems.Security.Options;

public sealed record RSACryptoOptions
{
    [Required]
    public required HashFunction HashFunction { get; set; }

    [Required]
    public required RSAEncryptionPadding EncryptionPadding { get; set; }

    [Required]
    public required RSASignaturePadding SignaturePadding { get; set; }

    [Required]
    public required string Thumbprint { get; set; }

    public bool RequireValidCertificate { get; set; } = true;
}