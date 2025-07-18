using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;

using AdvancedSystems.Security.Abstractions;

namespace AdvancedSystems.Security.Options;

/// <summary>
///     Configures options for the <seealso cref="RSACryptoContract"/>.
/// </summary>
public sealed record RSACryptoOptions
{
    /// <summary>
    ///     <inheritdoc cref="Abstractions.HashFunction"/>
    /// </summary>
    [Required]
    [EnumDataType(typeof(HashFunction))]
    public required HashFunction HashFunction { get; set; }

    /// <summary>
    ///     <inheritdoc cref="RSAEncryptionPadding"/>
    /// </summary>
    [Required]
    public required RSAEncryptionPadding EncryptionPadding { get; set; }

    /// <summary>
    ///     <inheritdoc cref="RSASignaturePadding"/>
    /// </summary>
    [Required]
    public required RSASignaturePadding SignaturePadding { get; set; }

    /// <summary>
    ///     The string representing the thumbprint of the encryption certificate to retrieve.
    /// </summary>
    [Required]
    public required string Thumbprint { get; set; }

    /// <summary>
    ///     <inheritdoc cref="ICertificateService.GetCertificate(string, string, bool)" path="/param[@name='storeService']"/>
    /// </summary>
    public required string StoreService { get; set; }

    /// <summary>
    ///     <inheritdoc cref="ICertificateService.GetCertificate(string, string, bool)" path="/param[@name='validOnly']"/>
    /// </summary>
    public bool ValidOnly { get; set; } = true;

    /// <summary>
    ///     Set this value to <see langword="true"/> to allow only valid certificates to be
    ///     used for the encryption and decryption; otherwise, <see langword="false"/>.
    /// </summary>
    public bool RequireValidCertificate { get; set; } = true;
}