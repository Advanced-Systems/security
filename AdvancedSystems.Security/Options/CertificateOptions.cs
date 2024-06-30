using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography.X509Certificates;

namespace AdvancedSystems.Security.Options;

public record CertificateOptions
{
    [Key]
    public required string Thumbprint { get; init; }

    [EnumDataType(typeof(StoreName))]
    public required StoreName StoreName { get; init; }

    [EnumDataType(typeof(StoreLocation))]
    public required StoreLocation StoreLocation { get; init; }
}
