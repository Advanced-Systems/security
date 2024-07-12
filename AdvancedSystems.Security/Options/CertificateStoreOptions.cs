using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography.X509Certificates;

namespace AdvancedSystems.Security.Options;

public sealed class CertificateStoreOptions
{
    [Required]
    [EnumDataType(typeof(StoreName))]
    public required StoreName Name { get; set; }

    [Required]
    [EnumDataType(typeof(StoreLocation))]
    public required StoreLocation Location { get; set; }
}
