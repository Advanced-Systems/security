using System.ComponentModel.DataAnnotations;

namespace AdvancedSystems.Security.Options;

public sealed record CertificateOptions
{
    public string? Thumbprint { get; set; }

    public CertificateStoreOptions? Store { get; set; }
}