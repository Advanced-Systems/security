﻿using System.ComponentModel.DataAnnotations;

namespace AdvancedSystems.Security.Options;

public sealed record CertificateOptions
{
    [Key]
    [Required(AllowEmptyStrings = false)]
    public required string Thumbprint { get; set; }

    [Required]
    public required CertificateStoreOptions Store { get; set; }
}