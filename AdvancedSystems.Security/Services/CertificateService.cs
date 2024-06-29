using AdvancedSystems.Security.Abstractions;

using Microsoft.Extensions.Logging;

namespace AdvancedSystems.Security.Services;

public sealed class CertificateService : ICertificateService
{
    private readonly ILogger<CertificateService> _logger;

    public CertificateService(ILogger<CertificateService> logger)
    {
        this._logger = logger;
    }
}
