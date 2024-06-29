using AdvancedSystems.Security.Abstractions;

using Microsoft.Extensions.Logging;

namespace AdvancedSystems.Security.Services;

public sealed class RSACryptoService : IRSACryptoService
{
    private readonly ILogger<RSACryptoService> _logger;

    public RSACryptoService(ILogger<RSACryptoService> logger)
    {
        this._logger = logger;
    }
}
