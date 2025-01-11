using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Abstractions.Exceptions;
using AdvancedSystems.Security.Options;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AdvancedSystems.Security.Validators;

public sealed class CertificateOptionsValidator : IValidateOptions<CertificateOptions>
{
    private readonly ILogger<CertificateOptionsValidator> _logger;
    private readonly ICertificateService _certificateService;

    public CertificateOptionsValidator(ILogger<CertificateOptionsValidator> logger, ICertificateService certificateService)
    {
        this._logger = logger;
        this._certificateService = certificateService;
    }

    #region Implementation

    public ValidateOptionsResult Validate(string? name, CertificateOptions options)
    {
        this._logger.LogDebug("Started validation of {Options}", nameof(CertificateOptions));

        if (string.IsNullOrEmpty(options.Thumbprint))
        {
            return ValidateOptionsResult.Fail("Thumbprint is null or empty.");
        }

        try
        {
            X509Certificate2? certificate = this._certificateService.GetConfiguredCertificate(validOnly: false);

            if (certificate is null)
            {
                return ValidateOptionsResult.Fail($"Configured certificate with thumbprint \"{options.Thumbprint}\" could not be found.");
            }
        }
        catch (CertificateNotFoundException exception)
        {
            return ValidateOptionsResult.Fail(exception.Message);
        }

        this._logger.LogDebug("Completed validation of {Options}", nameof(CertificateOptions));

        return ValidateOptionsResult.Success;
    }

    #endregion
}