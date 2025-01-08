using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Abstractions.Exceptions;
using AdvancedSystems.Security.Extensions;
using AdvancedSystems.Security.Options;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AdvancedSystems.Security.Validators;

public sealed class CertificateOptionsValidator : IValidateOptions<CertificateOptions>
{
    private readonly ILogger<CertificateOptionsValidator> _logger;
    private readonly ICertificateStore _certificateStore;

    public CertificateOptionsValidator(ILogger<CertificateOptionsValidator> logger, ICertificateStore certificateStore)
    {
        this._logger = logger;
        this._certificateStore = certificateStore;
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
            X509Certificate2 certificate = this._certificateStore.GetCertificate(options.Thumbprint);
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