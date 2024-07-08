using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Options;
using AdvancedSystems.Security.Services;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Moq;

namespace AdvancedSystems.Security.Tests.Fixtures;

public class CertificateFixture
{
    public Mock<ILogger<CertificateService>> Logger { get; private set; }

    public ICertificateService CertificateService { get; private set; }

    public Mock<IOptions<CertificateOptions>> Options { get; private set; }

    public CertificateFixture()
    {
        this.Logger = new Mock<ILogger<CertificateService>>();

        this.Options = new Mock<IOptions<CertificateOptions>>();
        this.CertificateService = new CertificateService(this.Logger.Object, this.Options.Object);
    }
}
