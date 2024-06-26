using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Services;

using Microsoft.Extensions.Logging;

using Moq;

namespace AdvancedSystems.Security.Tests.Fixtures;

public class HashServiceFixture
{
    public IHashService HashService { get; set; }

    public Mock<ILogger<HashService>> Logger { get; set; }

    public HashServiceFixture()
    {
        this.Logger = new Mock<ILogger<HashService>>();
        this.HashService = new HashService(this.Logger.Object);
    }
}
