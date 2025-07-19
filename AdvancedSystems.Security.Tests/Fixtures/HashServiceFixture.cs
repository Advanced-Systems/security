using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Services;

using Microsoft.Extensions.Logging;

using Moq;

namespace AdvancedSystems.Security.Tests.Fixtures;

public sealed class HashServiceFixture
{
    public HashServiceFixture()
    {
        this.Logger = new Mock<ILogger<HashService>>();
        this.HashService = new HashService(this.Logger.Object);
    }

    #region Properties

    public Mock<ILogger<HashService>> Logger { get; private set; }

    public IHashService HashService { get; private set; }

    #endregion
}