using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Services;

namespace AdvancedSystems.Security.Tests.Fixtures;

public sealed class HMACFixture
{
    public HMACFixture()
    {
        this.HMACService = new HMACService();
    }

    #region Properties

    public IHMACService HMACService { get; private set; }

    #endregion
}