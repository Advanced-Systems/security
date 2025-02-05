using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Services;

namespace AdvancedSystems.Security.Tests.Fixtures;

public sealed class KDFServiceFixture
{
    public KDFServiceFixture()
    {
        this.KDFService = new KDFService();
    }

    #region Properties

    public IKDFService KDFService { get; private set; }

    #endregion
}