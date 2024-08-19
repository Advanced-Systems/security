using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Services;

namespace AdvancedSystems.Security.Tests.Fixtures;

public class CryptoRandomFixture
{
    public CryptoRandomFixture()
    {
        this.CryptoRandomService = new CryptoRandomService();
    }

    #region Properties

    public ICryptoRandomService CryptoRandomService { get; private set; }

    #endregion
}
