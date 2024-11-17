using AdvancedSystems.Security.Tests.Fixtures;

using Xunit;

namespace AdvancedSystems.Security.Tests.Services;

public sealed class CertificateStoreTests : IClassFixture<CertificateStoreFixture>
{
    private readonly CertificateStoreFixture _sut;

    public CertificateStoreTests(CertificateStoreFixture fixture)
    {
        this._sut = fixture;
    }

    #region Tests

    // TODO

    #endregion
}