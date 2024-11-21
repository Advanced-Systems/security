using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Tests.Fixtures;

using Xunit;

namespace AdvancedSystems.Security.Tests.Services;

/// <summary>
///     Tests the public methods in <seealso cref="ICertificateStore"/>.
/// </summary>
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