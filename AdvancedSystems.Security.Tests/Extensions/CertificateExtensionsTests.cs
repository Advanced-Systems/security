using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Cryptography;
using AdvancedSystems.Security.Extensions;

using AdvancedSystems.Security.Tests.Fixtures;

using Microsoft.Extensions.DependencyInjection;

using Xunit;

namespace AdvancedSystems.Security.Tests.Extensions;

/// <summary>
///     Tests the public methods in <seealso cref="CertificateExtensions"/>.
/// </summary>
public sealed class CertificateExtensionsTests : IClassFixture<CertificateFixture>
{
    private readonly CertificateFixture _certificateFixture;

    public CertificateExtensionsTests(CertificateFixture certificateFixture)
    {
        this._certificateFixture = certificateFixture;
    }

    #region Tests

    /// <summary>
    ///      Tests that <seealso cref="CertificateExtensions.TryParseDistinguishedName(string, out DistinguishedName?)"/>
    ///      parses the DN from a certificate retrieved from a certificate store correctly.
    /// </summary>
    [Fact]
    public void TestTryParseDistinguishedName_FromCertificate()
    {
        // Arrange
        string storeService = this._certificateFixture.ConfiguredStoreService;
        string thumbprint = "2BFC1C18AC1A99E4284D07F1D2F0312C8EAB33FC";

        // Act
        ICertificateService? certificateService = this._certificateFixture.Host?.Services.GetService<ICertificateService>();
        X509Certificate2? certificate = certificateService?.GetCertificate(storeService, thumbprint, validOnly: false);
        bool isDsn = CertificateExtensions.TryParseDistinguishedName(certificate?.Subject ?? string.Empty, out DistinguishedName? dn);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.NotNull(certificateService);
            Assert.NotNull(certificate);
            Assert.NotNull(certificate?.Subject);
            Assert.True(isDsn);
            Assert.NotNull(dn);
            Assert.Equal("DE", dn?.Country);
            Assert.Equal("Berlin", dn?.State);
            Assert.Equal("Berlin", dn?.Locality);
            Assert.Equal("Advanced Systems", dn?.Organization);
            Assert.Equal("RnD", dn?.OrganizationalUnit);
            Assert.Equal("AdvancedSystems-CA", dn?.CommonName);
        });
    }

    /// <summary>
    ///     Tests that <seealso cref="CertificateExtensions.TryParseDistinguishedName(string, out DistinguishedName?)"/>
    ///     extracts the RDNs from the DN correctly from the string.
    /// </summary>
    [Fact]
    public void TestTryParseDistinguishedName()
    {
        // Arrange
        string commonName = "Advanced Systems Root";
        string organizationalUnit = "R&D Department";
        string organization = "Advanced Systems Inc.";
        string locality = "Berlin";
        string state = "Berlin";
        string country = "DE";
        string distinguiedName = $"CN={commonName}, OU={organizationalUnit}, O={organization}, L={locality}, S={state}, C={country}";

        // Act
        bool isDn = CertificateExtensions.TryParseDistinguishedName(distinguiedName, out DistinguishedName? dn);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.True(isDn);
            Assert.NotNull(dn);
            Assert.Equal(dn.CommonName, commonName);
            Assert.Equal(dn.OrganizationalUnit, organizationalUnit);
            Assert.Equal(dn.Organization, organization);
            Assert.Equal(dn.Locality, locality);
            Assert.Equal(dn.State, state);
            Assert.Equal(dn.Country, country);
        });
    }

    /// <summary>
    ///     Tests that <seealso cref="CertificateExtensions.TryParseDistinguishedName(string, out DistinguishedName?)"/>
    ///     when the DN is malformed.
    /// </summary>
    [Fact]
    public void TestTryParseDistinguishedName_ReturnsNull()
    {
        // Arrange
        string distinguishedName = string.Empty;

        // Act
        bool isDn = CertificateExtensions.TryParseDistinguishedName(distinguishedName, out DistinguishedName? dn);

        // Assert
        Assert.False(isDn);
        Assert.Null(dn);
    }

    #endregion
}