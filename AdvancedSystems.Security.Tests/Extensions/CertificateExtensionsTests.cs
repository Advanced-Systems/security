using AdvancedSystems.Security.Cryptography;
using AdvancedSystems.Security.Extensions;

using Xunit;

namespace AdvancedSystems.Security.Tests.Extensions;

/// <summary>
///     Tests the public methods in <seealso cref="CertificateExtensions"/>.
/// </summary>
public sealed class CertificateExtensionsTests
{
    #region Tests

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