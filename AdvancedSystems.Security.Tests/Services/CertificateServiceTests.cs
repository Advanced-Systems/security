using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Tests.Fixtures;
using AdvancedSystems.Security.Tests.Helpers;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

using Xunit;

namespace AdvancedSystems.Security.Tests.Services;

/// <summary>
///     Tests the public methods in <seealso cref="ICertificateService"/>.
/// </summary>
public sealed class CertificateServiceTests : IClassFixture<HostFixture>
{
    private readonly HostFixture _sut;

    public CertificateServiceTests(HostFixture certificateFixture)
    {
        this._sut = certificateFixture;
    }

    #region Tests

    /// <summary>
    ///     Tests that <seealso cref="ICertificateService.TryImportPemCertificate(string, string, string, string, out X509Certificate2?)"/>
    ///     successfully imports a password-protected PEM certificate.
    /// </summary>
    [Fact]
    public void TestTryImportPemCertificate_WithPassword()
    {
        // Arrange
        string storeService = this._sut.ConfiguredStoreService;
        string publicKey = Path.Combine(Assets.ProjectRoot, "development", "AdvancedSystems-PasswordCertificate.pem");
        string privateKey = Path.Combine(Assets.ProjectRoot, "development", "AdvancedSystems-PrivateKey.pk8");

        var configuration = new ConfigurationBuilder()
            .AddUserSecrets<CertificateServiceTests>()
            .Build();

        string? password = configuration[UserSecrets.CERTIFICATE_PASSWORD];
        Skip.If(string.IsNullOrEmpty(password), "A dotnet user-secrets is not configured for this test.");

        // Act
        ICertificateService? certificateService = this._sut.Host?.Services.GetService<ICertificateService>();
        bool? isImported = certificateService?.TryImportPemCertificate(storeService, publicKey, privateKey, password, out _);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.NotNull(certificateService);
            Assert.True(isImported.HasValue);
            Assert.True(isImported.Value);
        });
    }

    /// <summary>
    ///     Tests that <seealso cref="ICertificateService.TryImportPfxCertificate(string, string, string, out X509Certificate2?)"/>
    ///     successfully imports a password-protected PFX certificate.
    /// </summary>
    [SkippableFact]
    public void TestTryImportPfxCertificate()
    {
        // Arrange
        string storeService = this._sut.ConfiguredStoreService;
        string path = Path.Combine(Assets.ProjectRoot, "development", "AdvancedSystems-CA.pfx");

        var configuration = new ConfigurationBuilder()
            .AddUserSecrets<CertificateServiceTests>()
            .Build();

        string? password = configuration[UserSecrets.CERTIFICATE_PASSWORD];
        Skip.If(string.IsNullOrEmpty(password), "A dotnet user-secrets is not configured for this test.");

        // Act
        ICertificateService? certificateService = this._sut.Host?.Services.GetService<ICertificateService>();
        bool? isImported = certificateService?.TryImportPfxCertificate(storeService, path, password, out _);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.NotNull(certificateService);
            Assert.True(isImported.HasValue);
            Assert.True(isImported.Value);
        });
    }

    /// <summary>
    ///     Tests that <seealso cref="ICertificateService.GetCertificate(string)"/>
    ///     returns a collection of certificates from the configured certificate1 store.
    /// </summary>
    [Fact]
    public void TestGetCertificate()
    {
        // Arrange
        string storeService = this._sut.ConfiguredStoreService;

        // Act
        ICertificateService? certificateService = this._sut.Host?.Services.GetService<ICertificateService>();
        int? certificateCount = certificateService?.GetCertificate(storeService).Count();

        // Assert
        Assert.Multiple(() =>
        {
            Assert.NotNull(certificateCount);
            Assert.InRange(certificateCount.Value, 1, int.MaxValue);
        });
    }

    /// <summary>
    ///     Tests that <seealso cref="ICertificateService.GetCertificate(string, string, bool)"/>
    ///     returns a certificate1 from the certificate1 store.
    /// </summary>
    [Fact]
    public void TestGetCertificate_ByThumbprint()
    {
        // Arrange
        string storeService = this._sut.ConfiguredStoreService;
        string thumbprint = Certificates.PasswordCertificateThumbprint;

        // Act
        var certificateService = this._sut.Host?.Services.GetService<ICertificateService>();
        X509Certificate2? certificate = certificateService?.GetCertificate(storeService, thumbprint, validOnly: false);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.NotNull(certificate);
            Assert.Equal(thumbprint, certificate.Thumbprint);
        });
    }

    /// <summary>
    ///     Tests that <seealso cref="ICertificateService.AddCertificate(string, X509Certificate2)"/>
    ///     adds a self-signed test certificate to the certificate store, and that subsequently
    ///     <seealso cref="ICertificateService.RemoveCertificate(string, string)"/> removes the
    ///     self-signed test certificate from the certificate store.
    /// </summary>
    [Fact]
    public void TestAddRemoveCertificate()
    {
        // Arrange
        string storeService = this._sut.ConfiguredStoreService;
        var certificate1 = Certificates.CreateSelfSignedCertificate("O=AdvancedSystems");
        string thumbprint = certificate1.Thumbprint;

        // Act
        var certificateService = this._sut.Host?.Services.GetService<ICertificateService>();
        bool isAdded = certificateService?.AddCertificate(storeService, certificate1) ?? false;
        X509Certificate2? certificate2 = certificateService?.GetCertificate(storeService, thumbprint, validOnly: false);
        bool isRemoved = certificateService?.RemoveCertificate(storeService, thumbprint) ?? false;

        // Assert
        Assert.Multiple(() =>
        {
            Assert.NotNull(certificateService);
            Assert.True(isAdded);
            Assert.NotNull(certificate2);
            Assert.True(isRemoved);
        });
    }

    #endregion
}