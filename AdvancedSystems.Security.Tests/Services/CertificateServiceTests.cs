﻿using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Tests.Fixtures;

using Microsoft.Extensions.DependencyInjection;

using Xunit;

namespace AdvancedSystems.Security.Tests.Services;

/// <summary>
///     Tests the public methods in <seealso cref="ICertificateService"/>.
/// </summary>
public sealed class CertificateServiceTests : IClassFixture<CertificateFixture>
{
    private readonly CertificateFixture _sut;

    public CertificateServiceTests(CertificateFixture certificateFixture)
    {
        this._sut = certificateFixture;
    }

    #region Tests

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
        string thumbprint = "A24421E3B4149A12B219AA67CD263D419829BD53";

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
        var certificate1 = CreateSelfSignedCertificate("O=AdvancedSystems");
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

    #region Helpers

    private static X509Certificate2 CreateSelfSignedCertificate(string subject)
    {
        using var csdsa = ECDsa.Create();
        var request = new CertificateRequest(subject, csdsa, HashAlgorithmName.SHA256);
        var validFrom = DateTimeOffset.UtcNow;
        X509Certificate2 certificate = request.CreateSelfSigned(validFrom, validFrom.AddHours(1));
        return certificate;
    }

    #endregion
}