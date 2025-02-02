using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Abstractions;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AdvancedSystems.Security.Services;

/// <summary>
///      Defines a service for managing and retrieving X.509 certificates. 
/// </summary>
/// <remarks>
///     <inheritdoc cref="ICertificateService" path="/remarks"/>
/// </remarks>
public sealed class CertificateService : ICertificateService
{
    private readonly ILogger<CertificateService> _logger;
    private readonly IServiceProvider _serviceProvider;

    public CertificateService(ILogger<CertificateService> logger, IServiceProvider serviceProvider)
    {
        this._logger = logger;
        this._serviceProvider = serviceProvider;
    }

    #region Methods

    /// <inheritdoc />
    public bool AddCertificate(string storeService, X509Certificate2 certificate)
    {
        var store = this._serviceProvider.GetRequiredKeyedService<ICertificateStore>(storeService);

        try
        {
            store.Open(OpenFlags.ReadWrite);
            store.Add(certificate);
            return true;
        }
        catch (Exception)
        {
            this._logger.LogError(
                "Failed to remove certificate (\"{Thumbprint}\") from store (L='{Location}',N='{Name}').",
                certificate.Thumbprint,
                store.Location,
                store.Name
            );

            return false;
        }
        finally
        {
            store.Close();
        }
    }

    /// <inheritdoc />
    public bool TryImportPemCertificate(string storeService, string certificatePath, string? privateKeyPath, [NotNullWhen(true)] out X509Certificate2? certificate)
    {
        return this.TryImportPemCertificate(storeService, certificatePath, privateKeyPath, string.Empty, out certificate);
    }

    /// <inheritdoc />
    public bool TryImportPemCertificate(string storeService, string certificatePath, string? privateKeyPath, string password, [NotNullWhen(true)] out X509Certificate2? certificate)
    {
        try
        {
            bool withPassword = !string.IsNullOrEmpty(password);

            using var pemCertificate = withPassword
                ? new X509Certificate2(certificatePath, password, KeyStorageFlags)
                : new X509Certificate2(certificatePath);

            if (!string.IsNullOrEmpty(privateKeyPath))
            {
                string pemContent = File.ReadAllText(privateKeyPath);
                using var privateKey = RSA.Create();

                if (withPassword)
                {
                    privateKey.ImportFromEncryptedPem(pemContent, password);
                }
                else
                {
                    privateKey.ImportFromPem(pemContent);
                }

                certificate = pemCertificate.CopyWithPrivateKey(privateKey);
            }
            else
            {
                certificate = pemCertificate;
            }

            bool isImported = this.AddCertificate(storeService, certificate);
            return isImported;
        }
        catch (Exception exception)
        {
            this._logger.LogError(
                "Failed to initialize public key or private key from path (PublicKey=\"{PublicKey}\",PrivateKey=\"{PrivateKey}\"): {Reason}",
                certificatePath,
                privateKeyPath ?? "unspecified",
                exception.Message
            );

            certificate = null;
            return false;
        }
    }

    /// <inheritdoc />
    public bool TryImportPfxCertificate(string storeService, string certificatePath, [NotNullWhen(true)] out X509Certificate2? certificate)
    {
        return this.TryImportPfxCertificate(storeService, certificatePath, string.Empty, out certificate);
    }

    /// <inheritdoc />
    public bool TryImportPfxCertificate(string storeService, string certificatePath, string password, [NotNullWhen(true)] out X509Certificate2? certificate)
    {
        try
        {
            bool withPassword = !string.IsNullOrEmpty(password);

            certificate = withPassword
                ? new X509Certificate2(certificatePath, password, KeyStorageFlags)
                : new X509Certificate2(certificatePath);

            bool isImported = this.AddCertificate(storeService, certificate);
            return isImported;
        }
        catch (CryptographicException)
        {
            this._logger.LogError(
                "Failed to initialize certificate from path (Path=\"{Certificate}\").",
                certificatePath
            );

            certificate = null;
            return false;
        }
    }

    /// <inheritdoc />
    public IEnumerable<X509Certificate2> GetCertificate(string storeService)
    {
        var store = this._serviceProvider.GetRequiredKeyedService<ICertificateStore>(storeService);

        try
        {
            store.Open(OpenFlags.ReadOnly);

            return store.Certificates.OfType<X509Certificate2>();
        }
        catch (ArgumentNullException)
        {
            return Enumerable.Empty<X509Certificate2>();
        }
        finally
        {
            store.Close();
        }
    }

    /// <inheritdoc />
    public X509Certificate2? GetCertificate(string storeService, string thumbprint, bool validOnly = true)
    {
        var store = this._serviceProvider.GetRequiredKeyedService<ICertificateStore>(storeService);

        try
        {
            store.Open(OpenFlags.ReadOnly);

            var certificate = store.Certificates
                .Find(X509FindType.FindByThumbprint, thumbprint, validOnly)
                .OfType<X509Certificate2>()
                .FirstOrDefault();

            return certificate;
        }
        finally
        {
            store.Close();
        }
    }

    /// <inheritdoc />
    public bool RemoveCertificate(string storeService, string thumbprint)
    {
        var store = this._serviceProvider.GetRequiredKeyedService<ICertificateStore>(storeService);

        try
        {
            store.Open(OpenFlags.ReadWrite);

            X509Certificate2Collection? certificates = store.Certificates
                .Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);

            if (certificates is null) return false;

            store.RemoveRange(certificates);
            return true;
        }
        catch (CryptographicException)
        {
            this._logger.LogError(
                "Failed to remove certificate (\"{Thumbprint}\") from store (L='{Location}',N='{Name}').",
                thumbprint,
                store.Location,
                store.Name
            );

            return false;
        }
        finally
        {
            store.Close();
        }
    }

    #endregion

    #region Helpers

    private static X509KeyStorageFlags KeyStorageFlags
    {
        get
        {
            return OperatingSystem.IsMacOS()
                ? X509KeyStorageFlags.Exportable
                : X509KeyStorageFlags.DefaultKeySet;
        }
    }

    #endregion
}