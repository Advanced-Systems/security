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

/// <inheritdoc cref="ICertificateService"/>
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
    public bool TryImportPemCertificate(string storeService, string publicKeyPath, string? privateKeyPath, [NotNullWhen(true)] out X509Certificate2? certificate)
    {
        return this.TryImportPemCertificate(storeService, publicKeyPath, privateKeyPath, string.Empty, out certificate);
    }

    /// <inheritdoc />
    public bool TryImportPemCertificate(string storeService, string publicKeyPath, string? privateKeyPath, string password, [NotNullWhen(true)] out X509Certificate2? certificate)
    {
        if (!File.Exists(publicKeyPath))
        {
            this._logger.LogError(
                "Public key file does not exist (PublicKey=\"{PublicKey}\").",
                publicKeyPath
            );

            certificate = null;
            return false;
        }

        try
        {
            using var publicKey = string.IsNullOrEmpty(password)
                ? new X509Certificate2(publicKeyPath)
                : new X509Certificate2(publicKeyPath, password, KeyStorageFlags);

            if (!string.IsNullOrEmpty(privateKeyPath))
            {
                if (!File.Exists(privateKeyPath))
                {
                    this._logger.LogError(
                        "Private key file does not exist (PrivateKey=\"{PrivateKey}\").",
                        privateKeyPath
                    );

                    certificate = null;
                    return false;
                }

                string[] privateKeyBlocks = File.ReadAllText(privateKeyPath)
                    .Split("-", StringSplitOptions.RemoveEmptyEntries);

                string header = privateKeyBlocks[0];

                byte[] privateKeyBuffer = Convert.FromBase64String(privateKeyBlocks[1]);
                using var privateKey = RSA.Create();

                switch (header)
                {
                    case PKCS8_PRIVATE_KEY_HEADER:
                        privateKey.ImportPkcs8PrivateKey(privateKeyBuffer, out _);
                        break;
                    case PKCS8_ENCRYPTED_PRIVATE_KEY_HEADER:
                        privateKey.ImportEncryptedPkcs8PrivateKey(password, privateKeyBuffer, out _);
                        break;
                    case RSA_PRIVATE_KEY_HEADER:
                        privateKey.ImportRSAPrivateKey(privateKeyBuffer, out _);
                        break;
                    default:
                        this._logger.LogCritical(
                            "Unknown header in private key: {Header} (\"{PrivateKey}\").",
                            header,
                            privateKeyPath
                        );

                        certificate = null;
                        return false;
                }

                certificate = publicKey.CopyWithPrivateKey(privateKey);
            }
            else
            {
                certificate = publicKey;
            }

            bool isImported = this.AddCertificate(storeService, certificate);
            return isImported;
        }
        catch (CryptographicException)
        {
            if (!string.IsNullOrEmpty(privateKeyPath))
            {
                this._logger.LogError(
                    "Failed to initialize public key or private key from path (PublicKey=\"{PublicKey}\",PrivateKey=\"{PrivateKey}\").",
                    publicKeyPath,
                    privateKeyPath
                );
            }
            else
            {
                this._logger.LogError(
                    "Failed to initialize public key from path (PublicKey=\"{PublicKey}\").",
                    publicKeyPath
                );
            }

            certificate = null;
            return false;
        }
    }

    /// <inheritdoc />
    public bool TryImportPfxCertificate(string storeService, string path, [NotNullWhen(true)] out X509Certificate2? certificate)
    {
        return this.TryImportPfxCertificate(storeService, path, string.Empty, out certificate);
    }

    /// <inheritdoc />
    public bool TryImportPfxCertificate(string storeService, string path, string password, [NotNullWhen(true)] out X509Certificate2? certificate)
    {
        if (!File.Exists(path))
        {
            this._logger.LogError(
                "Certificate file does not exist (Path=\"{Certificate}\").",
                path
            );

            certificate = null;
            return false;
        }

        try
        {
            certificate = string.IsNullOrEmpty(password)
                ? new X509Certificate2(path)
                : new X509Certificate2(path, password, KeyStorageFlags);

            bool isImported = this.AddCertificate(storeService, certificate);
            return isImported;
        }
        catch (CryptographicException)
        {
            this._logger.LogError(
                "Failed to initialize certificate from path (Path=\"{Certificate}\").",
                path
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

    private const string PKCS8_PRIVATE_KEY_HEADER = "BEGIN PRIVATE KEY";

    private const string PKCS8_ENCRYPTED_PRIVATE_KEY_HEADER = "BEGIN ENCRYPTED PRIVATE KEY";

    private const string RSA_PRIVATE_KEY_HEADER = "BEGIN RSA PRIVATE KEY";

    private static X509KeyStorageFlags KeyStorageFlags
    {
        get
        {
            var keyStorageFlags = X509KeyStorageFlags.DefaultKeySet;

            if (OperatingSystem.IsMacOS())
            {
                keyStorageFlags = X509KeyStorageFlags.Exportable;
            }

            return keyStorageFlags;
        }
    }

    #endregion
}