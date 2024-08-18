using System;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Options;
using AdvancedSystems.Security.Services;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AdvancedSystems.Security.DependencyInjection;

public static class ServiceCollectionExtensions
{
    #region CryptoRandom

    public static IServiceCollection AddCryptoRandomService(this IServiceCollection services)
    {
        services.TryAdd(ServiceDescriptor.Scoped<ICryptoRandomService, CryptoRandomService>());
        return services;
    }

    #endregion

    #region HashService

    public static IServiceCollection AddHashService(this IServiceCollection services)
    {
        services.TryAdd(ServiceDescriptor.Scoped<IHashService, HashService>());
        return services;
    }

    #endregion

    #region CertificateStore

    internal static void AddCertificateStore<TOptions>(this IServiceCollection services) where TOptions : class
    {
        services.TryAdd(ServiceDescriptor.Singleton<ICertificateStore>(serviceProvider =>
        {
            var options = serviceProvider.GetRequiredService<IOptions<TOptions>>().Value switch
            {
                CertificateOptions certificateOptions => new { certificateOptions.Store.Name, certificateOptions.Store.Location },
                CertificateStoreOptions storeOptions => new { storeOptions.Name, storeOptions.Location },
                _ => throw new NotImplementedException()
            };

            return new CertificateStore(options.Name, options.Location);
        }));
    }

    public static IServiceCollection AddCertificateStore(this IServiceCollection services, Action<CertificateStoreOptions> setupAction)
    {
        services.AddOptions()
            .Configure(setupAction);

        services.AddCertificateStore<CertificateStoreOptions>();
        return services;
    }

    public static IServiceCollection AddCertificateStore(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<CertificateStoreOptions>()
            .Bind(configuration.GetRequiredSection(Sections.CERTIFICATE_STORE))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddCertificateStore<CertificateStoreOptions>();
        return services;
    }

    #endregion

    #region CertificateService

    internal static void AddCertificateService(this IServiceCollection services)
    {
        services.TryAdd(ServiceDescriptor.Scoped<ICertificateService, CertificateService>());
    }

    public static IServiceCollection AddCertificateService(this IServiceCollection services, Action<CertificateOptions> setupAction)
    {
        services.AddOptions()
            .Configure(setupAction);

        services.AddCertificateStore<CertificateOptions>();
        services.AddCertificateService();

        return services;
    }

    public static IServiceCollection AddCertificateService(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<CertificateOptions>()
            .Bind(configuration.GetRequiredSection(Sections.CERTIFICATE))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddCertificateStore(configuration);
        services.AddCertificateService();

        return services;
    }

    #endregion

    #region RSACryptoService

    internal static IServiceCollection AddRSACryptoService(this IServiceCollection services)
    {
        throw new NotImplementedException();
    }
    public static IServiceCollection AddRSACryptoService(this IServiceCollection services, Action<RSACryptoOptions> setupAction)
    {
        throw new NotImplementedException();
    }

    public static IServiceCollection AddRSACryptoService(this IServiceCollection services, IConfiguration configuration)
    {
        throw new NotImplementedException();
    }

    #endregion
}
