using System;
using System.IO.Abstractions;

using AdvancedSystems.Core.DependencyInjection;
using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Options;
using AdvancedSystems.Security.Services;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AdvancedSystems.Security.DependencyInjection;

public static partial class ServiceCollectionExtensions
{
    #region CertificateService

    /// <summary>
    ///     Adds the default implementation of <seealso cref="ICertificateService"/> to <paramref name="services"/>.
    /// </summary>
    /// <param name="services">
    ///     The service collection containing the service.
    /// </param>
    /// <returns>
    ///     The value of <paramref name="services"/>.
    /// </returns>
    public static IServiceCollection AddCertificateService(this IServiceCollection services)
    {
        services.TryAdd(ServiceDescriptor.Singleton<IFileSystem, FileSystem>());
        services.TryAdd(ServiceDescriptor.Scoped<ICertificateService, CertificateService>());

        return services;
    }

    #endregion

    #region CertificateStore

    private static IServiceCollection AddCertificateStore(this IServiceCollection services, string key)
    {
        services.TryAdd(ServiceDescriptor.KeyedSingleton<ICertificateStore>(key, (serviceProvider, _) =>
        {
            var options = serviceProvider.GetRequiredService<IOptions<CertificateStoreOptions>>().Value;
            return new CertificateStore(options.Name, options.Location);
        }));

        return services;
    }

    /// <summary>
    ///     Adds the default implementation of <seealso cref="ICertificateStore"/> to <paramref name="services"/>.
    /// </summary>
    /// <param name="services">
    ///     The service collection containing the service.
    /// </param>
    /// <param name="key">
    ///     Name of the keyed <seealso cref="ICertificateStore"/> service.
    /// </param>
    /// <param name="setupAction">
    ///     An action used to configure <seealso cref="CertificateStoreOptions"/>.
    /// </param>
    /// <returns>
    ///     The value of <paramref name="services"/>.
    /// </returns>
    public static IServiceCollection AddCertificateStore(this IServiceCollection services, string key, Action<CertificateStoreOptions> setupAction)
    {
        services.AddOptions()
            .Configure(setupAction);

        services.AddCertificateStore(key);
        return services;
    }

    /// <summary>
    ///     Adds the default implementation of <seealso cref="ICertificateStore"/> to <paramref name="services"/>.
    /// </summary>
    /// <param name="services">
    ///     The service collection containing the service.
    /// </param>
    /// <param name="key">
    ///     Name of the keyed <seealso cref="ICertificateStore"/> service.
    /// </param>
    /// <param name="configurationSection">
    ///     A configuration section targeting <seealso cref="CertificateStoreOptions"/>.
    /// </param>
    /// <returns>
    ///     The value of <paramref name="services"/>.
    /// </returns>
    public static IServiceCollection AddCertificateStore(this IServiceCollection services, string key, IConfigurationSection configurationSection)
    {
        services.TryAddOptions<CertificateStoreOptions>(configurationSection);
        services.AddCertificateStore(key);
        return services;
    }

    #endregion

    #region CryptoRandomService

    /// <summary>
    ///     Adds the default implementation of <seealso cref="ICryptoRandomService"/> to <paramref name="services"/>.
    /// </summary>
    /// <param name="services">
    ///     The service collection containing the service.
    /// </param>
    /// <returns>
    ///     The value of <paramref name="services"/>.
    /// </returns>
    public static IServiceCollection AddCryptoRandomService(this IServiceCollection services)
    {
        services.TryAdd(ServiceDescriptor.Scoped<ICryptoRandomService, CryptoRandomService>());
        return services;
    }

    #endregion

    #region HashService

    /// <summary>
    ///     Adds the default implementation of <seealso cref="IHashService"/> to <paramref name="services"/>.
    /// </summary>
    /// <param name="services">
    ///     The service collection containing the service.
    /// </param>
    /// <returns>
    ///     The value of <paramref name="services"/>.
    /// </returns>
    public static IServiceCollection AddHashService(this IServiceCollection services)
    {
        services.TryAdd(ServiceDescriptor.Scoped<IHashService, HashService>());
        return services;
    }

    #endregion

    #region HMACService

    /// <summary>
    ///     Adds the default implementation of <seealso cref="IHMACService"/> to <paramref name="services"/>.
    /// </summary>
    /// <param name="services">
    ///     The service collection containing the service.
    /// </param>
    /// <returns>
    ///     The value of <paramref name="services"/>.
    /// </returns>
    public static IServiceCollection AddHMACService(this IServiceCollection services)
    {
        services.TryAdd(ServiceDescriptor.Scoped<IHMACService, HMACService>());
        return services;
    }

    #endregion

    #region KDFService

    /// <summary>
    ///     Adds the default implementation of <seealso cref="IKDFService"/> to <paramref name="services"/>.
    /// </summary>
    /// <param name="services">
    ///     The service collection containing the service.
    /// </param>
    /// <returns>
    ///     The value of <paramref name="services"/>.
    /// </returns>
    public static IServiceCollection AddKDFService(this IServiceCollection services)
    {
        services.TryAdd(ServiceDescriptor.Scoped<IKDFService, KDFService>());
        return services;
    }

    #endregion

    #region RSACryptoService

    private static IServiceCollection AddRSACryptoService(this IServiceCollection services)
    {
        services.TryAdd(ServiceDescriptor.Singleton<IRSACryptoService, RSACryptoService>());

        return services;
    }

    /// <summary>
    ///     Adds the default implementation of <seealso cref="IRSACryptoService"/> to <paramref name="services"/>.
    /// </summary>
    /// <param name="services">
    ///     The service collection containing the service.
    /// </param>
    /// <param name="setupAction">
    ///     An action used to configure <seealso cref="RSACryptoOptions"/>.
    /// </param>
    /// <returns>
    ///     The value of <paramref name="services"/>.
    /// </returns>
    public static IServiceCollection AddRSACryptoService(this IServiceCollection services, Action<RSACryptoOptions> setupAction)
    {
        services.AddRSACryptoService();

        throw new NotImplementedException();
    }

    /// <summary>
    ///     Adds the default implementation of <seealso cref="IRSACryptoService"/> to <paramref name="services"/>.
    /// </summary>
    /// <param name="services">
    ///     The service collection containing the service.
    /// </param>
    /// <param name="configurationSection">
    ///     A configuration section targeting <seealso cref="RSACryptoOptions"/>.
    /// </param>
    /// <returns>
    ///     The value of <paramref name="services"/>.
    /// </returns>
    public static IServiceCollection AddRSACryptoService(this IServiceCollection services, IConfigurationSection configurationSection)
    {
        services.AddRSACryptoService();

        throw new NotImplementedException();
    }

    #endregion
}