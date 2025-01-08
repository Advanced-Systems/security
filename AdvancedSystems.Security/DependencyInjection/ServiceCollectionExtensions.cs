using System;
using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Core.DependencyInjection;
using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Options;
using AdvancedSystems.Security.Services;
using AdvancedSystems.Security.Validators;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.VisualBasic.FileIO;

namespace AdvancedSystems.Security.DependencyInjection;

public static partial class ServiceCollectionExtensions
{
    #region CryptoRandom

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

    #region CertificateStore

    private record CertificateOptionsCarrier(StoreName StoreName, StoreLocation StoreLocation);

    private static IServiceCollection AddCertificateStore(this IServiceCollection services)
    {
        services.TryAdd(ServiceDescriptor.Singleton<ICertificateStore>(serviceProvider =>
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
    /// <param name="setupAction">
    ///     An action used to configure <seealso cref="CertificateStoreOptions"/>.
    /// </param>
    /// <returns>
    ///     The value of <paramref name="services"/>.
    /// </returns>
    public static IServiceCollection AddCertificateStore(this IServiceCollection services, Action<CertificateStoreOptions> setupAction)
    {
        services.AddOptions()
            .Configure(setupAction);

        services.AddCertificateStore();
        return services;
    }

    /// <summary>
    ///     Adds the default implementation of <seealso cref="ICertificateStore"/> to <paramref name="services"/>.
    /// </summary>
    /// <param name="services">
    ///     The service collection containing the service.
    /// </param>
    /// <param name="configurationSection">
    ///     A configuration section targeting <seealso cref="CertificateStoreOptions"/>.
    /// </param>
    /// <returns>
    ///     The value of <paramref name="services"/>.
    /// </returns>
    public static IServiceCollection AddCertificateStore(this IServiceCollection services, IConfigurationSection configurationSection)
    {
        services.TryAddOptions<CertificateStoreOptions>(configurationSection);
        services.AddCertificateStore();
        return services;
    }

    #endregion

    #region CertificateService

    private static IServiceCollection AddCertificateService(this IServiceCollection services)
    {
        services.TryAdd(ServiceDescriptor.Scoped<ICertificateService, CertificateService>());
        services.TryAdd(ServiceDescriptor.Singleton<IValidateOptions<CertificateOptions>, CertificateOptionsValidator>());

        return services;
    }

    /// <summary>
    ///     Adds the default implementation of <seealso cref="ICertificateService"/> to <paramref name="services"/>.
    /// </summary>
    /// <param name="services">
    ///     The service collection containing the service.
    /// </param>
    /// <param name="setupAction">
    ///     An action used to configure <seealso cref="CertificateOptions"/>.
    /// </param>
    /// <returns>
    ///     The value of <paramref name="services"/>.
    /// </returns>
    public static IServiceCollection AddCertificateService(this IServiceCollection services, Action<CertificateOptions> setupAction)
    {
        services.AddOptions()
            .Configure(setupAction);

        services.Configure<CertificateStoreOptions>(options =>
        {
            var certificateOptions = new CertificateOptions();
            setupAction.Invoke(certificateOptions);

            var store = certificateOptions.Store
                ?? throw new ArgumentNullException(nameof(setupAction), $"{nameof(CertificateStoreOptions)} settings are undefined.");

            options.Name = store.Name;
            options.Location = store.Location;
        });

        services.AddCertificateStore();
        services.AddCertificateService();

        return services;
    }

    /// <summary>
    ///     Adds the default implementation of <seealso cref="ICertificateService"/> to <paramref name="services"/>.
    /// </summary>
    /// <param name="services">
    ///     The service collection containing the service.
    /// </param>
    /// <param name="configurationSection">
    ///     A configuration section targeting <seealso cref="CertificateOptions"/>. NOTE: This configuration requires a nested
    ///     <seealso cref="Sections.STORE"/> section within the previous section.
    /// </param>
    /// <returns>
    ///     The value of <paramref name="services"/>.
    /// </returns>
    public static IServiceCollection AddCertificateService(this IServiceCollection services, IConfigurationSection configurationSection)
    {
        services.TryAddOptions<CertificateOptions>(configurationSection);
        services.AddCertificateStore(configurationSection.GetRequiredSection(Sections.STORE));
        services.AddCertificateService();

        return services;
    }

    #endregion

    #region RSACryptoService

    private static IServiceCollection AddRSACryptoService(this IServiceCollection services)
    {
        throw new NotImplementedException();
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
        throw new NotImplementedException();
    }

    #endregion
}