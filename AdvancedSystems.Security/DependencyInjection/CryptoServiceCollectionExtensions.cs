using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Services;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AdvancedSystems.Security.DependencyInjection;

public static class CryptoServiceCollectionExtensions
{
    public static IServiceCollection AddHashService(this IServiceCollection services)
    {
        services.TryAdd(ServiceDescriptor.Scoped<IHashService, HashService>());
        return services;
    }

    public static IServiceCollection AddCertificateService(this IServiceCollection services)
    {
        // TODO: Bind settings, and provide a ICertificateBuilder
        services.AddOptions();
        services.TryAdd(ServiceDescriptor.Scoped<ICertificateService, CertificateService>());
        return services;
    }

    public static IServiceCollection AddRSACryptoService(this IServiceCollection services)
    {
        // Register services required by RSACryptoService
        services.AddCertificateService();

        // TODO: Bind settings, and provide a IRSACryptoBuilder
        services.AddOptions();

        services.TryAdd(ServiceDescriptor.Singleton<IRSACryptoService, RSACryptoService>());
        return services;
    }
}
