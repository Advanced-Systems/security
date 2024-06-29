using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Services;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AdvancedSystems.Security.DependencyInjection;

public static class CryptoServiceCollectionExtensions
{
    public static IServiceCollection AddHashService(this IServiceCollection services)
    {
        services.TryAdd(ServiceDescriptor.Singleton<IHashService, HashService>());
        return services;
    }

    public static IServiceCollection AddCertificateService(this IServiceCollection services)
    {
        services.TryAdd(ServiceDescriptor.Singleton<ICertificateService, CertificateService>());
        return services;
    }

    public static IServiceCollection AddRSACryptoService(this IServiceCollection services)
    {
        services.TryAdd(ServiceDescriptor.Singleton<IRSACryptoService, RSACryptoService>());
        return services;
    }
}
