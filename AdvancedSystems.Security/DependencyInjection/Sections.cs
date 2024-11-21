using AdvancedSystems.Security.Options;

namespace AdvancedSystems.Security.DependencyInjection;

/// <summary>
///     Defines section keys for <c>appsettings.json</c>.
/// </summary>
public static partial class Sections
{
    /// <summary>
    ///     Key used to bind the <seealso cref="CertificateOptions"/> configuration section.
    /// </summary>
    public const string CERTIFICATE = "Certificate";

    /// <summary>
    ///     Key used to bind the <seealso cref="RSACryptoOptions"/> configuration section.
    /// </summary>
    public const string RSA = "RSA";

    /// <summary>
    ///     Key used to bind the <seealso cref="STORE"/> configuration section.
    /// </summary>
    public const string STORE = "Store";
}