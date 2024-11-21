using System.Security.Cryptography.X509Certificates;

namespace AdvancedSystems.Security.Cryptography;

/// <summary>
///     Defines the Distinguished Name (DN) of an entity that owns or issued the certificate.
///     This entity is typically a Certificate Authority (CA) or an intermediate CA in a chain of trust.
/// </summary>
/// <remarks>
///     DN is a term that describes the identifying information in a certificate and is
///     part of the <seealso cref="X509Certificate2"/> itself. A certificate contains DN
///     information for both the owner or requestor of the certificate (called the Subject DN)
///     and the CA that issues the certificate (called the Issuer DN). Depending on the
///     identification policy of the CA that issues a certificate, the DN can include a variety
///     of information.
/// </remarks>
/// <seealso href="https://datatracker.ietf.org/doc/html/rfc4514"/>
public sealed record DistinguishedName
{
    /// <summary>
    ///     Gets or sets the <inheritdoc cref="RDN.C" path="/summary"/>.
    /// </summary>
    /// <remarks>
    ///     <inheritdoc cref="RDN.C" path="/remarks"/>
    /// </remarks>
    public string? Country { get; init; }

    /// <summary>
    ///     Gets or sets the <inheritdoc cref="RDN.CN" path="/summary"/>.
    /// </summary>
    /// <remarks>
    ///     <inheritdoc cref="RDN.CN" path="/remarks"/>
    /// </remarks>
    public string? CommonName { get; init; }

    /// <summary>
    ///     Gets or sets the <inheritdoc cref="RDN.L" path="/summary"/>.
    /// </summary>
    /// <remarks>
    ///     <inheritdoc cref="RDN.L" path="/remarks"/>
    /// </remarks>
    public string? Locality { get; init; }

    /// <summary>
    ///     Gets or sets the <inheritdoc cref="RDN.O" path="/summary"/>.
    /// </summary>
    public string? Organization { get; init; }

    /// <summary>
    ///     Gets or sets the <inheritdoc cref="RDN.OU" path="/summary"/>.
    /// </summary>
    public string? OrganizationalUnit { get; init; }

    /// <summary>
    ///     Gets or sets the <inheritdoc cref="RDN.S" path="/summary"/>..
    /// </summary>
    /// <remarks>
    ///     <inheritdoc cref="RDN.S" path="/remarks"/>
    /// </remarks>
    public string? State { get; init; }
}