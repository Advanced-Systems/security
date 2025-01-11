using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Abstractions.Exceptions;
using AdvancedSystems.Security.Cryptography;

namespace AdvancedSystems.Security.Extensions;

/// <summary>
///     Defines functions for interacting with X.509 certificates.
/// </summary>
/// <seealso href="https://datatracker.ietf.org/doc/rfc5280/"/>
public static partial class CertificateStoreExtensions
{
    /// <summary>
    ///     Retrieves an X.509 certificate from the specified store using the provided thumbprint.
    /// </summary>
    /// <typeparam name="T">
    ///     The type of the certificate store, which must implement the <see cref="ICertificateStore"/> interface.
    /// </typeparam>
    /// <param name="store">
    ///     The certificate store from which to retrieve the certificate.
    /// </param>
    /// <param name="thumbprint">
    ///     The thumbprint of the certificate to locate.
    /// </param>
    /// <param name="validOnly">
    ///     <see langword="true"/> to allow only valid certificates to be returned from the search; otherwise, <see langword="false"/>.
    /// </param>
    /// <returns>
    ///     The <see cref="X509Certificate2"/> object if the certificate is found.
    /// </returns>
    /// <exception cref="CertificateNotFoundException">
    ///     Thrown when no certificate with the specified thumbprint is found in the store.
    /// </exception>
    public static X509Certificate2 GetCertificate<T>(this T store, string thumbprint, bool validOnly = true) where T : ICertificateStore
    {
        store.Open(OpenFlags.ReadOnly);

        var certificate = store.Certificates
            .Find(X509FindType.FindByThumbprint, thumbprint, validOnly)
            .OfType<X509Certificate2>()
            .FirstOrDefault();

        return certificate
            ?? throw new CertificateNotFoundException($"""No {(validOnly ? "valid " : string.Empty)}certificate with thumbprint "{thumbprint}" could be found in the store.""");
    }

    /// <summary>
    ///     Attempts to parse the specified distinguished name (DN) string into a <see cref="DistinguishedName"/> object.
    /// </summary>
    /// <param name="distinguishedName">
    ///     The DN string to parse, typically in the X.500 or LDAP DN format.
    /// </param>
    /// <param name="result">
    ///     When this method returns, contains the parsed <see cref="DistinguishedName"/> object if the parsing was successful; 
    ///     otherwise, <see langword="null"/>.
    /// </param>
    /// <returns>
    ///     <see langword="true"/> if the parsing was successful; otherwise, <see langword="false"/>.
    /// </returns>
    /// <remarks>
    ///     The X.500 Distinguished Name (DN) and the LDAP Distinguished Name (DN) differ in syntax and conventions.
    ///     <list type="table">
    ///         <listheader>
    ///             <term>
    ///                 X.500 Format
    ///             </term>
    ///             <description>
    ///                 Comes from the X.500 standard for directory services
    ///             </description>
    ///         </listheader>
    ///         <item>
    ///             <term>
    ///                 Separator
    ///             </term>
    ///             <description>
    ///                 Components are separated by commas (<c>,</c>).
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <term>
    ///                 Order
    ///             </term>
    ///             <description>
    ///                 Attributes are typically listed in the most significant to least significant order
    ///                 (<i>root</i> to <i>leaf</i>).
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <term>
    ///                 Attributes
    ///             </term>
    ///             <description>
    ///                 Attributes are case-insensitive but are conventionally written in uppercase. Note that
    ///                 attribute names are more verbose in some X.500 implementations.
    ///             </description>
    ///         </item>
    ///     </list>
    ///     <list type="table">
    ///         <listheader>
    ///             <term>
    ///                 LDAP
    ///             </term>
    ///             <description>
    ///                 A streamlined version of the X.500 DN, tailored for LDAP (Lightweight Directory Access Protocol).
    ///             </description>
    ///         </listheader>
    ///         <item>
    ///             <term>
    ///                 Separator
    ///             </term>
    ///             <description>
    ///                 Components are separated by commas (<c>,</c>), like X.500, but semicolons (<c>;</c>) are also sometimes
    ///                 allowed (albeit less common).
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <term>
    ///                 Order
    ///             </term>
    ///             <description>
    ///                  Attributes are typically listed in the least significant to most significant order (<i>leaf</i> to <i>root</i>),
    ///                  though many implementations allow flexibility.
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <term>
    ///                 Attributes
    ///             </term>
    ///             <description>
    ///                 LDAP uses abbreviated attribute names (e.g., CN for common name, O for organization, OU for organizational unit).
    ///                 It is also more permissive with regards to case sensitivity and attribute formatting.
    ///             </description>
    ///         </item>
    ///     </list>
    /// </remarks>
    /// <seealso href="https://datatracker.ietf.org/doc/html/rfc4514"/>
    public static bool TryParseDistinguishedName(string distinguishedName, out DistinguishedName? result)
    {
        var rdns = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var dn = new X500DistinguishedName(distinguishedName);

        foreach (var rdn in dn.EnumerateRelativeDistinguishedNames())
        {
            string? attribute = rdn.GetSingleElementType().FriendlyName;
            string value = rdn.GetSingleElementValue() ?? string.Empty;

            if (string.IsNullOrEmpty(attribute)) continue;

            rdns.Add(attribute, value);
        }

        bool hasCountry = rdns.TryGetValue(RDN.C, out string? country);
        bool hasCommonName = rdns.TryGetValue(RDN.CN, out string? commonName);
        bool hasLocality = rdns.TryGetValue(RDN.L, out string? locality);
        bool hasOrganization = rdns.TryGetValue(RDN.O, out string? organization);
        bool hasOrganizationalUnit = rdns.TryGetValue(RDN.OU, out string? organizationalUnit);
        bool hasState = rdns.TryGetValue(RDN.S, out string? state);

        bool hasRelativeDistinguishedNames = hasCountry
            || hasCommonName
            || hasLocality
            || hasOrganization
            || hasOrganizationalUnit
            || hasState;

        result = hasRelativeDistinguishedNames ? new DistinguishedName
        {
            CommonName = commonName,
            OrganizationalUnit = organizationalUnit,
            Organization = organization,
            Locality = locality,
            State = state,
            Country = country,
        } : null;

        return hasRelativeDistinguishedNames;
    }
}