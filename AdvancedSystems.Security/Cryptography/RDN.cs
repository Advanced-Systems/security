namespace AdvancedSystems.Security.Cryptography;

/// <summary>
///     The Relative Distinguished Names (RDNs) are attribute-value pairs that
///     uniquely identify an entity.
/// </summary>
/// <remarks>
///     This class defines the attributes that annotate one or more values.
/// </remarks>
/// <seealso cref="DistinguishedName"/>
/// <seealso href="https://datatracker.ietf.org/doc/html/rfc4514"/>
public static class RDN
{
    /// <summary>
    ///     Country (<c>C</c>)
    /// </summary>
    /// <remarks>
    ///     This field could also be used to store the region.
    /// </remarks>
    public const string C = "C";

    /// <summary>
    ///     Common Name (<c>CN</c>)
    /// </summary>
    /// <remarks>
    ///     This field denotes the certificate owner's common name.
    /// </remarks>
    public const string CN = "CN";

    /// <summary>
    ///     Locality (<c>L</c>)
    /// </summary>
    /// <remarks>
    ///     This field could also be used to store the city.
    /// </remarks>
    public const string L = "L";

    /// <summary>
    ///     Organization (<c>O</c>)
    /// </summary>
    public const string O = "O";

    /// <summary>
    ///     Organizational Unit (<c>OU</c>)
    /// </summary>
    public const string OU = "OU";

    /// <summary>
    ///     State (<c>S</c>)
    /// </summary>
    /// <remarks>
    ///     This field could also be used to store the province.
    /// </remarks>
    public const string S = "S";
}