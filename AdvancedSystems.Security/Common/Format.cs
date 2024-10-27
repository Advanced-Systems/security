namespace AdvancedSystems.Security.Common;

/// <summary>
///     Describes string formatting options for byte arrays.
/// </summary>
public enum Format
{
    /// <summary>
    ///     Decode an array of bytes into a string using the operating system's current ANSI
    ///     code page.
    /// </summary>
    String = 0,

    /// <summary>
    ///     Convert the numeric value of each element of a specified array of bytes to its
    ///     equivalent hexadecimal string representation.
    /// </summary>
    Hex = 1,

    /// <summary>
    ///     Convert an array of bytes to its equivalent string representation that is encoded
    ///     with base-64 digits.
    /// </summary>
    Base64 = 2,
}