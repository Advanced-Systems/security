using System;
using System.Text;

using AdvancedSystems.Security.Cryptography;

namespace AdvancedSystems.Security.Extensions;

/// <summary>
///     Implements extension methods built-in types. See also:
///     <seealso href="https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/builtin-types/built-in-types"/>.
/// </summary>
public static class CoreExtensions
{
    public static string ToString(this byte[] array, Format format)
    {
        return format switch
        {
            Format.Hex => Convert.ToHexString(array).ToLower(),
            Format.Base64 => Convert.ToBase64String(array),
            Format.String => Encoding.UTF8.GetString(array),
            _ => throw new NotSupportedException($"Case {format} is not implemented.")
        };
    }

    public static byte[] GetBytes(this string @string, Format format)
    {
        return format switch
        {
            Format.Hex => Convert.FromHexString(@string),
            Format.Base64 => Convert.FromBase64String(@string),
            Format.String => Encoding.UTF8.GetBytes(@string),
            _ => throw new NotSupportedException($"Case {format} is not implemented.")
        };
    }
}