using System;
using System.Text;

using AdvancedSystems.Security.Common;

namespace AdvancedSystems.Security.Extensions;

/// <summary>
///     Implements extension methods for manipulating byte arrays.
/// </summary>
public static class Bytes
{
    public static string ToString(this byte[] array, Format format)
    {
        return format switch
        {
            Format.Hex => BitConverter.ToString(array).Replace("-", string.Empty).ToLower(),
            Format.Base64 => Convert.ToBase64String(array),
            Format.String => Encoding.UTF8.GetString(array),
            _ => throw new NotSupportedException($"String formatting is not implemted for {format}.")
        };
    }
}