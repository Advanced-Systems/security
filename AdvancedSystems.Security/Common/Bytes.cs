using System;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace AdvancedSystems.Security.Common;

/// <summary>
///     Implements various utility methods for manipulating byte arrays and spans in cryptographic operations.
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

    public static byte[] GetBytes<T>(T value) where T : INumber<T> => value switch
    {
        bool boolValue => BitConverter.GetBytes(boolValue),
        char charValue => BitConverter.GetBytes(charValue),
        double doubleValue => BitConverter.GetBytes(doubleValue),
        Half halfValue => BitConverter.GetBytes(halfValue),
        short shortValue => BitConverter.GetBytes(shortValue),
        int intValue => BitConverter.GetBytes(intValue),
        long longValue => BitConverter.GetBytes(longValue),
        float floatValue => BitConverter.GetBytes(floatValue),
        ushort ushortValue => BitConverter.GetBytes(ushortValue),
        uint uintValue => BitConverter.GetBytes(uintValue),
        ulong ulongValue => BitConverter.GetBytes(ulongValue),
        _ => throw new ArgumentException("Failed to convert T to an array of bytes.", nameof(value))
    };

    /// <summary>
    ///     Gets the bytes of a <see cref="SecureString"/> object.
    /// </summary>
    /// <param name="secureString">
    ///     Represents a text that should be kept confidential, such as a password.
    /// </param>
    /// <param name="encoding">
    ///     The character encoding used to convert all characters in the underlying <seealso cref="string"/>
    ///     into a sequence of bytes.
    /// </param>
    /// <returns>
    ///     Returns the bytes of the current instance.
    ///  </returns>
    /// <remarks>
    ///     This method exposes the internal state of <see cref="SecureString"/> through marshaling.
    ///     It is no longer recommended to use the <see cref="SecureString"/> for new development
    ///     on .NET Core projects.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    ///     Thrown when <paramref name="secureString"/> is <c>null</c>.
    /// </exception>
    /// <seealso href="https://github.com/dotnet/platform-compat/blob/master/docs/DE0001.md"/>
    [Obsolete]
    public static byte[] GetBytes(this SecureString secureString, Encoding? encoding = null)
    {
        ArgumentNullException.ThrowIfNull(secureString, nameof(secureString));
        encoding ??= Encoding.UTF8;
        IntPtr strPtr = IntPtr.Zero;

        try
        {
            strPtr = Marshal.SecureStringToGlobalAllocUnicode(secureString);
            return encoding.GetBytes(Marshal.PtrToStringUni(strPtr)!);
        }
        finally
        {
            if (strPtr != IntPtr.Zero)
            {
                Marshal.ZeroFreeGlobalAllocUnicode(strPtr);
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool Equals(this byte[] lhs, byte[] rhs)
    {
        return new Span<byte>(lhs).SequenceEqual(rhs);
    }
}
