using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace AdvancedSystems.Security.Extensions;

public static class SecureStringExtensions
{
    /// <summary>
    ///     Gets the bytes of a <see cref="SecureString"/> object.
    /// </summary>
    /// <param name="secureString">
    ///     Represents a text that should be kept confidential, such as a password.
    /// </param>
    /// <param name="encoding">
    ///     The character encoding used to convert all characters in the underlying <see langword="string"/>
    ///     into a sequence of bytes.
    /// </param>
    /// <returns>
    ///     Returns the bytes of the current instance.
    ///  </returns>
    /// <remarks>
    ///     <para>
    ///         This method exposes the internal state of <see cref="SecureString"/> through marshaling.
    ///         It is no longer recommended to use the <see cref="SecureString"/> for new development
    ///         on .NET CryptoCore projects.
    ///     </para>
    ///     <para>
    ///         See also: <seealso href="https://github.com/dotnet/platform-compat/blob/master/docs/DE0001.md"/>.
    ///     </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    ///     Thrown when <paramref name="secureString"/> is <see langword="null"/>.
    /// </exception>
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

    /// <summary>
    ///     Returns an managed derived from the contents of a managed <seealso cref="SecureString"/> object.
    /// </summary>
    /// <param name="secureString">
    ///     Represents a text that should be kept confidential, such as a password.
    /// </param>
    /// <returns>
    ///     A managed string that holds the contents of the <seealso cref="SecureString"/> object.
    /// </returns>
    /// <remarks>
    ///     <inheritdoc cref="GetBytes(SecureString, Encoding?)" path="/remarks"/>
    /// </remarks>
    [Obsolete]
    public static string ToString(this SecureString secureString)
    {
        ArgumentNullException.ThrowIfNull(secureString, nameof(secureString));
        IntPtr strPtr = IntPtr.Zero;

        try
        {
            strPtr = Marshal.SecureStringToBSTR(secureString);
            return Marshal.PtrToStringBSTR(strPtr);
        }
        finally
        {
            if (strPtr != IntPtr.Zero)
            {
                Marshal.ZeroFreeBSTR(strPtr);
            }
        }
    }
}