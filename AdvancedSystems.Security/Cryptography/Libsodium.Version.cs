using System;
using System.Runtime.InteropServices;

using static AdvancedSystems.Security.Interop.Libsodium;

namespace AdvancedSystems.Security.Cryptography;

/// <summary>
///     A .NET wrapper class that provides bindings to the native <c>libsodium</c> library.
/// </summary>
/// <remarks>
///     See also: <seealso href="https://www.nuget.org/packages/libsodium"/>.
/// </remarks>
public static partial class Libsodium
{
    #region Properties

    /// <summary>
    ///     Gets the version number of the underlying <c>libsodium</c> NuGet package.
    /// </summary>
    /// <exception cref="ArgumentNullException">
    ///     Raised if the native code execution failed to retrieve the version number.
    /// </exception>
    /// <remarks>
    ///     <inheritdoc cref="Libsodium" path="/remarks"/>
    /// </remarks>
    public static Version Version
    {
        get
        {
            string? version = Marshal.PtrToStringAnsi(SodiumVersionString());
            ArgumentNullException.ThrowIfNull(version, nameof(version));

            return new Version(version);
        }
    }

    /// <summary>
    ///     Gets the major version number of the underlying native <c>libsodium</c> DLL.
    /// </summary>
    public static int MajorVersion
    {
        get
        {
            return SodiumLibraryVersionMajor();
        }
    }

    /// <summary>
    ///     Gets the minor version number of the underlying native <c>libsodium</c> DLL.
    /// </summary>
    public static int MinorVersion
    {
        get
        {
            return SodiumLibraryVersionMinor();
        }
    }

    #endregion
}