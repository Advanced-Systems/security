using System;
using System.Runtime.InteropServices;

using static AdvancedSystems.Security.Interop.Libsodium;

namespace AdvancedSystems.Security.Cryptography;

public static partial class Libsodium
{
    #region Properties

    /// <summary>
    ///     Gets the version number of the underlying <c>libsodium</c> NuGet package.
    /// </summary>
    /// <remarks>
    ///     See also: <seealso href="https://www.nuget.org/packages/libsodium"/>.
    /// </remarks>
    public static Version Version
    {
        get
        {
            string? version = Marshal.PtrToStringAnsi(sodium_version_string());
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
            return sodium_library_version_major();
        }
    }

    /// <summary>
    ///     Gets the minor version number of the underlying native <c>libsodium</c> DLL.
    /// </summary>
    public static int MinorVersion
    {
        get
        {
            return sodium_library_version_minor();
        }
    }

    #endregion
}