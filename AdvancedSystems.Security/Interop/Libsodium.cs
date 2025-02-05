using System;
using System.Runtime.InteropServices;

namespace AdvancedSystems.Security.Interop;

internal partial class Libsodium
{
    #region version.c

    [LibraryImport(NativeLibrary.LIBSODIUM, EntryPoint = "sodium_library_version_major")]
    internal static partial int SodiumLibraryVersionMajor();

    [LibraryImport(NativeLibrary.LIBSODIUM, EntryPoint = "sodium_library_version_minor")]
    internal static partial int SodiumLibraryVersionMinor();

    [LibraryImport(NativeLibrary.LIBSODIUM, EntryPoint = "sodium_version_string")]
    internal static partial IntPtr SodiumVersionString();

    #endregion
}