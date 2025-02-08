using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace AdvancedSystems.Security.Interop;

internal static partial class Libsodium
{
    [LibraryImport(NativeLibrary.LIBSODIUM, EntryPoint = "sodium_library_version_major")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int SodiumLibraryVersionMajor();

    [LibraryImport(NativeLibrary.LIBSODIUM, EntryPoint = "sodium_library_version_minor")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int SodiumLibraryVersionMinor();

    [LibraryImport(NativeLibrary.LIBSODIUM, EntryPoint = "sodium_version_string")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial IntPtr SodiumVersionString();
}