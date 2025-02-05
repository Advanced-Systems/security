using System;
using System.Runtime.InteropServices;

namespace AdvancedSystems.Security.Interop;

internal static partial class Libsodium
{
    [DllImport(NativeLibrary.LIBSODIUM, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int sodium_library_version_major();

    [DllImport(NativeLibrary.LIBSODIUM, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int sodium_library_version_minor();

    [DllImport(NativeLibrary.LIBSODIUM, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr sodium_version_string();
}