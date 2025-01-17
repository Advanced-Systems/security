using System;

namespace AdvancedSystems.Security.Internals;

/// <summary>
///     Functions defined in this class can have <i>dangerous</i> security implications if
///     used incorrectly. Because of the high risk accociated with working at this level,
///     this is referred to as the "hazardous materials" (short: "hazmat") layer.
/// </summary>
public static class Hazmat
{
    /// <summary>
    ///     Gets an array of type <typeparamref name="T"/> and size <paramref name="size"/>
    ///     while skipping zero-initialization, if possible.
    /// </summary>
    /// <typeparam name="T">Specifies the type of the array element.</typeparam>
    /// <param name="size">The size of the array to initialize.</param>
    /// <returns>Returns an uninitialized array.</returns>
    /// <remarks>
    ///     Skipping zero-initialization is a security risk. The unitialized array can contain invalid
    ///     valuetype instances or sensitive information created by other parts of the application. The
    ///     code operating on unitialized arrays should be heavily scrutinized to ensure that the
    ///     unitialized data is never read.
    ///     
    ///     Skipping zero-initialization using this API only has a material performance benefit for
    ///     large arrays, such as buffers of several kilobytes or more.
    /// </remarks>
    public static T[] GetUninitializedArray<T>(int size) where T : unmanaged
    {
        // If pinned is set to true, T must not be a reference type or a type that contains object references.
        return GC.AllocateUninitializedArray<T>(size, pinned: true);
    }
}