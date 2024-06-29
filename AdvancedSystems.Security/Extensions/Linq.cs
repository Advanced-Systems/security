using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;

namespace AdvancedSystems.Security.Extensions;

public static class Linq
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool IsNullOrEmpty<T>(this IEnumerable<T> source)
    {
        return (source == null || !source.Any());
    }
}
